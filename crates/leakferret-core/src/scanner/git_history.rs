//! Git history scanner. Walks commits between `since` and `until` and
//! runs the regular regex pre-filter against each added/modified blob.
//!
//! # Strategy: shell out to `git`
//!
//! We deliberately **do not** depend on `git2` / `libgit2`. The
//! workspace targets `x86_64-pc-windows-gnu` (see `rust-toolchain.toml`)
//! and `git2`'s `vendored-libgit2` feature pulls in a `CMake` + Perl
//! libgit2 build that is fragile on the Windows GNU toolchain and adds
//! C code we'd rather not audit. `git` itself is a hard prerequisite
//! for users who want history scanning (you cannot scan history without
//! it) so shelling out is the simpler, more portable choice — the same
//! approach gitleaks took before switching to `go-git`.
//!
//! Subprocess calls use [`tokio::process::Command`] for non-blocking IO
//! and consistent error handling with the rest of the async pipeline.
//!
//! # Algorithm
//!
//! 1. `git rev-list <since>..<until>` → list of commit SHAs (newest first).
//! 2. For each commit, `git diff-tree -r --no-commit-id --name-only
//!    --diff-filter=AM --root <commit>` → list of added / modified blob paths.
//! 3. For each (commit, path), `git show <commit>:<path>` → blob bytes.
//! 4. Run the same NUL-byte binary skip + UTF-8 check + regex pre-filter
//!    used by the working-tree [`Scanner`](crate::scanner::Scanner).
//! 5. Tag each [`Finding`] with `git_commit` (full SHA) and
//!    `git_commit_subject` (first line of commit message).
//!
//! Findings from a history scan have a `path` equal to the *path inside
//! that commit* (which may not exist in the working tree).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use tokio::process::Command;

use crate::finding::{Finding, Verdict};
use crate::patterns::PatternRegistry;
use crate::scanner::context_window;
use crate::Result;

/// Hard cap on per-blob size we'll bother feeding to the regex set.
/// Matches the default `max_file_bytes` in `EngineConfig`.
const DEFAULT_MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024;

/// Diff filter passed to `git diff-tree`. `A` = added, `M` = modified.
/// We deliberately do NOT include `D` (deleted) — there is no blob to
/// scan after a delete.
const DIFF_FILTER: &str = "AM";

/// Walks the commit history of a repository and surfaces findings from
/// every added/modified blob.
///
/// See the module-level docs for the algorithm. The scanner is
/// `Send + Sync` so it can be invoked from an async context, but the
/// scan itself is synchronous from the caller's perspective (each `git`
/// subprocess is awaited internally).
#[derive(Debug)]
pub struct GitHistoryScanner<'a> {
    repo_path: &'a Path,
    since: Option<String>,
    until: Option<String>,
    paths: Option<Vec<PathBuf>>,
    registry: &'a PatternRegistry,
    context_lines: usize,
    max_depth: Option<usize>,
    max_blob_bytes: u64,
}

impl<'a> GitHistoryScanner<'a> {
    /// New scanner. `since` and `until` are git revisions (e.g. `HEAD~10`,
    /// `v1.0.0`, or a commit SHA). `paths`, when present, restricts the
    /// commit walk to commits that touched at least one of those paths.
    pub fn new(repo_path: &'a Path, registry: &'a PatternRegistry) -> Self {
        Self {
            repo_path,
            since: None,
            until: None,
            paths: None,
            registry,
            context_lines: 3,
            max_depth: None,
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
        }
    }

    pub fn since(mut self, rev: impl Into<String>) -> Self {
        self.since = Some(rev.into());
        self
    }

    pub fn until(mut self, rev: impl Into<String>) -> Self {
        self.until = Some(rev.into());
        self
    }

    pub fn paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.paths = Some(paths);
        self
    }

    pub fn context_lines(mut self, n: usize) -> Self {
        self.context_lines = n;
        self
    }

    pub fn max_depth(mut self, n: usize) -> Self {
        self.max_depth = Some(n);
        self
    }

    pub fn max_blob_bytes(mut self, bytes: u64) -> Self {
        self.max_blob_bytes = bytes;
        self
    }

    /// Drive the scan. Enumerates every added/modified blob across the
    /// commit range in a single `git log --raw` pass, streams their
    /// contents through one long-lived `git cat-file --batch` process
    /// (deduplicated by OID), then runs the regex set over them in
    /// parallel. Returns findings sorted by (path, line, column).
    pub async fn scan(&self) -> Result<Vec<Finding>> {
        let (subjects, entries) = self.enumerate_entries().await?;
        tracing::info!(
            target: "leakferret::scanner::git_history",
            commits = subjects.len(),
            blobs = entries.len(),
            repo = %self.repo_path.display(),
            "git history scan starting",
        );

        // Read each unique blob exactly once.
        let mut seen = HashSet::new();
        let unique: Vec<String> = entries
            .iter()
            .map(|(_, _, oid)| oid)
            .filter(|oid| seen.insert((*oid).clone()))
            .cloned()
            .collect();
        let blobs = self.read_blobs(&unique).await?;

        // CPU-bound regex pass, parallel over blob references. The git I/O
        // is already done, so this is pure compute over cached bytes.
        let mut findings: Vec<Finding> = entries
            .par_iter()
            .flat_map_iter(|(sha, path, oid)| {
                let empty = Vec::new().into_iter();
                let Some(bytes) = blobs.get(oid) else {
                    return empty;
                };
                if bytes.len() as u64 > self.max_blob_bytes {
                    return empty;
                }
                if memchr::memchr(0, &bytes[..bytes.len().min(8192)]).is_some() {
                    return empty;
                }
                let Ok(text) = std::str::from_utf8(bytes) else {
                    return empty;
                };
                let mut fs = self.scan_text(text, path);
                let subject = subjects.get(sha);
                for f in &mut fs {
                    f.git_commit = Some(sha.clone());
                    if let Some(s) = subject {
                        if !s.is_empty() {
                            f.git_commit_subject = Some(s.clone());
                        }
                    }
                }
                fs.into_iter()
            })
            .collect();

        findings.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
        });

        tracing::info!(
            target: "leakferret::scanner::git_history",
            findings = findings.len(),
            "git history scan complete",
        );
        Ok(findings)
    }

    fn path_allowed(&self, path: &Path) -> bool {
        match &self.paths {
            None => true,
            Some(allowed) => allowed.iter().any(|p| path.starts_with(p) || p == path),
        }
    }

    fn scan_text(&self, text: &str, rel: &Path) -> Vec<Finding> {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let mut findings = Vec::new();
        for (idx, line) in lines.iter().enumerate() {
            let line_no_newline = line.trim_end_matches('\n').trim_end_matches('\r');
            for pat_idx in self.registry.matches(line_no_newline) {
                let Some((pattern, regex)) = self.registry.get(pat_idx) else {
                    continue;
                };
                for caps in regex.captures_iter(line_no_newline) {
                    let cap_idx = pattern.capture_group.min(caps.len().saturating_sub(1));
                    let Some(m) = caps.get(cap_idx) else { continue };
                    if m.as_str().is_empty() {
                        continue;
                    }
                    findings.push(Finding {
                        path: rel.to_path_buf(),
                        line: idx + 1,
                        column: m.start() + 1,
                        r#match: m.as_str().to_string(),
                        pattern: pattern.id.clone(),
                        severity: pattern.severity,
                        context: context_window(&lines, idx, self.context_lines),
                        verdict: Verdict::Unknown,
                        reason: None,
                        confidence: None,
                        verification: None,
                        fingerprint: None,
                        replacement: None,
                        git_commit: None,
                        git_commit_subject: None,
                    });
                }
            }
        }
        findings
    }

    /// One `git log --raw` pass yielding a commit→subject map and the flat
    /// list of `(sha, path, post-image blob OID)` for every added/modified
    /// file. Replaces the per-commit `diff-tree` + `show -s` subprocesses
    /// with a single call.
    #[allow(clippy::type_complexity)]
    async fn enumerate_entries(
        &self,
    ) -> Result<(HashMap<String, String>, Vec<(String, PathBuf, String)>)> {
        let mut cmd = self.git();
        // quotePath=false so paths come back literal (split on the tab).
        cmd.arg("-c").arg("core.quotePath=false").arg("log");
        if let Some(n) = self.max_depth {
            cmd.arg(format!("--max-count={n}"));
        }
        cmd.arg("--raw")
            .arg("--no-abbrev")
            .arg("--no-renames")
            .arg("--root") // root commit's tree counts as adds
            .arg(format!("--diff-filter={DIFF_FILTER}"))
            // SOH (\x01) prefixes commit header lines so we can tell them
            // from `:`-prefixed raw diff lines; US (\x1f) splits SHA from
            // subject. NUL is avoided — it truncates args on Windows.
            .arg("--pretty=format:\x01%H\x1f%s");
        let range = match (self.since.as_deref(), self.until.as_deref()) {
            (Some(s), Some(u)) => format!("{s}..{u}"),
            (Some(s), None) => format!("{s}..HEAD"),
            (None, Some(u)) => u.to_string(),
            (None, None) => "HEAD".to_string(),
        };
        cmd.arg(range);

        let out = run(cmd).await?;
        let mut subjects: HashMap<String, String> = HashMap::new();
        let mut entries: Vec<(String, PathBuf, String)> = Vec::new();
        let mut cur = String::new();
        for line in out.lines() {
            if let Some(rest) = line.strip_prefix('\x01') {
                let mut it = rest.splitn(2, '\x1f');
                let sha = it.next().unwrap_or("").to_string();
                let subj = it.next().unwrap_or("").to_string();
                cur.clone_from(&sha);
                subjects.insert(sha, subj);
            } else if let Some(rest) = line.strip_prefix(':') {
                // :<mode> <mode> <src_oid> <dst_oid> <status>\t<path>
                let Some((meta, path)) = rest.split_once('\t') else {
                    continue;
                };
                let fields: Vec<&str> = meta.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }
                let dst = fields[3];
                if dst.bytes().all(|b| b == b'0') {
                    continue; // no post-image (defensive; AM excludes deletes)
                }
                let pb = PathBuf::from(path);
                if !self.path_allowed(&pb) {
                    continue;
                }
                entries.push((cur.clone(), pb, dst.to_string()));
            }
        }
        Ok((subjects, entries))
    }

    /// Read every OID's bytes via a single `git cat-file --batch` process,
    /// reading responses concurrently with writing requests so the pipe
    /// buffers can't deadlock. Blobs over `max_blob_bytes`, and non-blob
    /// objects, are consumed but not buffered.
    async fn read_blobs(&self, oids: &[String]) -> Result<HashMap<String, Vec<u8>>> {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        if oids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut child = self
            .git()
            .stdin(Stdio::piped())
            .arg("cat-file")
            .arg("--batch")
            .spawn()
            .map_err(|e| crate::Error::Other(format!("git cat-file spawn failed: {e}")))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| crate::Error::Other("cat-file stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| crate::Error::Other("cat-file stdout unavailable".into()))?;

        let requests: Vec<String> = oids.to_vec();
        let writer = tokio::spawn(async move {
            for oid in &requests {
                if stdin.write_all(oid.as_bytes()).await.is_err()
                    || stdin.write_all(b"\n").await.is_err()
                {
                    break;
                }
            }
            let _ = stdin.flush().await;
            // stdin drops here -> EOF -> cat-file drains and exits.
        });

        let max = self.max_blob_bytes;
        let mut reader = BufReader::new(stdout);
        let mut map: HashMap<String, Vec<u8>> = HashMap::new();
        let mut header = String::new();
        loop {
            header.clear();
            if reader.read_line(&mut header).await.map_err(io_err)? == 0 {
                break;
            }
            // "<oid> <type> <size>"  or  "<oid> missing"
            let parts: Vec<&str> = header.split_whitespace().collect();
            if parts.len() != 3 {
                continue; // missing / malformed: no content follows
            }
            let oid = parts[0].to_string();
            let is_blob = parts[1] == "blob";
            let size: usize = parts[2].parse().unwrap_or(0);

            if is_blob && size as u64 <= max {
                let mut buf = vec![0u8; size];
                reader.read_exact(&mut buf).await.map_err(io_err)?;
                map.insert(oid, buf);
            } else {
                discard(&mut reader, size).await?;
            }
            // Trailing newline after the object content.
            let mut nl = [0u8; 1];
            let _ = reader.read_exact(&mut nl).await;
        }
        let _ = writer.await;
        let _ = child.wait().await;
        Ok(map)
    }

    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.arg("-C").arg(self.repo_path);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd
    }
}

async fn run(mut cmd: Command) -> Result<String> {
    let output = cmd
        .output()
        .await
        .map_err(|e| crate::Error::Other(format!("git invocation failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(crate::Error::Other(format!(
            "git exited with status {}: {}",
            output.status, stderr
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn io_err(e: std::io::Error) -> crate::Error {
    crate::Error::Other(format!("git cat-file read failed: {e}"))
}

/// Read and discard exactly `n` bytes (content we won't keep — oversized
/// or non-blob objects), so the `cat-file --batch` stream stays in sync.
async fn discard<R: tokio::io::AsyncRead + Unpin>(r: &mut R, mut n: usize) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut scratch = [0u8; 8192];
    while n > 0 {
        let take = n.min(scratch.len());
        r.read_exact(&mut scratch[..take]).await.map_err(io_err)?;
        n -= take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EngineConfig;
    use crate::Scanner;
    use std::process::Command as StdCommand;
    use tempfile::TempDir;

    fn git(repo: &Path, args: &[&str]) {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .expect("spawn git");
        assert!(status.success(), "git {args:?} failed");
    }

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn init_repo() -> TempDir {
        let tmp = TempDir::new().unwrap();
        let repo = tmp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        git(repo, &["config", "user.email", "test@example.com"]);
        git(repo, &["config", "user.name", "Test"]);
        git(repo, &["config", "commit.gpgsign", "false"]);
        tmp
    }

    /// 3 commits: (1) baseline app file, (2) plants an AWS key, (3) removes it.
    /// Working tree at the end has NO key, but commit #2 does.
    #[tokio::test]
    async fn finds_planted_key_in_history_but_not_working_tree() {
        let tmp = init_repo();
        let repo = tmp.path();

        // Commit 1: clean baseline.
        write(&repo.join("app/config.rb"), "PORT = 3000\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "init: baseline app"]);

        // Commit 2: plant an AWS key.
        write(
            &repo.join("app/config.rb"),
            "PORT = 3000\nAWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "feat: add aws key (oops)"]);

        // Commit 3: remove the key.
        write(&repo.join("app/config.rb"), "PORT = 3000\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "fix: remove leaked aws key"]);

        let registry = PatternRegistry::builtin();
        let scanner = GitHistoryScanner::new(repo, &registry);
        let findings = scanner.scan().await.unwrap();

        // History scan: must find the key in commit #2.
        let aws_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.pattern == "aws_access_key")
            .collect();
        assert!(
            !aws_findings.is_empty(),
            "expected to find planted AWS key in history, got {findings:?}",
        );
        let with_commit: Vec<_> = aws_findings
            .iter()
            .filter(|f| f.git_commit.is_some())
            .collect();
        assert!(
            !with_commit.is_empty(),
            "git_commit metadata missing on history finding",
        );
        let subjects: Vec<&str> = with_commit
            .iter()
            .filter_map(|f| f.git_commit_subject.as_deref())
            .collect();
        assert!(
            subjects.iter().any(|s| s.contains("aws key")),
            "expected planting commit subject in findings, got {subjects:?}",
        );

        // Working tree check: regular Scanner on the same dir should NOT find it.
        let cfg = EngineConfig {
            root: repo.to_path_buf(),
            ..EngineConfig::default()
        };
        let working = Scanner::new(&cfg, &registry).scan().unwrap();
        assert!(
            !working.iter().any(|f| f.pattern == "aws_access_key"),
            "key must not be present in the working tree at HEAD",
        );
    }

    /// With `--since=HEAD~1`, only the most recent commit should be scanned.
    #[tokio::test]
    async fn since_head_minus_one_only_scans_last_commit() {
        let tmp = init_repo();
        let repo = tmp.path();

        // Commit 1: plant an AWS key (will be excluded by --since=HEAD~1).
        write(
            &repo.join("a.rb"),
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "old: plant key"]);

        // Commit 2: a different key (this one IS in scope).
        write(
            &repo.join("b.rb"),
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7TESTING'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "new: another key"]);

        let registry = PatternRegistry::builtin();
        let scanner = GitHistoryScanner::new(repo, &registry).since("HEAD~1");
        let findings = scanner.scan().await.unwrap();

        let matches: Vec<&str> = findings.iter().map(|f| f.r#match.as_str()).collect();
        assert!(
            matches.contains(&"AKIAIOSFODNN7TESTING"),
            "expected new key in scope, got {matches:?}",
        );
        assert!(
            !matches.contains(&"AKIAIOSFODNN7EXAMPLE"),
            "old key must be excluded by --since=HEAD~1, got {matches:?}",
        );
    }
}
