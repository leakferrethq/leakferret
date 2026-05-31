//! Git history scanner. Walks commits and runs the regex pre-filter over the
//! lines each commit **adds** — not the full content of every file it touches.
//!
//! # Strategy: shell out to `git`
//!
//! We deliberately **do not** depend on `git2` / `libgit2`. The workspace
//! targets `x86_64-pc-windows-gnu` (see `rust-toolchain.toml`) and `git2`'s
//! `vendored-libgit2` feature pulls in a `CMake` + Perl libgit2 build that is
//! fragile on the Windows GNU toolchain. `git` is a hard prerequisite for
//! history scanning anyway, so shelling out is the simpler, portable choice —
//! the same approach gitleaks took before switching to `go-git`.
//!
//! # Algorithm — diff-only
//!
//! A single `git log -p` pass yields, per commit, the unified diff of every
//! added/modified file. We scan only the **added (`+`) lines**, attributing
//! each finding to the commit that introduced it and the line number it has in
//! that commit's version of the file. A secret that already existed in a file
//! is therefore reported once (at the commit that added it), not again every
//! time a later commit happens to touch the same file.
//!
//! Each [`Finding`] is tagged with `git_commit` (full SHA) and
//! `git_commit_subject` (first line of the commit message), and its `path` is
//! the path inside that commit (which may not exist in the working tree).

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use crate::finding::{Finding, Verdict};
use crate::patterns::PatternRegistry;
use crate::scanner::context_window;
use crate::Result;

/// Default per-line byte cap — a single line longer than this is almost
/// certainly minified/generated and not worth feeding to the regex set.
const DEFAULT_MAX_BLOB_BYTES: u64 = 2 * 1024 * 1024;

/// Diff filter passed to `git log`. `A` = added, `M` = modified. Deletes are
/// excluded — there is nothing added to scan.
const DIFF_FILTER: &str = "AM";

/// A line as it appears in the *new* version of a file within one diff hunk,
/// used both for scanning (added lines) and for building context windows.
struct HunkLine {
    text: String,
    added: bool,
    line_no: usize,
}

/// Walks the commit history of a repository and surfaces findings from the
/// lines each commit adds. See the module-level docs for the algorithm.
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
    all_refs: bool,
}

impl<'a> GitHistoryScanner<'a> {
    /// New scanner. `since` and `until` are git revisions (e.g. `HEAD~10`,
    /// `v1.0.0`, or a commit SHA). `paths`, when present, restricts findings to
    /// those whose file is under one of those paths.
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
            all_refs: false,
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

    /// Scan every ref (all branches and tags) instead of just HEAD's history —
    /// catches secrets on un-merged branches. Overrides the `since..until`
    /// range when set.
    pub fn all_refs(mut self, yes: bool) -> Self {
        self.all_refs = yes;
        self
    }

    /// Drive the scan: one `git log -p` pass, parsed into per-commit added
    /// lines, scanned with the regex set. Returns findings sorted by
    /// (path, line, column).
    pub async fn scan(&self) -> Result<Vec<Finding>> {
        let patch = self.run_log_patch().await?;
        let mut findings = self.parse_patch(&patch);
        findings.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
        });
        tracing::info!(
            target: "leakferret::scanner::git_history",
            findings = findings.len(),
            repo = %self.repo_path.display(),
            "git history (diff) scan complete",
        );
        Ok(findings)
    }

    /// One `git log -p` invocation over the configured commit range, emitting
    /// each commit header (SOH/US-delimited) followed by its unified diff.
    async fn run_log_patch(&self) -> Result<String> {
        let mut cmd = self.git();
        // quotePath=false so paths come back literal.
        cmd.arg("-c").arg("core.quotePath=false").arg("log");
        if let Some(n) = self.max_depth {
            cmd.arg(format!("--max-count={n}"));
        }
        cmd.arg("-p")
            .arg(format!("-U{}", self.context_lines))
            .arg("--no-color")
            .arg("--no-renames")
            .arg("--root") // root commit's tree counts as all-additions
            .arg(format!("--diff-filter={DIFF_FILTER}"))
            // SOH (\x01) prefixes commit header lines so we can tell them from
            // diff content; US (\x1f) splits SHA from subject.
            .arg("--pretty=format:\x01%H\x1f%s");
        if self.all_refs {
            cmd.arg("--all");
        } else {
            let range = match (self.since.as_deref(), self.until.as_deref()) {
                (Some(s), Some(u)) => format!("{s}..{u}"),
                (Some(s), None) => format!("{s}..HEAD"),
                (None, Some(u)) => u.to_string(),
                (None, None) => "HEAD".to_string(),
            };
            cmd.arg(range);
        }
        run(cmd).await
    }

    /// Parse the `git log -p` stream and scan added lines. State machine over
    /// commit headers, file headers, hunk headers, and `+`/`-`/` ` content.
    fn parse_patch(&self, out: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut sha = String::new();
        let mut subject = String::new();
        let mut path: Option<PathBuf> = None;
        let mut new_line_no: usize = 0;
        let mut hunk: Vec<HunkLine> = Vec::new();

        for line in out.lines() {
            if let Some(rest) = line.strip_prefix('\x01') {
                self.flush_hunk(&hunk, path.as_deref(), &sha, &subject, &mut findings);
                hunk.clear();
                let mut it = rest.splitn(2, '\x1f');
                sha = it.next().unwrap_or("").to_string();
                subject = it.next().unwrap_or("").to_string();
                path = None;
                new_line_no = 0;
            } else if line.starts_with("diff --git ") {
                self.flush_hunk(&hunk, path.as_deref(), &sha, &subject, &mut findings);
                hunk.clear();
                path = None;
                new_line_no = 0;
            } else if new_line_no == 0 && line.starts_with("+++ ") {
                // "+++ b/<path>" (post-image) or "+++ /dev/null" (delete).
                path = line.strip_prefix("+++ b/").map(PathBuf::from);
            } else if new_line_no == 0 && line.starts_with("--- ") {
                // old-file header; ignored.
            } else if line.starts_with("@@") {
                self.flush_hunk(&hunk, path.as_deref(), &sha, &subject, &mut findings);
                hunk.clear();
                new_line_no = parse_hunk_new_start(line).unwrap_or(0);
            } else if path.is_some() && new_line_no > 0 {
                if let Some(text) = line.strip_prefix('+') {
                    hunk.push(HunkLine {
                        text: text.to_string(),
                        added: true,
                        line_no: new_line_no,
                    });
                    new_line_no += 1;
                } else if line.starts_with('-') {
                    // removed line — not present in the new file; do not advance.
                } else if let Some(text) = line.strip_prefix(' ') {
                    hunk.push(HunkLine {
                        text: text.to_string(),
                        added: false,
                        line_no: new_line_no,
                    });
                    new_line_no += 1;
                }
                // '\' (no-newline marker) and anything else: ignored.
            }
        }
        self.flush_hunk(&hunk, path.as_deref(), &sha, &subject, &mut findings);
        findings
    }

    /// Scan the added lines of one completed hunk, building context windows
    /// from the surrounding new-file lines.
    fn flush_hunk(
        &self,
        hunk: &[HunkLine],
        path: Option<&Path>,
        sha: &str,
        subject: &str,
        out: &mut Vec<Finding>,
    ) {
        let Some(path) = path else {
            return;
        };
        if hunk.is_empty() || !self.path_allowed(path) {
            return;
        }
        let texts: Vec<&str> = hunk.iter().map(|h| h.text.as_str()).collect();
        for (i, h) in hunk.iter().enumerate() {
            if !h.added || h.text.len() as u64 > self.max_blob_bytes {
                continue;
            }
            for pat_idx in self.registry.matches(h.text.as_str()) {
                let Some((pattern, regex)) = self.registry.get(pat_idx) else {
                    continue;
                };
                for caps in regex.captures_iter(h.text.as_str()) {
                    let cap_idx = pattern.capture_group.min(caps.len().saturating_sub(1));
                    let Some(m) = caps.get(cap_idx) else { continue };
                    if m.as_str().is_empty() {
                        continue;
                    }
                    out.push(Finding {
                        path: path.to_path_buf(),
                        line: h.line_no,
                        column: m.start() + 1,
                        r#match: m.as_str().to_string(),
                        pattern: pattern.id.clone(),
                        severity: pattern.severity,
                        context: context_window(&texts, i, self.context_lines),
                        verdict: Verdict::Unknown,
                        reason: None,
                        confidence: None,
                        verification: None,
                        fingerprint: None,
                        replacement: None,
                        git_commit: (!sha.is_empty()).then(|| sha.to_string()),
                        git_commit_subject: (!subject.is_empty()).then(|| subject.to_string()),
                    });
                }
            }
        }
    }

    fn path_allowed(&self, path: &Path) -> bool {
        match &self.paths {
            None => true,
            Some(allowed) => allowed.iter().any(|p| path.starts_with(p) || p == path),
        }
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

/// Extract the new-file start line from a hunk header `@@ -a,b +c,d @@`.
fn parse_hunk_new_start(header: &str) -> Option<usize> {
    let after_plus = header.split('+').nth(1)?;
    let digits: String = after_plus
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
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

    /// 3 commits: (1) baseline, (2) plants an AWS key, (3) removes it. Working
    /// tree at the end has NO key, but commit #2 added it.
    #[tokio::test]
    async fn finds_planted_key_in_history_but_not_working_tree() {
        let tmp = init_repo();
        let repo = tmp.path();

        write(&repo.join("app/config.rb"), "PORT = 3000\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "init: baseline app"]);

        write(
            &repo.join("app/config.rb"),
            "PORT = 3000\nAWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "feat: add aws key (oops)"]);

        write(&repo.join("app/config.rb"), "PORT = 3000\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "fix: remove leaked aws key"]);

        let registry = PatternRegistry::builtin();
        let findings = GitHistoryScanner::new(repo, &registry)
            .scan()
            .await
            .unwrap();

        let aws: Vec<_> = findings
            .iter()
            .filter(|f| f.pattern == "aws_access_key")
            .collect();
        assert!(
            !aws.is_empty(),
            "expected the planted AWS key in history, got {findings:?}",
        );
        assert!(
            aws.iter().all(|f| f.git_commit.is_some()),
            "git_commit metadata missing on history finding",
        );
        let subjects: Vec<&str> = aws
            .iter()
            .filter_map(|f| f.git_commit_subject.as_deref())
            .collect();
        assert!(
            subjects.iter().any(|s| s.contains("aws key")),
            "expected the planting commit subject, got {subjects:?}",
        );

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

    /// The core diff-only guarantee: a secret added in one commit must NOT be
    /// re-reported when a later commit merely modifies the same file.
    #[tokio::test]
    async fn modified_file_only_reports_newly_added_secret() {
        let tmp = init_repo();
        let repo = tmp.path();

        // Commit 1: add a file containing a key.
        write(&repo.join("c.rb"), "API = 'AKIAIOSFODNN7EXAMPLE'\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c1: add key"]);

        // Commit 2: modify the file (append an unrelated line). The key line is
        // unchanged — a full-blob scan would wrongly re-report it here.
        write(
            &repo.join("c.rb"),
            "API = 'AKIAIOSFODNN7EXAMPLE'\nPORT = 3000\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "c2: add port"]);

        let registry = PatternRegistry::builtin();
        let findings = GitHistoryScanner::new(repo, &registry)
            .scan()
            .await
            .unwrap();
        let aws: Vec<_> = findings
            .iter()
            .filter(|f| f.pattern == "aws_access_key")
            .collect();
        assert_eq!(
            aws.len(),
            1,
            "key should be reported once, at its introducing commit, got {aws:?}",
        );
        assert!(
            aws[0]
                .git_commit_subject
                .as_deref()
                .unwrap_or("")
                .contains("c1"),
            "key should be attributed to the commit that added it, got {:?}",
            aws[0].git_commit_subject,
        );
    }

    /// With `--since=HEAD~1`, only the most recent commit is scanned.
    #[tokio::test]
    async fn since_head_minus_one_only_scans_last_commit() {
        let tmp = init_repo();
        let repo = tmp.path();

        write(
            &repo.join("a.rb"),
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "old: plant key"]);

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
            "expected the new key in scope, got {matches:?}",
        );
        assert!(
            !matches.contains(&"AKIAIOSFODNN7EXAMPLE"),
            "old key must be excluded by --since=HEAD~1, got {matches:?}",
        );
    }

    /// A key committed only on an un-merged branch: HEAD-only history misses
    /// it; `--all` finds it.
    #[tokio::test]
    async fn all_refs_finds_key_on_unmerged_branch() {
        let tmp = init_repo();
        let repo = tmp.path();

        write(&repo.join("a.rb"), "PORT = 3000\n");
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "init: baseline"]);

        git(repo, &["checkout", "-q", "-b", "feature"]);
        write(
            &repo.join("b.rb"),
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        git(repo, &["add", "."]);
        git(repo, &["commit", "-q", "-m", "feat: key on branch"]);
        git(repo, &["checkout", "-q", "main"]);

        let registry = PatternRegistry::builtin();

        let head_only = GitHistoryScanner::new(repo, &registry)
            .scan()
            .await
            .unwrap();
        assert!(
            !head_only.iter().any(|f| f.pattern == "aws_access_key"),
            "HEAD-only history must not see the feature-branch key",
        );

        let all = GitHistoryScanner::new(repo, &registry)
            .all_refs(true)
            .scan()
            .await
            .unwrap();
        assert!(
            all.iter().any(|f| f.pattern == "aws_access_key"),
            "--all must find the key on the un-merged branch",
        );
    }
}
