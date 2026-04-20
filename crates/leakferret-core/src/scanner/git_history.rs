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

use std::path::{Path, PathBuf};
use std::process::Stdio;

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

    /// Drive the scan. Walks commits, diffs each against its parent, and
    /// scans every added/modified blob. Returns a flat list of findings
    /// sorted by (commit-walk-order, path, line, column).
    pub async fn scan(&self) -> Result<Vec<Finding>> {
        let commits = self.list_commits().await?;
        let total = commits.len();
        tracing::info!(
            target: "leakferret::scanner::git_history",
            commits = total,
            repo = %self.repo_path.display(),
            "git history scan starting",
        );

        let mut findings = Vec::new();
        for (idx, sha) in commits.iter().enumerate() {
            if idx > 0 && idx % 1000 == 0 {
                tracing::info!(
                    target: "leakferret::scanner::git_history",
                    progress = idx,
                    total,
                    "git history scan progress",
                );
            }
            let subject = self.commit_subject(sha).await.unwrap_or_default();
            let changed = match self.changed_paths(sha).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        target: "leakferret::scanner::git_history",
                        commit = %sha,
                        error = %e,
                        "skipping commit (diff-tree failed)",
                    );
                    continue;
                }
            };
            for path in changed {
                if !self.path_allowed(&path) {
                    continue;
                }
                let blob = match self.read_blob(sha, &path).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::debug!(
                            target: "leakferret::scanner::git_history",
                            commit = %sha,
                            path = %path.display(),
                            error = %e,
                            "skipping blob (git show failed)",
                        );
                        continue;
                    }
                };
                if blob.len() as u64 > self.max_blob_bytes {
                    continue;
                }
                // Binary check.
                if memchr::memchr(0, &blob[..blob.len().min(8192)]).is_some() {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(&blob) else {
                    continue;
                };
                let mut blob_findings = self.scan_text(text, &path);
                for f in &mut blob_findings {
                    f.git_commit = Some(sha.clone());
                    if !subject.is_empty() {
                        f.git_commit_subject = Some(subject.clone());
                    }
                }
                findings.extend(blob_findings);
            }
        }

        tracing::info!(
            target: "leakferret::scanner::git_history",
            commits = total,
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

    /// `git rev-list` between `since` and `until`, capped at `max_depth`.
    /// When `since` is omitted, walks all the way to the root commit.
    /// When `until` is omitted, defaults to `HEAD`.
    async fn list_commits(&self) -> Result<Vec<String>> {
        let mut cmd = self.git();
        cmd.arg("rev-list");
        if let Some(n) = self.max_depth {
            cmd.arg(format!("--max-count={n}"));
        }
        let range = match (self.since.as_deref(), self.until.as_deref()) {
            (Some(s), Some(u)) => format!("{s}..{u}"),
            (Some(s), None) => format!("{s}..HEAD"),
            (None, Some(u)) => u.to_string(),
            (None, None) => "HEAD".to_string(),
        };
        cmd.arg(range);
        let output = run(cmd).await?;
        Ok(output
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// First line of the commit message.
    async fn commit_subject(&self, sha: &str) -> Result<String> {
        let mut cmd = self.git();
        cmd.args(["show", "-s", "--format=%s", sha]);
        let out = run(cmd).await?;
        Ok(out.lines().next().unwrap_or("").to_string())
    }

    /// Paths added or modified by `sha` (relative to repo root).
    async fn changed_paths(&self, sha: &str) -> Result<Vec<PathBuf>> {
        let mut cmd = self.git();
        cmd.args([
            "diff-tree",
            "-r",
            "--no-commit-id",
            "--name-only",
            "--root", // include the root commit's tree as adds
            &format!("--diff-filter={DIFF_FILTER}"),
            sha,
        ]);
        let out = run(cmd).await?;
        Ok(out
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect())
    }

    /// `git show <sha>:<path>` — raw blob bytes.
    async fn read_blob(&self, sha: &str, path: &Path) -> Result<Vec<u8>> {
        // git uses forward slashes regardless of host platform.
        let path_str = path.to_string_lossy().replace('\\', "/");
        let spec = format!("{sha}:{path_str}");
        let mut cmd = self.git();
        cmd.args(["show", &spec]);
        run_bytes(cmd).await
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

async fn run_bytes(mut cmd: Command) -> Result<Vec<u8>> {
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
    Ok(output.stdout)
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
