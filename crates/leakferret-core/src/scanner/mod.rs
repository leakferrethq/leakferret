//! File walker + regex pre-filter. Produces `Finding`s with verdict
//! [`Verdict::Unknown`]; downstream stages set the verdict.
//!
//! Walking is delegated to the `ignore` crate (the engine behind
//! `ripgrep`) so we get correct gitignore semantics, multi-thread
//! walking, hidden-file rules, and `.ignore`/`.rgignore` support for
//! free.

pub mod allowlist;
mod context;
mod git_history;
mod walker;

pub use allowlist::{scan_for_pragmas, AllowPragma, AllowlistMap};
pub use context::context_window;
pub use git_history::GitHistoryScanner;
pub use walker::{walk, WalkConfig};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rayon::iter::{IntoParallelIterator, ParallelIterator};

use crate::config::EngineConfig;
use crate::finding::{Finding, Verdict};
use crate::patterns::PatternRegistry;
use crate::Result;

/// Live counters for an in-flight scan, shared between the scanner and a
/// caller-supplied progress renderer (e.g. a CLI spinner). The fields are
/// read and written with `Relaxed` ordering — they drive a progress
/// display, not any correctness-bearing logic.
#[derive(Debug, Default)]
pub struct ScanProgress {
    /// Total files to scan. Zero until the walk completes, then set once.
    pub total: AtomicUsize,
    /// Files scanned so far.
    pub scanned: AtomicUsize,
}

/// Orchestrates walking + scanning. Wraps a [`PatternRegistry`] and
/// an [`EngineConfig`].
#[derive(Debug)]
pub struct Scanner<'a> {
    config: &'a EngineConfig,
    registry: &'a PatternRegistry,
}

impl<'a> Scanner<'a> {
    pub fn new(config: &'a EngineConfig, registry: &'a PatternRegistry) -> Self {
        Self { config, registry }
    }

    /// Scan the configured root and return a flat list of findings.
    /// Files are scanned in parallel via `rayon`; ordering of the
    /// returned vector is not stable across runs but findings within
    /// the same file are returned in document order.
    pub fn scan(&self) -> Result<Vec<Finding>> {
        self.scan_reporting(None)
    }

    /// Like [`scan`](Self::scan), but bumps `progress` as the walk
    /// completes and each file is scanned, so a caller can render a
    /// live progress indicator. Pass `None` for the plain behaviour.
    pub fn scan_reporting(&self, progress: Option<&ScanProgress>) -> Result<Vec<Finding>> {
        let walk_cfg = WalkConfig {
            root: self.config.root.clone(),
            extra_excludes: self.config.extra_excludes.clone(),
            max_file_bytes: self.config.max_file_bytes,
            only_paths: self.config.only_paths.clone(),
        };
        let files = walk(&walk_cfg)?;
        if let Some(p) = progress {
            p.total.store(files.len(), Ordering::Relaxed);
        }

        let findings: Vec<Vec<Finding>> = files
            .into_par_iter()
            .map(|path| {
                let found = self.scan_file(&path);
                if let Some(p) = progress {
                    p.scanned.fetch_add(1, Ordering::Relaxed);
                }
                found
            })
            .collect();

        let mut flat: Vec<Finding> = findings.into_iter().flatten().collect();
        flat.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then(a.line.cmp(&b.line))
                .then(a.column.cmp(&b.column))
        });
        Ok(flat)
    }

    /// Scan a single file. Returns empty on read errors (logged at
    /// debug level via `tracing`).
    pub fn scan_file(&self, absolute: &Path) -> Vec<Finding> {
        let bytes = match std::fs::read(absolute) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(target: "leakferret::scanner", path = %absolute.display(), error = %e, "skipping unreadable file");
                return Vec::new();
            }
        };
        // Reject binaries cheaply via NUL-byte check on the first 8KB.
        if memchr::memchr(0, &bytes[..bytes.len().min(8192)]).is_some() {
            return Vec::new();
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Vec::new();
        };

        let rel = relative_path(&self.config.root, absolute);
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        // Operator-acknowledged false positives are dropped *before*
        // they enter the findings vector — they don't even reach
        // classification.
        let allowlist = allowlist::scan_for_pragmas(&lines);
        let mut findings = Vec::new();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let line_no_newline = line.trim_end_matches('\n').trim_end_matches('\r');
            for pat_idx in self.registry.matches(line_no_newline) {
                let Some((pattern, regex)) = self.registry.get(pat_idx) else {
                    continue;
                };
                if allowlist.suppresses(line_no, &pattern.id) {
                    tracing::debug!(
                        target: "leakferret::scanner::allowlist",
                        path = %rel.display(),
                        line = line_no,
                        pattern = %pattern.id,
                        "suppressed by inline pragma",
                    );
                    continue;
                }
                for caps in regex.captures_iter(line_no_newline) {
                    let cap_idx = pattern.capture_group.min(caps.len().saturating_sub(1));
                    let Some(m) = caps.get(cap_idx) else { continue };
                    if m.as_str().is_empty() {
                        continue;
                    }
                    findings.push(Finding {
                        path: rel.clone(),
                        line: line_no,
                        column: m.start() + 1,
                        r#match: m.as_str().to_string(),
                        pattern: pattern.id.clone(),
                        severity: pattern.severity,
                        context: context_window(&lines, idx, self.config.context_lines),
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
}

fn relative_path(root: &Path, absolute: &Path) -> PathBuf {
    absolute
        .strip_prefix(root)
        .map_or_else(|_| absolute.to_path_buf(), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn finds_aws_key_in_simple_repo() {
        let tmp = TempDir::new().unwrap();
        write(
            &tmp.path().join("app/config.rb"),
            "AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        let cfg = EngineConfig {
            root: tmp.path().to_path_buf(),
            ..EngineConfig::default()
        };
        let registry = PatternRegistry::builtin();
        let scanner = Scanner::new(&cfg, &registry);
        let findings = scanner.scan().unwrap();
        assert!(findings.iter().any(|f| f.pattern == "aws_access_key"));
    }

    #[test]
    fn ignores_binary_files() {
        let tmp = TempDir::new().unwrap();
        let mut content = vec![0u8; 32];
        content.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE");
        std::fs::write(tmp.path().join("blob.bin"), &content).unwrap();
        let cfg = EngineConfig {
            root: tmp.path().to_path_buf(),
            ..EngineConfig::default()
        };
        let registry = PatternRegistry::builtin();
        let scanner = Scanner::new(&cfg, &registry);
        let findings = scanner.scan().unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn allowlist_pragma_on_same_line_drops_finding() {
        let tmp = TempDir::new().unwrap();
        write(
            &tmp.path().join("app/config.rb"),
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # leakferret:allow\n",
        );
        let cfg = EngineConfig {
            root: tmp.path().to_path_buf(),
            ..EngineConfig::default()
        };
        let registry = PatternRegistry::builtin();
        let scanner = Scanner::new(&cfg, &registry);
        let findings = scanner.scan().unwrap();
        assert!(findings.is_empty(), "pragma should suppress {findings:?}");
    }

    #[test]
    fn allowlist_pragma_on_preceding_line_drops_finding() {
        let tmp = TempDir::new().unwrap();
        write(
            &tmp.path().join("app/config.rb"),
            "# leakferret:allow\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        );
        let cfg = EngineConfig {
            root: tmp.path().to_path_buf(),
            ..EngineConfig::default()
        };
        let registry = PatternRegistry::builtin();
        let scanner = Scanner::new(&cfg, &registry);
        let findings = scanner.scan().unwrap();
        assert!(
            findings.is_empty(),
            "preceding-line pragma should suppress {findings:?}"
        );
    }

    #[test]
    fn allowlist_pragma_with_pattern_id_only_suppresses_matching() {
        let tmp = TempDir::new().unwrap();
        write(
            &tmp.path().join("app/config.rb"),
            // Pragma names a different pattern, so the AWS finding
            // must still be reported.
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE' # leakferret:allow stripe_secret\n",
        );
        let cfg = EngineConfig {
            root: tmp.path().to_path_buf(),
            ..EngineConfig::default()
        };
        let registry = PatternRegistry::builtin();
        let scanner = Scanner::new(&cfg, &registry);
        let findings = scanner.scan().unwrap();
        assert!(findings.iter().any(|f| f.pattern == "aws_access_key"));
    }
}
