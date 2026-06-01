//! CLI subcommand dispatch.

use anyhow::Result;
use clap::Subcommand;

mod baseline;
mod catalog;
mod mcp;
mod progress;
mod rewrite;
mod scan;
mod verify;

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Scan a path with regex pre-filter only (no classifier / verifier).
    Scan(scan::Args),
    /// Scan + offline-heuristic classify (no LLM call).
    Verify(verify::Args),
    /// Scan + classify + propose ENV-fetch rewrites for REAL findings.
    Rewrite(rewrite::Args),
    /// Manage the baseline file (`.leakferret-baseline.json`).
    Baseline(baseline::Args),
    /// Manage the fixture catalog (load, refresh, info).
    Catalog(catalog::Args),
    /// Start the MCP server on stdio.
    Mcp(mcp::Args),
}

pub async fn dispatch(cmd: Cmd, quiet: bool, verbose: u8) -> Result<i32> {
    match cmd {
        Cmd::Scan(a) => scan::run(a, quiet, verbose).await,
        Cmd::Verify(a) => verify::run(a).await,
        Cmd::Rewrite(a) => rewrite::run(a, verbose).await,
        Cmd::Baseline(a) => baseline::run(a).await,
        Cmd::Catalog(a) => catalog::run(a).await,
        Cmd::Mcp(a) => mcp::run(a).await,
    }
}

/// Choose the scan root for a single-file path argument so the recorded
/// (root-relative) path keeps its directory context. Returns `cwd` when the
/// file lives under it — so a path like `src/config.js` is preserved and the
/// app-path classifier still fires — otherwise the file's parent directory.
/// `root.join(relative)` always still resolves back to the file, which the
/// rewriter relies on.
fn root_for_file(abs_file: &std::path::Path, cwd: &std::path::Path) -> std::path::PathBuf {
    if abs_file.starts_with(cwd) {
        cwd.to_path_buf()
    } else {
        abs_file
            .parent()
            .map_or_else(|| abs_file.to_path_buf(), std::path::Path::to_path_buf)
    }
}

/// Resolve `(root, only_paths)` for a scan target. A directory passes straight
/// through. A single file is scanned from a directory root (see
/// [`root_for_file`]) with the file appended to `only_paths`, so classification,
/// display, and rewrite all see a stable, context-preserving path whether the
/// user passes `.` or `src/config.js` — previously a bare file argument made the
/// root the file itself, which dropped the directory context and broke rewrite.
pub fn resolve_scan_target(
    path: &std::path::Path,
    extra_only: &[std::path::PathBuf],
) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let abs = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if abs.is_file() {
        let cwd = std::env::current_dir()
            .ok()
            .and_then(|c| std::fs::canonicalize(c).ok())
            .unwrap_or_else(|| {
                abs.parent()
                    .map_or_else(|| abs.clone(), std::path::Path::to_path_buf)
            });
        let root = root_for_file(&abs, &cwd);
        let mut only = extra_only.to_vec();
        only.push(abs);
        (root, only)
    } else {
        (abs, extra_only.to_vec())
    }
}

#[cfg(test)]
mod target_tests {
    use super::root_for_file;
    use std::path::{Path, PathBuf};

    #[test]
    fn uses_cwd_when_file_is_under_it() {
        // A file under the cwd roots at the cwd, so the relative path keeps its
        // directory context (`src/config.js`) for the app-path classifier.
        assert_eq!(
            root_for_file(
                Path::new("/work/proj/src/config.js"),
                Path::new("/work/proj")
            ),
            PathBuf::from("/work/proj")
        );
    }

    #[test]
    fn falls_back_to_parent_when_file_is_outside_cwd() {
        assert_eq!(
            root_for_file(Path::new("/other/src/config.js"), Path::new("/work/proj")),
            PathBuf::from("/other/src")
        );
    }
}

/// Shared CLI args block reused by scan/verify/rewrite for the
/// classifier-output knobs.
#[derive(Debug, Clone, clap::Args)]
pub struct OutputArgs {
    /// Output format.
    #[arg(short = 'f', long, default_value = "pretty",
          value_parser = ["pretty", "json", "sarif"])]
    pub format: String,
    /// Include FIXTURE-classified findings in the output.
    #[arg(long)]
    pub show_fixtures: bool,
    /// Glob patterns to exclude (in addition to .gitignore).
    #[arg(long, value_name = "GLOB", num_args = 0..)]
    pub exclude: Vec<String>,
    /// Limit scan to these specific files (pre-commit hook mode).
    #[arg(long, value_name = "PATH", num_args = 0..)]
    pub only: Vec<std::path::PathBuf>,
    /// Only emit findings the verifier confirmed live (trufflehog
    /// `--only-verified` parity). Implies running the verifier even on
    /// the cheap `scan` command, and filters the output to verified
    /// findings only. On `verify`, this is equivalent to passing
    /// `--verify-mode only-verified`.
    #[arg(long)]
    pub only_verified: bool,

    /// Make the CLI exit non-zero when findings at this level are present.
    /// Omitted keeps the historical behaviour (exit 1 only on a REAL finding
    /// for `scan`, or per `--verify-mode` for `verify`). Use `--fail-on any`
    /// in a pre-commit hook or CI to block on every detected secret; pair it
    /// with `--verify-mode none` to stay fully offline.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub fail_on: Option<FailOn>,
}

impl OutputArgs {
    pub fn format(&self) -> leakferret_core::ReporterFormat {
        leakferret_core::ReporterFormat::from_str(&self.format).unwrap_or_default()
    }
}

/// Threshold at which the CLI exits non-zero, selected by `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOn {
    /// Never exit non-zero on findings.
    None,
    /// Exit non-zero if any non-fixture finding is present (real or unknown).
    Any,
    /// Exit non-zero only on findings classified real.
    Real,
    /// Exit non-zero only on findings verified live against the provider.
    Verified,
}

impl FailOn {
    /// Exit code (0 or 1) for `findings` under this policy. FIXTURE findings
    /// (documented public examples) never count, so `--fail-on any` still
    /// ignores `AKIAIOSFODNN7EXAMPLE` and friends.
    pub fn exit_code(self, findings: &[leakferret_core::Finding]) -> i32 {
        let hit = match self {
            FailOn::None => false,
            FailOn::Any => findings.iter().any(|f| !f.is_fixture()),
            FailOn::Real => findings.iter().any(leakferret_core::Finding::is_real),
            FailOn::Verified => findings.iter().any(leakferret_core::Finding::is_verified),
        };
        i32::from(hit)
    }
}
