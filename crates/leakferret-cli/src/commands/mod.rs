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
