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
}

impl OutputArgs {
    pub fn format(&self) -> leakferret_core::ReporterFormat {
        leakferret_core::ReporterFormat::from_str(&self.format).unwrap_or_default()
    }
}
