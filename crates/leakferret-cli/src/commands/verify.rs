//! `leakferret verify` — scan + offline classify + optional verifier.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use leakferret_core::{reporter, Engine, EngineConfig, VerifyMode};

use super::OutputArgs;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Verifier mode.
    #[arg(long, default_value = "best-effort",
          value_parser = ["none", "best-effort", "only-verified", "ever-verified"])]
    pub verify_mode: String,

    /// Per-verifier timeout in seconds.
    #[arg(long, default_value_t = 10)]
    pub verifier_timeout_secs: u64,

    /// Record the current findings into the baseline (and history/salt).
    /// Without this, `verify` is read-only and never writes to your repo —
    /// it only diffs against an existing baseline. Use this to snapshot.
    #[arg(long, default_value_t = false)]
    pub update_baseline: bool,

    #[command(flatten)]
    pub out: OutputArgs,
}

pub async fn run(args: Args) -> Result<i32> {
    // `--only-verified` lives on the shared OutputArgs group so it
    // applies to scan/verify/rewrite uniformly. On `verify` it is
    // documented as an alias for `--verify-mode only-verified` and
    // wins over any conflicting `--verify-mode` value.
    let mode = if args.out.only_verified {
        VerifyMode::OnlyVerified
    } else {
        match args.verify_mode.as_str() {
            "none" => VerifyMode::None,
            "only-verified" => VerifyMode::OnlyVerified,
            "ever-verified" => VerifyMode::EverVerified,
            _ => VerifyMode::BestEffort,
        }
    };
    let cfg = EngineConfig {
        root: args.path.canonicalize().unwrap_or(args.path.clone()),
        extra_excludes: args.out.exclude.clone(),
        only_paths: if args.out.only.is_empty() {
            None
        } else {
            Some(args.out.only.clone())
        },
        verify_mode: mode,
        verifier_timeout_secs: args.verifier_timeout_secs,
        update_baseline: args.update_baseline,
        ..EngineConfig::default()
    };

    let engine = Engine::new(cfg.clone());
    let report = engine.scan_path(&cfg.root).await?;

    let visible: Vec<_> = if mode == VerifyMode::OnlyVerified {
        report
            .findings
            .iter()
            .filter(|f| f.is_verified())
            .cloned()
            .collect()
    } else {
        report.findings.clone()
    };

    let mut stdout = std::io::stdout().lock();
    reporter::emit(
        args.out.format(),
        &visible,
        &mut stdout,
        args.out.show_fixtures,
    )?;
    Ok(report.ci_exit_code(mode))
}
