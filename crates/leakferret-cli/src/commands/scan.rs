//! `leakferret scan` — regex pre-filter, no LLM, no verifier.
//!
//! When `--only-verified` is passed the scan command upgrades itself
//! into a full `Engine`-driven run (with `VerifyMode::OnlyVerified`)
//! so we can emit trufflehog-style "only verified live secrets" output
//! even from the cheap subcommand.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use leakferret_core::{
    reporter, Engine, EngineConfig, GitHistoryScanner, PatternRegistry, ScanProgress, Scanner,
    VerifyMode,
};

use super::progress::Spinner;
use super::OutputArgs;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Scan git history instead of the working tree. Every added or
    /// modified blob between `--since` and `--until` is fed through the
    /// regex pre-filter.
    #[arg(long, default_value_t = false)]
    pub git: bool,

    /// Start revision for `--git` (e.g. `HEAD~10`, `v1.0.0`, a SHA).
    /// Defaults to the root commit.
    #[arg(long, value_name = "REV", requires = "git")]
    pub since: Option<String>,

    /// End revision for `--git`. Defaults to `HEAD`.
    #[arg(long, value_name = "REV", requires = "git")]
    pub until: Option<String>,

    /// Cap on the number of commits walked. Safety valve for huge
    /// histories (Linux-kernel-sized repos). Only applies with `--git`.
    #[arg(long, value_name = "N", requires = "git")]
    pub max_depth: Option<usize>,

    /// Scan every branch and tag's history, not just HEAD — catches
    /// secrets on un-merged branches. Requires `--git`; overrides
    /// `--since`/`--until`.
    #[arg(long, requires = "git", conflicts_with_all = ["since", "until"])]
    pub all: bool,

    #[command(flatten)]
    pub out: OutputArgs,
}

pub async fn run(args: Args, quiet: bool, verbose: u8) -> Result<i32> {
    let canonical_only: Option<Vec<PathBuf>> = if args.out.only.is_empty() {
        None
    } else {
        Some(
            args.out
                .only
                .iter()
                .map(|p| canonicalize_relaxed(p))
                .collect(),
        )
    };

    // --git: scan history instead of the working tree. Mutually
    // exclusive with --only-verified for now; verifier-on-history is a
    // separate, larger feature (replays of historical secrets).
    if args.git {
        let root = args.path.canonicalize().unwrap_or(args.path.clone());
        let cfg = EngineConfig::default();
        let registry = PatternRegistry::builtin();
        let mut scanner = GitHistoryScanner::new(&root, &registry)
            .context_lines(cfg.context_lines)
            .max_blob_bytes(cfg.max_file_bytes)
            .all_refs(args.all);
        if let Some(s) = args.since.clone() {
            scanner = scanner.since(s);
        }
        if let Some(u) = args.until.clone() {
            scanner = scanner.until(u);
        }
        if let Some(n) = args.max_depth {
            scanner = scanner.max_depth(n);
        }
        let findings = scanner.scan().await?;
        let mut stdout = std::io::stdout().lock();
        reporter::emit(
            args.out.format(),
            &findings,
            &mut stdout,
            args.out.show_fixtures,
        )?;
        return Ok(reporter::exit_code(&findings));
    }

    // --only-verified upgrades the cheap scan into a full Engine run so
    // we can actually verify findings before filtering. See doc-comment.
    if args.out.only_verified {
        let cfg = EngineConfig {
            root: args.path.canonicalize().unwrap_or(args.path.clone()),
            extra_excludes: args.out.exclude.clone(),
            only_paths: canonical_only,
            verify_mode: VerifyMode::OnlyVerified,
            ..EngineConfig::default()
        };
        let engine = Engine::new(cfg.clone());
        let report = engine.scan_path(&cfg.root).await?;
        let visible: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.is_verified())
            .cloned()
            .collect();
        let mut stdout = std::io::stdout().lock();
        reporter::emit(
            args.out.format(),
            &visible,
            &mut stdout,
            args.out.show_fixtures,
        )?;
        return Ok(report.ci_exit_code(VerifyMode::OnlyVerified));
    }

    let cfg = EngineConfig {
        root: args.path.canonicalize().unwrap_or(args.path.clone()),
        extra_excludes: args.out.exclude.clone(),
        only_paths: canonical_only,
        ..EngineConfig::default()
    };
    let registry = PatternRegistry::builtin();
    let scanner = Scanner::new(&cfg, &registry);

    // Live progress on stderr for interactive runs; stays silent when
    // piped, when --quiet, or when -v already streams tracing to stderr.
    let progress = Arc::new(ScanProgress::default());
    let spinner = (!quiet && verbose == 0).then(|| Spinner::start(Arc::clone(&progress)));
    let findings = scanner.scan_reporting(spinner.is_some().then(|| progress.as_ref()))?;
    drop(spinner);

    let mut stdout = std::io::stdout().lock();
    reporter::emit(
        args.out.format(),
        &findings,
        &mut stdout,
        args.out.show_fixtures,
    )?;
    Ok(reporter::exit_code(&findings))
}

fn canonicalize_relaxed(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}
