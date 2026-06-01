//! `leakferret rewrite` — scan + classify + propose (and optionally apply) rewrites.
//!
//! Default behaviour: emit findings + rewrite proposals via the
//! configured reporter and exit with the standard "any real findings?"
//! exit code.
//!
//! `--apply` writes the rewrites in-place. `--dry-run-diff` shows the
//! unified diff that *would* be applied without touching disk.
//! `--check` is the CI-friendly variant — same as `--dry-run-diff` but
//! exits 1 when any rewrites would happen and suppresses all output
//! except a one-line summary (unless `-v` was passed on the root CLI).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use leakferret_core::{reporter, Engine, EngineConfig, Finding, RewriteBackend, VerifyMode};
use similar::{ChangeTag, TextDiff};

use super::OutputArgs;

#[derive(Debug, Parser)]
pub struct Args {
    /// Path to scan.
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Actually apply the rewrites in-place (default: dry-run).
    #[arg(long, conflicts_with_all = ["dry_run_diff", "check"])]
    pub apply: bool,

    /// Print the unified diff per file that would result from
    /// `--apply`, without writing to disk.
    #[arg(long, conflicts_with = "check")]
    pub dry_run_diff: bool,

    /// CI-friendly check mode: same as `--dry-run-diff` but exits 1
    /// when any rewrites would happen. Suppresses output (except a
    /// one-line summary) unless `-v` was passed.
    #[arg(long)]
    pub check: bool,

    /// Also propose rewrites for UNKNOWN (unconfirmed) findings, not only
    /// confirmed-real ones. Use this to fix candidates when there is no live
    /// verifier or host-LLM classification to promote them to REAL.
    #[arg(long)]
    pub include_unknown: bool,

    /// Secret-manager backend for seed commands.
    #[arg(long, default_value = "env",
          value_parser = ["env", "vault", "doppler", "aws-secrets-manager", "infisical"])]
    pub backend: String,

    #[command(flatten)]
    pub out: OutputArgs,
}

pub async fn run(args: Args, verbose: u8) -> Result<i32> {
    let backend = match args.backend.as_str() {
        "vault" => RewriteBackend::Vault,
        "doppler" => RewriteBackend::Doppler,
        "aws-secrets-manager" => RewriteBackend::AwsSecretsManager,
        "infisical" => RewriteBackend::Infisical,
        _ => RewriteBackend::Env,
    };
    let (root, only) = super::resolve_scan_target(&args.path, &args.out.only);
    let cfg = EngineConfig {
        root,
        only_paths: (!only.is_empty()).then_some(only),
        extra_excludes: args.out.exclude.clone(),
        verify_mode: VerifyMode::BestEffort,
        rewrite_backend: backend,
        rewrite_include_unknown: args.include_unknown,
        ..EngineConfig::default()
    };

    let engine = Engine::new(cfg.clone());
    let report = engine.scan_path(&cfg.root).await?;

    if args.check || args.dry_run_diff {
        let diffs = build_diffs(&cfg.root, &report.findings)?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        return emit_dry_run(&mut out, &diffs, args.check, verbose);
    }

    if args.apply {
        apply_rewrites(&cfg.root, &report.findings)?;
    }

    let mut stdout = std::io::stdout().lock();
    reporter::emit(
        args.out.format(),
        &report.findings,
        &mut stdout,
        args.out.show_fixtures,
    )?;
    Ok(reporter::exit_code(&report.findings))
}

/// A per-file unified diff that `--apply` would write. `_file` is
/// the path relative to the scan root and is kept for traceability /
/// future structured output even though only `unified` is rendered.
#[derive(Debug)]
struct FileDiff {
    #[allow(dead_code)]
    file: PathBuf,
    unified: String,
}

/// Plan rewrites without touching disk and render a per-file unified
/// diff in the standard `--- a/x +++ b/x @@ ... @@` format.
fn build_diffs(root: &Path, findings: &[Finding]) -> Result<Vec<FileDiff>> {
    let mut by_file: BTreeMap<PathBuf, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        // The engine only attaches a replacement to findings eligible for
        // rewrite (Real, or Unknown under --include-unknown), so the
        // presence of one is the authoritative filter here.
        if f.replacement.is_some() {
            by_file.entry(f.path.clone()).or_default().push(f);
        }
    }

    let mut out = Vec::new();
    for (rel, group) in &by_file {
        let abs = root.join(rel);
        let Ok(orig) = std::fs::read_to_string(&abs) else {
            tracing::debug!(target: "leakferret::rewrite", path = %abs.display(), "skip diff: unreadable");
            continue;
        };
        let new = rewrite_in_memory(&orig, group);
        if new == orig {
            continue;
        }
        let display = rel.display().to_string().replace('\\', "/");
        let diff = TextDiff::from_lines(&orig, &new);
        let mut unified = String::new();
        unified.push_str(&format!("--- a/{display}\n"));
        unified.push_str(&format!("+++ b/{display}\n"));
        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            unified.push_str(&format!("{}\n", hunk.header()));
            for change in hunk.iter_changes() {
                let sign = match change.tag() {
                    ChangeTag::Delete => '-',
                    ChangeTag::Insert => '+',
                    ChangeTag::Equal => ' ',
                };
                let value = change.value();
                unified.push(sign);
                unified.push_str(value);
                if !value.ends_with('\n') {
                    unified.push('\n');
                }
            }
        }
        out.push(FileDiff {
            file: rel.clone(),
            unified,
        });
    }
    Ok(out)
}

/// Apply the same in-place mutation `apply_rewrites` does, but to an
/// in-memory string copy. Kept tightly mirrored with `apply_rewrites`
/// so `--dry-run-diff` is faithful.
fn rewrite_in_memory(orig: &str, group: &[&Finding]) -> String {
    let mut lines: Vec<String> = orig.split_inclusive('\n').map(str::to_string).collect();
    for f in group {
        let idx = f.line.saturating_sub(1);
        let Some(line) = lines.get_mut(idx) else {
            continue;
        };
        if !line.contains(&f.r#match) {
            continue;
        }
        let Some(replacement) = f.replacement.as_ref() else {
            continue;
        };
        let trailing = if line.ends_with('\n') { "\n" } else { "" };
        *line = format!("{}{trailing}", replacement.new_line);
    }
    lines.join("")
}

fn emit_dry_run<W: Write>(
    out: &mut W,
    diffs: &[FileDiff],
    check_mode: bool,
    verbose: u8,
) -> Result<i32> {
    let any = !diffs.is_empty();

    if check_mode {
        // CI mode: one-line summary only, unless -v was passed.
        if verbose > 0 {
            for d in diffs {
                write!(out, "{}", d.unified)?;
            }
        }
        if any {
            writeln!(
                out,
                "leakferret rewrite --check: {n} file(s) would be rewritten",
                n = diffs.len()
            )?;
            return Ok(1);
        }
        writeln!(out, "leakferret rewrite --check: clean")?;
        return Ok(0);
    }

    // Plain --dry-run-diff: always print every diff.
    for d in diffs {
        write!(out, "{}", d.unified)?;
    }
    Ok(0)
}

fn apply_rewrites(root: &Path, findings: &[Finding]) -> Result<()> {
    let mut by_file: BTreeMap<PathBuf, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        if f.replacement.is_some() {
            by_file.entry(root.join(&f.path)).or_default().push(f);
        }
    }

    for (path, group) in &by_file {
        let Ok(orig) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut lines: Vec<String> = orig.split_inclusive('\n').map(str::to_string).collect();
        for f in group {
            let idx = f.line.saturating_sub(1);
            let Some(line) = lines.get_mut(idx) else {
                continue;
            };
            if !line.contains(&f.r#match) {
                continue;
            }
            let Some(replacement) = f.replacement.as_ref() else {
                continue;
            };
            let trailing = if line.ends_with('\n') { "\n" } else { "" };
            *line = format!("{}{trailing}", replacement.new_line);
        }
        std::fs::write(path, lines.join(""))?;
    }

    // Append to .env.example
    let env_example = root.join(".env.example");
    let entries: Vec<String> = findings
        .iter()
        .filter_map(|f| f.replacement.as_ref().map(|r| r.env_example_line.clone()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if entries.is_empty() {
        return Ok(());
    }
    let existing = std::fs::read_to_string(&env_example).unwrap_or_default();
    let mut new_block = String::new();
    if !existing.is_empty() && !existing.ends_with('\n') {
        new_block.push('\n');
    }
    new_block.push_str("# Added by leakferret rewrite:\n");
    for e in entries {
        if !existing.contains(e.split('=').next().unwrap_or("")) {
            new_block.push_str(&e);
            new_block.push('\n');
        }
    }
    std::fs::write(&env_example, format!("{existing}{new_block}"))?;
    Ok(())
}
