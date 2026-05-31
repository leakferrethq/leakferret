//! `leakferret baseline` — manage `.leakferret-baseline.json`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use leakferret_core::baseline::{self, BaselineStatus};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Sub,
}

#[derive(Debug, Subcommand)]
pub enum Sub {
    /// Create an empty baseline at `<root>/.leakferret-baseline.json`.
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Print baseline contents as JSON.
    Show {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Mark a fingerprint as ignored (operator-acknowledged false positive).
    Ignore {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        fingerprint: String,
        #[arg(long, default_value = "operator-ack")]
        reason: String,
    },
}

pub async fn run(args: Args) -> Result<i32> {
    match args.cmd {
        Sub::Init { path } => init(&path),
        Sub::Show { path } => show(&path),
        Sub::Ignore {
            path,
            fingerprint,
            reason,
        } => ignore(&path, &fingerprint, &reason),
    }
}

fn baseline_file(root: &std::path::Path) -> PathBuf {
    root.join(".leakferret-baseline.json")
}

fn init(root: &std::path::Path) -> Result<i32> {
    let path = baseline_file(root);
    if path.exists() {
        eprintln!("baseline already exists at {}", path.display());
        return Ok(0);
    }
    let b = baseline::Baseline::default();
    baseline::save(&path, &b).context("save baseline")?;
    // Keep the secret salt out of git — committing it next to the
    // fingerprints would let an attacker brute-force them.
    ensure_gitignored(root, ".leakferret-salt").context("update .gitignore")?;
    println!("initialised baseline at {}", path.display());
    println!(
        "commit .leakferret-baseline.json + .leakferret-history.jsonl; .leakferret-salt is gitignored"
    );
    println!("then run `leakferret verify . --update-baseline` to record current findings");
    Ok(0)
}

/// Append `entry` to `<root>/.gitignore` if it isn't already listed.
fn ensure_gitignored(root: &std::path::Path, entry: &str) -> Result<()> {
    let gi = root.join(".gitignore");
    let existing = std::fs::read_to_string(&gi).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == entry) {
        return Ok(());
    }
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(entry);
    content.push('\n');
    std::fs::write(&gi, content)?;
    Ok(())
}

fn show(root: &std::path::Path) -> Result<i32> {
    let path = baseline_file(root);
    let b = baseline::load_or_init(&path)?;
    serde_json::to_writer_pretty(std::io::stdout().lock(), &b)?;
    println!();
    Ok(0)
}

fn ignore(root: &std::path::Path, fingerprint: &str, reason: &str) -> Result<i32> {
    let path = baseline_file(root);
    let mut b = baseline::load_or_init(&path)?;
    let Some(entry) = b.entries.get_mut(fingerprint) else {
        anyhow::bail!("fingerprint not found in baseline: {fingerprint}");
    };
    entry.status = BaselineStatus::Ignored;
    baseline::save(&path, &b)?;
    println!("marked {fingerprint} as ignored: {reason}");
    Ok(0)
}
