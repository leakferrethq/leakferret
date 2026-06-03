//! `leakferret org` — scan every public repository owned by a GitHub user or
//! organization in one command.
//!
//! Lists the owner's public repos via the GitHub API, shallow-clones each into
//! a temp directory, runs the normal scan engine, and emits one aggregated
//! report with every finding's path prefixed by `owner/repo/`. Forks and
//! archived repos are skipped by default. The raw secret never leaves the
//! machine; only the clone and the GitHub repo listing touch the network.

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::Deserialize;

use leakferret_core::{reporter, Engine, EngineConfig, Finding};

use super::OutputArgs;

#[derive(Debug, Parser)]
pub struct Args {
    /// GitHub user or organization whose public repositories to scan.
    pub owner: String,

    /// GitHub token for a higher API rate limit. Falls back to the
    /// `GITHUB_TOKEN` then `LEAKFERRET_GITHUB_TOKEN` environment variables.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Include forked repositories (skipped by default).
    #[arg(long)]
    pub include_forks: bool,

    /// Include archived repositories (skipped by default).
    #[arg(long)]
    pub include_archived: bool,

    /// Stop after scanning this many repositories.
    #[arg(long, value_name = "N")]
    pub max_repos: Option<usize>,

    #[command(flatten)]
    pub out: OutputArgs,
}

#[derive(Debug, Deserialize)]
struct Repo {
    name: String,
    clone_url: String,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    archived: bool,
}

pub async fn run(args: Args, quiet: bool) -> Result<i32> {
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .or_else(|| std::env::var("LEAKFERRET_GITHUB_TOKEN").ok());

    let repos = list_repos(&args.owner, token.as_deref(), &args).await?;
    if repos.is_empty() {
        if !quiet {
            eprintln!(
                "leakferret: no matching public repositories for '{}'.",
                args.owner
            );
        }
        return Ok(0);
    }

    // One work dir per owner under the system temp dir. Cleared up front so a
    // re-run never reuses a stale clone, and removed again at the end.
    let base = std::env::temp_dir()
        .join("leakferret-org")
        .join(&args.owner);
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base)
        .with_context(|| format!("creating work directory {}", base.display()))?;

    let total = repos.len();
    let mut all: Vec<Finding> = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        if !quiet {
            eprintln!("[{}/{}] {}/{}", i + 1, total, args.owner, repo.name);
        }
        let dest = base.join(&repo.name);
        let _ = std::fs::remove_dir_all(&dest);
        if let Err(e) = clone_repo(&repo.clone_url, &dest).await {
            if !quiet {
                eprintln!("  skipped (clone failed): {e}");
            }
            continue;
        }

        let cfg = EngineConfig {
            root: dest.clone(),
            ..EngineConfig::default()
        };
        let engine = Engine::new(cfg.clone());
        match engine.scan_path(&cfg.root).await {
            Ok(report) => {
                for mut f in report.findings {
                    // Prefix each finding's path with owner/repo so the
                    // aggregated report reads coherently across the whole org.
                    f.path = PathBuf::from(&args.owner).join(&repo.name).join(&f.path);
                    all.push(f);
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("  scan error: {e}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dest);
    }
    let _ = std::fs::remove_dir_all(&base);

    let mut stdout = std::io::stdout().lock();
    reporter::emit(args.out.format(), &all, &mut stdout, args.out.show_fixtures)?;
    Ok(match args.out.fail_on {
        Some(f) => f.exit_code(&all),
        None => reporter::exit_code(&all),
    })
}

/// List the owner's repositories via the GitHub API, paginating until exhausted
/// and applying the fork/archived/max filters.
async fn list_repos(owner: &str, token: Option<&str>, args: &Args) -> Result<Vec<Repo>> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("leakferret/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building the HTTP client")?;

    let mut out: Vec<Repo> = Vec::new();
    // Hard page cap (100 pages * 100 = 10k repos) as a safety valve.
    for page in 1..=100u32 {
        let url = format!(
            "https://api.github.com/users/{owner}/repos?per_page=100&page={page}&type=owner&sort=full_name"
        );
        let mut req = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }

        let resp = req.send().await.context("calling the GitHub API")?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("GitHub user or organization '{owner}' not found"));
        }
        if status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        {
            return Err(anyhow!(
                "GitHub API rate limit reached. Pass --token (or set GITHUB_TOKEN) to raise it."
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("GitHub API returned HTTP {status}"));
        }

        let body = resp
            .text()
            .await
            .context("reading the GitHub API response")?;
        let page_repos: Vec<Repo> =
            serde_json::from_str(&body).context("parsing the GitHub API response")?;
        let got = page_repos.len();

        for r in page_repos {
            if r.fork && !args.include_forks {
                continue;
            }
            if r.archived && !args.include_archived {
                continue;
            }
            out.push(r);
            if let Some(max) = args.max_repos {
                if out.len() >= max {
                    return Ok(out);
                }
            }
        }

        // A short page means we have reached the last one.
        if got < 100 {
            break;
        }
    }
    Ok(out)
}

/// Shallow-clone a repository into `dest` using the system `git`.
async fn clone_repo(clone_url: &str, dest: &std::path::Path) -> Result<()> {
    let status = tokio::process::Command::new("git")
        .args(["clone", "--depth", "1", "--quiet", clone_url])
        .arg(dest)
        .status()
        .await
        .context("running git clone (is git installed and on PATH?)")?;
    if !status.success() {
        return Err(anyhow!("git clone exited with {status}"));
    }
    Ok(())
}
