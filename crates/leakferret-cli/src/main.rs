//! `leakferret` CLI binary.

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

mod commands;

#[derive(Debug, Parser)]
#[command(
    name = "leakferret",
    version,
    about = "Context-aware secret detection with provider verification and ENV.fetch rewrites.",
    long_about = None,
    propagate_version = true,
    disable_help_subcommand = true,
    arg_required_else_help = true,
)]
struct Cli {
    /// Quiet (suppress informational tracing output).
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Verbose tracing (`-v` = info, `-vv` = debug, `-vvv` = trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    cmd: commands::Cmd,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.quiet, cli.verbose);

    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(commands::dispatch(cli.cmd, cli.quiet, cli.verbose))
}

fn init_tracing(quiet: bool, verbose: u8) {
    let level = if quiet {
        tracing::Level::ERROR
    } else {
        match verbose {
            0 => tracing::Level::WARN,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();
}
