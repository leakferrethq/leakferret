//! `leakferret mcp` — start MCP server on stdio.

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {}

pub async fn run(_args: Args) -> Result<i32> {
    leakferret_mcp::run().await?;
    Ok(0)
}
