//! `leakferret mcp` — start MCP server on stdio.

use std::io::IsTerminal;

use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Args {}

pub async fn run(_args: Args) -> Result<i32> {
    // Run by hand in a terminal this looks like a hang — it's a stdio JSON-RPC
    // server waiting for an editor/agent to connect. Make that obvious instead
    // of leaving the user staring at a blank cursor.
    if std::io::stdin().is_terminal() {
        eprintln!("leakferret mcp: an MCP server speaking JSON-RPC over stdin/stdout.");
        eprintln!("It's meant to be launched by your editor or agent, not run by hand.");
        eprintln!("Add it to your MCP config (Cursor: Settings -> MCP · Claude Desktop:");
        eprintln!("claude_desktop_config.json):");
        eprintln!();
        eprintln!(
            "  {{\"mcpServers\": {{\"leakferret\": {{\"command\": \"leakferret\", \"args\": [\"mcp\"]}}}}}}"
        );
        eprintln!();
        eprintln!("Now waiting for requests on stdin... (Ctrl-C to exit)");
    }
    leakferret_mcp::run().await?;
    Ok(0)
}
