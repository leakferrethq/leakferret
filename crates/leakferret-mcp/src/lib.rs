//! MCP (Model Context Protocol) server for `leakferret`. Speaks
//! JSON-RPC 2.0 over stdio.
//!
//! Tools exposed:
//!   * `scan_repository` — walks a path, returns regex-pre-filter candidates (verdict `unknown`).
//!   * `classify_candidates` — applies offline heuristic verdicts.
//!   * `propose_rewrite` — proposes ENV-fetch replacement for a real finding.
//!   * `verify_finding` — runs the matching provider verifier (live HTTP call); the secret value goes from the user's machine directly to the provider.
//!   * `baseline_diff` — diff scan findings against the repo's baseline; returns new + ever-verified.
//!
//! Prompt exposed:
//!   * `classify` — system prompt the host LLM uses to classify candidates inline.
//!
//! Reference: <https://spec.modelcontextprotocol.io>

mod methods;
mod protocol;
mod server;

pub use server::Server;

/// Start the MCP server reading from stdin / writing to stdout. Runs
/// until EOF.
pub async fn run() -> anyhow::Result<()> {
    let server = Server::stdio();
    server.run().await
}
