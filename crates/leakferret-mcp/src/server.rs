//! JSON-RPC stdio loop. One request per line; responses written to
//! stdout flushed immediately so MCP hosts can stream them.

use anyhow::Result;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::io::{Stdin, Stdout};

use crate::methods;
use crate::protocol::{codes, PromptsList, Response, ToolsList, PROTOCOL_VERSION};

/// MCP server bound to a stdio pair. The default is stdin/stdout
/// (per the MCP spec); the constructors are split out for tests.
pub struct Server<R, W> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
}

impl Server<Stdin, Stdout> {
    pub fn stdio() -> Self {
        Self {
            reader: BufReader::new(tokio::io::stdin()),
            writer: BufWriter::new(tokio::io::stdout()),
        }
    }
}

impl<R, W> Server<R, W>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                return Ok(());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let response = match serde_json::from_str::<crate::protocol::Request>(trimmed) {
                Ok(req) => handle(req).await,
                Err(e) => Response::error(None, codes::PARSE_ERROR, format!("parse error: {e}")),
            };

            // Notifications (no id) get no response.
            if response.id.is_none() && response.payload.is_none() {
                continue;
            }

            let bytes = serde_json::to_vec(&response)?;
            self.writer.write_all(&bytes).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;
        }
    }
}

async fn handle(req: crate::protocol::Request) -> Response {
    let id = req.id.clone();
    match req.method.as_str() {
        "initialize" => initialize(id),
        "initialized" | "notifications/initialized" | "ping" => Response::ok(id, json!({})),
        "tools/list" => Response::ok(
            id,
            serde_json::to_value(ToolsList {
                tools: methods::TOOLS,
            })
            .unwrap_or(Value::Null),
        ),
        "prompts/list" => Response::ok(
            id,
            serde_json::to_value(PromptsList {
                prompts: methods::PROMPTS,
            })
            .unwrap_or(Value::Null),
        ),
        "tools/call" => methods::call_tool(id, req.params).await,
        "prompts/get" => methods::get_prompt(id, req.params),
        m => Response::error(
            id,
            codes::METHOD_NOT_FOUND,
            format!("method not found: {m}"),
        ),
    }
}

fn initialize(id: Option<Value>) -> Response {
    Response::ok(
        id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools":   { "listChanged": false },
                "prompts": { "listChanged": false },
            },
            "serverInfo": {
                "name":    "leakferret",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn initialize_handshake() {
        let req = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.to_vec();
        let (mut wread, wwrite) = tokio::io::duplex(8192);
        let (rread, mut rwrite) = tokio::io::duplex(8192);
        rwrite.write_all(&req).await.unwrap();
        rwrite.write_all(b"\n").await.unwrap();
        drop(rwrite);

        let server = Server::new(rread, wwrite);
        server.run().await.unwrap();

        let mut out = String::new();
        wread.read_to_string(&mut out).await.unwrap();
        assert!(out.contains("\"protocolVersion\""));
        assert!(out.contains("\"leakferret\""));
    }
}
