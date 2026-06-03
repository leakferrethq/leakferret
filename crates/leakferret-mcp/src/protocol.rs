//! JSON-RPC 2.0 + MCP message envelopes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Inbound request.
#[derive(Debug, Deserialize)]
pub struct Request {
    #[allow(dead_code)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Outbound response.
#[derive(Debug, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub payload: Option<Payload>,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Payload {
    Result { result: Value },
    Error { error: RpcError },
}

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Response {
    pub fn ok(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            payload: Some(Payload::Result { result }),
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            payload: Some(Payload::Error {
                error: RpcError {
                    code,
                    message: message.into(),
                    data: None,
                },
            }),
        }
    }
}

/// Codes from the JSON-RPC 2.0 spec + MCP extensions.
pub mod codes {
    pub const PARSE_ERROR: i32 = -32_700;
    // Part of the JSON-RPC spec error set; kept for completeness.
    #[allow(dead_code)]
    pub const INVALID_REQUEST: i32 = -32_600;
    pub const METHOD_NOT_FOUND: i32 = -32_601;
    pub const INVALID_PARAMS: i32 = -32_602;
    pub const INTERNAL: i32 = -32_603;
}

/// `tools/list` response.
#[derive(Debug, Serialize)]
pub struct ToolsList<'a> {
    pub tools: &'a [Tool],
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

/// `prompts/list` response.
#[derive(Debug, Serialize)]
pub struct PromptsList<'a> {
    pub prompts: &'a [Prompt],
}

#[derive(Debug, Serialize)]
pub struct Prompt {
    pub name: &'static str,
    pub description: &'static str,
}

/// `resources/list` response.
#[derive(Debug, Serialize)]
pub struct ResourcesList<'a> {
    pub resources: &'a [Resource],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mime_type: &'static str,
}
