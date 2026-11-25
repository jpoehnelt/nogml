//! Built-in Model Context Protocol (MCP) JSON-RPC 2.0 server supporting:
//! - stdio transport (`nogml mcp`)
//! - Streamable HTTP transport (`POST /mcp`, `DELETE /mcp`, `GET /mcp` on `nogml serve`)
//!
//! Owned by the `ai-mcp` worker.

use axum::Router;
use serde_json::Value;

use crate::{AppState, error::AppResult};

/// Stateful-optional MCP JSON-RPC 2.0 dispatcher shared by stdio and HTTP transports.
#[derive(Clone)]
pub struct McpServer {
    _state: AppState,
}

impl McpServer {
    pub fn new(state: AppState) -> Self {
        Self { _state: state }
    }

    /// Handle one JSON-RPC 2.0 request object. Returns `Ok(None)` for notifications (no `id`).
    pub async fn handle_request(&self, _request: Value) -> AppResult<Option<Value>> {
        todo!("ai-mcp worker: MCP JSON-RPC 2.0 dispatcher")
    }
}

/// Run the newline-delimited JSON-RPC 2.0 MCP server on stdin/stdout (`nogml mcp`).
/// All logs MUST go to `stderr` so `stdout` carries strictly valid JSON-RPC frames.
pub async fn run_stdio(_state: AppState) -> AppResult<()> {
    todo!("ai-mcp worker: stdio MCP loop")
}

/// Mount Streamable HTTP MCP routes (`/mcp`).
pub fn mcp_router() -> Router<AppState> {
    Router::new()
}
