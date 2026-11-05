//! JSON-RPC 2.0 envelope, error codes and the role table (`docs/05 §2–4`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Caller role, derived from the client's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Admin,
}

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;
pub const UNAUTHORIZED: i32 = -32001;
pub const INVALID_STATE: i32 = -32002;
pub const NOT_FOUND: i32 = -32003;
pub const CONFLICT: i32 = -32004;
pub const RATE_LIMITED: i32 = -32005;
pub const AI_UNAVAILABLE: i32 = -32006;
pub const PROTECTED_TARGET: i32 = -32007;
pub const ENFORCEMENT_OFF: i32 = -32008;

/// Every code with its schema name.
pub const ERROR_CODES: [(i32, &str); 13] = [
    (PARSE_ERROR, "parse_error"),
    (INVALID_REQUEST, "invalid_request"),
    (METHOD_NOT_FOUND, "method_not_found"),
    (INVALID_PARAMS, "invalid_params"),
    (INTERNAL_ERROR, "internal_error"),
    (UNAUTHORIZED, "unauthorized"),
    (INVALID_STATE, "invalid_state"),
    (NOT_FOUND, "not_found"),
    (CONFLICT, "conflict"),
    (RATE_LIMITED, "rate_limited"),
    (AI_UNAVAILABLE, "ai_unavailable"),
    (PROTECTED_TARGET, "protected_target"),
    (ENFORCEMENT_OFF, "enforcement_off"),
];

/// Minimum role per method; the contract test pins this to `x-methods` in the schema.
pub const METHODS: [(&str, Role); 39] = [
    ("hello", Role::Viewer),
    ("status.get", Role::Viewer),
    ("mode.set", Role::Admin),
    ("process.list", Role::Viewer),
    ("process.get", Role::Viewer),
    ("process.modules", Role::Admin),
    ("process.kill", Role::Admin),
    ("connection.list", Role::Viewer),
    ("pending.list", Role::Viewer),
    ("decision.submit", Role::Admin),
    ("decision.list", Role::Viewer),
    ("decision.revoke", Role::Admin),
    ("decision.exception", Role::Admin),
    ("reopen.answer", Role::Admin),
    ("launcher.answer", Role::Admin),
    ("identity.get", Role::Viewer),
    ("rule.list", Role::Viewer),
    ("rule.upsert", Role::Admin),
    ("rule.delete", Role::Admin),
    ("trust.list", Role::Viewer),
    ("trust.pin", Role::Admin),
    ("trust.revoke", Role::Admin),
    ("persistence.scan", Role::Admin),
    ("persistence.apply", Role::Admin),
    ("ai.activity", Role::Viewer),
    ("ai.config.get", Role::Viewer),
    ("ai.config.set", Role::Admin),
    ("ai.preview", Role::Admin),
    ("ai.test", Role::Admin),
    ("ai.explain", Role::Admin),
    ("audit.query", Role::Viewer),
    ("audit.export", Role::Admin),
    ("decision.export", Role::Admin),
    ("decision.import", Role::Admin),
    ("settings.get", Role::Viewer),
    ("settings.set", Role::Admin),
    ("enforcement.panic", Role::Admin),
    ("subscribe", Role::Viewer),
    ("unsubscribe", Role::Viewer),
];

/// `error` member of a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// Client request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Server response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    #[must_use]
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn err(id: Value, error: RpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Server-initiated message (no `id`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// Role required by `method`, or `None` for an unknown method.
#[must_use]
pub fn required_role(method: &str) -> Option<Role> {
    METHODS.iter().find(|(m, _)| *m == method).map(|(_, r)| *r)
}

/// Check that `role` may call `method`: unknown → `-32601`, insufficient role → `-32001`.
pub fn authorize(role: Role, method: &str) -> Result<(), RpcError> {
    match required_role(method) {
        None => Err(RpcError::new(
            METHOD_NOT_FOUND,
            format!("unknown method {method}"),
        )),
        Some(Role::Admin) if role != Role::Admin => Err(RpcError::new(
            UNAUTHORIZED,
            format!("{method} requires the admin role"),
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn viewer_cannot_call_admin_methods() {
        assert_eq!(
            authorize(Role::Viewer, "mode.set").unwrap_err().code,
            UNAUTHORIZED
        );
        assert!(authorize(Role::Viewer, "process.list").is_ok());
        assert!(authorize(Role::Admin, "mode.set").is_ok());
    }

    #[test]
    fn unknown_method_is_32601_for_everyone() {
        assert_eq!(
            authorize(Role::Admin, "nope").unwrap_err().code,
            METHOD_NOT_FOUND
        );
    }
}
