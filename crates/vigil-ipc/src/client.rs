//! Minimal sequential client: one request in flight, notifications queued for the caller.

use std::collections::VecDeque;
use std::io;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::frame::{read_frame, write_frame};
use crate::proto::{Notification, Request, Response, RpcError};

/// Failure of a call: transport or an error returned by the service.
#[derive(Debug)]
pub enum CallError {
    Io(io::Error),
    Rpc(RpcError),
}

impl From<io::Error> for CallError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Rpc(e) => write!(f, "rpc: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

pub struct Client<S> {
    stream: S,
    next_id: u64,
    pub notifications: VecDeque<Notification>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    #[must_use]
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next_id: 1,
            notifications: VecDeque::new(),
        }
    }

    /// Send a request and wait for its response; notifications that arrive meanwhile are queued.
    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = Request {
            jsonrpc: "2.0".into(),
            id: Value::from(id),
            method: method.into(),
            params: Some(params),
        };
        let bytes = serde_json::to_vec(&req).map_err(io::Error::from)?;
        write_frame(&mut self.stream, &bytes).await?;
        loop {
            let frame = read_frame(&mut self.stream)
                .await?
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
            let value: Value = serde_json::from_slice(&frame).map_err(io::Error::from)?;
            if value.get("id").is_none() {
                if let Ok(n) = serde_json::from_value(value) {
                    self.notifications.push_back(n);
                }
                continue;
            }
            let resp: Response = serde_json::from_value(value).map_err(io::Error::from)?;
            if resp.id.as_u64() != Some(id) {
                continue;
            }
            return match resp.error {
                Some(e) => Err(CallError::Rpc(e)),
                None => Ok(resp.result.unwrap_or(Value::Null)),
            };
        }
    }
}
