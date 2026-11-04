//! Per-connection request loop with role enforcement and server-pushed notifications.

use std::future::Future;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::frame::{read_frame, write_frame};
use crate::proto::{
    INVALID_REQUEST, Notification, PARSE_ERROR, Request, Response, Role, RpcError, authorize,
};

/// Business logic behind the pipe. `call` is only reached for known methods the role may use.
pub trait Handler: Sync {
    fn call(
        &self,
        role: Role,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<Value, RpcError>> + Send;
}

/// Serve one connection until the peer disconnects. `notifications` carries pushed events.
pub async fn serve<S, H>(
    stream: S,
    role: Role,
    handler: &H,
    mut notifications: UnboundedReceiver<Notification>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        tokio::select! {
            frame = read_frame(&mut rd) => {
                let Some(bytes) = frame? else { return Ok(()) };
                let resp = respond(role, handler, &bytes).await;
                write_frame(&mut wr, &serde_json::to_vec(&resp)?).await?;
            }
            Some(n) = notifications.recv() => {
                write_frame(&mut wr, &serde_json::to_vec(&n)?).await?;
            }
        }
    }
}

async fn respond<H: Handler>(role: Role, handler: &H, bytes: &[u8]) -> Response {
    let req: Request = match serde_json::from_slice(bytes) {
        Ok(r) => r,
        Err(e) => {
            return Response::err(Value::Null, RpcError::new(PARSE_ERROR, e.to_string()));
        }
    };
    if req.jsonrpc != "2.0" {
        return Response::err(
            req.id,
            RpcError::new(INVALID_REQUEST, "jsonrpc must be \"2.0\""),
        );
    }
    if let Err(e) = authorize(role, &req.method) {
        return Response::err(req.id, e);
    }
    let params = req
        .params
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    match handler.call(role, &req.method, params).await {
        Ok(v) => Response::ok(req.id, v),
        Err(e) => Response::err(req.id, e),
    }
}
