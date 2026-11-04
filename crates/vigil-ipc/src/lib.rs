#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
//! Named-pipe framing and JSON-RPC protocol types shared by the service, CLI and UI bridge.
//!
//! Transport-agnostic: everything works over any `AsyncRead + AsyncWrite`, so the service uses a
//! named pipe while tests use in-memory duplex streams.

pub mod client;
pub mod frame;
pub mod proto;
pub mod server;

/// Pipe name (`docs/05 §1`).
pub const PIPE_NAME: &str = r"\\.\pipe\vigil-control";
/// Protocol version.
pub const PROTOCOL: u32 = 1;
