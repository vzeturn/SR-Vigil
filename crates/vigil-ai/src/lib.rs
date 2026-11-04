//! Claude second-opinion client (`docs/06`). No unsafe, no OS access: the service owns the key
//! storage and decides what to do with an [`Opinion`].
#![forbid(unsafe_code)]

mod client;
mod error;
mod limits;
mod opinion;

pub use client::{Advisor, Config, SYSTEM_PROMPT, user_message};
pub use error::AiError;
pub use limits::Limiter;
pub use opinion::{Opinion, validate};
