#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::implicit_hasher,
    clippy::struct_excessive_bools
)]
//! Pure Vigil logic: shared types, rule engine, scoring, masquerade detection, policy decisions, redaction. No OS calls.

pub mod analysis;
pub mod audit;
pub mod consts;
pub mod eval;
pub mod observe;
pub mod rules;
