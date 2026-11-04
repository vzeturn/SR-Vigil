#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
//! Pure Vigil logic: shared types, rule engine, scoring, masquerade detection, policy decisions, redaction. No OS calls.

pub mod consts;
pub mod rules;
