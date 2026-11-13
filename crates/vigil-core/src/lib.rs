#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::implicit_hasher,
    clippy::struct_excessive_bools
)]
//! Pure Vigil logic: shared types, rule engine, scoring, masquerade detection, policy decisions, redaction. No OS calls.

pub mod analysis;
pub mod audit;
pub mod auto;
pub mod consts;
pub mod eval;
pub mod kill;
pub mod observe;
pub mod origin;
pub mod posture;
pub mod profile;
pub mod redact;
pub mod rules;
pub mod service;
pub mod storm;
pub mod urlfilter;
