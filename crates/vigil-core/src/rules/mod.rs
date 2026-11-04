//! Rule pack: typed model of `rules/*.toml`, validation, embedded defaults and `rules.d` overrides.
//!
//! A pack is either fully valid or rejected; [`RuleStore::reload`] keeps the previous pack on any error.

mod aux_data;
mod model;
mod store;

pub use aux_data::{Lolbins, Publisher, Publishers, SystemProcess, SystemProcesses};
pub use model::{
    Kind, PackMeta, PathClass, Rule, RuleError, RulePack, SignatureState, Verdict, VersionStatus,
    When,
};
pub use store::{EMBEDDED_DEFAULT, RuleStore};
