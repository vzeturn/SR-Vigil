#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::implicit_hasher)]
//! `VigilSvc`: live state, IPC handlers and (on Windows) the observer and service host.

pub mod ai;
pub mod ai_usage;
pub mod catalogue;
pub mod decide;
pub mod enforce;
pub mod events;
pub mod handler;
pub mod kill;
pub mod launcher;
pub mod persist;
pub mod portable;
pub mod reopen;
pub mod state;

#[cfg(windows)]
pub mod host;
#[cfg(windows)]
pub mod observer;
#[cfg(windows)]
pub mod winctl;
#[cfg(windows)]
pub mod winfilter;
