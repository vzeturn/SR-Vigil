//! `vigilctl`: administrative and diagnostic command-line client for `VigilSvc`.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod scan;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod status;

#[derive(Parser)]
#[command(version, about = "Vigil command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Classify every running process (works without administrator rights).
    Scan {
        /// Emit machine-readable JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show the running service's mode, health and verdict counts.
    Status {
        /// Emit machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Register or control the Windows service (needs an elevated shell).
    #[command(subcommand)]
    Service(ServiceCmd),
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Register `VigilSvc` (auto-start, restart on failure) and start it.
    Install,
    /// Stop and remove `VigilSvc`; data is kept.
    Uninstall,
    /// Start the installed service.
    Start,
    /// Stop the installed service.
    Stop,
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Scan { json } => scan::run(json),
        Command::Status { json } => status::run(json),
        Command::Service(ServiceCmd::Install) => service::install(),
        Command::Service(ServiceCmd::Uninstall) => service::uninstall(),
        Command::Service(ServiceCmd::Start) => service::start(),
        Command::Service(ServiceCmd::Stop) => service::stop(),
    }
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    let _ = Cli::parse();
    anyhow::bail!("vigilctl requires Windows")
}
