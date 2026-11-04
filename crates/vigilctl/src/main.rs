//! `vigilctl`: administrative and diagnostic command-line client for `VigilSvc`.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod scan;

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
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        #[cfg(windows)]
        Command::Scan { json } => scan::run(json),
        #[cfg(not(windows))]
        Command::Scan { .. } => anyhow::bail!("scan requires Windows"),
    }
}
