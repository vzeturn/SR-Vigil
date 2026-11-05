//! `vigilctl`: administrative and diagnostic command-line client for `VigilSvc`.
#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};

#[cfg(windows)]
mod control;
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
    /// List reclaimable junk; deletes only the categories named with --clean.
    Junk {
        /// Category ids to delete (for example `user_temp`).
        #[arg(long, value_name = "ID")]
        clean: Vec<String>,
    },
    /// Report which Defender Attack Surface Reduction rules are on (read-only; changes nothing).
    Posture,
    /// Show the running service's mode, health and verdict counts.
    Status {
        /// Emit machine-readable JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Remove every Vigil filter and return to observe mode (needs an elevated shell).
    Panic,
    /// Set the enforcement mode (needs an elevated shell).
    Mode {
        #[arg(value_parser = ["observe", "learning", "enforce"])]
        mode: String,
        /// Enter enforce before the minimum learning time has passed.
        #[arg(long = "override")]
        override_minimum: bool,
    },
    /// Show the AI advisor settings, or set its mode (needs an elevated shell).
    Ai {
        #[arg(long, value_parser = ["off", "advisor", "auto"])]
        mode: Option<String>,
        /// Ask the deeper model whenever the first answer is less sure than this (0.5 to 1).
        #[arg(long)]
        escalate_below: Option<f64>,
    },
    /// List the active user decisions, or lift one with `--revoke <ID>` (needs an elevated shell).
    Decisions {
        #[arg(long)]
        revoke: Option<String>,
        /// Lift a kill and pin an allow exception for the same program.
        #[arg(long, conflicts_with = "revoke")]
        except: Option<String>,
    },
    /// Allow one program by hash after you verified where it came from (needs an elevated shell).
    Allow {
        /// Full path of the program, as shown in the pending list.
        path: String,
        /// SHA-256 of the exact file you verified; refused if the service sees different bytes.
        #[arg(long)]
        sha256: String,
        /// Where the hash was verified (kept in the decision note).
        #[arg(long)]
        source: String,
    },
    /// Lockdown: stop untrusted background programs and hold them off (needs an elevated shell).
    Purge {
        #[command(subcommand)]
        action: PurgeCmd,
    },
    /// Kill a process (and optionally its tree) and keep it from respawning (needs an elevated shell).
    Kill {
        pid: u32,
        /// The process start time exactly as shown by `vigilctl scan --json`.
        start_time: String,
        #[arg(long)]
        tree: bool,
    },
    /// Inspect and reversibly disable autostart entries (needs an elevated shell).
    #[command(subcommand)]
    Persistence(PersistenceCmd),
    /// Register or control the Windows service (needs an elevated shell).
    #[command(subcommand)]
    Service(ServiceCmd),
}

#[derive(Subcommand)]
enum PurgeCmd {
    /// Start a lockdown for the given number of minutes (1 to 30).
    Start {
        #[arg(long, default_value_t = 5)]
        minutes: u32,
    },
    /// Release the hold now.
    Stop,
    /// Show the current or last lockdown.
    Status,
}

#[derive(Subcommand)]
enum PersistenceCmd {
    /// List autostart entries, optionally only those pointing at one image.
    Scan { image: Option<String> },
    /// Disable, restore or delete (after disable) one scanned entry.
    Apply {
        item_id: String,
        #[arg(value_parser = ["disable", "restore", "delete"])]
        action: String,
    },
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
        Command::Junk { clean } => {
            if clean.is_empty() {
                for c in vigil_win::junk::scan() {
                    println!("{:<14} {:>7} files {:>7} MB", c.id, c.files, c.bytes >> 20);
                }
            } else {
                let freed = vigil_win::junk::clean(&clean);
                println!("freed {} MB", freed >> 20);
            }
            Ok(())
        }
        Command::Posture => {
            let mut off = 0;
            for (guid, what) in vigil_core::posture::RECOMMENDED_ASR {
                let s = vigil_win::asr::state(guid);
                off += usize::from(!s.enforces());
                println!("{what:<44} {s}");
            }
            println!(
                "{off} of {} recommended ASR rules are not enforcing",
                vigil_core::posture::RECOMMENDED_ASR.len()
            );
            Ok(())
        }
        Command::Status { json } => status::run(json),
        Command::Panic => control::panic(),
        Command::Mode {
            mode,
            override_minimum,
        } => control::mode(&mode, override_minimum),
        Command::Ai {
            mode,
            escalate_below,
        } => control::ai(mode.as_deref(), escalate_below),
        Command::Decisions { revoke, except } => {
            control::decisions(revoke.as_deref(), except.as_deref())
        }
        Command::Allow {
            path,
            sha256,
            source,
        } => control::allow(&path, &sha256, &source),
        Command::Purge { action } => match action {
            PurgeCmd::Start { minutes } => {
                control::purge("purge.start", serde_json::json!({ "minutes": minutes }))
            }
            PurgeCmd::Stop => control::purge("purge.stop", serde_json::json!({})),
            PurgeCmd::Status => control::purge("purge.status", serde_json::json!({})),
        },
        Command::Kill {
            pid,
            start_time,
            tree,
        } => control::kill(pid, &start_time, tree),
        Command::Persistence(PersistenceCmd::Scan { image }) => {
            control::persistence_scan(image.as_deref())
        }
        Command::Persistence(PersistenceCmd::Apply { item_id, action }) => {
            control::persistence_apply(&item_id, &action)
        }
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
