//! `cargo xtask check`: the full local gate (same steps as CI `lint` + `core-tests`).

use std::process::{Command, ExitCode};

/// Gate steps. `deny` and `audit` are skipped with a notice when the cargo subcommand is not installed.
const STEPS: [(&str, &[&str], Option<&str>); 5] = [
    ("fmt", &["fmt", "--all", "--", "--check"], None),
    (
        "clippy",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
        None,
    ),
    ("test", &["test", "--workspace"], None),
    ("deny", &["deny", "check"], Some("cargo-deny")),
    ("audit", &["audit"], Some("cargo-audit")),
];

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("check") {
        return check();
    }
    eprintln!("usage: cargo xtask check");
    ExitCode::from(2)
}

fn check() -> ExitCode {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut failed = Vec::new();
    for (name, args, tool) in STEPS {
        if tool.is_some_and(|_| !tool_installed(&cargo, args[0])) {
            eprintln!(
                "xtask: skipping `{name}` (cargo-{} not installed; CI runs it)",
                args[0]
            );
            continue;
        }
        eprintln!("xtask: running `{name}`");
        match Command::new(&cargo).args(args).status() {
            Ok(s) if s.success() => {}
            Ok(_) => failed.push(name),
            Err(e) => {
                eprintln!("xtask: cannot run cargo for `{name}`: {e}");
                failed.push(name);
            }
        }
    }
    if failed.is_empty() {
        eprintln!("xtask: all gates passed");
        ExitCode::SUCCESS
    } else {
        eprintln!("xtask: FAILED: {}", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn tool_installed(cargo: &str, subcommand: &str) -> bool {
    Command::new(cargo)
        .args([subcommand, "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
}
