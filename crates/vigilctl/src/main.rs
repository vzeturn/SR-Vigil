//! `vigilctl`: administrative and diagnostic command-line client for `VigilSvc`.
#![forbid(unsafe_code)]

fn main() {
    println!("vigilctl {}", env!("CARGO_PKG_VERSION"));
}
