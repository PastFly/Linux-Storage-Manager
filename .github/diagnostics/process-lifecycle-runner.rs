//! Disposable Linux test entry point; never an operator execution gate.
#[path = "diagnostic-controller-channel.rs"]
mod channel;
#[path = "gated-worker-module.rs"]
mod gated;
#[path = "../../crates/executor/src/process_lifecycle.rs"]
mod process_lifecycle;

fn main() {
    if let Err(error) = process_lifecycle::run(std::env::args_os().collect()) {
        eprintln!("process lifecycle: {error}");
        std::process::exit(1);
    }
}
