//! Disposable Linux test entry point for the isolated lifecycle module.
#[path = "../../crates/executor/src/process_lifecycle.rs"]
mod process_lifecycle;

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 || args[1] != "--manager" {
        eprintln!("usage: process-lifecycle-runner --manager DISPOSABLE_ROOT");
        std::process::exit(2);
    }
    if let Err(error) = process_lifecycle::run_disposable_manager(std::path::Path::new(&args[2])) {
        eprintln!("process lifecycle: {error}");
        std::process::exit(1);
    }
}
