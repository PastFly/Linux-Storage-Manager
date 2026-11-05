use std::io;
use std::process::{Command, Output};

/// The caller chooses how read-only discovery utilities are resolved and run.
pub trait DiscoveryCommandRunner {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<Output>;
    fn available(&self, program: &str) -> bool;
}

pub struct SystemDiscoveryRunner;

impl DiscoveryCommandRunner for SystemDiscoveryRunner {
    fn output(&self, program: &str, args: &[&str]) -> io::Result<Output> {
        Command::new(program).env("LC_ALL", "C").args(args).output()
    }

    fn available(&self, program: &str) -> bool {
        crate::command_exists(program)
    }
}
