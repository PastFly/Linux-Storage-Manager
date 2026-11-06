//! Test-only fs-verity experiment; not a production recovery proof.
#![allow(dead_code)]
use std::fs::File;
use std::io;

pub(crate) fn enable(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "not implemented",
    ))
}

pub(crate) fn measure(_file: &File) -> io::Result<[u8; 32]> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "not implemented",
    ))
}

#[path = "backup_verity_tests.rs"]
mod tests;
