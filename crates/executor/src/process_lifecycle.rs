//! Experimental isolated process lifecycle. Not wired to production.
//!
//! A successful return must eventually mean that a worker was born in a
//! dedicated cgroup, an independent guard retained the manager pidfd, and
//! cleanup has verified `populated 0`. No lease or backup proof is implied.
//! The implementation remains fail-closed until the Linux protocol is proven.

use std::io;
use std::path::Path;

pub(crate) fn run_disposable_manager(_root: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "isolated process lifecycle not implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_cgroup_root_is_rejected_without_changes() {
        let root =
            std::env::temp_dir().join(format!("lsm-lifecycle-not-cgroup-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let result = run_disposable_manager(&root);
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir(root).unwrap();
    }
}
