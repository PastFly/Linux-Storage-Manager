use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisposableLoopOwnershipProof {
    pub loop_device: String,
    pub backing_file: PathBuf,
    pub backing_dev: u64,
    pub backing_ino: u64,
    pub owned_root: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisposableOwnershipError {
    #[error("disposable loop device path is invalid")]
    InvalidLoopDevice,
    #[error("disposable backing file must be inside the owned root")]
    BackingFileOutsideOwnedRoot,
    #[error("disposable backing file is not a regular file")]
    BackingFileNotRegular,
    #[error("disposable backing file identity changed")]
    BackingFileIdentityChanged,
    #[error("disposable ownership path metadata failed: {0}")]
    Metadata(String),
}

fn valid_loop_path(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("/dev/loop") else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn metadata(path: &Path) -> Result<fs::Metadata, DisposableOwnershipError> {
    fs::symlink_metadata(path)
        .map_err(|error| DisposableOwnershipError::Metadata(format!("{}: {error}", path.display())))
}

/// Freeze harness-owned loop identity before any disposable mutation.
///
/// This does not inspect or mutate the loop block device. The integration harness remains
/// responsible for proving loop major/backing-file association immediately before execution.
pub fn capture_disposable_loop_ownership(
    loop_device: &str,
    backing_file: &Path,
    owned_root: &Path,
) -> Result<DisposableLoopOwnershipProof, DisposableOwnershipError> {
    if !valid_loop_path(loop_device) {
        return Err(DisposableOwnershipError::InvalidLoopDevice);
    }

    let root = owned_root.canonicalize().map_err(|error| {
        DisposableOwnershipError::Metadata(format!("{}: {error}", owned_root.display()))
    })?;
    let parent = backing_file
        .parent()
        .ok_or(DisposableOwnershipError::BackingFileOutsideOwnedRoot)?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        DisposableOwnershipError::Metadata(format!("{}: {error}", parent.display()))
    })?;
    if canonical_parent != root {
        return Err(DisposableOwnershipError::BackingFileOutsideOwnedRoot);
    }

    let info = metadata(backing_file)?;
    if info.file_type().is_symlink() || !info.file_type().is_file() {
        return Err(DisposableOwnershipError::BackingFileNotRegular);
    }

    Ok(DisposableLoopOwnershipProof {
        loop_device: loop_device.to_owned(),
        backing_file: backing_file.to_path_buf(),
        backing_dev: info.dev(),
        backing_ino: info.ino(),
        owned_root: root,
    })
}

pub fn revalidate_disposable_loop_ownership(
    proof: &DisposableLoopOwnershipProof,
) -> Result<(), DisposableOwnershipError> {
    if !valid_loop_path(&proof.loop_device) {
        return Err(DisposableOwnershipError::InvalidLoopDevice);
    }
    let parent = proof
        .backing_file
        .parent()
        .ok_or(DisposableOwnershipError::BackingFileOutsideOwnedRoot)?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        DisposableOwnershipError::Metadata(format!("{}: {error}", parent.display()))
    })?;
    if canonical_parent != proof.owned_root {
        return Err(DisposableOwnershipError::BackingFileOutsideOwnedRoot);
    }

    let info = metadata(&proof.backing_file)?;
    if info.file_type().is_symlink() || !info.file_type().is_file() {
        return Err(DisposableOwnershipError::BackingFileNotRegular);
    }
    if info.dev() != proof.backing_dev || info.ino() != proof.backing_ino {
        return Err(DisposableOwnershipError::BackingFileIdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lsm-disposable-ownership-{}-{id}",
            std::process::id()
        ))
    }

    #[test]
    fn loop_path_boundary_rejects_partitions_and_non_loop_devices() {
        assert!(valid_loop_path("/dev/loop0"));
        assert!(valid_loop_path("/dev/loop42"));
        assert!(!valid_loop_path("/dev/loop"));
        assert!(!valid_loop_path("/dev/loop7p1"));
        assert!(!valid_loop_path("/dev/sda"));
        assert!(!valid_loop_path("loop7"));
    }

    #[test]
    fn captures_and_revalidates_owned_regular_backing_file() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        let image = root.join("owned.img");
        File::create(&image).unwrap();

        let proof = capture_disposable_loop_ownership("/dev/loop7", &image, &root).unwrap();

        assert_eq!(proof.loop_device, "/dev/loop7");
        assert_eq!(revalidate_disposable_loop_ownership(&proof), Ok(()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_loop_and_outside_backing_file() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        let image = root.join("owned.img");
        File::create(&image).unwrap();

        assert_eq!(
            capture_disposable_loop_ownership("/dev/sda", &image, &root),
            Err(DisposableOwnershipError::InvalidLoopDevice)
        );

        let outside_root = root.with_extension("outside");
        fs::create_dir_all(&outside_root).unwrap();
        let outside = outside_root.join("outside.img");
        File::create(&outside).unwrap();
        assert_eq!(
            capture_disposable_loop_ownership("/dev/loop7", &outside, &root),
            Err(DisposableOwnershipError::BackingFileOutsideOwnedRoot)
        );

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside_root).unwrap();
    }

    #[test]
    fn replacement_inode_invalidates_frozen_ownership() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        let image = root.join("owned.img");
        File::create(&image).unwrap();
        let proof = capture_disposable_loop_ownership("/dev/loop7", &image, &root).unwrap();

        let replacement = root.join("replacement.img");
        File::create(&replacement).unwrap();
        fs::rename(&replacement, &image).unwrap();

        assert_eq!(
            revalidate_disposable_loop_ownership(&proof),
            Err(DisposableOwnershipError::BackingFileIdentityChanged)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
