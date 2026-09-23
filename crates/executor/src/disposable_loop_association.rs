use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableLoopAssociation {
    loop_device: String,
    backing_file: PathBuf,
}

impl DisposableLoopAssociation {
    pub fn loop_device(&self) -> &str {
        &self.loop_device
    }

    pub fn backing_file(&self) -> &Path {
        &self.backing_file
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisposableLoopAssociationError {
    #[error("loop association line is malformed")]
    Malformed,
    #[error("loop association does not match the owned loop device")]
    DeviceMismatch,
    #[error("loop association does not match the owned backing file")]
    BackingFileMismatch,
}

fn normalized_loop_device(value: &str) -> &str {
    value.trim()
}

/// Parse one `losetup --list --noheadings --output NAME,BACK-FILE <loop>` row.
///
/// This is deliberately a pure parser. Process execution remains outside this module.
pub fn verify_disposable_loop_association_row(
    expected_loop_device: &str,
    expected_backing_file: &Path,
    row: &str,
) -> Result<DisposableLoopAssociation, DisposableLoopAssociationError> {
    let row = row.trim();
    let split = row
        .find(char::is_whitespace)
        .ok_or(DisposableLoopAssociationError::Malformed)?;
    let (device, rest) = row.split_at(split);
    let backing = rest.trim();
    if device.is_empty() || backing.is_empty() {
        return Err(DisposableLoopAssociationError::Malformed);
    }
    if normalized_loop_device(device) != expected_loop_device {
        return Err(DisposableLoopAssociationError::DeviceMismatch);
    }

    let expected = expected_backing_file.to_string_lossy();
    if backing != expected {
        return Err(DisposableLoopAssociationError::BackingFileMismatch);
    }

    Ok(DisposableLoopAssociation {
        loop_device: device.to_owned(),
        backing_file: expected_backing_file.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_loop_association_is_accepted() {
        let association = verify_disposable_loop_association_row(
            "/dev/loop7",
            Path::new("/tmp/lsm-owned/disk image.raw"),
            "/dev/loop7 /tmp/lsm-owned/disk image.raw\n",
        )
        .unwrap();

        assert_eq!(association.loop_device(), "/dev/loop7");
        assert_eq!(
            association.backing_file(),
            Path::new("/tmp/lsm-owned/disk image.raw")
        );
    }

    #[test]
    fn device_or_backing_mismatch_fails_closed() {
        assert_eq!(
            verify_disposable_loop_association_row(
                "/dev/loop7",
                Path::new("/tmp/owned.img"),
                "/dev/loop8 /tmp/owned.img",
            ),
            Err(DisposableLoopAssociationError::DeviceMismatch)
        );
        assert_eq!(
            verify_disposable_loop_association_row(
                "/dev/loop7",
                Path::new("/tmp/owned.img"),
                "/dev/loop7 /tmp/other.img",
            ),
            Err(DisposableLoopAssociationError::BackingFileMismatch)
        );
    }

    #[test]
    fn malformed_row_fails_closed() {
        assert_eq!(
            verify_disposable_loop_association_row(
                "/dev/loop7",
                Path::new("/tmp/owned.img"),
                "/dev/loop7",
            ),
            Err(DisposableLoopAssociationError::Malformed)
        );
    }
}
