use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PrivilegedProgram, ProductionCreateRuntimePreflightReceipt, TrustedToolIdentity};

const TOOL_READ_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub struct PinnedProductionCreateTools {
    preflight_receipt_id: String,
    pub sfdisk: TrustedToolIdentity,
    pub partx: TrustedToolIdentity,
    pub mkfs: TrustedToolIdentity,
    _sfdisk: File,
    _partx: File,
    _mkfs: File,
}

impl PinnedProductionCreateTools {
    pub fn preflight_receipt_id(&self) -> &str {
        &self.preflight_receipt_id
    }

    pub(crate) fn sfdisk_file(&self) -> &File {
        &self._sfdisk
    }

    pub(crate) fn partx_file(&self) -> &File {
        &self._partx
    }

    pub(crate) fn mkfs_file(&self) -> &File {
        &self._mkfs
    }

    pub fn revalidate(
        &self,
        preflight: &ProductionCreateRuntimePreflightReceipt,
    ) -> Result<(), ProductionCreateToolLeaseError> {
        validate_preflight(preflight)?;
        if self.preflight_receipt_id != preflight.receipt_id
            || self.sfdisk != preflight.sfdisk
            || self.partx != preflight.partx
            || self.mkfs != preflight.mkfs
        {
            return Err(ProductionCreateToolLeaseError::PreflightInvalid);
        }
        validate_open_tool(self.sfdisk_file(), &self.sfdisk)?;
        validate_open_tool(self.partx_file(), &self.partx)?;
        validate_open_tool(self.mkfs_file(), &self.mkfs)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateToolLeaseError {
    #[error("create runtime preflight integrity or state is invalid")]
    PreflightInvalid,
    #[error("create preflight tool identity is bound to the wrong program")]
    ProgramMismatch,
    #[error("pinned create executable no longer matches trusted identity")]
    ToolIdentityMismatch,
    #[error("create executable pinning I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

fn validate_preflight(
    preflight: &ProductionCreateRuntimePreflightReceipt,
) -> Result<(), ProductionCreateToolLeaseError> {
    if preflight.schema_version != 1
        || !preflight.integrity_matches().unwrap_or(false)
        || !preflight.runtime_ready
        || preflight.mutation_enabled
        || preflight.process_spawned
        || preflight.partition_table_changed
        || preflight.filesystem_formatted
    {
        return Err(ProductionCreateToolLeaseError::PreflightInvalid);
    }
    let mkfs_expected = match preflight.filesystem.as_str() {
        "ext4" => PrivilegedProgram::MkfsExt4,
        "xfs" => PrivilegedProgram::MkfsXfs,
        _ => return Err(ProductionCreateToolLeaseError::ProgramMismatch),
    };
    if preflight.sfdisk.program != PrivilegedProgram::Sfdisk
        || preflight.partx.program != PrivilegedProgram::Partx
        || preflight.mkfs.program != mkfs_expected
    {
        return Err(ProductionCreateToolLeaseError::ProgramMismatch);
    }
    Ok(())
}

fn sha256_file(file: &File, expected_size: u64) -> Result<String, std::io::Error> {
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; TOOL_READ_CHUNK];

    while offset < expected_size {
        let remaining = (expected_size - offset) as usize;
        let want = remaining.min(buffer.len());
        let read = file.read_at(&mut buffer[..want], offset)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("tool hash offset overflow"))?;
    }
    if offset != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "trusted create tool size changed while hashing",
        ));
    }
    let mut probe = [0_u8; 1];
    if file.read_at(&mut probe, expected_size)? != 0 {
        return Err(std::io::Error::other(
            "trusted create tool grew while hashing",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_open_tool(
    file: &File,
    identity: &TrustedToolIdentity,
) -> Result<(), ProductionCreateToolLeaseError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device_id
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.uid
        || metadata.mode() != identity.mode
        || metadata.len() != identity.size_bytes
        || sha256_file(file, identity.size_bytes)? != identity.sha256
    {
        return Err(ProductionCreateToolLeaseError::ToolIdentityMismatch);
    }
    Ok(())
}

fn open_exact_tool(identity: &TrustedToolIdentity) -> Result<File, ProductionCreateToolLeaseError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(&identity.canonical_path))?;
    validate_open_tool(&file, identity)?;
    Ok(file)
}

/// Pin the exact M2A6 sfdisk/partx/mkfs executable objects by open descriptor.
/// No process is spawned and no disk/filesystem state is changed.
pub fn pin_production_create_tools(
    preflight: &ProductionCreateRuntimePreflightReceipt,
) -> Result<PinnedProductionCreateTools, ProductionCreateToolLeaseError> {
    validate_preflight(preflight)?;

    let sfdisk_file = open_exact_tool(&preflight.sfdisk)?;
    let partx_file = open_exact_tool(&preflight.partx)?;
    let mkfs_file = open_exact_tool(&preflight.mkfs)?;

    Ok(PinnedProductionCreateTools {
        preflight_receipt_id: preflight.receipt_id.clone(),
        sfdisk: preflight.sfdisk.clone(),
        partx: preflight.partx.clone(),
        mkfs: preflight.mkfs.clone(),
        _sfdisk: sfdisk_file,
        _partx: partx_file,
        _mkfs: mkfs_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_executable(name: &str, bytes: &[u8]) -> (std::path::PathBuf, File) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "lsm-create-tool-lease-{}-{stamp}-{name}",
            std::process::id()
        ));
        fs::write(&path, bytes).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        let file = File::open(&path).unwrap();
        (path, file)
    }

    fn identity(
        program: PrivilegedProgram,
        path: &Path,
        file: &File,
        bytes: &[u8],
    ) -> TrustedToolIdentity {
        let metadata = file.metadata().unwrap();
        TrustedToolIdentity {
            program,
            requested_path: path.to_string_lossy().into_owned(),
            canonical_path: path.to_string_lossy().into_owned(),
            device_id: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            size_bytes: metadata.len(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    #[test]
    fn exact_open_descriptor_matches_frozen_create_tool() {
        let bytes = b"trusted-mkfs-bytes";
        let (path, file) = temp_executable("exact", bytes);
        let expected = identity(PrivilegedProgram::MkfsExt4, &path, &file, bytes);

        let pinned = open_exact_tool(&expected).unwrap();
        assert_eq!(pinned.metadata().unwrap().ino(), expected.inode);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn in_place_create_tool_change_is_rejected() {
        let bytes = b"trusted-sfdisk-bytes";
        let (path, file) = temp_executable("changed", bytes);
        let expected = identity(PrivilegedProgram::Sfdisk, &path, &file, bytes);
        let pinned = open_exact_tool(&expected).unwrap();

        fs::write(&path, b"different-sfdisk-bytes").unwrap();

        assert!(matches!(
            validate_open_tool(&pinned, &expected),
            Err(ProductionCreateToolLeaseError::ToolIdentityMismatch)
        ));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pathname_replacement_is_rejected() {
        let bytes = b"trusted-partx-bytes";
        let (path, file) = temp_executable("replaced", bytes);
        let expected = identity(PrivilegedProgram::Partx, &path, &file, bytes);
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, bytes).unwrap();
        let mut permissions = fs::metadata(&replacement).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&replacement, permissions).unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert!(matches!(
            open_exact_tool(&expected),
            Err(ProductionCreateToolLeaseError::ToolIdentityMismatch)
        ));

        fs::remove_file(path).unwrap();
    }
}
