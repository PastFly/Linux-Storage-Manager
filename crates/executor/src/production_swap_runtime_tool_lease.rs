use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PrivilegedProgram, ProductionSwapRuntimePreflightReceipt, TrustedToolIdentity};

const TOOL_READ_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub struct PinnedProductionSwapRuntimeTools {
    preflight_receipt_id: String,
    _mkswap: File,
    _swapon: File,
    _swapoff: File,
}

impl PinnedProductionSwapRuntimeTools {
    pub fn preflight_receipt_id(&self) -> &str {
        &self.preflight_receipt_id
    }

    pub(crate) fn mkswap_file(&self) -> &File {
        &self._mkswap
    }

    pub(crate) fn swapon_file(&self) -> &File {
        &self._swapon
    }

    pub(crate) fn swapoff_file(&self) -> &File {
        &self._swapoff
    }

    /// Revalidate the exact already-open executable objects against the fresh
    /// M1B60 identities immediately before building or crossing the descriptor
    /// launch boundary. This catches in-place inode/content mutation even
    /// though the descriptors themselves remain pinned.
    pub fn revalidate(
        &self,
        preflight: &ProductionSwapRuntimePreflightReceipt,
    ) -> Result<(), ProductionSwapRuntimeToolLeaseError> {
        validate_preflight(preflight)?;
        if self.preflight_receipt_id != preflight.receipt_id {
            return Err(ProductionSwapRuntimeToolLeaseError::PreflightInvalid);
        }
        validate_open_tool(self.mkswap_file(), &preflight.mkswap)?;
        validate_open_tool(self.swapon_file(), &preflight.swapon)?;
        validate_open_tool(self.swapoff_file(), &preflight.swapoff)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapRuntimeToolLeaseError {
    #[error("swap runtime preflight receipt integrity or state is invalid")]
    PreflightInvalid,
    #[error("swap runtime preflight tool identity is bound to the wrong program")]
    ProgramMismatch,
    #[error("pinned swap runtime executable no longer matches trusted identity")]
    ToolIdentityMismatch,
    #[error("swap runtime executable pinning I/O failed: {0}")]
    Io(#[from] std::io::Error),
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
            "trusted tool size changed while hashing",
        ));
    }
    let mut probe = [0_u8; 1];
    if file.read_at(&mut probe, expected_size)? != 0 {
        return Err(std::io::Error::other("trusted tool grew while hashing"));
    }

    Ok(format!("{:x}", digest.finalize()))
}

fn validate_open_tool(
    file: &File,
    identity: &TrustedToolIdentity,
) -> Result<(), ProductionSwapRuntimeToolLeaseError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device_id
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.uid
        || metadata.mode() != identity.mode
        || metadata.len() != identity.size_bytes
        || sha256_file(file, identity.size_bytes)? != identity.sha256
    {
        return Err(ProductionSwapRuntimeToolLeaseError::ToolIdentityMismatch);
    }
    Ok(())
}

fn open_exact_tool(
    identity: &TrustedToolIdentity,
) -> Result<File, ProductionSwapRuntimeToolLeaseError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(&identity.canonical_path))?;
    validate_open_tool(&file, identity)?;
    Ok(file)
}

fn validate_preflight(
    preflight: &ProductionSwapRuntimePreflightReceipt,
) -> Result<(), ProductionSwapRuntimeToolLeaseError> {
    if preflight.schema_version != 1
        || !preflight.integrity_matches().unwrap_or(false)
        || !preflight.runtime_ready
        || preflight.mutation_enabled
        || preflight.process_spawned
    {
        return Err(ProductionSwapRuntimeToolLeaseError::PreflightInvalid);
    }
    if preflight.mkswap.program != PrivilegedProgram::Mkswap
        || preflight.swapon.program != PrivilegedProgram::Swapon
        || preflight.swapoff.program != PrivilegedProgram::Swapoff
    {
        return Err(ProductionSwapRuntimeToolLeaseError::ProgramMismatch);
    }
    Ok(())
}

/// Pin all swap runtime executables by descriptor after the fresh M1B60
/// preflight. No process is spawned and no storage/swap state is changed.
pub fn pin_production_swap_runtime_tools(
    preflight: &ProductionSwapRuntimePreflightReceipt,
) -> Result<PinnedProductionSwapRuntimeTools, ProductionSwapRuntimeToolLeaseError> {
    validate_preflight(preflight)?;

    let mkswap = open_exact_tool(&preflight.mkswap)?;
    let swapon = open_exact_tool(&preflight.swapon)?;
    let swapoff = open_exact_tool(&preflight.swapoff)?;

    Ok(PinnedProductionSwapRuntimeTools {
        preflight_receipt_id: preflight.receipt_id.clone(),
        _mkswap: mkswap,
        _swapon: swapon,
        _swapoff: swapoff,
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
            "lsm-swap-tool-lease-{}-{stamp}-{name}",
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
    fn exact_open_file_matches_frozen_tool_identity() {
        let bytes = b"trusted-tool-bytes";
        let (path, file) = temp_executable("exact", bytes);
        let expected = identity(PrivilegedProgram::Mkswap, &path, &file, bytes);

        let pinned = open_exact_tool(&expected).unwrap();
        assert_eq!(pinned.metadata().unwrap().ino(), expected.inode);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn in_place_tool_change_is_rejected() {
        let bytes = b"trusted-tool-bytes";
        let (path, file) = temp_executable("changed", bytes);
        let expected = identity(PrivilegedProgram::Swapon, &path, &file, bytes);
        fs::write(&path, b"different-tool-bytes").unwrap();

        assert!(matches!(
            open_exact_tool(&expected),
            Err(ProductionSwapRuntimeToolLeaseError::ToolIdentityMismatch)
        ));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pathname_replacement_is_rejected_by_inode_binding() {
        let bytes = b"trusted-tool-bytes";
        let (path, file) = temp_executable("replaced", bytes);
        let expected = identity(PrivilegedProgram::Swapoff, &path, &file, bytes);
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, bytes).unwrap();
        let mut permissions = fs::metadata(&replacement).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&replacement, permissions).unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert!(matches!(
            open_exact_tool(&expected),
            Err(ProductionSwapRuntimeToolLeaseError::ToolIdentityMismatch)
        ));

        fs::remove_file(path).unwrap();
    }
}
