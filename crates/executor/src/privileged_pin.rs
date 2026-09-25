use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    resolve_privileged_command_tools, PrivilegedCommandSpec, PrivilegedProgram,
    PrivilegedSpawnAuthorization, PrivilegedToolResolution, TrustedToolError, TrustedToolIdentity,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinnedToolReceipt {
    pub program: PrivilegedProgram,
    pub canonical_path: String,
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug)]
pub struct PinnedPrivilegedTools {
    pub schema_version: u32,
    pub pin_id: String,
    pub authorization_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub tool_resolution_digest: String,
    pub primary: PinnedToolReceipt,
    pub kernel_refresh: Option<PinnedToolReceipt>,
    primary_file: File,
    kernel_refresh_file: Option<File>,
}

impl PinnedPrivilegedTools {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.pin_id == self.expected_pin_id()?)
    }

    pub fn primary_is_open(&self) -> bool {
        self.primary_file.metadata().is_ok()
    }

    pub fn kernel_refresh_is_open(&self) -> bool {
        match &self.kernel_refresh {
            Some(_) => self
                .kernel_refresh_file
                .as_ref()
                .is_some_and(|file| file.metadata().is_ok()),
            None => self.kernel_refresh_file.is_none(),
        }
    }

    pub(crate) fn primary_file(&self) -> &File {
        &self.primary_file
    }

    pub(crate) fn kernel_refresh_file(&self) -> Option<&File> {
        self.kernel_refresh_file.as_ref()
    }

    fn expected_pin_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.authorization_id,
            self.plan_step_id,
            &self.command_digest,
            &self.tool_resolution_digest,
            &self.primary,
            &self.kernel_refresh,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedToolPinError {
    #[error("spawn authorization integrity check failed")]
    AuthorizationIntegrityMismatch,
    #[error("spawn authorization does not match the exact command")]
    AuthorizationCommandMismatch,
    #[error("trusted executable provenance changed before file-descriptor pinning")]
    ToolResolutionDrift,
    #[error("trusted executable identity is unsafe for pinning")]
    UnsafeExpectedIdentity,
    #[error("opened executable does not match the trusted identity")]
    PinnedExecutableMismatch,
    #[error("trusted executable pinning I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("trusted tool provenance validation failed: {0}")]
    Tools(#[from] TrustedToolError),
    #[error("pinned-tool receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn sha256_open_file(file: &File) -> Result<String, io::Error> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_u64;

    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("executable offset overflow"))?;
    }

    Ok(format!("{:x}", digest.finalize()))
}

fn receipt_from_open_file(
    file: &File,
    expected: &TrustedToolIdentity,
) -> Result<PinnedToolReceipt, PrivilegedToolPinError> {
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode();
    let sha256 = sha256_open_file(file)?;

    if !metadata.is_file()
        || metadata.dev() != expected.device_id
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.uid
        || mode != expected.mode
        || metadata.len() != expected.size_bytes
        || sha256 != expected.sha256
    {
        return Err(PrivilegedToolPinError::PinnedExecutableMismatch);
    }

    Ok(PinnedToolReceipt {
        program: expected.program,
        canonical_path: expected.canonical_path.clone(),
        device_id: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode,
        size_bytes: metadata.len(),
        sha256,
    })
}

fn pin_trusted_tool(
    expected: &TrustedToolIdentity,
) -> Result<(File, PinnedToolReceipt), PrivilegedToolPinError> {
    if expected.uid != 0
        || expected.mode & 0o111 == 0
        || expected.mode & 0o022 != 0
        || !Path::new(&expected.canonical_path).is_absolute()
    {
        return Err(PrivilegedToolPinError::UnsafeExpectedIdentity);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&expected.canonical_path)?;
    let receipt = receipt_from_open_file(&file, expected)?;
    Ok((file, receipt))
}

fn pin_resolved_tools(
    authorization: &PrivilegedSpawnAuthorization,
    command: &PrivilegedCommandSpec,
    tools: &PrivilegedToolResolution,
) -> Result<PinnedPrivilegedTools, PrivilegedToolPinError> {
    if !authorization.integrity_matches()? {
        return Err(PrivilegedToolPinError::AuthorizationIntegrityMismatch);
    }

    let command_digest = command
        .digest()
        .map_err(|error| TrustedToolError::CommandDigest(error.to_string()))?;
    if authorization.plan_step_id != command.plan_step_id
        || authorization.command_digest != command_digest
        || tools.command_digest != command_digest
        || tools.digest()? != authorization.tool_resolution_digest
    {
        return Err(PrivilegedToolPinError::AuthorizationCommandMismatch);
    }

    let (primary_file, primary) = pin_trusted_tool(&tools.primary)?;
    let (kernel_refresh_file, kernel_refresh) = match &tools.kernel_refresh {
        Some(identity) => {
            let (file, receipt) = pin_trusted_tool(identity)?;
            (Some(file), Some(receipt))
        }
        None => (None, None),
    };

    let mut pinned = PinnedPrivilegedTools {
        schema_version: 1,
        pin_id: String::new(),
        authorization_id: authorization.authorization_id.clone(),
        plan_step_id: command.plan_step_id,
        command_digest,
        tool_resolution_digest: authorization.tool_resolution_digest.clone(),
        primary,
        kernel_refresh,
        primary_file,
        kernel_refresh_file,
    };
    pinned.pin_id = pinned.expected_pin_id()?;
    Ok(pinned)
}

/// Pin the exact trusted executable objects after the M1B24 pre-spawn
/// authorization. The canonical paths are opened with O_NOFOLLOW and the
/// resulting file descriptors are checked against the trusted device/inode,
/// ownership, mode, size and SHA-256 identity.
///
/// Once this returns, later path replacement cannot change the already-open
/// executable object. This gate still does not execute either file descriptor.
pub fn pin_privileged_tools_for_spawn(
    authorization: &PrivilegedSpawnAuthorization,
    command: &PrivilegedCommandSpec,
) -> Result<PinnedPrivilegedTools, PrivilegedToolPinError> {
    let tools = resolve_privileged_command_tools(command)?;
    if tools.digest()? != authorization.tool_resolution_digest {
        return Err(PrivilegedToolPinError::ToolResolutionDrift);
    }
    pin_resolved_tools(authorization, command, &tools)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lsm-pinned-tool-{}-{id}-{name}",
            std::process::id()
        ))
    }

    fn identity_for_file(path: &Path, program: PrivilegedProgram) -> TrustedToolIdentity {
        let file = File::open(path).unwrap();
        let metadata = file.metadata().unwrap();
        TrustedToolIdentity {
            program,
            requested_path: path.to_string_lossy().into_owned(),
            canonical_path: path.to_string_lossy().into_owned(),
            device_id: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.permissions().mode(),
            size_bytes: metadata.len(),
            sha256: sha256_open_file(&file).unwrap(),
        }
    }

    #[test]
    fn opened_file_remains_bound_after_path_replacement() {
        let root = temp_path("root");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("lvextend");
        fs::write(&path, b"verified-executable-v1").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();

        let expected = identity_for_file(&path, PrivilegedProgram::Lvextend);
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .unwrap();

        let replacement = root.join("replacement");
        fs::write(&replacement, b"untrusted-executable-v2").unwrap();
        let mut permissions = fs::metadata(&replacement).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&replacement, permissions).unwrap();
        fs::rename(&replacement, &path).unwrap();

        let receipt = receipt_from_open_file(&opened, &expected).unwrap();
        assert_eq!(receipt.inode, expected.inode);
        assert_eq!(receipt.sha256, expected.sha256);
        assert_ne!(fs::metadata(&path).unwrap().ino(), expected.inode);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn opened_file_digest_mismatch_fails_closed() {
        let root = temp_path("digest");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("lvextend");
        fs::write(&path, b"verified-executable").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();

        let mut expected = identity_for_file(&path, PrivilegedProgram::Lvextend);
        expected.sha256 = "0".repeat(64);
        let opened = File::open(&path).unwrap();

        assert!(matches!(
            receipt_from_open_file(&opened, &expected),
            Err(PrivilegedToolPinError::PinnedExecutableMismatch)
        ));

        fs::remove_dir_all(root).unwrap();
    }
}
