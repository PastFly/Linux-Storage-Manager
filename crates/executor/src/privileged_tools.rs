use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PrivilegedCommandSpec, PrivilegedProgram};

const TRUSTED_TOOL_DIRECTORIES: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedToolIdentity {
    pub program: PrivilegedProgram,
    pub requested_path: String,
    pub canonical_path: String,
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedToolResolution {
    pub command_digest: String,
    pub primary: TrustedToolIdentity,
    pub kernel_refresh: Option<TrustedToolIdentity>,
}

impl PrivilegedToolResolution {
    pub fn digest(&self) -> Result<String, TrustedToolError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| TrustedToolError::Serialization(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum TrustedToolError {
    #[error("trusted executable for {0:?} was not found in fixed system directories")]
    NotFound(PrivilegedProgram),
    #[error("candidate system tool path is unsafe: {0}")]
    UnsafeCandidate(String),
    #[error("multiple distinct trusted executables exist for {0:?}")]
    Ambiguous(PrivilegedProgram),
    #[error("trusted tool path is not valid UTF-8")]
    NonUtf8Path,
    #[error("trusted tool I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("trusted tool provenance serialization failed: {0}")]
    Serialization(String),
    #[error("compiled command digest could not be produced: {0}")]
    CommandDigest(String),
}

fn root_owned_non_writable_directory_chain(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let Ok(metadata) = fs::symlink_metadata(&current) else {
            return false;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return false;
        }
    }
    true
}

fn sha256_file(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn inspect_candidate(
    program: PrivilegedProgram,
    path: &Path,
) -> Result<Option<TrustedToolIdentity>, TrustedToolError> {
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some(program.as_str())
    {
        return Ok(None);
    }

    let path_metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    let mode = canonical_metadata.permissions().mode();

    if canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.is_file()
        || canonical_metadata.uid() != 0
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        return Ok(None);
    }

    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let Some(canonical_parent) = canonical.parent() else {
        return Ok(None);
    };
    if !root_owned_non_writable_directory_chain(parent)
        || !root_owned_non_writable_directory_chain(canonical_parent)
    {
        return Ok(None);
    }

    if path_metadata.file_type().is_symlink() {
        if path_metadata.uid() != 0 {
            return Ok(None);
        }
    } else if path_metadata.uid() != 0 {
        return Ok(None);
    }

    let requested_path = path
        .to_str()
        .ok_or(TrustedToolError::NonUtf8Path)?
        .to_owned();
    let canonical_path = canonical
        .to_str()
        .ok_or(TrustedToolError::NonUtf8Path)?
        .to_owned();

    Ok(Some(TrustedToolIdentity {
        program,
        requested_path,
        canonical_path,
        device_id: canonical_metadata.dev(),
        inode: canonical_metadata.ino(),
        uid: canonical_metadata.uid(),
        mode,
        size_bytes: canonical_metadata.len(),
        sha256: sha256_file(&canonical)?,
    }))
}

pub fn resolve_trusted_privileged_tool(
    program: PrivilegedProgram,
) -> Result<TrustedToolIdentity, TrustedToolError> {
    let mut found = Vec::new();
    let mut unsafe_candidates = Vec::new();
    for directory in TRUSTED_TOOL_DIRECTORIES {
        let candidate = Path::new(directory).join(program.as_str());
        match fs::symlink_metadata(&candidate) {
            Ok(_) => match inspect_candidate(program, &candidate)? {
                Some(identity) => found.push(identity),
                None => unsafe_candidates.push(candidate),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(TrustedToolError::Io(error)),
        }
    }

    if found.is_empty() {
        if let Some(candidate) = unsafe_candidates.first() {
            return Err(TrustedToolError::UnsafeCandidate(
                candidate.to_string_lossy().into_owned(),
            ));
        }
        return Err(TrustedToolError::NotFound(program));
    }

    let mut unique = BTreeMap::<(u64, u64), TrustedToolIdentity>::new();
    for identity in found {
        unique
            .entry((identity.device_id, identity.inode))
            .or_insert(identity);
    }
    if unique.len() != 1 {
        return Err(TrustedToolError::Ambiguous(program));
    }

    Ok(unique.into_values().next().expect("non-empty trusted tool set"))
}

pub fn resolve_privileged_command_tools(
    command: &PrivilegedCommandSpec,
) -> Result<PrivilegedToolResolution, TrustedToolError> {
    let command_digest = command
        .digest()
        .map_err(|error| TrustedToolError::CommandDigest(error.to_string()))?;
    let primary = resolve_trusted_privileged_tool(command.program)?;
    let kernel_refresh = command
        .kernel_refresh
        .as_ref()
        .map(|refresh| resolve_trusted_privileged_tool(refresh.program))
        .transpose()?;

    Ok(PrivilegedToolResolution {
        command_digest,
        primary,
        kernel_refresh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "lsm-trusted-tool-{}-{id}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn rejects_user_controlled_executable_even_with_expected_name() {
        let root = temp_path("root");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("lvextend");
        fs::write(&path, b"not-a-real-tool").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();

        assert!(inspect_candidate(PrivilegedProgram::Lvextend, &path)
            .unwrap()
            .is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn privileged_program_names_are_fixed_and_shell_free() {
        assert_eq!(PrivilegedProgram::Sfdisk.as_str(), "sfdisk");
        assert_eq!(PrivilegedProgram::Partx.as_str(), "partx");
        assert_eq!(PrivilegedProgram::Pvresize.as_str(), "pvresize");
        assert_eq!(PrivilegedProgram::Lvextend.as_str(), "lvextend");
        assert_eq!(PrivilegedProgram::Resize2fs.as_str(), "resize2fs");
        assert_eq!(PrivilegedProgram::XfsGrowfs.as_str(), "xfs_growfs");
    }
}
