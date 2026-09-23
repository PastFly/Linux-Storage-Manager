use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use lsm_planner::{LvmIdentityKind, TargetIdentityManifest};
use thiserror::Error;

use crate::{DisposableCommandPlan, DisposableCommandSpec, DisposableProgram};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableToolPaths {
    pub lvextend: PathBuf,
    pub resize2fs: PathBuf,
    pub xfs_growfs: PathBuf,
}

impl DisposableToolPaths {
    fn path_for(&self, program: DisposableProgram) -> &Path {
        match program {
            DisposableProgram::Lvextend => &self.lvextend,
            DisposableProgram::Resize2fs => &self.resize2fs,
            DisposableProgram::XfsGrowfs => &self.xfs_growfs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableLoopOwnershipRequest {
    pub owned_root: PathBuf,
    pub loop_device: PathBuf,
    pub backing_file: PathBuf,
    pub expected_backing_dev: u64,
    pub expected_backing_ino: u64,
    pub plan_step_id: u32,
    pub tools: DisposableToolPaths,
}

#[derive(Debug)]
pub struct DisposableExecutionPermit {
    source_manifest_id: String,
    native_manifest_digest: String,
    fresh_identity_digest: String,
    loop_device: PathBuf,
    command: DisposableCommandSpec,
    tool_path: PathBuf,
}

impl DisposableExecutionPermit {
    pub fn source_manifest_id(&self) -> &str {
        &self.source_manifest_id
    }

    pub fn native_manifest_digest(&self) -> &str {
        &self.native_manifest_digest
    }

    pub fn fresh_identity_digest(&self) -> &str {
        &self.fresh_identity_digest
    }

    pub fn loop_device(&self) -> &Path {
        &self.loop_device
    }

    pub fn plan_step_id(&self) -> u32 {
        self.command.plan_step_id
    }

    pub fn program(&self) -> DisposableProgram {
        self.command.program
    }

    pub fn args(&self) -> &[String] {
        &self.command.args
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableCommandOutcome {
    pub plan_step_id: u32,
    pub program: DisposableProgram,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum DisposableExecutionError {
    #[error("command plan is not bound to the supplied fresh target identity")]
    FreshIdentityBindingMismatch,
    #[error("requested disposable plan step {0} did not resolve to exactly one command")]
    CommandStepNotUnique(u32),
    #[error("loop device path is not an exact /dev/loopN path")]
    InvalidLoopDevice,
    #[error("loop device is not a block device")]
    LoopDeviceNotBlock,
    #[error("loop device sysfs major number is not 7")]
    LoopMajorMismatch,
    #[error("owned root is not a directory")]
    OwnedRootInvalid,
    #[error("backing file is not a regular file inside the owned root")]
    BackingFileInvalid,
    #[error("backing file inode identity changed")]
    BackingIdentityMismatch,
    #[error("loop sysfs backing file does not match the exact tracked backing file")]
    LoopBackingMismatch,
    #[error("fresh target identity is not rooted exclusively in the owned loop device")]
    TargetNotOwnedByLoop,
    #[error("selected disposable tool path is unsafe for {0:?}")]
    UnsafeToolPath(DisposableProgram),
    #[error("disposable ownership proof I/O failed: {0}")]
    OwnershipIo(#[source] io::Error),
    #[error("could not spawn disposable command for step {step_id}: {source}")]
    Spawn {
        step_id: u32,
        #[source]
        source: io::Error,
    },
    #[error("disposable command step {step_id} exited unsuccessfully with status {status:?}: {stderr}")]
    CommandFailed {
        step_id: u32,
        status: Option<i32>,
        stderr: String,
    },
}

fn loop_device_name(path: &Path) -> Option<&str> {
    if path.parent() != Some(Path::new("/dev")) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let suffix = name.strip_prefix("loop")?;
    (!suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())).then_some(name)
}

fn belongs_to_loop(path: &str, loop_path: &str) -> bool {
    if path == loop_path {
        return true;
    }
    path.strip_prefix(loop_path)
        .and_then(|suffix| suffix.strip_prefix('p'))
        .is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn validate_tool_path(
    program: DisposableProgram,
    paths: &DisposableToolPaths,
) -> Result<PathBuf, DisposableExecutionError> {
    let path = paths.path_for(program);
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some(program.as_str())
    {
        return Err(DisposableExecutionError::UnsafeToolPath(program));
    }

    let metadata = fs::metadata(path).map_err(DisposableExecutionError::OwnershipIo)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Err(DisposableExecutionError::UnsafeToolPath(program));
    }

    fs::canonicalize(path).map_err(DisposableExecutionError::OwnershipIo)?;
    Ok(path.to_path_buf())
}

fn prove_loop_ownership(
    identity: &TargetIdentityManifest,
    request: &DisposableLoopOwnershipRequest,
) -> Result<PathBuf, DisposableExecutionError> {
    let loop_name =
        loop_device_name(&request.loop_device).ok_or(DisposableExecutionError::InvalidLoopDevice)?;
    let loop_metadata =
        fs::metadata(&request.loop_device).map_err(DisposableExecutionError::OwnershipIo)?;
    if !loop_metadata.file_type().is_block_device() {
        return Err(DisposableExecutionError::LoopDeviceNotBlock);
    }

    let sysfs_root = Path::new("/sys/class/block").join(loop_name);
    let dev_number =
        fs::read_to_string(sysfs_root.join("dev")).map_err(DisposableExecutionError::OwnershipIo)?;
    let Some((major, minor)) = dev_number.trim().split_once(':') else {
        return Err(DisposableExecutionError::LoopMajorMismatch);
    };
    if major != "7" || minor.parse::<u32>().is_err() {
        return Err(DisposableExecutionError::LoopMajorMismatch);
    }

    let owned_root =
        fs::canonicalize(&request.owned_root).map_err(DisposableExecutionError::OwnershipIo)?;
    if !owned_root.is_dir() {
        return Err(DisposableExecutionError::OwnedRootInvalid);
    }
    let backing =
        fs::canonicalize(&request.backing_file).map_err(DisposableExecutionError::OwnershipIo)?;
    let backing_metadata =
        fs::metadata(&backing).map_err(DisposableExecutionError::OwnershipIo)?;
    if !backing_metadata.is_file() || !backing.starts_with(&owned_root) {
        return Err(DisposableExecutionError::BackingFileInvalid);
    }
    if backing_metadata.dev() != request.expected_backing_dev
        || backing_metadata.ino() != request.expected_backing_ino
    {
        return Err(DisposableExecutionError::BackingIdentityMismatch);
    }

    let sysfs_backing = fs::read_to_string(sysfs_root.join("loop/backing_file"))
        .map_err(DisposableExecutionError::OwnershipIo)?;
    let sysfs_backing = PathBuf::from(sysfs_backing.trim());
    if !sysfs_backing.is_absolute() {
        return Err(DisposableExecutionError::LoopBackingMismatch);
    }
    let sysfs_backing =
        fs::canonicalize(sysfs_backing).map_err(DisposableExecutionError::OwnershipIo)?;
    if sysfs_backing != backing {
        return Err(DisposableExecutionError::LoopBackingMismatch);
    }

    let loop_path = request
        .loop_device
        .to_str()
        .ok_or(DisposableExecutionError::InvalidLoopDevice)?;
    let device_chain_has_loop = identity.devices.iter().any(|device| device.path == loop_path);
    let foreign_loop = identity
        .devices
        .iter()
        .filter(|device| device.path.starts_with("/dev/loop"))
        .any(|device| !belongs_to_loop(&device.path, loop_path));
    let pvs = identity
        .lvm
        .iter()
        .filter(|entry| entry.kind == LvmIdentityKind::PhysicalVolume)
        .collect::<Vec<_>>();
    if !device_chain_has_loop
        || foreign_loop
        || pvs.len() != 1
        || !belongs_to_loop(&pvs[0].name, loop_path)
    {
        return Err(DisposableExecutionError::TargetNotOwnedByLoop);
    }

    Ok(request.loop_device.clone())
}

pub fn prove_disposable_execution_permit(
    plan: &DisposableCommandPlan,
    fresh_identity: &TargetIdentityManifest,
    request: &DisposableLoopOwnershipRequest,
) -> Result<DisposableExecutionPermit, DisposableExecutionError> {
    if plan.fresh_identity_digest != fresh_identity.manifest_digest {
        return Err(DisposableExecutionError::FreshIdentityBindingMismatch);
    }

    let matches = plan
        .commands
        .iter()
        .filter(|command| command.plan_step_id == request.plan_step_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableExecutionError::CommandStepNotUnique(
            request.plan_step_id,
        ));
    }
    let command = matches[0].clone();
    let tool_path = validate_tool_path(command.program, &request.tools)?;
    let loop_device = prove_loop_ownership(fresh_identity, request)?;

    Ok(DisposableExecutionPermit {
        source_manifest_id: plan.source_manifest_id.clone(),
        native_manifest_digest: plan.native_manifest_digest.clone(),
        fresh_identity_digest: plan.fresh_identity_digest.clone(),
        loop_device,
        command,
        tool_path,
    })
}

fn stderr_summary(stderr: &[u8]) -> String {
    const LIMIT: usize = 4096;
    let bytes = &stderr[..stderr.len().min(LIMIT)];
    String::from_utf8_lossy(bytes).into_owned()
}

/// Execute exactly one already-compiled command.
///
/// The permit is consumed, forcing fresh ownership/identity proof before any
/// subsequent destructive layer.
pub fn execute_disposable_command(
    permit: DisposableExecutionPermit,
) -> Result<DisposableCommandOutcome, DisposableExecutionError> {
    let step_id = permit.command.plan_step_id;
    let program = permit.command.program;
    let output = Command::new(&permit.tool_path)
        .args(&permit.command.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| DisposableExecutionError::Spawn { step_id, source })?;

    if !output.status.success() {
        return Err(DisposableExecutionError::CommandFailed {
            step_id,
            status: output.status.code(),
            stderr: stderr_summary(&output.stderr),
        });
    }

    Ok(DisposableCommandOutcome {
        plan_step_id: step_id,
        program,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_device_parser_rejects_partitions_and_non_loop_paths() {
        assert_eq!(loop_device_name(Path::new("/dev/loop0")), Some("loop0"));
        assert_eq!(loop_device_name(Path::new("/dev/loop42")), Some("loop42"));
        assert_eq!(loop_device_name(Path::new("/dev/loop0p1")), None);
        assert_eq!(loop_device_name(Path::new("/dev/sda")), None);
        assert_eq!(loop_device_name(Path::new("loop0")), None);
    }

    #[test]
    fn loop_descendants_are_exact() {
        assert!(belongs_to_loop("/dev/loop7", "/dev/loop7"));
        assert!(belongs_to_loop("/dev/loop7p1", "/dev/loop7"));
        assert!(!belongs_to_loop("/dev/loop70", "/dev/loop7"));
        assert!(!belongs_to_loop("/dev/loop8p1", "/dev/loop7"));
    }

    #[test]
    fn stderr_summary_is_bounded() {
        let stderr = vec![b'x'; 5000];
        assert_eq!(stderr_summary(&stderr).len(), 4096);
    }
}
