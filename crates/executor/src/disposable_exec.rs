use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use thiserror::Error;

use crate::{
    revalidate_disposable_loop_ownership, DisposableCommandSpec, DisposableExecutionPermit,
    DisposableOwnershipError, DisposableProgram, LockedExecutionSession,
};
use lsm_planner::JournalPhase;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableToolPaths {
    pvresize: PathBuf,
    lvextend: PathBuf,
    resize2fs: PathBuf,
    xfs_growfs: PathBuf,
}

impl DisposableToolPaths {
    pub fn new(
        pvresize: PathBuf,
        lvextend: PathBuf,
        resize2fs: PathBuf,
        xfs_growfs: PathBuf,
    ) -> Self {
        Self {
            pvresize,
            lvextend,
            resize2fs,
            xfs_growfs,
        }
    }

    fn path_for(&self, program: DisposableProgram) -> &Path {
        match program {
            DisposableProgram::Pvresize => &self.pvresize,
            DisposableProgram::Lvextend => &self.lvextend,
            DisposableProgram::Resize2fs => &self.resize2fs,
            DisposableProgram::XfsGrowfs => &self.xfs_growfs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisposableCommandOutcome {
    pub plan_step_id: u32,
    pub program: DisposableProgram,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum DisposableExecutionError {
    #[error("disposable ownership proof is no longer valid: {0}")]
    Ownership(#[from] DisposableOwnershipError),
    #[error("loop device is not an exact block device at execution time")]
    LoopDeviceNotBlock,
    #[error("loop device sysfs major number is not 7")]
    LoopMajorMismatch,
    #[error("live loop backing file does not match the owned backing file")]
    LoopBackingMismatch,
    #[error("durable executing journal does not match this one-shot permit")]
    DurableExecutionStateMismatch,
    #[error("selected disposable tool path is unsafe for {0:?}")]
    UnsafeToolPath(DisposableProgram),
    #[error("disposable execution I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("could not spawn disposable command for step {step_id}: {source}")]
    Spawn {
        step_id: u32,
        #[source]
        source: io::Error,
    },
    #[error(
        "disposable command step {step_id} exited unsuccessfully with status {status:?}: {stderr}"
    )]
    CommandFailed {
        step_id: u32,
        status: Option<i32>,
        stderr: String,
    },
}

fn loop_device_name(path: &str) -> Option<&str> {
    let suffix = path.strip_prefix("/dev/loop")?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(path.trim_start_matches("/dev/"))
}

fn validate_durable_execution_state(
    permit: &DisposableExecutionPermit,
    session: &LockedExecutionSession<'_>,
) -> Result<(), DisposableExecutionError> {
    session
        .require_current_durable_journal()
        .map_err(|_| DisposableExecutionError::DurableExecutionStateMismatch)?;
    let journal = session.journal();
    let Some(binding) = journal.execution.as_ref() else {
        return Err(DisposableExecutionError::DurableExecutionStateMismatch);
    };
    if journal.phase != JournalPhase::Executing
        || !journal.mutation_may_have_started
        || binding.execution_id != permit.execution_id()
        || !binding.integrity_matches().unwrap_or(false)
    {
        return Err(DisposableExecutionError::DurableExecutionStateMismatch);
    }
    Ok(())
}

fn validate_live_loop(permit: &DisposableExecutionPermit) -> Result<(), DisposableExecutionError> {
    revalidate_disposable_loop_ownership(permit.ownership())?;

    let loop_path = Path::new(permit.loop_device());
    let name = loop_device_name(permit.loop_device())
        .ok_or(DisposableExecutionError::LoopDeviceNotBlock)?;
    let metadata = fs::metadata(loop_path).map_err(DisposableExecutionError::Io)?;
    if !metadata.file_type().is_block_device() {
        return Err(DisposableExecutionError::LoopDeviceNotBlock);
    }

    let sysfs_root = Path::new("/sys/class/block").join(name);
    let dev_number =
        fs::read_to_string(sysfs_root.join("dev")).map_err(DisposableExecutionError::Io)?;
    let Some((major, minor)) = dev_number.trim().split_once(':') else {
        return Err(DisposableExecutionError::LoopMajorMismatch);
    };
    if major != "7" || minor.parse::<u32>().is_err() {
        return Err(DisposableExecutionError::LoopMajorMismatch);
    }

    let live_backing = fs::read_to_string(sysfs_root.join("loop/backing_file"))
        .map_err(DisposableExecutionError::Io)?;
    let live_backing = PathBuf::from(live_backing.trim());
    if !live_backing.is_absolute() {
        return Err(DisposableExecutionError::LoopBackingMismatch);
    }
    let live_backing = fs::canonicalize(live_backing).map_err(DisposableExecutionError::Io)?;
    let expected = fs::canonicalize(permit.ownership().backing_file())
        .map_err(DisposableExecutionError::Io)?;
    if live_backing != expected {
        return Err(DisposableExecutionError::LoopBackingMismatch);
    }

    Ok(())
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

pub(crate) fn exact_safe_system_tool_path(
    path: &Path,
    expected_name: &str,
) -> Result<bool, io::Error> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        return Ok(false);
    }

    let path_metadata = fs::symlink_metadata(path)?;
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o111 == 0 || mode & 0o022 != 0 {
        return Ok(false);
    }

    if path_metadata.file_type().is_symlink() {
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        let canonical = fs::canonicalize(path)?;
        let Some(canonical_parent) = canonical.parent() else {
            return Ok(false);
        };
        let canonical_metadata = fs::symlink_metadata(&canonical)?;
        if path_metadata.uid() != 0
            || canonical_metadata.file_type().is_symlink()
            || canonical_metadata.uid() != 0
            || !root_owned_non_writable_directory_chain(parent)
            || !root_owned_non_writable_directory_chain(canonical_parent)
        {
            return Ok(false);
        }
    }

    Ok(true)
}

fn validate_tool_path(
    program: DisposableProgram,
    paths: &DisposableToolPaths,
) -> Result<PathBuf, DisposableExecutionError> {
    let path = paths.path_for(program);
    if !exact_safe_system_tool_path(path, program.as_str()).map_err(DisposableExecutionError::Io)? {
        return Err(DisposableExecutionError::UnsafeToolPath(program));
    }

    Ok(path.to_path_buf())
}

fn stderr_summary(stderr: &[u8]) -> String {
    const LIMIT: usize = 4096;
    let bytes = &stderr[..stderr.len().min(LIMIT)];
    String::from_utf8_lossy(bytes).into_owned()
}

/// Execute exactly one already-compiled disposable command.
///
/// The permit is consumed. A second destructive layer therefore requires a new
/// ownership/association/fresh-identity proof and a new permit.
pub fn execute_disposable_command(
    permit: DisposableExecutionPermit,
    session: &LockedExecutionSession<'_>,
    tools: &DisposableToolPaths,
) -> Result<DisposableCommandOutcome, DisposableExecutionError> {
    validate_durable_execution_state(&permit, session)?;
    validate_live_loop(&permit)?;

    let command: &DisposableCommandSpec = permit.command();
    let step_id = command.plan_step_id();
    let program = command.program();
    let tool_path = validate_tool_path(program, tools)?;

    let output = Command::new(&tool_path)
        .args(command.args())
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
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsm-disposable-exec-{}-{id}", std::process::id()))
    }

    #[test]
    fn tool_validation_requires_exact_safe_executable_file() {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        let lvextend = root.join("lvextend");
        let resize2fs = root.join("resize2fs");
        let xfs_growfs = root.join("xfs_growfs");
        for path in [&lvextend, &resize2fs, &xfs_growfs] {
            File::create(path).unwrap();
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
        let pvresize = root.join("pvresize");
        File::create(&pvresize).unwrap();
        let mut permissions = fs::metadata(&pvresize).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&pvresize, permissions).unwrap();
        let paths =
            DisposableToolPaths::new(pvresize, lvextend.clone(), resize2fs, xfs_growfs);

        assert_eq!(
            validate_tool_path(DisposableProgram::Lvextend, &paths).unwrap(),
            lvextend
        );

        let mut permissions = fs::metadata(&lvextend).unwrap().permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(&lvextend, permissions).unwrap();
        assert!(matches!(
            validate_tool_path(DisposableProgram::Lvextend, &paths),
            Err(DisposableExecutionError::UnsafeToolPath(
                DisposableProgram::Lvextend
            ))
        ));

        let mut permissions = fs::metadata(&lvextend).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&lvextend, permissions).unwrap();
        let target = root.join("lvm");
        File::create(&target).unwrap();
        let mut target_permissions = fs::metadata(&target).unwrap().permissions();
        target_permissions.set_mode(0o755);
        fs::set_permissions(&target, target_permissions).unwrap();
        fs::remove_file(&lvextend).unwrap();
        std::os::unix::fs::symlink(&target, &lvextend).unwrap();
        assert!(matches!(
            validate_tool_path(DisposableProgram::Lvextend, &paths),
            Err(DisposableExecutionError::UnsafeToolPath(
                DisposableProgram::Lvextend
            ))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stderr_summary_is_bounded() {
        let stderr = vec![b'x'; 5000];
        assert_eq!(stderr_summary(&stderr).len(), 4096);
    }

    #[test]
    fn loop_device_parser_rejects_partitions_and_non_loop_paths() {
        assert_eq!(loop_device_name("/dev/loop0"), Some("loop0"));
        assert_eq!(loop_device_name("/dev/loop42"), Some("loop42"));
        assert_eq!(loop_device_name("/dev/loop0p1"), None);
        assert_eq!(loop_device_name("/dev/sda"), None);
        assert_eq!(loop_device_name("loop0"), None);
    }
}
