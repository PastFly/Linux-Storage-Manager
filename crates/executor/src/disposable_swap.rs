use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use lsm_discovery::{discover_snapshot, discover_swaps};
use serde::Serialize;
use thiserror::Error;

use crate::{
    revalidate_disposable_loop_ownership, DisposableLoopAssociation, DisposableLoopOwnershipProof,
    DisposableOwnershipError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableSwapToolPaths {
    mkswap: PathBuf,
    swapon: PathBuf,
    swapoff: PathBuf,
}

impl DisposableSwapToolPaths {
    pub fn new(mkswap: PathBuf, swapon: PathBuf, swapoff: PathBuf) -> Self {
        Self {
            mkswap,
            swapon,
            swapoff,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisposableSwapExecutionStage {
    ReplacementActiveOldPreserved,
    OldSwapDeactivated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisposableSwapExecutionReceipt {
    pub stage: DisposableSwapExecutionStage,
    pub loop_device: String,
    pub old_swap_device: String,
    pub swapfile_path: String,
    pub raw_swap_bytes: u64,
    pub old_reported_swap_bytes: u64,
    pub replacement_reported_swap_bytes: u64,
    pub priority: i32,
    pub old_swap_active: bool,
    pub replacement_swap_active: bool,
    pub injected_failure_before_old_swapoff: bool,
    pub partition_mutation_performed: bool,
    pub production_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct DisposableSwapActivationOptions {
    pub inject_failure_before_old_swapoff: bool,
}

#[derive(Debug, Error)]
pub enum DisposableSwapActivationError {
    #[error("disposable loop ownership proof is no longer valid: {0}")]
    Ownership(#[from] DisposableOwnershipError),
    #[error("loop association does not match the frozen ownership proof")]
    AssociationMismatch,
    #[error("swap activation requires root")]
    RootRequired,
    #[error("old swap device is not an exact partition of the owned loop")]
    OldSwapNotOwnedLoopPartition,
    #[error("old swap device sysfs size is invalid")]
    OldSwapSizeInvalid,
    #[error("old swap runtime state is absent or ambiguous")]
    OldSwapRuntimeStateInvalid,
    #[error("owned mountpoint is invalid or no longer the exact read-write ext4 mount")]
    MountStateInvalid,
    #[error("swapfile path is not the fixed absent path inside the owned mount")]
    SwapfilePathInvalid,
    #[error("swapfile path already exists")]
    SwapfilePathOccupied,
    #[error("selected disposable swap tool path is unsafe: {0}")]
    UnsafeToolPath(&'static str),
    #[error("swapfile creation or allocation failed: {0}")]
    FileIo(#[source] io::Error),
    #[error("swapfile allocation did not produce the exact fully allocated regular file")]
    SwapfileAllocationMismatch,
    #[error("{tool} could not be spawned: {source}")]
    Spawn {
        tool: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{tool} failed with status {status:?}: {stderr}")]
    CommandFailed {
        tool: &'static str,
        status: Option<i32>,
        stderr: String,
    },
    #[error("replacement swap runtime verification failed")]
    ReplacementVerificationFailed,
    #[error("old swapoff post-state verification failed")]
    OldSwapoffVerificationFailed,
}

fn exact_loop_partition(loop_device: &str, candidate: &str) -> bool {
    let Some(loop_name) = loop_device.strip_prefix("/dev/") else {
        return false;
    };
    let Some(suffix) = candidate.strip_prefix(loop_device) else {
        return false;
    };
    let Some(number) = suffix.strip_prefix('p') else {
        return false;
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    let candidate_name = candidate.trim_start_matches("/dev/");
    let sysfs = Path::new("/sys/class/block").join(candidate_name);
    if !sysfs.join("partition").is_file() {
        return false;
    }
    let Ok(real) = sysfs.canonicalize() else {
        return false;
    };
    real.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        == Some(loop_name)
}

fn sysfs_raw_device_bytes(device: &str) -> Result<u64, DisposableSwapActivationError> {
    let name = device.trim_start_matches("/dev/");
    let sectors = fs::read_to_string(Path::new("/sys/class/block").join(name).join("size"))
        .map_err(DisposableSwapActivationError::FileIo)?;
    let sectors = sectors
        .trim()
        .parse::<u64>()
        .map_err(|_| DisposableSwapActivationError::OldSwapSizeInvalid)?;
    sectors
        .checked_mul(512)
        .filter(|bytes| *bytes > 0)
        .ok_or(DisposableSwapActivationError::OldSwapSizeInvalid)
}

fn exact_swap_entry(
    name: &str,
) -> Result<lsm_core::SwapEntry, DisposableSwapActivationError> {
    let matches = discover_swaps()
        .map_err(|error| {
            DisposableSwapActivationError::FileIo(io::Error::other(error.to_string()))
        })?
        .into_iter()
        .filter(|entry| entry.name == name)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableSwapActivationError::OldSwapRuntimeStateInvalid);
    }
    Ok(matches.into_iter().next().expect("length checked"))
}

fn validate_mount(
    ownership: &DisposableLoopOwnershipProof,
    mountpoint: &Path,
    old_swap_device: &str,
) -> Result<PathBuf, DisposableSwapActivationError> {
    let canonical = mountpoint
        .canonicalize()
        .map_err(DisposableSwapActivationError::FileIo)?;
    let parent = canonical
        .parent()
        .ok_or(DisposableSwapActivationError::MountStateInvalid)?;
    if parent != ownership.owned_root() {
        return Err(DisposableSwapActivationError::MountStateInvalid);
    }

    let snapshot = discover_snapshot().map_err(|error| {
        DisposableSwapActivationError::FileIo(io::Error::other(error.to_string()))
    })?;
    let matches = snapshot
        .mounts
        .iter()
        .filter(|mount| mount.target == canonical.to_string_lossy())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableSwapActivationError::MountStateInvalid);
    }
    let mount = matches[0];
    if mount.fs_type.as_deref() != Some("ext4")
        || !mount.options.iter().any(|option| option == "rw")
        || mount.options.iter().any(|option| option == "ro")
        || mount.source.as_deref() == Some(old_swap_device)
    {
        return Err(DisposableSwapActivationError::MountStateInvalid);
    }

    Ok(canonical)
}

fn validate_swapfile_path(
    mountpoint: &Path,
    swapfile_path: &Path,
) -> Result<(), DisposableSwapActivationError> {
    if swapfile_path != mountpoint.join(".linux-storage-manager.swap") {
        return Err(DisposableSwapActivationError::SwapfilePathInvalid);
    }
    match fs::symlink_metadata(swapfile_path) {
        Ok(_) => Err(DisposableSwapActivationError::SwapfilePathOccupied),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DisposableSwapActivationError::FileIo(error)),
    }
}

fn validate_tool(
    path: &Path,
    expected: &'static str,
) -> Result<PathBuf, DisposableSwapActivationError> {
    let safe = crate::disposable_exec::exact_safe_system_tool_path(path, expected)
        .map_err(DisposableSwapActivationError::FileIo)?;
    if !safe {
        return Err(DisposableSwapActivationError::UnsafeToolPath(expected));
    }
    Ok(path.to_path_buf())
}

fn stderr_summary(stderr: &[u8]) -> String {
    const LIMIT: usize = 4096;
    String::from_utf8_lossy(&stderr[..stderr.len().min(LIMIT)]).into_owned()
}

fn run_tool(
    tool_name: &'static str,
    path: &Path,
    args: &[String],
) -> Result<(), DisposableSwapActivationError> {
    let output = Command::new(path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|source| DisposableSwapActivationError::Spawn {
            tool: tool_name,
            source,
        })?;
    if !output.status.success() {
        return Err(DisposableSwapActivationError::CommandFailed {
            tool: tool_name,
            status: output.status.code(),
            stderr: stderr_summary(&output.stderr),
        });
    }
    Ok(())
}

fn create_exact_swapfile(
    path: &Path,
    bytes: u64,
) -> Result<(File, (u64, u64)), DisposableSwapActivationError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(DisposableSwapActivationError::FileIo)?;

    let length = libc::off_t::try_from(bytes)
        .map_err(|_| DisposableSwapActivationError::SwapfileAllocationMismatch)?;
    let allocation = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
    if allocation != 0 {
        return Err(DisposableSwapActivationError::FileIo(
            io::Error::from_raw_os_error(allocation),
        ));
    }
    file.sync_all()
        .map_err(DisposableSwapActivationError::FileIo)?;

    let metadata = file
        .metadata()
        .map_err(DisposableSwapActivationError::FileIo)?;
    let allocated_bytes = metadata
        .blocks()
        .checked_mul(512)
        .ok_or(DisposableSwapActivationError::SwapfileAllocationMismatch)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() != bytes
        || allocated_bytes < bytes
    {
        return Err(DisposableSwapActivationError::SwapfileAllocationMismatch);
    }

    Ok((file, (metadata.dev(), metadata.ino())))
}

fn remove_unactivated_swapfile(
    path: &Path,
    identity: (u64, u64),
) -> Result<(), DisposableSwapActivationError> {
    let metadata = fs::symlink_metadata(path).map_err(DisposableSwapActivationError::FileIo)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.dev() != identity.0
        || metadata.ino() != identity.1
    {
        return Err(DisposableSwapActivationError::SwapfileAllocationMismatch);
    }
    fs::remove_file(path).map_err(DisposableSwapActivationError::FileIo)
}

fn replacement_and_old(
    old_swap_device: &str,
    swapfile_path: &Path,
) -> Result<(lsm_core::SwapEntry, lsm_core::SwapEntry), DisposableSwapActivationError> {
    let swaps = discover_swaps().map_err(|error| {
        DisposableSwapActivationError::FileIo(io::Error::other(error.to_string()))
    })?;
    let old = swaps
        .iter()
        .filter(|entry| entry.name == old_swap_device)
        .collect::<Vec<_>>();
    let swapfile_name = swapfile_path.to_string_lossy();
    let replacement = swaps
        .iter()
        .filter(|entry| entry.name == swapfile_name.as_ref())
        .collect::<Vec<_>>();
    if old.len() != 1 || replacement.len() != 1 {
        return Err(DisposableSwapActivationError::ReplacementVerificationFailed);
    }
    Ok((old[0].clone(), replacement[0].clone()))
}

/// Prove the runtime replacement ordering on an explicitly owned disposable
/// loop fixture. This helper has no partition-table mutation code and is not a
/// production execution gate.
pub fn execute_disposable_swap_replacement(
    ownership: &DisposableLoopOwnershipProof,
    association: &DisposableLoopAssociation,
    mountpoint: &Path,
    old_swap_device: &str,
    swapfile_path: &Path,
    tools: &DisposableSwapToolPaths,
    options: DisposableSwapActivationOptions,
) -> Result<DisposableSwapExecutionReceipt, DisposableSwapActivationError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(DisposableSwapActivationError::RootRequired);
    }
    revalidate_disposable_loop_ownership(ownership)?;
    if association.loop_device() != ownership.loop_device()
        || association.backing_file() != ownership.backing_file()
    {
        return Err(DisposableSwapActivationError::AssociationMismatch);
    }
    if !exact_loop_partition(ownership.loop_device(), old_swap_device) {
        return Err(DisposableSwapActivationError::OldSwapNotOwnedLoopPartition);
    }

    let raw_swap_bytes = sysfs_raw_device_bytes(old_swap_device)?;
    let old_before = exact_swap_entry(old_swap_device)?;
    if old_before.kind != "partition" || old_before.size_bytes == 0 {
        return Err(DisposableSwapActivationError::OldSwapRuntimeStateInvalid);
    }
    let priority = old_before.priority;

    let mountpoint = validate_mount(ownership, mountpoint, old_swap_device)?;
    validate_swapfile_path(&mountpoint, swapfile_path)?;

    let mkswap = validate_tool(&tools.mkswap, "mkswap")?;
    let swapon = validate_tool(&tools.swapon, "swapon")?;
    let swapoff = validate_tool(&tools.swapoff, "swapoff")?;

    let (swapfile, file_identity) = create_exact_swapfile(swapfile_path, raw_swap_bytes)?;
    drop(swapfile);

    if let Err(error) = run_tool(
        "mkswap",
        &mkswap,
        &["--force".to_owned(), swapfile_path.to_string_lossy().into_owned()],
    ) {
        remove_unactivated_swapfile(swapfile_path, file_identity)?;
        return Err(error);
    }
    if let Err(error) = run_tool(
        "swapon",
        &swapon,
        &[
            "--priority".to_owned(),
            priority.to_string(),
            swapfile_path.to_string_lossy().into_owned(),
        ],
    ) {
        remove_unactivated_swapfile(swapfile_path, file_identity)?;
        return Err(error);
    }

    let (old_after_activation, replacement) =
        replacement_and_old(old_swap_device, swapfile_path)?;
    if old_after_activation.priority != priority
        || replacement.priority != priority
        || replacement.size_bytes != old_after_activation.size_bytes
    {
        return Err(DisposableSwapActivationError::ReplacementVerificationFailed);
    }

    if options.inject_failure_before_old_swapoff {
        return Ok(DisposableSwapExecutionReceipt {
            stage: DisposableSwapExecutionStage::ReplacementActiveOldPreserved,
            loop_device: ownership.loop_device().to_owned(),
            old_swap_device: old_swap_device.to_owned(),
            swapfile_path: swapfile_path.to_string_lossy().into_owned(),
            raw_swap_bytes,
            old_reported_swap_bytes: old_after_activation.size_bytes,
            replacement_reported_swap_bytes: replacement.size_bytes,
            priority,
            old_swap_active: true,
            replacement_swap_active: true,
            injected_failure_before_old_swapoff: true,
            partition_mutation_performed: false,
            production_enabled: false,
        });
    }

    run_tool("swapoff", &swapoff, &[old_swap_device.to_owned()])?;

    let swaps = discover_swaps().map_err(|error| {
        DisposableSwapActivationError::FileIo(io::Error::other(error.to_string()))
    })?;
    let old_active = swaps.iter().any(|entry| entry.name == old_swap_device);
    let replacement_matches = swaps
        .iter()
        .filter(|entry| entry.name == swapfile_path.to_string_lossy().as_ref())
        .collect::<Vec<_>>();
    if old_active
        || replacement_matches.len() != 1
        || replacement_matches[0].priority != priority
        || replacement_matches[0].size_bytes != replacement.size_bytes
    {
        return Err(DisposableSwapActivationError::OldSwapoffVerificationFailed);
    }

    Ok(DisposableSwapExecutionReceipt {
        stage: DisposableSwapExecutionStage::OldSwapDeactivated,
        loop_device: ownership.loop_device().to_owned(),
        old_swap_device: old_swap_device.to_owned(),
        swapfile_path: swapfile_path.to_string_lossy().into_owned(),
        raw_swap_bytes,
        old_reported_swap_bytes: old_after_activation.size_bytes,
        replacement_reported_swap_bytes: replacement.size_bytes,
        priority,
        old_swap_active: false,
        replacement_swap_active: true,
        injected_failure_before_old_swapoff: false,
        partition_mutation_performed: false,
        production_enabled: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_partition_parser_rejects_foreign_and_malformed_devices_without_sysfs() {
        assert!(!exact_loop_partition("/dev/loop7", "/dev/sda5"));
        assert!(!exact_loop_partition("/dev/loop7", "/dev/loop8p5"));
        assert!(!exact_loop_partition("/dev/loop7", "/dev/loop7"));
        assert!(!exact_loop_partition("/dev/loop7", "/dev/loop7p"));
        assert!(!exact_loop_partition("/dev/loop7", "/dev/loop7p5x"));
    }

    #[test]
    fn diagnostic_summary_is_bounded() {
        assert_eq!(stderr_summary(&vec![b'x'; 5000]).len(), 4096);
    }
}
