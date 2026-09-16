mod analysis;
mod diagnostics;
mod fstab;
mod lvm;
mod mounts;
mod reconcile;
mod snapshot;
mod swap;

use std::env;
use std::path::Path;
use std::process::Command;

use lsm_core::{BlockDevice, Filesystem, HostCapabilities, NodeKind, StorageGraph, ToolCapability};
use serde::Deserialize;
use thiserror::Error;

pub use analysis::{analyze_extendability, ExtendAnalysisError};
pub use diagnostics::diagnose_storage;
pub use fstab::{discover_fstab, parse_fstab, FstabDiscoveryError};
pub use lvm::{
    discover_lvm, parse_lvs_json, parse_pvs_json, parse_vgs_json, LvmDiscoveryError,
};
pub use mounts::{discover_mounts, parse_findmnt_json, MountDiscoveryError};
pub use reconcile::reconcile_snapshot;
pub use snapshot::{discover_snapshot, SnapshotDiscoveryError};
pub use swap::{discover_swaps, parse_proc_swaps, SwapDiscoveryError};

const LSBLK_COLUMNS: &str =
    "NAME,KNAME,PATH,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,PKNAME,MODEL,SERIAL,UUID,PARTUUID,PTTYPE";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("required command `lsblk` could not be executed: {0}")]
    LsblkIo(#[from] std::io::Error),
    #[error("`lsblk` failed with status {status}: {stderr}")]
    LsblkFailed { status: String, stderr: String },
    #[error("invalid `lsblk` JSON: {0}")]
    InvalidLsblkJson(#[from] serde_json::Error),
}

pub fn discover_storage() -> Result<StorageGraph, DiscoveryError> {
    let output = Command::new("lsblk")
        .args(["--json", "--bytes", "--output", LSBLK_COLUMNS])
        .output()?;

    if !output.status.success() {
        return Err(DiscoveryError::LsblkFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    parse_lsblk_json(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_lsblk_json(input: &str) -> Result<StorageGraph, DiscoveryError> {
    let raw: LsblkOutput = serde_json::from_str(input)?;
    Ok(StorageGraph {
        block_devices: raw.blockdevices.into_iter().map(normalize_device).collect(),
    })
}

pub fn discover_capabilities() -> HostCapabilities {
    const TOOLS: &[&str] = &[
        "lsblk",
        "findmnt",
        "sfdisk",
        "pvs",
        "vgs",
        "lvs",
        "swapon",
        "resize2fs",
        "xfs_growfs",
        "cryptsetup",
        "mdadm",
        "btrfs",
    ];

    HostCapabilities {
        tools: TOOLS
            .iter()
            .map(|tool| ToolCapability {
                name: (*tool).to_owned(),
                available: command_exists(tool),
            })
            .collect(),
    }
}

fn command_exists(command: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&path).any(|directory| Path::new(&directory).join(command).is_file())
}

fn normalize_device(raw: LsblkDevice) -> BlockDevice {
    let filesystem = raw.fstype.as_ref().map(|fs_type| Filesystem {
        fs_type: fs_type.clone(),
        version: raw.fsver.clone(),
    });

    BlockDevice {
        name: raw.name,
        kernel_name: raw.kname,
        path: raw.path,
        kind: normalize_kind(&raw.device_type),
        size_bytes: raw.size,
        filesystem,
        mountpoints: raw
            .mountpoints
            .into_iter()
            .flatten()
            .filter(|mountpoint| !mountpoint.is_empty())
            .collect(),
        parent_kernel_name: raw.pkname,
        model: trim_optional(raw.model),
        serial: trim_optional(raw.serial),
        uuid: raw.uuid,
        partition_uuid: raw.partuuid,
        partition_table: raw.pttype,
        children: raw.children.into_iter().map(normalize_device).collect(),
    }
}

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn normalize_kind(kind: &str) -> NodeKind {
    match kind {
        "disk" => NodeKind::Disk,
        "part" => NodeKind::Partition,
        "lvm" => NodeKind::Lvm,
        "crypt" => NodeKind::Crypt,
        "loop" => NodeKind::Loop,
        "rom" => NodeKind::Rom,
        "zram" => NodeKind::Zram,
        value if value.starts_with("raid") || value.starts_with("md") => NodeKind::Raid,
        _ => NodeKind::Unknown,
    }
}

#[derive(Debug, Deserialize)]
struct LsblkOutput {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Debug, Deserialize)]
struct LsblkDevice {
    name: String,
    #[serde(default)]
    kname: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "type")]
    device_type: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    fsver: Option<String>,
    #[serde(default)]
    mountpoints: Vec<Option<String>>,
    #[serde(default)]
    pkname: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    partuuid: Option<String>,
    #[serde(default)]
    pttype: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDevice>,
}
