use std::path::{Component, Path};

use lsm_planner::CreatePartitionTablePolicy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PinnedProductionCreateTools, PrivilegedProgram, ProductionCreateRuntimePreflightReceipt,
    ProductionCreateToolLeaseError, TrustedToolIdentity,
};

pub const PRODUCTION_CREATE_LAUNCH_COMPILED: bool =
    cfg!(feature = "production-create-launch");

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";
const GPT_LINUX_FILESYSTEM_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
const DOS_LINUX_FILESYSTEM_TYPE: &str = "83";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub stdin_payload: Option<String>,
    pub tool: TrustedToolIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub preflight_receipt_id: String,
    pub disk: String,
    pub partition_device: String,
    pub partition_table: CreatePartitionTablePolicy,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub sfdisk: ProductionCreateLaunchStage,
    pub partx: ProductionCreateLaunchStage,
    pub mkfs: ProductionCreateLaunchStage,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct LaunchDigestPayload<'a> {
    schema_version: u32,
    preflight_receipt_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    partition_table: CreatePartitionTablePolicy,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    sfdisk: &'a ProductionCreateLaunchStage,
    partx: &'a ProductionCreateLaunchStage,
    mkfs: &'a ProductionCreateLaunchStage,
    fixed_path: &'a str,
    fixed_locale: &'a str,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionCreateLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let payload = LaunchDigestPayload {
            schema_version: self.schema_version,
            preflight_receipt_id: &self.preflight_receipt_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            partition_table: self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            sfdisk: &self.sfdisk,
            partx: &self.partx,
            mkfs: &self.mkfs,
            fixed_path: &self.fixed_path,
            fixed_locale: &self.fixed_locale,
            process_spawned: self.process_spawned,
            partition_table_changed: self.partition_table_changed,
            filesystem_formatted: self.filesystem_formatted,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateLaunchError {
    #[error("production create launch feature is not compiled")]
    FeatureDisabled,
    #[error("create runtime preflight integrity or state is invalid")]
    PreflightInvalid,
    #[error("pinned create tool lease is invalid: {0}")]
    ToolLease(#[from] ProductionCreateToolLeaseError),
    #[error("create launch tool identities do not match required programs")]
    ProgramMismatch,
    #[error("create disk path cannot produce a safe partition-1 device path")]
    PartitionPathInvalid,
    #[error("create launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn safe_device_path(value: &str) -> bool {
    if value.is_empty() || value.as_bytes().contains(&0) || !value.starts_with("/dev/") {
        return false;
    }
    Path::new(value)
        .components()
        .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn partition_one_path(disk: &str) -> Option<String> {
    if !safe_device_path(disk) {
        return None;
    }
    let suffix = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        "p1"
    } else {
        "1"
    };
    let partition = format!("{disk}{suffix}");
    safe_device_path(&partition).then_some(partition)
}

fn validate_preflight(
    preflight: &ProductionCreateRuntimePreflightReceipt,
) -> Result<(), ProductionCreateLaunchError> {
    if preflight.schema_version != 1
        || !preflight.integrity_matches().unwrap_or(false)
        || !preflight.runtime_ready
        || preflight.mutation_enabled
        || preflight.process_spawned
        || preflight.partition_table_changed
        || preflight.filesystem_formatted
        || preflight.partition_start_sector == 0
        || preflight.partition_sector_count == 0
        || preflight.logical_sector_bytes == 0
        || preflight.partition_size_bytes
            != preflight
                .partition_sector_count
                .checked_mul(preflight.logical_sector_bytes)
                .unwrap_or(0)
    {
        return Err(ProductionCreateLaunchError::PreflightInvalid);
    }
    Ok(())
}

fn sfdisk_payload(preflight: &ProductionCreateRuntimePreflightReceipt) -> String {
    let (label, partition_type) = match preflight.partition_table {
        CreatePartitionTablePolicy::Gpt => ("gpt", GPT_LINUX_FILESYSTEM_TYPE),
        CreatePartitionTablePolicy::Dos => ("dos", DOS_LINUX_FILESYSTEM_TYPE),
    };
    format!(
        "label: {label}\nunit: sectors\n\nstart={}, size={}, type={partition_type}\n",
        preflight.partition_start_sector, preflight.partition_sector_count
    )
}

fn build_from_tools(
    preflight: &ProductionCreateRuntimePreflightReceipt,
    tools: &PinnedProductionCreateTools,
) -> Result<ProductionCreateLaunchSpec, ProductionCreateLaunchError> {
    validate_preflight(preflight)?;
    tools.revalidate(preflight)?;

    let expected_mkfs = match preflight.filesystem.as_str() {
        "ext4" => PrivilegedProgram::MkfsExt4,
        "xfs" => PrivilegedProgram::MkfsXfs,
        _ => return Err(ProductionCreateLaunchError::PreflightInvalid),
    };
    if tools.sfdisk.program != PrivilegedProgram::Sfdisk
        || tools.partx.program != PrivilegedProgram::Partx
        || tools.mkfs.program != expected_mkfs
    {
        return Err(ProductionCreateLaunchError::ProgramMismatch);
    }

    let partition_device =
        partition_one_path(&preflight.disk).ok_or(ProductionCreateLaunchError::PartitionPathInvalid)?;

    let sfdisk = ProductionCreateLaunchStage {
        program: PrivilegedProgram::Sfdisk,
        argv: vec![
            "sfdisk".into(),
            "--lock=yes".into(),
            "--wipe=always".into(),
            "--wipe-partitions=always".into(),
            preflight.disk.clone(),
        ],
        stdin_payload: Some(sfdisk_payload(preflight)),
        tool: tools.sfdisk.clone(),
    };
    let partx = ProductionCreateLaunchStage {
        program: PrivilegedProgram::Partx,
        argv: vec![
            "partx".into(),
            "--add".into(),
            "--nr".into(),
            "1".into(),
            preflight.disk.clone(),
        ],
        stdin_payload: None,
        tool: tools.partx.clone(),
    };
    let mkfs_args = match expected_mkfs {
        PrivilegedProgram::MkfsExt4 => vec!["mkfs.ext4".into(), "-F".into(), partition_device.clone()],
        PrivilegedProgram::MkfsXfs => vec!["mkfs.xfs".into(), "-f".into(), partition_device.clone()],
        _ => unreachable!("mkfs program was restricted above"),
    };
    let mkfs = ProductionCreateLaunchStage {
        program: expected_mkfs,
        argv: mkfs_args,
        stdin_payload: None,
        tool: tools.mkfs.clone(),
    };

    let mut launch = ProductionCreateLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        disk: preflight.disk.clone(),
        partition_device,
        partition_table: preflight.partition_table,
        partition_start_sector: preflight.partition_start_sector,
        partition_sector_count: preflight.partition_sector_count,
        partition_size_bytes: preflight.partition_size_bytes,
        filesystem: preflight.filesystem.clone(),
        sfdisk,
        partx,
        mkfs,
        fixed_path: FIXED_PATH.into(),
        fixed_locale: FIXED_LOCALE.into(),
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

/// Freeze the exact descriptor-backed command sequence for the future blank-disk
/// Create crossing. This function does not spawn or mutate anything.
pub fn build_production_create_launch_spec(
    preflight: &ProductionCreateRuntimePreflightReceipt,
    tools: &PinnedProductionCreateTools,
) -> Result<ProductionCreateLaunchSpec, ProductionCreateLaunchError> {
    if !PRODUCTION_CREATE_LAUNCH_COMPILED {
        return Err(ProductionCreateLaunchError::FeatureDisabled);
    }
    build_from_tools(preflight, tools)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_path_handles_classic_and_digit_terminated_disk_names() {
        assert_eq!(partition_one_path("/dev/sda").as_deref(), Some("/dev/sda1"));
        assert_eq!(
            partition_one_path("/dev/loop7").as_deref(),
            Some("/dev/loop7p1")
        );
        assert_eq!(
            partition_one_path("/dev/nvme0n1").as_deref(),
            Some("/dev/nvme0n1p1")
        );
        assert_eq!(partition_one_path("sda"), None);
    }

    #[test]
    fn sfdisk_payload_freezes_exact_gpt_geometry() {
        let preflight = ProductionCreateRuntimePreflightReceipt {
            schema_version: 1,
            receipt_id: "a".repeat(64),
            activation_id: "b".repeat(64),
            execution_permit_id: "c".repeat(64),
            consent_receipt_id: "d".repeat(64),
            create_intent_id: "e".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            partition_table: CreatePartitionTablePolicy::Gpt,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            sfdisk: dummy_identity(PrivilegedProgram::Sfdisk),
            partx: dummy_identity(PrivilegedProgram::Partx),
            mkfs: dummy_identity(PrivilegedProgram::MkfsExt4),
            runtime_ready: true,
            mutation_enabled: false,
            process_spawned: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        assert_eq!(
            sfdisk_payload(&preflight),
            format!(
                "label: gpt\nunit: sectors\n\nstart=2048, size=262144, type={GPT_LINUX_FILESYSTEM_TYPE}\n"
            )
        );
    }

    fn dummy_identity(program: PrivilegedProgram) -> TrustedToolIdentity {
        TrustedToolIdentity {
            program,
            requested_path: format!("/usr/sbin/{}", program.as_str()),
            canonical_path: format!("/usr/sbin/{}", program.as_str()),
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: "f".repeat(64),
        }
    }
}
