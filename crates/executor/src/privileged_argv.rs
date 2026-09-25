use std::path::{Component, Path};

use lsm_planner::{LvmIdentityKind, TargetIdentityManifest};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    validate_privileged_helper_live_identity, validate_privileged_helper_request,
    NativeOperationSpec, PrivilegedHelperProtocolError, PrivilegedHelperRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedProgram {
    Sfdisk,
    Partx,
    Pvresize,
    Lvextend,
    Resize2fs,
    XfsGrowfs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedKernelRefreshSpec {
    pub program: PrivilegedProgram,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedCommandSpec {
    pub plan_step_id: u32,
    pub program: PrivilegedProgram,
    pub args: Vec<String>,
    pub stdin_payload: Option<String>,
    pub kernel_refresh: Option<PrivilegedKernelRefreshSpec>,
}

impl PrivilegedCommandSpec {
    pub fn digest(&self) -> Result<String, PrivilegedArgvError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| PrivilegedArgvError::Serialization(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivilegedArgvError {
    #[error("privileged-helper protocol validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("privileged command payload cannot be serialized: {0}")]
    Serialization(String),
    #[error("partition identity is missing or ambiguous")]
    PartitionIdentityNotUnique,
    #[error("partition geometry no longer matches the authorized operation")]
    PartitionGeometryMismatch,
    #[error("partition or parent disk path is unsafe")]
    UnsafePartitionPath,
    #[error("partition number could not be derived exactly")]
    PartitionNumberInvalid,
    #[error("partition growth would exceed the live parent disk")]
    PartitionGrowthOutOfBounds,
    #[error("physical-volume identity is missing or ambiguous")]
    PhysicalVolumeIdentityNotUnique,
    #[error("physical-volume identity no longer matches the authorized operation")]
    PhysicalVolumeMismatch,
    #[error("logical-volume identity is missing or ambiguous")]
    LogicalVolumeIdentityNotUnique,
    #[error("logical-volume identity no longer matches the authorized operation")]
    LogicalVolumeMismatch,
    #[error("filesystem identity is missing")]
    FilesystemIdentityMissing,
    #[error("filesystem identity no longer matches the authorized operation")]
    FilesystemMismatch,
    #[error("filesystem mount identity is missing or ambiguous")]
    FilesystemMountMismatch,
    #[error("unsupported privileged mutation operation")]
    UnsupportedOperation,
}

fn safe_absolute_path(value: &str) -> bool {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn safe_device_path(value: &str) -> bool {
    safe_absolute_path(value) && value.starts_with("/dev/")
}

fn partition_number(partition: &str, disk: &str) -> Option<u32> {
    let suffix = partition.strip_prefix(disk)?;
    let digits = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        suffix.strip_prefix('p')?
    } else {
        suffix.strip_prefix('p').unwrap_or(suffix)
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = digits.parse::<u32>().ok()?;
    (number > 0).then_some(number)
}

fn compile_operation(
    plan_step_id: u32,
    operation: &NativeOperationSpec,
    identity: &TargetIdentityManifest,
) -> Result<PrivilegedCommandSpec, PrivilegedArgvError> {
    match operation {
        NativeOperationSpec::ExtendPartition {
            partition,
            start_sector,
            old_size_sectors,
            new_size_sectors,
            sector_size_bytes,
        } => {
            let matches = identity
                .partitions
                .iter()
                .filter(|entry| entry.partition == *partition)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(PrivilegedArgvError::PartitionIdentityNotUnique);
            }
            let geometry = matches[0];
            let disk = geometry
                .disk
                .as_deref()
                .ok_or(PrivilegedArgvError::PartitionGeometryMismatch)?;
            if !safe_device_path(partition) || !safe_device_path(disk) {
                return Err(PrivilegedArgvError::UnsafePartitionPath);
            }
            if !matches!(geometry.table_label.as_deref(), Some("gpt" | "dos"))
                || geometry.start_sector != Some(*start_sector)
                || geometry.size_sectors != Some(*old_size_sectors)
                || geometry.sector_size_bytes != Some(*sector_size_bytes)
                || *sector_size_bytes == 0
                || *old_size_sectors == 0
                || *new_size_sectors <= *old_size_sectors
            {
                return Err(PrivilegedArgvError::PartitionGeometryMismatch);
            }

            let number = partition_number(partition, disk)
                .ok_or(PrivilegedArgvError::PartitionNumberInvalid)?;
            let disk_identity = identity
                .devices
                .iter()
                .find(|device| device.path == disk)
                .ok_or(PrivilegedArgvError::PartitionGrowthOutOfBounds)?;
            let end_sector = start_sector
                .checked_add(*new_size_sectors)
                .ok_or(PrivilegedArgvError::PartitionGrowthOutOfBounds)?;
            let disk_sectors = disk_identity.size_bytes / *sector_size_bytes;
            if end_sector > disk_sectors {
                return Err(PrivilegedArgvError::PartitionGrowthOutOfBounds);
            }

            Ok(PrivilegedCommandSpec {
                plan_step_id,
                program: PrivilegedProgram::Sfdisk,
                args: vec![
                    "--lock=yes".into(),
                    "--no-reread".into(),
                    "--no-tell-kernel".into(),
                    "-N".into(),
                    number.to_string(),
                    disk.to_owned(),
                ],
                stdin_payload: Some(format!("start={start_sector}, size={new_size_sectors}\n")),
                kernel_refresh: Some(PrivilegedKernelRefreshSpec {
                    program: PrivilegedProgram::Partx,
                    args: vec![
                        "--update".into(),
                        "--nr".into(),
                        number.to_string(),
                        disk.to_owned(),
                    ],
                }),
            })
        }
        NativeOperationSpec::ResizePhysicalVolume {
            pv_uuid,
            expected_pv_size_bytes,
        } => {
            let matches = identity
                .lvm
                .iter()
                .filter(|entry| {
                    entry.kind == LvmIdentityKind::PhysicalVolume
                        && entry.uuid.as_deref() == Some(pv_uuid)
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(PrivilegedArgvError::PhysicalVolumeIdentityNotUnique);
            }
            let pv = matches[0];
            if !safe_device_path(&pv.name)
                || *expected_pv_size_bytes == 0
                || *expected_pv_size_bytes <= pv.size_bytes
            {
                return Err(PrivilegedArgvError::PhysicalVolumeMismatch);
            }
            let pe_start = pv
                .pe_start_bytes
                .ok_or(PrivilegedArgvError::PhysicalVolumeMismatch)?;
            let raw_limit = expected_pv_size_bytes
                .checked_add(pe_start)
                .ok_or(PrivilegedArgvError::PhysicalVolumeMismatch)?;
            Ok(PrivilegedCommandSpec {
                plan_step_id,
                program: PrivilegedProgram::Pvresize,
                args: vec![
                    "--yes".into(),
                    "--setphysicalvolumesize".into(),
                    format!("{raw_limit}B"),
                    "--".into(),
                    pv.name.clone(),
                ],
                stdin_payload: None,
                kernel_refresh: None,
            })
        }
        NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid,
            additional_extents,
            expected_lv_size_bytes,
        } => {
            let matches = identity
                .lvm
                .iter()
                .filter(|entry| {
                    entry.kind == LvmIdentityKind::LogicalVolume
                        && entry.uuid.as_deref() == Some(lv_uuid)
                })
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(PrivilegedArgvError::LogicalVolumeIdentityNotUnique);
            }
            let lv = matches[0];
            if !safe_device_path(&lv.name)
                || *additional_extents == 0
                || *expected_lv_size_bytes == 0
                || *expected_lv_size_bytes <= lv.size_bytes
            {
                return Err(PrivilegedArgvError::LogicalVolumeMismatch);
            }
            Ok(PrivilegedCommandSpec {
                plan_step_id,
                program: PrivilegedProgram::Lvextend,
                args: vec![
                    "--extents".into(),
                    format!("+{additional_extents}"),
                    "--".into(),
                    lv.name.clone(),
                ],
                stdin_payload: None,
                kernel_refresh: None,
            })
        }
        NativeOperationSpec::GrowFilesystem {
            fs_type,
            mountpoint,
        } => {
            let filesystem = identity
                .filesystem
                .as_ref()
                .ok_or(PrivilegedArgvError::FilesystemIdentityMissing)?;
            if filesystem.device != identity.resolved_device
                || filesystem.fs_type != *fs_type
                || !safe_device_path(&filesystem.device)
            {
                return Err(PrivilegedArgvError::FilesystemMismatch);
            }
            let mounted = |expected: &str| {
                safe_absolute_path(expected)
                    && identity
                        .mounts
                        .iter()
                        .filter(|mount| {
                            mount.target == expected
                                && mount.fs_type.as_deref() == Some(fs_type.as_str())
                        })
                        .count()
                        == 1
            };
            match fs_type.as_str() {
                "ext4" => {
                    if let Some(mountpoint) = mountpoint {
                        if !mounted(mountpoint) {
                            return Err(PrivilegedArgvError::FilesystemMountMismatch);
                        }
                    } else if !identity.mounts.is_empty() {
                        return Err(PrivilegedArgvError::FilesystemMountMismatch);
                    }
                    Ok(PrivilegedCommandSpec {
                        plan_step_id,
                        program: PrivilegedProgram::Resize2fs,
                        args: vec![filesystem.device.clone()],
                        stdin_payload: None,
                        kernel_refresh: None,
                    })
                }
                "xfs" => {
                    let mountpoint = mountpoint
                        .as_deref()
                        .ok_or(PrivilegedArgvError::FilesystemMountMismatch)?;
                    if !mounted(mountpoint) {
                        return Err(PrivilegedArgvError::FilesystemMountMismatch);
                    }
                    Ok(PrivilegedCommandSpec {
                        plan_step_id,
                        program: PrivilegedProgram::XfsGrowfs,
                        args: vec!["-d".into(), mountpoint.to_owned()],
                        stdin_payload: None,
                        kernel_refresh: None,
                    })
                }
                _ => Err(PrivilegedArgvError::FilesystemMismatch),
            }
        }
        _ => Err(PrivilegedArgvError::UnsupportedOperation),
    }
}

pub fn compile_privileged_helper_command(
    request: &PrivilegedHelperRequest,
    live_identity: &TargetIdentityManifest,
) -> Result<PrivilegedCommandSpec, PrivilegedArgvError> {
    validate_privileged_helper_request(request)?;
    validate_privileged_helper_live_identity(request, live_identity)?;
    compile_operation(request.plan_step_id, &request.operation, live_identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::NodeKind;
    use lsm_planner::{
        DeviceIdentity, FilesystemIdentity, LayerRouteStatus, LvmIdentity, MountIdentity,
        PartitionGeometryIdentity,
    };

    fn identity() -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/data".into(),
            manifest_digest: "b".repeat(64),
            resolved_device: "/dev/mapper/vg-data".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![DeviceIdentity {
                kind: NodeKind::Disk,
                path: "/dev/sda".into(),
                kernel_name: Some("sda".into()),
                parent_kernel_name: None,
                size_bytes: 2 * 1024 * 1024 * 1024,
                start_512_sector: None,
                logical_sector_bytes: Some(512),
                uuid: None,
                partition_uuid: None,
                model: None,
                serial: None,
                filesystem_type: None,
            }],
            partitions: vec![PartitionGeometryIdentity {
                partition: "/dev/sda1".into(),
                disk: Some("/dev/sda".into()),
                table_label: Some("gpt".into()),
                table_id: None,
                sector_size_bytes: Some(512),
                start_sector: Some(2048),
                size_sectors: Some(1024 * 1024),
                record_uuid: None,
            }],
            lvm: vec![
                LvmIdentity {
                    kind: LvmIdentityKind::PhysicalVolume,
                    name: "/dev/sda1".into(),
                    uuid: Some("pv-uuid".into()),
                    size_bytes: 512 * 1024 * 1024,
                    free_bytes: None,
                    pe_start_bytes: Some(1024 * 1024),
                    extent_size_bytes: None,
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: None,
                    layout: None,
                    role: None,
                },
                LvmIdentity {
                    kind: LvmIdentityKind::LogicalVolume,
                    name: "/dev/mapper/vg-data".into(),
                    uuid: Some("lv-uuid".into()),
                    size_bytes: 256 * 1024 * 1024,
                    free_bytes: None,
                    pe_start_bytes: None,
                    extent_size_bytes: None,
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: Some("-wi-ao----".into()),
                    layout: None,
                    role: None,
                },
            ],
            filesystem: Some(FilesystemIdentity {
                device: "/dev/mapper/vg-data".into(),
                fs_type: "ext4".into(),
                fs_version: Some("1.0".into()),
                uuid: Some("fs-uuid".into()),
                backing_device_size_bytes: 256 * 1024 * 1024,
                observed_filesystem_size_bytes: Some(240 * 1024 * 1024),
            }),
            mounts: vec![MountIdentity {
                target: "/mnt/data".into(),
                source: Some("/dev/mapper/vg-data".into()),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            }],
        }
    }

    #[test]
    fn compiles_exact_lvextend_without_shell_surface() {
        let spec = compile_operation(
            3,
            &NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid: "lv-uuid".into(),
                additional_extents: 8,
                expected_lv_size_bytes: 288 * 1024 * 1024,
            },
            &identity(),
        )
        .unwrap();
        assert_eq!(spec.program, PrivilegedProgram::Lvextend);
        assert_eq!(
            spec.args,
            vec![
                "--extents".to_owned(),
                "+8".to_owned(),
                "--".to_owned(),
                "/dev/mapper/vg-data".to_owned()
            ]
        );
        assert!(spec.stdin_payload.is_none());
        assert!(spec.kernel_refresh.is_none());
        assert_eq!(spec.digest().unwrap().len(), 64);
    }

    #[test]
    fn compiles_exact_partition_geometry_and_kernel_refresh() {
        let spec = compile_operation(
            1,
            &NativeOperationSpec::ExtendPartition {
                partition: "/dev/sda1".into(),
                start_sector: 2048,
                old_size_sectors: 1024 * 1024,
                new_size_sectors: 2 * 1024 * 1024,
                sector_size_bytes: 512,
            },
            &identity(),
        )
        .unwrap();
        assert_eq!(spec.program, PrivilegedProgram::Sfdisk);
        assert_eq!(
            spec.stdin_payload.as_deref(),
            Some("start=2048, size=2097152\n")
        );
        let refresh = spec.kernel_refresh.unwrap();
        assert_eq!(refresh.program, PrivilegedProgram::Partx);
        assert_eq!(refresh.args.last().map(String::as_str), Some("/dev/sda"));
    }

    #[test]
    fn rejects_live_identity_mismatch_before_compilation() {
        let mut changed = identity();
        changed.resolved_device = "/dev/mapper/vg-other".into();
        let result = compile_operation(
            4,
            &NativeOperationSpec::GrowFilesystem {
                fs_type: "ext4".into(),
                mountpoint: Some("/mnt/data".into()),
            },
            &changed,
        );
        assert_eq!(result, Err(PrivilegedArgvError::FilesystemMismatch));
    }
}
