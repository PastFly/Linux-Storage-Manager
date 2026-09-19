use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use lsm_planner::{
    ExecutionHandoffStatus, FrozenExecutionHandoff, LvmIdentityKind, Operation,
    PartitionGeometryIdentity, TargetIdentityManifest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const BACKUP_DIRECTORY: &str = "/var/lib/linux-storage-manager/backups";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataBackupKind {
    PartitionTable,
    LvmVolumeGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupCommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub stdin_path: Option<String>,
    pub stdout_path: Option<String>,
    pub mutates_storage_metadata: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackupExpectedIdentity {
    PartitionTable {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    LvmVolumeGroup {
        vg_name: String,
        vg_uuid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetadataBackupRequirement {
    pub ordinal: u32,
    pub kind: MetadataBackupKind,
    pub artifact_path: String,
    pub expected_identity: BackupExpectedIdentity,
    pub capture: BackupCommandSpec,
    pub recovery: BackupCommandSpec,
    pub verification_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetadataBackupManifest {
    schema_version: u32,
    manifest_id: String,
    handoff_id: String,
    plan_id: String,
    target_manifest_digest: String,
    artifact_directory: String,
    mutation_enabled: bool,
    owner_acceptance_required: bool,
    requirements: Vec<MetadataBackupRequirement>,
}

#[derive(Debug, Error)]
pub enum BackupManifestError {
    #[error("blocked execution handoff cannot produce an executor backup manifest")]
    HandoffBlocked,
    #[error("mutation-enabled handoff is forbidden before owner acceptance")]
    MutationEnabled,
    #[error("owner-acceptance gate unexpectedly appears satisfied")]
    OwnerAcceptanceBypassed,
    #[error("frozen handoff identity is invalid: {0}")]
    InvalidIdentity(String),
    #[error("partition-table backup step has no exact target identity for {0}")]
    PartitionIdentityMissing(String),
    #[error("partition-table backup step is ambiguous for {0}")]
    PartitionIdentityAmbiguous(String),
    #[error("LVM backup step has no exact VG identity for UUID {0}")]
    VolumeGroupIdentityMissing(String),
    #[error("LVM backup step is ambiguous for UUID {0}")]
    VolumeGroupIdentityAmbiguous(String),
    #[error("could not serialize backup manifest basis: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl MetadataBackupManifest {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.target_manifest_digest
    }

    pub fn artifact_directory(&self) -> &str {
        &self.artifact_directory
    }

    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }

    pub fn owner_acceptance_required(&self) -> bool {
        self.owner_acceptance_required
    }

    pub fn requirements(&self) -> &[MetadataBackupRequirement] {
        &self.requirements
    }
}

pub fn build_metadata_backup_manifest(
    handoff: &FrozenExecutionHandoff,
) -> Result<MetadataBackupManifest, BackupManifestError> {
    if handoff.status() == ExecutionHandoffStatus::Blocked {
        return Err(BackupManifestError::HandoffBlocked);
    }
    if handoff.mutation_enabled() {
        return Err(BackupManifestError::MutationEnabled);
    }
    if !handoff.owner_acceptance_required() {
        return Err(BackupManifestError::OwnerAcceptanceBypassed);
    }
    validate_digest(handoff.handoff_id(), "handoff ID")?;
    validate_digest(handoff.plan().plan_id(), "plan ID")?;
    validate_digest(
        &handoff.target_identity().manifest_digest,
        "target manifest digest",
    )?;

    let artifact_directory = Path::new(BACKUP_DIRECTORY)
        .join(handoff.handoff_id())
        .to_string_lossy()
        .into_owned();
    let mut requirements = Vec::new();
    let mut seen = BTreeSet::new();

    for step in handoff.plan().steps() {
        let key = match &step.operation {
            Operation::BackupPartitionTableMetadata { disk, .. } => {
                Some(format!("partition-table:{disk}"))
            }
            Operation::BackupLvmMetadata { vg_uuid } => Some(format!("lvm-vg:{vg_uuid}")),
            _ => None,
        };
        let Some(key) = key else {
            continue;
        };
        if !seen.insert(key) {
            continue;
        }

        let ordinal = requirements.len() as u32 + 1;
        if let Some(requirement) = requirement_for_operation(
            handoff.target_identity(),
            &step.operation,
            Path::new(&artifact_directory),
            ordinal,
        )? {
            requirements.push(requirement);
        }
    }

    let manifest_id = fingerprint(&(
        1_u32,
        handoff.handoff_id(),
        handoff.plan().plan_id(),
        &handoff.target_identity().manifest_digest,
        &artifact_directory,
        false,
        true,
        &requirements,
    ))?;

    Ok(MetadataBackupManifest {
        schema_version: 1,
        manifest_id,
        handoff_id: handoff.handoff_id().to_owned(),
        plan_id: handoff.plan().plan_id().to_owned(),
        target_manifest_digest: handoff.target_identity().manifest_digest.clone(),
        artifact_directory,
        mutation_enabled: false,
        owner_acceptance_required: true,
        requirements,
    })
}

fn requirement_for_operation(
    identity: &TargetIdentityManifest,
    operation: &Operation,
    artifact_directory: &Path,
    ordinal: u32,
) -> Result<Option<MetadataBackupRequirement>, BackupManifestError> {
    match operation {
        Operation::BackupPartitionTableMetadata {
            disk,
            table_label,
            table_id,
        } => {
            validate_atom(disk, "partition-table disk")?;
            validate_atom(table_label, "partition-table label")?;
            if let Some(table_id) = table_id {
                validate_atom(table_id, "partition-table ID")?;
            }

            let matches = identity
                .partitions
                .iter()
                .filter(|partition| partition_matches(partition, disk, table_label, table_id))
                .collect::<Vec<_>>();
            let partition = match matches.as_slice() {
                [partition] => *partition,
                [] => return Err(BackupManifestError::PartitionIdentityMissing(disk.clone())),
                _ => {
                    return Err(BackupManifestError::PartitionIdentityAmbiguous(
                        disk.clone(),
                    ))
                }
            };

            let artifact_path =
                artifact_path(artifact_directory, ordinal, "partition-table.sfdisk");
            let artifact = artifact_path.to_string_lossy().into_owned();
            let expected_identity = BackupExpectedIdentity::PartitionTable {
                disk: disk.clone(),
                table_label: partition.table_label.clone().unwrap_or_default(),
                table_id: partition.table_id.clone(),
            };

            Ok(Some(MetadataBackupRequirement {
                ordinal,
                kind: MetadataBackupKind::PartitionTable,
                artifact_path: artifact.clone(),
                expected_identity,
                capture: BackupCommandSpec {
                    program: "sfdisk".to_owned(),
                    args: vec!["--dump".to_owned(), disk.clone()],
                    stdin_path: None,
                    stdout_path: Some(artifact.clone()),
                    mutates_storage_metadata: false,
                },
                recovery: BackupCommandSpec {
                    program: "sfdisk".to_owned(),
                    args: vec![disk.clone()],
                    stdin_path: Some(artifact),
                    stdout_path: None,
                    mutates_storage_metadata: true,
                },
                verification_notes: vec![
                    "backup artifact must be non-empty and readable".to_owned(),
                    "parsed dump must identify the exact frozen disk, table label and table ID"
                        .to_owned(),
                    "restore drill is allowed only on a disposable fixture or explicit recovery path"
                        .to_owned(),
                ],
            }))
        }
        Operation::BackupLvmMetadata { vg_uuid } => {
            validate_atom(vg_uuid, "VG UUID")?;
            let matches = identity
                .lvm
                .iter()
                .filter(|item| {
                    item.kind == LvmIdentityKind::VolumeGroup
                        && item.uuid.as_deref() == Some(vg_uuid.as_str())
                })
                .collect::<Vec<_>>();
            let vg = match matches.as_slice() {
                [vg] => *vg,
                [] => {
                    return Err(BackupManifestError::VolumeGroupIdentityMissing(
                        vg_uuid.clone(),
                    ));
                }
                _ => {
                    return Err(BackupManifestError::VolumeGroupIdentityAmbiguous(
                        vg_uuid.clone(),
                    ));
                }
            };
            validate_atom(&vg.name, "VG name")?;

            let artifact_path = artifact_path(artifact_directory, ordinal, "lvm-vg.conf");
            let artifact = artifact_path.to_string_lossy().into_owned();

            Ok(Some(MetadataBackupRequirement {
                ordinal,
                kind: MetadataBackupKind::LvmVolumeGroup,
                artifact_path: artifact.clone(),
                expected_identity: BackupExpectedIdentity::LvmVolumeGroup {
                    vg_name: vg.name.clone(),
                    vg_uuid: vg_uuid.clone(),
                },
                capture: BackupCommandSpec {
                    program: "vgcfgbackup".to_owned(),
                    args: vec![
                        "--file".to_owned(),
                        artifact.clone(),
                        vg.name.clone(),
                    ],
                    stdin_path: None,
                    stdout_path: None,
                    mutates_storage_metadata: false,
                },
                recovery: BackupCommandSpec {
                    program: "vgcfgrestore".to_owned(),
                    args: vec![
                        "--file".to_owned(),
                        artifact.clone(),
                        vg.name.clone(),
                    ],
                    stdin_path: None,
                    stdout_path: None,
                    mutates_storage_metadata: true,
                },
                verification_notes: vec![
                    "backup artifact must be non-empty and readable".to_owned(),
                    "backup metadata must identify the exact frozen VG name and UUID".to_owned(),
                    "restore drill is allowed only on a disposable fixture or explicit recovery path"
                        .to_owned(),
                ],
            }))
        }
        _ => Ok(None),
    }
}

fn partition_matches(
    partition: &PartitionGeometryIdentity,
    disk: &str,
    table_label: &str,
    table_id: &Option<String>,
) -> bool {
    partition.disk.as_deref() == Some(disk)
        && partition.table_label.as_deref() == Some(table_label)
        && &partition.table_id == table_id
}

fn artifact_path(root: &Path, ordinal: u32, suffix: &str) -> PathBuf {
    root.join(format!("{ordinal:02}-{suffix}"))
}

fn validate_atom(value: &str, label: &str) -> Result<(), BackupManifestError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(BackupManifestError::InvalidIdentity(format!(
            "{label} is empty or contains control characters"
        )));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), BackupManifestError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(BackupManifestError::InvalidIdentity(format!(
            "{label} is not a lowercase SHA-256 digest"
        )))
    }
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{HostCapabilities, HostSnapshot, NodeKind};
    use lsm_planner::{
        build_frozen_execution_handoff, plan_extend, DeviceIdentity, ExtendRequest, Growth,
        LvmIdentity, LvmIdentityKind, PlanStatus,
    };
    use serde_json::json;

    const GIB: u64 = 1024 * 1024 * 1024;
    const EXTENT: u64 = 4 * 1024 * 1024;

    fn empty_identity() -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/".to_owned(),
            manifest_digest: "a".repeat(64),
            resolved_device: "/dev/test".to_owned(),
            route_status: lsm_planner::LayerRouteStatus::SupportedProfile,
            route_issue_codes: Vec::new(),
            devices: vec![DeviceIdentity {
                kind: NodeKind::Disk,
                path: "/dev/test".to_owned(),
                kernel_name: Some("test".to_owned()),
                parent_kernel_name: None,
                size_bytes: GIB,
                start_512_sector: None,
                logical_sector_bytes: Some(512),
                uuid: None,
                partition_uuid: None,
                model: None,
                serial: None,
                filesystem_type: None,
            }],
            partitions: Vec::new(),
            lvm: Vec::new(),
            filesystem: None,
            mounts: Vec::new(),
        }
    }

    #[test]
    fn partition_requirement_uses_exact_argv_and_identity() {
        let mut identity = empty_identity();
        identity.partitions.push(PartitionGeometryIdentity {
            partition: "/dev/vda1".to_owned(),
            disk: Some("/dev/vda".to_owned()),
            table_label: Some("gpt".to_owned()),
            table_id: Some("disk-guid".to_owned()),
            sector_size_bytes: Some(512),
            start_sector: Some(2048),
            size_sectors: Some(4096),
            record_uuid: Some("part-guid".to_owned()),
        });
        let operation = Operation::BackupPartitionTableMetadata {
            disk: "/dev/vda".to_owned(),
            table_label: "gpt".to_owned(),
            table_id: Some("disk-guid".to_owned()),
        };

        let requirement = requirement_for_operation(&identity, &operation, Path::new("/safe"), 1)
            .unwrap()
            .unwrap();

        assert_eq!(requirement.kind, MetadataBackupKind::PartitionTable);
        assert_eq!(requirement.capture.program, "sfdisk");
        assert_eq!(
            requirement.capture.args,
            vec!["--dump".to_owned(), "/dev/vda".to_owned()]
        );
        assert_eq!(
            requirement.capture.stdout_path.as_deref(),
            Some("/safe/01-partition-table.sfdisk")
        );
        assert!(!requirement.capture.mutates_storage_metadata);
        assert_eq!(requirement.recovery.program, "sfdisk");
        assert_eq!(requirement.recovery.args, vec!["/dev/vda".to_owned()]);
        assert_eq!(
            requirement.recovery.stdin_path.as_deref(),
            Some("/safe/01-partition-table.sfdisk")
        );
        assert!(requirement.recovery.mutates_storage_metadata);
    }

    #[test]
    fn lvm_requirement_resolves_vg_uuid_to_frozen_name() {
        let mut identity = empty_identity();
        identity.lvm.push(LvmIdentity {
            kind: LvmIdentityKind::VolumeGroup,
            name: "vg0".to_owned(),
            uuid: Some("vg-uuid-1".to_owned()),
            size_bytes: 16 * GIB,
            free_bytes: Some(8 * GIB),
            extent_size_bytes: Some(EXTENT),
            free_extent_count: Some(2048),
            pv_count: Some(1),
            lv_count: Some(1),
            attributes: Some("wz--n-".to_owned()),
            layout: None,
            role: None,
        });
        let operation = Operation::BackupLvmMetadata {
            vg_uuid: "vg-uuid-1".to_owned(),
        };

        let requirement = requirement_for_operation(&identity, &operation, Path::new("/safe"), 1)
            .unwrap()
            .unwrap();

        assert_eq!(requirement.kind, MetadataBackupKind::LvmVolumeGroup);
        assert_eq!(requirement.capture.program, "vgcfgbackup");
        assert_eq!(
            requirement.capture.args,
            vec![
                "--file".to_owned(),
                "/safe/01-lvm-vg.conf".to_owned(),
                "vg0".to_owned()
            ]
        );
        assert!(!requirement.capture.mutates_storage_metadata);
        assert_eq!(requirement.recovery.program, "vgcfgrestore");
        assert!(requirement.recovery.mutates_storage_metadata);
    }

    fn fixture() -> (HostSnapshot, HostCapabilities) {
        let snapshot: HostSnapshot = serde_json::from_value(json!({
            "storage": {"block_devices": [{
                "name":"vda","kernel_name":"vda","path":"/dev/vda","kind":"disk",
                "size_bytes":20*GIB,"mountpoints":[],"partition_table":"gpt","children":[{
                    "name":"vda1","kernel_name":"vda1","path":"/dev/vda1","kind":"partition",
                    "size_bytes":16*GIB,"start_512_sector":2048,"logical_sector_bytes":512,
                    "uuid":"pv-1","partition_uuid":"part-1",
                    "filesystem":{"fs_type":"LVM2_member"},"mountpoints":[],
                    "parent_kernel_name":"vda","children":[{
                        "name":"vg0-root","kernel_name":"dm-0","path":"/dev/mapper/vg0-root",
                        "kind":"lvm","size_bytes":8*GIB,"uuid":"fs-1",
                        "filesystem":{"fs_type":"ext4","version":"1.0"},"mountpoints":["/"],
                        "parent_kernel_name":"vda1","children":[]
                    }]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/vda","label":"gpt","id":"gpt-test","unit":"sectors",
                "first_lba":34,"last_lba":41943006,"sector_size_bytes":512,
                "partitions":[{
                    "node":"/dev/vda1","start_sector":2048,"size_sectors":33554432,
                    "partition_type":"E6D6D379-F507-44C2-A23C-238F2A3DF928","uuid":"part-1"
                }]
            }],
            "mounts":[{"source":"/dev/vg0/root","target":"/","fs_type":"ext4","options":["rw","relatime"]}],
            "fstab":[],"swaps":[],"diagnostics":[],
            "collectors":[
                {"component":"lsblk","state":"complete"},
                {"component":"partition_tables","state":"complete"},
                {"component":"mounts","state":"complete"},
                {"component":"fstab","state":"complete"},
                {"component":"swap","state":"complete"},
                {"component":"lvm","state":"complete"}
            ],
            "lvm":{
                "physical_volumes":[{"name":"/dev/vda1","uuid":"pv-1","vg_name":"vg0","size_bytes":16*GIB,"free_bytes":8*GIB}],
                "volume_groups":[{
                    "name":"vg0","uuid":"vg-uuid-1","size_bytes":16*GIB,"free_bytes":8*GIB,
                    "pv_count":1,"lv_count":1,"extent_size_bytes":EXTENT,"free_extent_count":2048,
                    "missing_pv_count":0,"attributes":"wz--n-"
                }],
                "logical_volumes":[{
                    "name":"root","path":"/dev/vg0/root","uuid":"lv-1","vg_name":"vg0",
                    "size_bytes":8*GIB,"attributes":"-wi-ao----","layout":"linear","role":"public"
                }]
            },
            "filesystem_preflight":[{
                "device":"/dev/mapper/vg0-root","mountpoint":"/","fs_type":"ext4",
                "fs_version":"1.0","state":"verified","filesystem_state":"clean",
                "revision":"1","features":["has_journal","extent","64bit","metadata_csum"],
                "block_size_bytes":4096,"block_count":2097152,"size_bytes":8*GIB,
                "grow_check_passed":null,"detail":"fixture"
            }]
        }))
        .unwrap();
        let capabilities: HostCapabilities = serde_json::from_value(json!({"tools":[
            {"name":"vgcfgbackup","available":true},
            {"name":"lvextend","available":true},
            {"name":"resize2fs","available":true},
            {"name":"e2fsck","available":true}
        ]}))
        .unwrap();
        (snapshot, capabilities)
    }

    fn frozen_handoff(
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> FrozenExecutionHandoff {
        let plan = plan_extend(
            snapshot,
            capabilities,
            ExtendRequest {
                target: "/".into(),
                growth: Growth::ByBytes(GIB),
            },
        )
        .unwrap();
        assert_eq!(plan.status(), PlanStatus::Preview);
        build_frozen_execution_handoff(snapshot, capabilities, &plan).unwrap()
    }

    #[test]
    fn manifest_is_repeatable_and_contains_only_required_lvm_backup() {
        let (snapshot, capabilities) = fixture();
        let handoff = frozen_handoff(&snapshot, &capabilities);

        let first = build_metadata_backup_manifest(&handoff).unwrap();
        let second = build_metadata_backup_manifest(&handoff).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.requirements().len(), 1);
        assert_eq!(
            first.requirements()[0].kind,
            MetadataBackupKind::LvmVolumeGroup
        );
        assert!(!first.mutation_enabled());
        assert!(first.owner_acceptance_required());
        assert_eq!(first.handoff_id(), handoff.handoff_id());
        assert_eq!(first.plan_id(), handoff.plan().plan_id());
        assert_eq!(
            first.target_manifest_digest(),
            handoff.target_identity().manifest_digest
        );
    }

    #[test]
    fn blocked_handoff_cannot_produce_backup_manifest() {
        let (mut snapshot, capabilities) = fixture();
        snapshot.filesystem_preflight.clear();
        let handoff = frozen_handoff(&snapshot, &capabilities);
        assert_eq!(handoff.status(), ExecutionHandoffStatus::Blocked);

        let result = build_metadata_backup_manifest(&handoff);
        assert!(matches!(result, Err(BackupManifestError::HandoffBlocked)));
    }
}
