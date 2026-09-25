use lsm_planner::{LvmIdentityKind, TargetIdentityManifest};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    validate_privileged_helper_request, NativeOperationSpec, PrivilegedHelperProtocolError,
    PrivilegedHelperRequest, PrivilegedProcessReceipt, PrivilegedRuntimeDisposition,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedLayerVerificationReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub execution_id: String,
    pub process_receipt_id: String,
    pub request_id: String,
    pub plan_step_id: u32,
    pub before_identity_digest: String,
    pub fresh_identity_digest: String,
    pub verified_operation: String,
    pub expected_state_verified: bool,
}

impl PrivilegedLayerVerificationReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    pub(crate) fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.process_receipt_id,
            &self.request_id,
            self.plan_step_id,
            &self.before_identity_digest,
            &self.fresh_identity_digest,
            &self.verified_operation,
            self.expected_state_verified,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedLayerVerificationError {
    #[error("privileged-helper request validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("process receipt integrity check failed")]
    ProcessReceiptIntegrityMismatch,
    #[error("process outcome requires recovery instead of rediscovery")]
    RecoveryRequired,
    #[error("request/process receipt binding mismatch")]
    ProcessBindingMismatch,
    #[error("before identity does not match the request binding")]
    BeforeIdentityMismatch,
    #[error("fresh identity changed target or resolved device")]
    TargetIdentityMismatch,
    #[error("partition post-state does not match the exact authorized geometry")]
    PartitionStateMismatch,
    #[error("physical-volume post-state does not match the exact authorized size")]
    PhysicalVolumeStateMismatch,
    #[error("logical-volume post-state does not match the exact authorized size")]
    LogicalVolumeStateMismatch,
    #[error("filesystem post-state does not prove the exact authorized growth")]
    FilesystemStateMismatch,
    #[error("unsupported mutation operation for production layer verification")]
    UnsupportedOperation,
    #[error("layer-verification receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn operation_name(operation: &NativeOperationSpec) -> &'static str {
    match operation {
        NativeOperationSpec::ExtendPartition { .. } => "extend_partition",
        NativeOperationSpec::ResizePhysicalVolume { .. } => "resize_physical_volume",
        NativeOperationSpec::ExtendLogicalVolume { .. } => "extend_logical_volume",
        NativeOperationSpec::GrowFilesystem { .. } => "grow_filesystem",
        _ => "unsupported",
    }
}

fn verify_partition(
    partition: &str,
    start_sector: u64,
    new_size_sectors: u64,
    before: &TargetIdentityManifest,
    fresh: &TargetIdentityManifest,
) -> bool {
    let before_matches = before
        .partitions
        .iter()
        .filter(|entry| entry.partition == partition)
        .collect::<Vec<_>>();
    let fresh_matches = fresh
        .partitions
        .iter()
        .filter(|entry| entry.partition == partition)
        .collect::<Vec<_>>();
    if before_matches.len() != 1 || fresh_matches.len() != 1 {
        return false;
    }
    let old = before_matches[0];
    let new = fresh_matches[0];
    old.start_sector == Some(start_sector)
        && new.start_sector == Some(start_sector)
        && new.size_sectors == Some(new_size_sectors)
        && old.size_sectors.is_some_and(|size| size < new_size_sectors)
        && old.disk == new.disk
        && old.table_label == new.table_label
        && old.table_id == new.table_id
        && old.sector_size_bytes == new.sector_size_bytes
        && old.record_uuid == new.record_uuid
}

fn verify_lvm_size(
    kind: LvmIdentityKind,
    uuid: &str,
    expected_size_bytes: u64,
    before: &TargetIdentityManifest,
    fresh: &TargetIdentityManifest,
) -> bool {
    let old = before
        .lvm
        .iter()
        .filter(|entry| entry.kind == kind && entry.uuid.as_deref() == Some(uuid))
        .collect::<Vec<_>>();
    let new = fresh
        .lvm
        .iter()
        .filter(|entry| entry.kind == kind && entry.uuid.as_deref() == Some(uuid))
        .collect::<Vec<_>>();
    old.len() == 1
        && new.len() == 1
        && old[0].name == new[0].name
        && old[0].size_bytes < expected_size_bytes
        && new[0].size_bytes == expected_size_bytes
}

fn verify_filesystem(
    fs_type: &str,
    mountpoint: Option<&str>,
    before: &TargetIdentityManifest,
    fresh: &TargetIdentityManifest,
) -> bool {
    let (Some(old), Some(new)) = (before.filesystem.as_ref(), fresh.filesystem.as_ref()) else {
        return false;
    };
    if old.device != before.resolved_device
        || new.device != fresh.resolved_device
        || old.device != new.device
        || old.fs_type != fs_type
        || new.fs_type != fs_type
        || old.uuid.is_none()
        || old.uuid != new.uuid
        || old.fs_version != new.fs_version
        || old.backing_device_size_bytes != new.backing_device_size_bytes
    {
        return false;
    }

    let mounts_match = match mountpoint {
        Some(expected) => {
            let old_mounts = before
                .mounts
                .iter()
                .filter(|mount| {
                    mount.target == expected && mount.fs_type.as_deref() == Some(fs_type)
                })
                .collect::<Vec<_>>();
            let new_mounts = fresh
                .mounts
                .iter()
                .filter(|mount| {
                    mount.target == expected && mount.fs_type.as_deref() == Some(fs_type)
                })
                .collect::<Vec<_>>();
            old_mounts.len() == 1 && new_mounts.len() == 1 && old_mounts[0] == new_mounts[0]
        }
        None => fs_type == "ext4" && before.mounts.is_empty() && fresh.mounts.is_empty(),
    };
    if !mounts_match {
        return false;
    }

    match (
        old.observed_filesystem_size_bytes,
        new.observed_filesystem_size_bytes,
    ) {
        (Some(old_size), Some(new_size)) => {
            old_size > 0
                && old_size < old.backing_device_size_bytes
                && new_size > old_size
                && new_size <= new.backing_device_size_bytes
        }
        _ => false,
    }
}

/// Verify one successful spawned mutation against a fresh read-only target
/// identity. A process exit of zero is only permission to rediscover; this
/// function is what proves the exact layer post-state.
///
/// The function is pure with respect to storage and does not advance the
/// durable journal.
pub fn verify_privileged_layer_post_state(
    request: &PrivilegedHelperRequest,
    process: &PrivilegedProcessReceipt,
    before: &TargetIdentityManifest,
    fresh: &TargetIdentityManifest,
) -> Result<PrivilegedLayerVerificationReceipt, PrivilegedLayerVerificationError> {
    validate_privileged_helper_request(request)?;
    if !process.integrity_matches()? {
        return Err(PrivilegedLayerVerificationError::ProcessReceiptIntegrityMismatch);
    }
    if process.disposition != PrivilegedRuntimeDisposition::RediscoveryRequired {
        return Err(PrivilegedLayerVerificationError::RecoveryRequired);
    }
    if process.execution_id != request.execution_id || process.plan_step_id != request.plan_step_id
    {
        return Err(PrivilegedLayerVerificationError::ProcessBindingMismatch);
    }
    if before.manifest_digest != request.fresh_identity_digest
        || before.target != request.target
        || before.resolved_device != request.resolved_device
    {
        return Err(PrivilegedLayerVerificationError::BeforeIdentityMismatch);
    }
    if fresh.target != before.target || fresh.resolved_device != before.resolved_device {
        return Err(PrivilegedLayerVerificationError::TargetIdentityMismatch);
    }

    let verified = match &request.operation {
        NativeOperationSpec::ExtendPartition {
            partition,
            start_sector,
            new_size_sectors,
            ..
        } => verify_partition(partition, *start_sector, *new_size_sectors, before, fresh),
        NativeOperationSpec::ResizePhysicalVolume {
            pv_uuid,
            expected_pv_size_bytes,
        } => verify_lvm_size(
            LvmIdentityKind::PhysicalVolume,
            pv_uuid,
            *expected_pv_size_bytes,
            before,
            fresh,
        ),
        NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid,
            expected_lv_size_bytes,
            ..
        } => verify_lvm_size(
            LvmIdentityKind::LogicalVolume,
            lv_uuid,
            *expected_lv_size_bytes,
            before,
            fresh,
        ),
        NativeOperationSpec::GrowFilesystem {
            fs_type,
            mountpoint,
        } => verify_filesystem(fs_type, mountpoint.as_deref(), before, fresh),
        _ => return Err(PrivilegedLayerVerificationError::UnsupportedOperation),
    };

    if !verified {
        return Err(match request.operation {
            NativeOperationSpec::ExtendPartition { .. } => {
                PrivilegedLayerVerificationError::PartitionStateMismatch
            }
            NativeOperationSpec::ResizePhysicalVolume { .. } => {
                PrivilegedLayerVerificationError::PhysicalVolumeStateMismatch
            }
            NativeOperationSpec::ExtendLogicalVolume { .. } => {
                PrivilegedLayerVerificationError::LogicalVolumeStateMismatch
            }
            NativeOperationSpec::GrowFilesystem { .. } => {
                PrivilegedLayerVerificationError::FilesystemStateMismatch
            }
            _ => PrivilegedLayerVerificationError::UnsupportedOperation,
        });
    }

    let mut receipt = PrivilegedLayerVerificationReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        execution_id: request.execution_id.clone(),
        process_receipt_id: process.receipt_id.clone(),
        request_id: request.request_id.clone(),
        plan_step_id: request.plan_step_id,
        before_identity_digest: before.manifest_digest.clone(),
        fresh_identity_digest: fresh.manifest_digest.clone(),
        verified_operation: operation_name(&request.operation).to_owned(),
        expected_state_verified: true,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_planner::{
        LayerRouteStatus, LvmIdentity, PartitionGeometryIdentity, TargetIdentityManifest,
    };

    fn identity() -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/data".into(),
            manifest_digest: "a".repeat(64),
            resolved_device: "/dev/mapper/vg-data".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![],
            partitions: vec![PartitionGeometryIdentity {
                partition: "/dev/sda1".into(),
                disk: Some("/dev/sda".into()),
                table_label: Some("gpt".into()),
                table_id: Some("table".into()),
                sector_size_bytes: Some(512),
                start_sector: Some(2048),
                size_sectors: Some(1024),
                record_uuid: Some("part-uuid".into()),
            }],
            lvm: vec![LvmIdentity {
                kind: LvmIdentityKind::LogicalVolume,
                name: "/dev/mapper/vg-data".into(),
                uuid: Some("lv-uuid".into()),
                size_bytes: 256,
                free_bytes: None,
                pe_start_bytes: None,
                extent_size_bytes: None,
                free_extent_count: None,
                pv_count: None,
                lv_count: None,
                attributes: None,
                layout: None,
                role: None,
            }],
            filesystem: None,
            mounts: vec![],
        }
    }

    #[test]
    fn exact_lv_size_transition_is_required() {
        let before = identity();
        let mut fresh = before.clone();
        fresh.manifest_digest = "b".repeat(64);
        fresh.lvm[0].size_bytes = 512;

        assert!(verify_lvm_size(
            LvmIdentityKind::LogicalVolume,
            "lv-uuid",
            512,
            &before,
            &fresh
        ));
        assert!(!verify_lvm_size(
            LvmIdentityKind::LogicalVolume,
            "lv-uuid",
            513,
            &before,
            &fresh
        ));
    }

    #[test]
    fn partition_start_and_identity_must_remain_stable() {
        let before = identity();
        let mut fresh = before.clone();
        fresh.partitions[0].size_sectors = Some(2048);

        assert!(verify_partition("/dev/sda1", 2048, 2048, &before, &fresh));
        fresh.partitions[0].start_sector = Some(4096);
        assert!(!verify_partition("/dev/sda1", 2048, 2048, &before, &fresh));
    }
}
