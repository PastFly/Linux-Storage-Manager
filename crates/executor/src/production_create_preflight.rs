use lsm_core::{CollectorState, HostSnapshot, NodeKind};
use lsm_discovery::discover_snapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    resolve_trusted_privileged_tool, revalidate_pinned_production_create_consent,
    PinnedProductionCreateConsent, PrivilegedProgram, ProductionCreateActivationIntent,
    ProductionCreateConsentLeaseError, ProductionCreateExecutionPermit, TrustedToolError,
    TrustedToolIdentity,
};

pub const PRODUCTION_CREATE_RUNTIME_PREFLIGHT_COMPILED: bool =
    cfg!(feature = "production-create-runtime-preflight");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateRuntimePreflightReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub consent_receipt_id: String,
    pub create_intent_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub sfdisk: TrustedToolIdentity,
    pub partx: TrustedToolIdentity,
    pub mkfs: TrustedToolIdentity,
    pub runtime_ready: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    consent_receipt_id: &'a str,
    create_intent_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    sfdisk: &'a TrustedToolIdentity,
    partx: &'a TrustedToolIdentity,
    mkfs: &'a TrustedToolIdentity,
    runtime_ready: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionCreateRuntimePreflightReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            execution_permit_id: &self.execution_permit_id,
            consent_receipt_id: &self.consent_receipt_id,
            create_intent_id: &self.create_intent_id,
            disk: &self.disk,
            disk_size_bytes: self.disk_size_bytes,
            logical_sector_bytes: self.logical_sector_bytes,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            sfdisk: &self.sfdisk,
            partx: &self.partx,
            mkfs: &self.mkfs,
            runtime_ready: self.runtime_ready,
            mutation_enabled: self.mutation_enabled,
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
pub enum ProductionCreateRuntimePreflightError {
    #[error("production create runtime preflight feature is not compiled")]
    FeatureDisabled,
    #[error("create activation or execution permit integrity check failed")]
    AuthorizationInvalid,
    #[error("create execution permit does not bind the exact activation")]
    AuthorizationBindingMismatch,
    #[error("upstream create authorization unexpectedly crossed a mutation boundary")]
    UpstreamAlreadyEnabled,
    #[error("pinned create consent revalidation failed: {0}")]
    Consent(#[from] ProductionCreateConsentLeaseError),
    #[error("fresh partition-table collector is incomplete")]
    PartitionCollectorIncomplete,
    #[error("fresh blank-disk identity or geometry changed")]
    BlankDiskChanged,
    #[error("fresh snapshot reports usage or storage state on the selected blank disk")]
    BlankDiskNoLongerBlank,
    #[error("trusted create tool resolution failed: {0}")]
    Tool(#[from] TrustedToolError),
    #[error("read-only create preflight discovery failed: {0}")]
    Discovery(String),
    #[error("create runtime preflight serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_authorization(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
) -> Result<(), ProductionCreateRuntimePreflightError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !permit.compile_feature_enabled
    {
        return Err(ProductionCreateRuntimePreflightError::AuthorizationInvalid);
    }
    if activation.execution_enabled
        || activation.partition_table_changed
        || activation.filesystem_formatted
        || permit.mutation_enabled
        || permit.process_spawned
        || permit.partition_table_changed
        || permit.filesystem_formatted
    {
        return Err(ProductionCreateRuntimePreflightError::UpstreamAlreadyEnabled);
    }
    if permit.activation_id != activation.activation_id
        || permit.create_intent_id != activation.create_intent_id
        || permit.create_plan_id != activation.create_plan_id
        || permit.source_id != activation.source_id
        || permit.disk != activation.disk
        || permit.disk_size_bytes != activation.disk_size_bytes
        || permit.logical_sector_bytes != activation.logical_sector_bytes
        || permit.partition_table != activation.partition_table
        || permit.partition_start_sector != activation.partition_start_sector
        || permit.partition_sector_count != activation.partition_sector_count
        || permit.partition_size_bytes != activation.partition_size_bytes
        || permit.filesystem != activation.filesystem
    {
        return Err(ProductionCreateRuntimePreflightError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_fresh_blank_disk(
    activation: &ProductionCreateActivationIntent,
    snapshot: &HostSnapshot,
) -> Result<(), ProductionCreateRuntimePreflightError> {
    let collector = snapshot
        .collectors
        .iter()
        .filter(|status| status.component == "partition_tables")
        .collect::<Vec<_>>();
    if collector.len() != 1 || collector[0].state != CollectorState::Complete {
        return Err(ProductionCreateRuntimePreflightError::PartitionCollectorIncomplete);
    }

    let disks = snapshot
        .storage
        .block_devices
        .iter()
        .filter(|device| device.path.as_deref() == Some(activation.disk.as_str()))
        .collect::<Vec<_>>();
    if disks.len() != 1 {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskChanged);
    }
    let disk = disks[0];
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
        || disk.size_bytes != activation.disk_size_bytes
        || disk.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || disk.model != activation.disk_model
        || disk.serial != activation.disk_serial
    {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskChanged);
    }

    let referenced_by_mount = snapshot
        .mounts
        .iter()
        .any(|mount| mount.source.as_deref() == Some(activation.disk.as_str()));
    let referenced_by_fstab = snapshot
        .fstab
        .iter()
        .any(|entry| entry.source == activation.disk);
    let active_swap = snapshot
        .swaps
        .iter()
        .any(|entry| entry.name == activation.disk);
    let table_present = snapshot
        .partition_tables
        .iter()
        .any(|table| table.device == activation.disk);

    if !disk.children.is_empty()
        || disk.filesystem.is_some()
        || disk.partition_table.is_some()
        || !disk.mountpoints.is_empty()
        || disk.parent_kernel_name.is_some()
        || referenced_by_mount
        || referenced_by_fstab
        || active_swap
        || table_present
    {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskNoLongerBlank);
    }

    if activation.logical_sector_bytes == 0 {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskChanged);
    }
    let Some(end_sector) = activation
        .partition_start_sector
        .checked_add(activation.partition_sector_count)
    else {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskChanged);
    };
    let disk_sectors = activation.disk_size_bytes / activation.logical_sector_bytes;
    if activation.partition_start_sector == 0
        || activation.partition_sector_count == 0
        || end_sector > disk_sectors
        || activation
            .partition_sector_count
            .checked_mul(activation.logical_sector_bytes)
            != Some(activation.partition_size_bytes)
    {
        return Err(ProductionCreateRuntimePreflightError::BlankDiskChanged);
    }

    Ok(())
}

fn mkfs_program(
    filesystem: &str,
) -> Result<PrivilegedProgram, ProductionCreateRuntimePreflightError> {
    match filesystem {
        "ext4" => Ok(PrivilegedProgram::MkfsExt4),
        "xfs" => Ok(PrivilegedProgram::MkfsXfs),
        _ => Err(ProductionCreateRuntimePreflightError::AuthorizationBindingMismatch),
    }
}

fn prepare_from_snapshot_inner(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    consent_lease: &PinnedProductionCreateConsent,
    snapshot: &HostSnapshot,
) -> Result<ProductionCreateRuntimePreflightReceipt, ProductionCreateRuntimePreflightError> {
    if !PRODUCTION_CREATE_RUNTIME_PREFLIGHT_COMPILED {
        return Err(ProductionCreateRuntimePreflightError::FeatureDisabled);
    }
    validate_authorization(activation, permit)?;
    validate_fresh_blank_disk(activation, snapshot)?;

    let consent = revalidate_pinned_production_create_consent(activation, consent_lease)?;
    if consent.receipt_id != permit.consent_receipt_id {
        return Err(ProductionCreateRuntimePreflightError::AuthorizationBindingMismatch);
    }

    let sfdisk = resolve_trusted_privileged_tool(PrivilegedProgram::Sfdisk)?;
    let partx = resolve_trusted_privileged_tool(PrivilegedProgram::Partx)?;
    let mkfs = resolve_trusted_privileged_tool(mkfs_program(&activation.filesystem)?)?;

    let mut receipt = ProductionCreateRuntimePreflightReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        consent_receipt_id: consent.receipt_id,
        create_intent_id: activation.create_intent_id.clone(),
        disk: activation.disk.clone(),
        disk_size_bytes: activation.disk_size_bytes,
        logical_sector_bytes: activation.logical_sector_bytes,
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        sfdisk,
        partx,
        mkfs,
        runtime_ready: true,
        mutation_enabled: false,
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Re-read the host storage snapshot, revalidate the exact M2A5 permit and
/// pinned M2A4 consent, then resolve trusted create tools without spawning any
/// process or changing storage.
pub fn prepare_production_create_runtime_preflight(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    consent_lease: &PinnedProductionCreateConsent,
) -> Result<ProductionCreateRuntimePreflightReceipt, ProductionCreateRuntimePreflightError> {
    let snapshot = discover_snapshot()
        .map_err(|error| ProductionCreateRuntimePreflightError::Discovery(error.to_string()))?;
    prepare_from_snapshot_inner(activation, permit, consent_lease, &snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{BlockDevice, CollectorStatus, StorageGraph};

    fn activation() -> ProductionCreateActivationIntent {
        let mut value = ProductionCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: crate::ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: "space-".to_owned() + &"c".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            partition_table: lsm_planner::CreatePartitionTablePolicy::Gpt,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    fn permit(activation: &ProductionCreateActivationIntent) -> ProductionCreateExecutionPermit {
        let mut value = ProductionCreateExecutionPermit {
            schema_version: 1,
            permit_id: String::new(),
            activation_id: activation.activation_id.clone(),
            consent_receipt_id: "d".repeat(64),
            profile: activation.profile,
            create_intent_id: activation.create_intent_id.clone(),
            create_plan_id: activation.create_plan_id.clone(),
            source_id: activation.source_id.clone(),
            disk: activation.disk.clone(),
            disk_size_bytes: activation.disk_size_bytes,
            logical_sector_bytes: activation.logical_sector_bytes,
            partition_table: activation.partition_table,
            partition_start_sector: activation.partition_start_sector,
            partition_sector_count: activation.partition_sector_count,
            partition_size_bytes: activation.partition_size_bytes,
            filesystem: activation.filesystem.clone(),
            compile_feature_enabled: true,
            mutation_enabled: false,
            process_spawned: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        value.permit_id = value.expected_permit_id().unwrap();
        value
    }

    fn snapshot(activation: &ProductionCreateActivationIntent) -> HostSnapshot {
        HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![BlockDevice {
                    name: "loop7".into(),
                    kernel_name: Some("loop7".into()),
                    path: Some(activation.disk.clone()),
                    kind: NodeKind::Loop,
                    size_bytes: activation.disk_size_bytes,
                    start_512_sector: None,
                    logical_sector_bytes: Some(activation.logical_sector_bytes),
                    filesystem: None,
                    mountpoints: vec![],
                    parent_kernel_name: None,
                    model: activation.disk_model.clone(),
                    serial: activation.disk_serial.clone(),
                    uuid: None,
                    partition_uuid: None,
                    partition_table: None,
                    children: vec![],
                }],
            },
            partition_tables: vec![],
            mounts: vec![],
            fstab: vec![],
            swaps: vec![],
            lvm: None,
            filesystem_preflight: vec![],
            diagnostics: vec![],
            collectors: vec![CollectorStatus {
                component: "partition_tables".into(),
                state: CollectorState::Complete,
                detail: None,
            }],
        }
    }

    #[test]
    fn exact_fresh_blank_disk_matches_the_frozen_create_scope() {
        let activation = activation();
        assert!(validate_fresh_blank_disk(&activation, &snapshot(&activation)).is_ok());
        assert!(validate_authorization(&activation, &permit(&activation)).is_ok());
    }

    #[test]
    fn fresh_partition_table_or_child_blocks_preflight() {
        let activation = activation();
        let mut snapshot = snapshot(&activation);
        snapshot.storage.block_devices[0].partition_table = Some("gpt".into());
        assert!(matches!(
            validate_fresh_blank_disk(&activation, &snapshot),
            Err(ProductionCreateRuntimePreflightError::BlankDiskNoLongerBlank)
        ));
    }

    #[test]
    fn changed_disk_geometry_fails_closed() {
        let activation = activation();
        let mut snapshot = snapshot(&activation);
        snapshot.storage.block_devices[0].size_bytes += 4096;
        assert!(matches!(
            validate_fresh_blank_disk(&activation, &snapshot),
            Err(ProductionCreateRuntimePreflightError::BlankDiskChanged)
        ));
    }

    #[test]
    fn create_preflight_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_RUNTIME_PREFLIGHT_COMPILED,
            cfg!(feature = "production-create-runtime-preflight")
        );
    }
}
