use std::collections::BTreeSet;

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind, PartitionTable};
use lsm_discovery::discover_snapshot;
use lsm_planner::{list_provisioning_opportunities, ProvisioningSpaceKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    resolve_trusted_privileged_tool, revalidate_pinned_production_gpt_tail_create_consent,
    PinnedProductionGptTailCreateConsent, PrivilegedProgram,
    ProductionGptTailCreateActivationIntent, ProductionGptTailCreateConsentLeaseError,
    ProductionGptTailCreateExecutionPermit, TrustedToolError, TrustedToolIdentity,
};

pub const PRODUCTION_GPT_TAIL_CREATE_RUNTIME_PREFLIGHT_COMPILED: bool =
    cfg!(feature = "production-gpt-tail-runtime-preflight");

const CREATE_PARTITION_ALIGNMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateRuntimePreflightReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub consent_receipt_id: String,
    pub create_intent_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub gpt_disk_id: String,
    pub gpt_first_lba: u64,
    pub gpt_last_lba: u64,
    pub gpt_sector_size_bytes: u64,
    pub gpt_table_sha256: String,
    pub existing_partition_count: u32,
    pub source_start_sector: u64,
    pub source_sector_count: u64,
    pub source_size_bytes: u64,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub sfdisk: TrustedToolIdentity,
    pub partx: TrustedToolIdentity,
    pub mkfs: TrustedToolIdentity,
    pub partition_slot_deferred: bool,
    pub partition_backup_required: bool,
    pub partition_backup_captured: bool,
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
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    gpt_disk_id: &'a str,
    gpt_first_lba: u64,
    gpt_last_lba: u64,
    gpt_sector_size_bytes: u64,
    gpt_table_sha256: &'a str,
    existing_partition_count: u32,
    source_start_sector: u64,
    source_sector_count: u64,
    source_size_bytes: u64,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    sfdisk: &'a TrustedToolIdentity,
    partx: &'a TrustedToolIdentity,
    mkfs: &'a TrustedToolIdentity,
    partition_slot_deferred: bool,
    partition_backup_required: bool,
    partition_backup_captured: bool,
    runtime_ready: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionGptTailCreateRuntimePreflightReceipt {
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
            source_id: &self.source_id,
            disk: &self.disk,
            disk_size_bytes: self.disk_size_bytes,
            logical_sector_bytes: self.logical_sector_bytes,
            gpt_disk_id: &self.gpt_disk_id,
            gpt_first_lba: self.gpt_first_lba,
            gpt_last_lba: self.gpt_last_lba,
            gpt_sector_size_bytes: self.gpt_sector_size_bytes,
            gpt_table_sha256: &self.gpt_table_sha256,
            existing_partition_count: self.existing_partition_count,
            source_start_sector: self.source_start_sector,
            source_sector_count: self.source_sector_count,
            source_size_bytes: self.source_size_bytes,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            sfdisk: &self.sfdisk,
            partx: &self.partx,
            mkfs: &self.mkfs,
            partition_slot_deferred: self.partition_slot_deferred,
            partition_backup_required: self.partition_backup_required,
            partition_backup_captured: self.partition_backup_captured,
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
pub enum ProductionGptTailCreateRuntimePreflightError {
    #[error("production GPT-tail create runtime preflight feature is not compiled")]
    FeatureDisabled,
    #[error("GPT-tail activation or execution permit integrity check failed")]
    AuthorizationInvalid,
    #[error("GPT-tail execution permit does not bind the exact activation")]
    AuthorizationBindingMismatch,
    #[error("upstream GPT-tail authorization unexpectedly crossed a mutation boundary")]
    UpstreamAlreadyEnabled,
    #[error("pinned GPT-tail consent revalidation failed: {0}")]
    Consent(#[from] ProductionGptTailCreateConsentLeaseError),
    #[error("fresh storage collectors required for GPT-tail preflight are incomplete")]
    CollectorIncomplete,
    #[error("fresh GPT-tail disk identity or geometry changed")]
    DiskIdentityChanged,
    #[error("fresh GPT table identity, geometry or canonical content changed")]
    GptTableChanged,
    #[error("fresh GPT partition records are malformed, overlapping or out of range")]
    GptPartitionRecordsInvalid,
    #[error("fresh GPT-tail free-space source changed or is no longer unique")]
    TailSourceChanged,
    #[error("frozen GPT-tail allocation is no longer contained in the exact free tail")]
    AllocationChanged,
    #[error("trusted GPT-tail create tool resolution failed: {0}")]
    Tool(#[from] TrustedToolError),
    #[error("fresh GPT-tail preflight discovery failed: {0}")]
    Discovery(String),
    #[error("GPT-tail runtime preflight serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct CanonicalPartition<'a> {
    node: &'a str,
    start_sector: u64,
    size_sectors: u64,
    partition_type: Option<&'a str>,
    uuid: Option<&'a str>,
    name: Option<&'a str>,
    attrs: Option<&'a str>,
    bootable: Option<bool>,
}

#[derive(Serialize)]
struct CanonicalTable<'a> {
    device: &'a str,
    label: Option<&'a str>,
    id: Option<&'a str>,
    unit: Option<&'a str>,
    first_lba: Option<u64>,
    last_lba: Option<u64>,
    sector_size_bytes: Option<u64>,
    partitions: Vec<CanonicalPartition<'a>>,
}

fn canonical_table_sha256(table: &PartitionTable) -> Result<String, serde_json::Error> {
    let mut partitions = table.partitions.iter().collect::<Vec<_>>();
    partitions.sort_by(|left, right| {
        left.start_sector
            .cmp(&right.start_sector)
            .then_with(|| left.node.cmp(&right.node))
    });
    let partitions = partitions
        .into_iter()
        .map(|record| CanonicalPartition {
            node: &record.node,
            start_sector: record.start_sector,
            size_sectors: record.size_sectors,
            partition_type: record.partition_type.as_deref(),
            uuid: record.uuid.as_deref(),
            name: record.name.as_deref(),
            attrs: record.attrs.as_deref(),
            bootable: record.bootable,
        })
        .collect();
    let payload = CanonicalTable {
        device: &table.device,
        label: table.label.as_deref(),
        id: table.id.as_deref(),
        unit: table.unit.as_deref(),
        first_lba: table.first_lba,
        last_lba: table.last_lba,
        sector_size_bytes: table.sector_size_bytes,
        partitions,
    };
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&payload)?)
    ))
}

fn flatten<'a>(devices: &'a [BlockDevice], output: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        output.push(device);
        flatten(&device.children, output);
    }
}

fn required_collectors_complete(snapshot: &HostSnapshot) -> bool {
    ["lsblk", "partition_tables", "mounts", "fstab", "swap"]
        .into_iter()
        .all(|component| {
            let matches = snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component)
                .collect::<Vec<_>>();
            matches.len() == 1 && matches[0].state == CollectorState::Complete
        })
}

fn validate_partition_records(table: &PartitionTable, first_lba: u64, last_lba: u64) -> bool {
    let Some(limit) = last_lba.checked_add(1) else {
        return false;
    };
    let mut records = table.partitions.iter().collect::<Vec<_>>();
    records.sort_by(|left, right| {
        left.start_sector
            .cmp(&right.start_sector)
            .then_with(|| left.node.cmp(&right.node))
    });

    let mut nodes = BTreeSet::new();
    let mut previous_end = first_lba;
    for record in records {
        let Some(end) = record.start_sector.checked_add(record.size_sectors) else {
            return false;
        };
        if record.node.is_empty()
            || !nodes.insert(record.node.as_str())
            || record.size_sectors == 0
            || record.start_sector < first_lba
            || end > limit
            || record.start_sector < previous_end
        {
            return false;
        }
        previous_end = end;
    }
    true
}

fn validate_authorization(
    activation: &ProductionGptTailCreateActivationIntent,
    permit: &ProductionGptTailCreateExecutionPermit,
) -> Result<(), ProductionGptTailCreateRuntimePreflightError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !permit.compile_feature_enabled
        || !activation.partition_slot_deferred
        || !permit.partition_slot_deferred
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationInvalid);
    }
    if activation.execution_enabled
        || activation.partition_table_changed
        || activation.filesystem_formatted
        || permit.mutation_enabled
        || permit.process_spawned
        || permit.partition_table_changed
        || permit.filesystem_formatted
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::UpstreamAlreadyEnabled);
    }
    if permit.activation_id != activation.activation_id
        || permit.create_intent_id != activation.create_intent_id
        || permit.create_plan_id != activation.create_plan_id
        || permit.source_id != activation.source_id
        || permit.disk != activation.disk
        || permit.disk_size_bytes != activation.disk_size_bytes
        || permit.logical_sector_bytes != activation.logical_sector_bytes
        || permit.gpt_disk_id != activation.gpt_disk_id
        || permit.gpt_first_lba != activation.gpt_first_lba
        || permit.gpt_last_lba != activation.gpt_last_lba
        || permit.gpt_sector_size_bytes != activation.gpt_sector_size_bytes
        || permit.gpt_table_sha256 != activation.gpt_table_sha256
        || permit.existing_partition_count != activation.existing_partition_count
        || permit.source_start_sector != activation.source_start_sector
        || permit.source_sector_count != activation.source_sector_count
        || permit.source_size_bytes != activation.source_size_bytes
        || permit.partition_start_sector != activation.partition_start_sector
        || permit.partition_sector_count != activation.partition_sector_count
        || permit.partition_size_bytes != activation.partition_size_bytes
        || permit.filesystem != activation.filesystem
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_fresh_gpt_tail(
    activation: &ProductionGptTailCreateActivationIntent,
    snapshot: &HostSnapshot,
) -> Result<(), ProductionGptTailCreateRuntimePreflightError> {
    if !required_collectors_complete(snapshot) {
        return Err(ProductionGptTailCreateRuntimePreflightError::CollectorIncomplete);
    }

    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let disks = nodes
        .iter()
        .copied()
        .filter(|device| {
            matches!(device.kind, NodeKind::Disk | NodeKind::Loop)
                && device.path.as_deref() == Some(activation.disk.as_str())
        })
        .collect::<Vec<_>>();
    let [disk] = disks.as_slice() else {
        return Err(ProductionGptTailCreateRuntimePreflightError::DiskIdentityChanged);
    };
    if disk.size_bytes != activation.disk_size_bytes
        || disk.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || disk.model != activation.disk_model
        || disk.serial != activation.disk_serial
        || disk.filesystem.is_some()
        || !disk.mountpoints.is_empty()
        || disk.parent_kernel_name.is_some()
        || disk.partition_table.as_deref() != Some("gpt")
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::DiskIdentityChanged);
    }

    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == activation.disk)
        .collect::<Vec<_>>();
    let [table] = tables.as_slice() else {
        return Err(ProductionGptTailCreateRuntimePreflightError::GptTableChanged);
    };
    if table.label.as_deref() != Some("gpt")
        || table.id.as_deref() != Some(activation.gpt_disk_id.as_str())
        || table.unit.as_deref() != Some("sectors")
        || table.first_lba != Some(activation.gpt_first_lba)
        || table.last_lba != Some(activation.gpt_last_lba)
        || table.sector_size_bytes != Some(activation.gpt_sector_size_bytes)
        || table.partitions.len() != activation.existing_partition_count as usize
        || canonical_table_sha256(table)? != activation.gpt_table_sha256
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::GptTableChanged);
    }
    if !validate_partition_records(table, activation.gpt_first_lba, activation.gpt_last_lba) {
        return Err(ProductionGptTailCreateRuntimePreflightError::GptPartitionRecordsInvalid);
    }

    let opportunities = list_provisioning_opportunities(snapshot);
    let sources = opportunities
        .iter()
        .filter(|source| source.id == activation.source_id)
        .collect::<Vec<_>>();
    let [source] = sources.as_slice() else {
        return Err(ProductionGptTailCreateRuntimePreflightError::TailSourceChanged);
    };
    if source.kind != ProvisioningSpaceKind::DiskTail
        || source.disk.as_deref() != Some(activation.disk.as_str())
        || source.sector_size_bytes != Some(activation.gpt_sector_size_bytes)
        || source.start_sector != Some(activation.source_start_sector)
        || source.sector_count != Some(activation.source_sector_count)
        || source.available_bytes != activation.source_size_bytes
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::TailSourceChanged);
    }

    let sector = activation.logical_sector_bytes;
    if sector == 0
        || sector != activation.gpt_sector_size_bytes
        || CREATE_PARTITION_ALIGNMENT_BYTES % sector != 0
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::AllocationChanged);
    }
    let alignment_sectors = CREATE_PARTITION_ALIGNMENT_BYTES / sector;
    let Some(source_end) = activation
        .source_start_sector
        .checked_add(activation.source_sector_count)
    else {
        return Err(ProductionGptTailCreateRuntimePreflightError::AllocationChanged);
    };
    let Some(partition_end) = activation
        .partition_start_sector
        .checked_add(activation.partition_sector_count)
    else {
        return Err(ProductionGptTailCreateRuntimePreflightError::AllocationChanged);
    };
    if activation.source_sector_count == 0
        || activation.source_sector_count.checked_mul(sector) != Some(activation.source_size_bytes)
        || activation.partition_start_sector != activation.source_start_sector
        || activation.partition_start_sector % alignment_sectors != 0
        || activation.partition_sector_count == 0
        || activation.partition_sector_count > activation.source_sector_count
        || activation.partition_sector_count.checked_mul(sector)
            != Some(activation.partition_size_bytes)
        || partition_end > source_end
        || source_end > activation.gpt_last_lba.saturating_add(1)
    {
        return Err(ProductionGptTailCreateRuntimePreflightError::AllocationChanged);
    }

    Ok(())
}

fn mkfs_program(
    filesystem: &str,
) -> Result<PrivilegedProgram, ProductionGptTailCreateRuntimePreflightError> {
    match filesystem {
        "ext4" => Ok(PrivilegedProgram::MkfsExt4),
        "xfs" => Ok(PrivilegedProgram::MkfsXfs),
        _ => Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationBindingMismatch),
    }
}

fn prepare_from_snapshot_inner(
    activation: &ProductionGptTailCreateActivationIntent,
    permit: &ProductionGptTailCreateExecutionPermit,
    consent_lease: &PinnedProductionGptTailCreateConsent,
    snapshot: &HostSnapshot,
) -> Result<
    ProductionGptTailCreateRuntimePreflightReceipt,
    ProductionGptTailCreateRuntimePreflightError,
> {
    if !PRODUCTION_GPT_TAIL_CREATE_RUNTIME_PREFLIGHT_COMPILED {
        return Err(ProductionGptTailCreateRuntimePreflightError::FeatureDisabled);
    }
    validate_authorization(activation, permit)?;
    validate_fresh_gpt_tail(activation, snapshot)?;

    let consent = revalidate_pinned_production_gpt_tail_create_consent(activation, consent_lease)?;
    if consent.receipt_id != permit.consent_receipt_id {
        return Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationBindingMismatch);
    }

    let sfdisk = resolve_trusted_privileged_tool(PrivilegedProgram::Sfdisk)?;
    let partx = resolve_trusted_privileged_tool(PrivilegedProgram::Partx)?;
    let mkfs = resolve_trusted_privileged_tool(mkfs_program(&activation.filesystem)?)?;

    let mut receipt = ProductionGptTailCreateRuntimePreflightReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        consent_receipt_id: consent.receipt_id,
        create_intent_id: activation.create_intent_id.clone(),
        source_id: activation.source_id.clone(),
        disk: activation.disk.clone(),
        disk_size_bytes: activation.disk_size_bytes,
        logical_sector_bytes: activation.logical_sector_bytes,
        gpt_disk_id: activation.gpt_disk_id.clone(),
        gpt_first_lba: activation.gpt_first_lba,
        gpt_last_lba: activation.gpt_last_lba,
        gpt_sector_size_bytes: activation.gpt_sector_size_bytes,
        gpt_table_sha256: activation.gpt_table_sha256.clone(),
        existing_partition_count: activation.existing_partition_count,
        source_start_sector: activation.source_start_sector,
        source_sector_count: activation.source_sector_count,
        source_size_bytes: activation.source_size_bytes,
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        sfdisk,
        partx,
        mkfs,
        partition_slot_deferred: true,
        partition_backup_required: true,
        partition_backup_captured: false,
        runtime_ready: true,
        mutation_enabled: false,
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Re-read the complete storage snapshot and fail closed unless the exact M2B1
/// GPT-tail free range and all M2B2-M2B5 authorization bindings remain
/// unchanged. This preflight resolves trusted sfdisk/partx/mkfs identities but
/// deliberately does not spawn them, capture the GPT backup or select a
/// partition slot.
pub fn prepare_production_gpt_tail_create_runtime_preflight(
    activation: &ProductionGptTailCreateActivationIntent,
    permit: &ProductionGptTailCreateExecutionPermit,
    consent_lease: &PinnedProductionGptTailCreateConsent,
) -> Result<
    ProductionGptTailCreateRuntimePreflightReceipt,
    ProductionGptTailCreateRuntimePreflightError,
> {
    let snapshot = discover_snapshot().map_err(|error| {
        ProductionGptTailCreateRuntimePreflightError::Discovery(error.to_string())
    })?;
    prepare_from_snapshot_inner(activation, permit, consent_lease, &snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProductionGptTailCreateProfile;
    use lsm_core::{CollectorStatus, Filesystem, PartitionRecord, StorageGraph};
    use lsm_planner::list_provisioning_opportunities;

    const MIB: u64 = 1024 * 1024;

    fn snapshot() -> HostSnapshot {
        let disk_bytes = 512 * MIB;
        let sector = 512_u64;
        let disk_sectors = disk_bytes / sector;
        let first_start = 2048_u64;
        let first_size_sectors = 64 * MIB / sector;
        HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![BlockDevice {
                    name: "loop7".into(),
                    kernel_name: Some("loop7".into()),
                    path: Some("/dev/loop7".into()),
                    kind: NodeKind::Loop,
                    size_bytes: disk_bytes,
                    start_512_sector: None,
                    logical_sector_bytes: Some(sector),
                    filesystem: None,
                    mountpoints: vec![],
                    parent_kernel_name: None,
                    model: Some("loop-test".into()),
                    serial: Some("fixture-001".into()),
                    uuid: None,
                    partition_uuid: None,
                    partition_table: Some("gpt".into()),
                    children: vec![BlockDevice {
                        name: "loop7p1".into(),
                        kernel_name: Some("loop7p1".into()),
                        path: Some("/dev/loop7p1".into()),
                        kind: NodeKind::Partition,
                        size_bytes: 64 * MIB,
                        start_512_sector: Some(first_start),
                        logical_sector_bytes: Some(sector),
                        filesystem: Some(Filesystem {
                            fs_type: "ext4".into(),
                            version: None,
                        }),
                        mountpoints: vec![],
                        parent_kernel_name: Some("loop7".into()),
                        model: None,
                        serial: None,
                        uuid: Some("11111111-1111-1111-1111-111111111111".into()),
                        partition_uuid: Some("22222222-2222-2222-2222-222222222222".into()),
                        partition_table: None,
                        children: vec![],
                    }],
                }],
            },
            partition_tables: vec![PartitionTable {
                device: "/dev/loop7".into(),
                label: Some("gpt".into()),
                id: Some("12345678-1234-1234-1234-123456789abc".into()),
                unit: Some("sectors".into()),
                first_lba: Some(34),
                last_lba: Some(disk_sectors - 34),
                sector_size_bytes: Some(sector),
                partitions: vec![PartitionRecord {
                    node: "/dev/loop7p1".into(),
                    start_sector: first_start,
                    size_sectors: first_size_sectors,
                    partition_type: Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4".into()),
                    uuid: Some("22222222-2222-2222-2222-222222222222".into()),
                    name: None,
                    attrs: None,
                    bootable: None,
                }],
            }],
            mounts: vec![],
            fstab: vec![],
            swaps: vec![],
            lvm: None,
            filesystem_preflight: vec![],
            diagnostics: vec![],
            collectors: ["lsblk", "partition_tables", "mounts", "fstab", "swap"]
                .into_iter()
                .map(|component| CollectorStatus {
                    component: component.into(),
                    state: CollectorState::Complete,
                    detail: None,
                })
                .collect(),
        }
    }

    fn activation_and_permit(
        snapshot: &HostSnapshot,
    ) -> (
        ProductionGptTailCreateActivationIntent,
        ProductionGptTailCreateExecutionPermit,
    ) {
        let source = list_provisioning_opportunities(snapshot)
            .into_iter()
            .find(|source| source.kind == ProvisioningSpaceKind::DiskTail)
            .unwrap();
        let table = &snapshot.partition_tables[0];
        let sector = table.sector_size_bytes.unwrap();
        let partition_sector_count = 64 * MIB / sector;
        let mut activation = ProductionGptTailCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionGptTailCreateProfile::ExistingGptTailFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: source.id.clone(),
            disk: "/dev/loop7".into(),
            disk_size_bytes: snapshot.storage.block_devices[0].size_bytes,
            logical_sector_bytes: sector,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            gpt_disk_id: table.id.clone().unwrap(),
            gpt_first_lba: table.first_lba.unwrap(),
            gpt_last_lba: table.last_lba.unwrap(),
            gpt_sector_size_bytes: sector,
            gpt_table_sha256: canonical_table_sha256(table).unwrap(),
            existing_partition_count: table.partitions.len() as u32,
            source_start_sector: source.start_sector.unwrap(),
            source_sector_count: source.sector_count.unwrap(),
            source_size_bytes: source.available_bytes,
            partition_start_sector: source.start_sector.unwrap(),
            partition_sector_count,
            partition_size_bytes: partition_sector_count * sector,
            filesystem: "ext4".into(),
            partition_slot_deferred: true,
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        activation.activation_id = activation.expected_activation_id().unwrap();

        let mut permit = ProductionGptTailCreateExecutionPermit {
            schema_version: 1,
            permit_id: String::new(),
            activation_id: activation.activation_id.clone(),
            consent_receipt_id: "c".repeat(64),
            profile: activation.profile,
            create_intent_id: activation.create_intent_id.clone(),
            create_plan_id: activation.create_plan_id.clone(),
            source_id: activation.source_id.clone(),
            disk: activation.disk.clone(),
            disk_size_bytes: activation.disk_size_bytes,
            logical_sector_bytes: activation.logical_sector_bytes,
            gpt_disk_id: activation.gpt_disk_id.clone(),
            gpt_first_lba: activation.gpt_first_lba,
            gpt_last_lba: activation.gpt_last_lba,
            gpt_sector_size_bytes: activation.gpt_sector_size_bytes,
            gpt_table_sha256: activation.gpt_table_sha256.clone(),
            existing_partition_count: activation.existing_partition_count,
            source_start_sector: activation.source_start_sector,
            source_sector_count: activation.source_sector_count,
            source_size_bytes: activation.source_size_bytes,
            partition_start_sector: activation.partition_start_sector,
            partition_sector_count: activation.partition_sector_count,
            partition_size_bytes: activation.partition_size_bytes,
            filesystem: activation.filesystem.clone(),
            partition_slot_deferred: true,
            compile_feature_enabled: true,
            mutation_enabled: false,
            process_spawned: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        permit.permit_id = permit.expected_permit_id().unwrap();
        (activation, permit)
    }

    #[test]
    fn exact_fresh_gpt_tail_matches_frozen_authorization() {
        let snapshot = snapshot();
        let (activation, permit) = activation_and_permit(&snapshot);
        assert!(validate_authorization(&activation, &permit).is_ok());
        assert!(validate_fresh_gpt_tail(&activation, &snapshot).is_ok());
    }

    #[test]
    fn changed_existing_partition_geometry_fails_closed() {
        let mut snapshot = snapshot();
        let (activation, _) = activation_and_permit(&snapshot);
        snapshot.partition_tables[0].partitions[0].size_sectors += 1;
        assert!(matches!(
            validate_fresh_gpt_tail(&activation, &snapshot),
            Err(ProductionGptTailCreateRuntimePreflightError::GptTableChanged)
                | Err(ProductionGptTailCreateRuntimePreflightError::TailSourceChanged)
        ));
    }

    #[test]
    fn changed_gpt_disk_id_fails_closed() {
        let mut snapshot = snapshot();
        let (activation, _) = activation_and_permit(&snapshot);
        snapshot.partition_tables[0].id = Some("99999999-9999-9999-9999-999999999999".into());
        assert!(matches!(
            validate_fresh_gpt_tail(&activation, &snapshot),
            Err(ProductionGptTailCreateRuntimePreflightError::GptTableChanged)
        ));
    }

    #[test]
    fn incomplete_runtime_collector_fails_closed() {
        let mut snapshot = snapshot();
        let (activation, _) = activation_and_permit(&snapshot);
        snapshot
            .collectors
            .retain(|collector| collector.component != "swap");
        assert!(matches!(
            validate_fresh_gpt_tail(&activation, &snapshot),
            Err(ProductionGptTailCreateRuntimePreflightError::CollectorIncomplete)
        ));
    }

    #[test]
    fn permit_geometry_drift_is_rejected() {
        let snapshot = snapshot();
        let (activation, mut permit) = activation_and_permit(&snapshot);
        permit.partition_sector_count += 1;
        assert!(matches!(
            validate_authorization(&activation, &permit),
            Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationInvalid)
                | Err(ProductionGptTailCreateRuntimePreflightError::AuthorizationBindingMismatch)
        ));
    }

    #[test]
    fn runtime_preflight_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_GPT_TAIL_CREATE_RUNTIME_PREFLIGHT_COMPILED,
            cfg!(feature = "production-gpt-tail-runtime-preflight")
        );
    }
}
