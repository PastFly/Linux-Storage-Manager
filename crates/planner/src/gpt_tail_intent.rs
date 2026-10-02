use std::collections::BTreeSet;

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind, PartitionTable};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    resolve_create_source_adapter, Blocker, CreatePlanPreview, CreatePurpose, PlanStatus,
    PlannerError, ProvisioningSpaceKind,
};

const CREATE_PARTITION_ALIGNMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenGptTailDiskIdentity {
    pub path: String,
    pub size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenGptTailTableIdentity {
    pub label: String,
    pub id: String,
    pub unit: String,
    pub first_lba: u64,
    pub last_lba: u64,
    pub sector_size_bytes: u64,
    pub table_sha256: String,
    pub existing_partition_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenGptTailAllocation {
    pub source_start_sector: u64,
    pub source_sector_count: u64,
    pub source_size_bytes: u64,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenGptTailFilesystemIntent {
    pub schema_version: u32,
    pub intent_id: String,
    pub executable: bool,
    pub status: PlanStatus,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: FrozenGptTailDiskIdentity,
    pub gpt: FrozenGptTailTableIdentity,
    pub allocation: FrozenGptTailAllocation,
    pub filesystem: String,
    pub mountpoint: Option<String>,
    pub partition_slot_deferred: bool,
    pub partition_table_write_authorized: bool,
    pub filesystem_format_authorized: bool,
    pub blockers: Vec<Blocker>,
    pub ordered_future_steps: Vec<String>,
}

#[derive(Serialize)]
struct IntentDigestPayload<'a> {
    schema_version: u32,
    executable: bool,
    status: PlanStatus,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a FrozenGptTailDiskIdentity,
    gpt: &'a FrozenGptTailTableIdentity,
    allocation: &'a FrozenGptTailAllocation,
    filesystem: &'a str,
    mountpoint: &'a Option<String>,
    partition_slot_deferred: bool,
    partition_table_write_authorized: bool,
    filesystem_format_authorized: bool,
    blockers: &'a [Blocker],
    ordered_future_steps: &'a [String],
}

impl FrozenGptTailFilesystemIntent {
    pub fn ready(&self) -> bool {
        self.status == PlanStatus::Preview
            && self.blockers.is_empty()
            && !self.executable
            && self.partition_slot_deferred
            && !self.partition_table_write_authorized
            && !self.filesystem_format_authorized
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.intent_id == self.expected_intent_id()?)
    }

    fn expected_intent_id(&self) -> Result<String, serde_json::Error> {
        let payload = IntentDigestPayload {
            schema_version: self.schema_version,
            executable: self.executable,
            status: self.status,
            create_plan_id: &self.create_plan_id,
            source_id: &self.source_id,
            disk: &self.disk,
            gpt: &self.gpt,
            allocation: &self.allocation,
            filesystem: &self.filesystem,
            mountpoint: &self.mountpoint,
            partition_slot_deferred: self.partition_slot_deferred,
            partition_table_write_authorized: self.partition_table_write_authorized,
            filesystem_format_authorized: self.filesystem_format_authorized,
            blockers: &self.blockers,
            ordered_future_steps: &self.ordered_future_steps,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
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

fn push_blocker(blockers: &mut Vec<Blocker>, code: &str, message: &str) {
    blockers.push(Blocker {
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

fn collector_complete(snapshot: &HostSnapshot, component: &str) -> bool {
    let matches = snapshot
        .collectors
        .iter()
        .filter(|status| status.component == component)
        .collect::<Vec<_>>();
    matches.len() == 1 && matches[0].state == CollectorState::Complete
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty() && !value.as_bytes().contains(&0) && !value.chars().any(char::is_control)
}

fn validate_existing_gpt_records(table: &PartitionTable, first_lba: u64, last_lba: u64) -> bool {
    let Some(limit) = last_lba.checked_add(1) else {
        return false;
    };
    let mut partitions = table.partitions.iter().collect::<Vec<_>>();
    partitions.sort_by(|left, right| {
        left.start_sector
            .cmp(&right.start_sector)
            .then_with(|| left.node.cmp(&right.node))
    });

    let mut nodes = BTreeSet::new();
    let mut previous_end = first_lba;
    for record in partitions {
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

/// Freeze the first existing-disk provisioning profile:
/// verified GPT disk tail -> one future partition -> ext4/XFS filesystem.
///
/// This contract deliberately does not select a GPT partition slot and cannot
/// authorize a partition-table write or mkfs. A later runtime gate must reload
/// the exact GPT table, prove the table digest and free-tail geometry unchanged,
/// resolve one unused partition slot from fresh trusted tooling, and only then
/// construct a mutation launch.
pub fn freeze_gpt_tail_filesystem_create_intent(
    snapshot: &HostSnapshot,
    plan: &CreatePlanPreview,
) -> Result<FrozenGptTailFilesystemIntent, PlannerError> {
    let mut blockers = Vec::new();

    if plan.status() != PlanStatus::Preview || plan.executable() || !plan.blockers().is_empty() {
        blockers.extend(plan.blockers().iter().cloned());
        push_blocker(
            &mut blockers,
            "m2b1-preview-not-freezable",
            "only a successful non-executable Create preview can be frozen",
        );
    }

    let request = plan.request();
    if request.purpose != CreatePurpose::Filesystem {
        push_blocker(
            &mut blockers,
            "m2b1-purpose-unsupported",
            "M2B1 freezes only filesystem creation inside an existing GPT tail",
        );
    }
    let filesystem = request.filesystem.clone().unwrap_or_default();
    if !matches!(filesystem.as_str(), "ext4" | "xfs") {
        push_blocker(
            &mut blockers,
            "m2b1-filesystem-unsupported",
            "M2B1 accepts only ext4 or XFS filesystem intent",
        );
    }
    if request.mountpoint.is_some() {
        push_blocker(
            &mut blockers,
            "m2b1-mount-intent-deferred",
            "mount and persistent configuration remain a later activation gate",
        );
    }
    if request.partition_table.is_some() {
        push_blocker(
            &mut blockers,
            "m2b1-partition-policy-unexpected",
            "an existing GPT table must be preserved rather than recreated",
        );
    }

    if !collector_complete(snapshot, "lsblk") || !collector_complete(snapshot, "partition_tables") {
        push_blocker(
            &mut blockers,
            "m2b1-discovery-incomplete",
            "complete lsblk and authoritative partition-table discovery are required",
        );
    }

    let source = plan.source();
    if source.is_none_or(|source| source.kind != ProvisioningSpaceKind::DiskTail) {
        push_blocker(
            &mut blockers,
            "m2b1-source-not-gpt-tail",
            "M2B1 accepts only an exact verified existing-disk tail free range",
        );
    }

    let disk_path = source
        .and_then(|source| source.disk.clone())
        .unwrap_or_default();
    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let disk_matches = nodes
        .iter()
        .copied()
        .filter(|device| {
            matches!(device.kind, NodeKind::Disk | NodeKind::Loop)
                && device.path.as_deref() == Some(disk_path.as_str())
        })
        .collect::<Vec<_>>();
    let disk = if disk_matches.len() == 1 {
        Some(disk_matches[0])
    } else {
        push_blocker(
            &mut blockers,
            "m2b1-disk-identity-ambiguous",
            "selected GPT-tail disk is absent or ambiguous in fresh discovery",
        );
        None
    };

    if let Some(disk) = disk {
        if disk.size_bytes == 0
            || disk.logical_sector_bytes.is_none()
            || disk.filesystem.is_some()
            || !disk.mountpoints.is_empty()
            || disk.partition_table.as_deref() != Some("gpt")
            || snapshot.swaps.iter().any(|swap| swap.name == disk_path)
        {
            push_blocker(
                &mut blockers,
                "m2b1-disk-state-invalid",
                "selected device is not a plain GPT disk identity suitable for tail provisioning",
            );
        }
    }

    let table_matches = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == disk_path)
        .collect::<Vec<_>>();
    let table = if table_matches.len() == 1 {
        Some(table_matches[0])
    } else {
        push_blocker(
            &mut blockers,
            "m2b1-gpt-table-ambiguous",
            "exactly one authoritative partition table must match the selected disk",
        );
        None
    };

    let mut table_id = String::new();
    let mut first_lba = 0;
    let mut last_lba = 0;
    let mut table_sector = 0;
    let mut table_sha256 = String::new();
    let mut existing_partition_count = 0_u32;

    if let Some(table) = table {
        table_id = table.id.clone().unwrap_or_default();
        first_lba = table.first_lba.unwrap_or(0);
        last_lba = table.last_lba.unwrap_or(0);
        table_sector = table.sector_size_bytes.unwrap_or(0);
        table_sha256 = canonical_table_sha256(table)?;
        existing_partition_count = u32::try_from(table.partitions.len()).unwrap_or(u32::MAX);

        if table.label.as_deref() != Some("gpt")
            || table.unit.as_deref() != Some("sectors")
            || !safe_identifier(&table_id)
            || first_lba == 0
            || last_lba < first_lba
            || table_sector < 512
            || !table_sector.is_power_of_two()
            || existing_partition_count == u32::MAX
            || !validate_existing_gpt_records(table, first_lba, last_lba)
        {
            push_blocker(
                &mut blockers,
                "m2b1-gpt-table-invalid",
                "GPT label, disk identifier, sector geometry or existing partition records are incomplete or unsafe",
            );
        }
        if table
            .id
            .as_deref()
            .is_none_or(|value| !safe_identifier(value))
        {
            push_blocker(
                &mut blockers,
                "m2b1-gpt-id-missing",
                "a stable non-empty GPT disk identifier is required before freezing tail creation",
            );
        }
        if let Some(disk) = disk {
            if disk.logical_sector_bytes != Some(table_sector)
                || disk.size_bytes % table_sector.max(1) != 0
            {
                push_blocker(
                    &mut blockers,
                    "m2b1-sector-geometry-mismatch",
                    "GPT and block-device logical-sector geometry do not match exactly",
                );
            }
        }
    }

    let adapter =
        source.and_then(
            |source| match resolve_create_source_adapter(snapshot, source, None) {
                Ok(adapter) => Some(adapter),
                Err(blocker) => {
                    blockers.push(blocker);
                    None
                }
            },
        );

    let source_start_sector = adapter
        .as_ref()
        .and_then(|value| value.start_sector)
        .unwrap_or(0);
    let source_sector_count = adapter
        .as_ref()
        .and_then(|value| value.sector_count)
        .unwrap_or(0);
    let source_size_bytes = adapter
        .as_ref()
        .map(|value| value.available_bytes)
        .unwrap_or(0);

    if let Some(adapter) = adapter.as_ref() {
        if adapter.kind != ProvisioningSpaceKind::DiskTail
            || adapter.disk.as_deref() != Some(disk_path.as_str())
            || adapter.partition_table.is_some()
            || adapter.allocation_unit_bytes != table_sector
            || adapter.available_bytes == 0
        {
            push_blocker(
                &mut blockers,
                "m2b1-tail-adapter-mismatch",
                "fresh Create source adapter no longer matches the exact GPT tail",
            );
        }
    }

    let allocation = plan.allocation();
    let partition_start_sector = allocation.and_then(|value| value.start_sector).unwrap_or(0);
    let partition_sector_count = allocation.and_then(|value| value.sector_count).unwrap_or(0);
    let partition_size_bytes = partition_sector_count
        .checked_mul(table_sector)
        .unwrap_or(0);

    if allocation.is_none()
        || partition_start_sector != source_start_sector
        || partition_sector_count == 0
        || partition_sector_count > source_sector_count
        || partition_size_bytes == 0
        || allocation.is_some_and(|value| {
            value.rounded_bytes != partition_size_bytes
                || value.available_bytes != source_size_bytes
                || value.partition_table.is_some()
                || value.volume_group.is_some()
        })
    {
        push_blocker(
            &mut blockers,
            "m2b1-allocation-mismatch",
            "frozen partition allocation no longer matches exact GPT-tail sector geometry",
        );
    }

    if table_sector == 0
        || CREATE_PARTITION_ALIGNMENT_BYTES % table_sector != 0
        || partition_start_sector % (CREATE_PARTITION_ALIGNMENT_BYTES / table_sector.max(1)).max(1)
            != 0
    {
        push_blocker(
            &mut blockers,
            "m2b1-tail-start-unaligned",
            "the future partition start must already be aligned to the 1 MiB Create boundary",
        );
    }

    let source_end = source_start_sector.checked_add(source_sector_count);
    let partition_end = partition_start_sector.checked_add(partition_sector_count);
    if source_end.is_none()
        || partition_end.is_none()
        || partition_end > source_end
        || partition_end.is_some_and(|end| end > last_lba.saturating_add(1))
    {
        push_blocker(
            &mut blockers,
            "m2b1-tail-range-invalid",
            "future partition extent escapes the freshly verified GPT tail",
        );
    }

    let status = if blockers.is_empty() {
        PlanStatus::Preview
    } else {
        PlanStatus::Blocked
    };

    let logical_sector_bytes = disk
        .and_then(|device| device.logical_sector_bytes)
        .unwrap_or(0);
    let mut intent = FrozenGptTailFilesystemIntent {
        schema_version: 1,
        intent_id: String::new(),
        executable: false,
        status,
        create_plan_id: plan.plan_id().to_owned(),
        source_id: source.map(|value| value.id.clone()).unwrap_or_default(),
        disk: FrozenGptTailDiskIdentity {
            path: disk_path,
            size_bytes: disk.map(|device| device.size_bytes).unwrap_or(0),
            logical_sector_bytes,
            model: disk.and_then(|device| device.model.clone()),
            serial: disk.and_then(|device| device.serial.clone()),
        },
        gpt: FrozenGptTailTableIdentity {
            label: "gpt".into(),
            id: table_id,
            unit: "sectors".into(),
            first_lba,
            last_lba,
            sector_size_bytes: table_sector,
            table_sha256,
            existing_partition_count,
        },
        allocation: FrozenGptTailAllocation {
            source_start_sector,
            source_sector_count,
            source_size_bytes,
            partition_start_sector,
            partition_sector_count,
            partition_size_bytes,
        },
        filesystem,
        mountpoint: request.mountpoint.clone(),
        partition_slot_deferred: true,
        partition_table_write_authorized: false,
        filesystem_format_authorized: false,
        blockers,
        ordered_future_steps: vec![
            "rediscover and require the exact same disk identity, GPT disk identifier, canonical table digest and tail geometry"
                .into(),
            "capture and fsync a pre-mutation GPT partition-table backup and evidence record"
                .into(),
            "resolve exactly one unused GPT partition slot from fresh trusted runtime tooling; partition number is deliberately not frozen by M2B1"
                .into(),
            "prepare one partition addition at the frozen tail start/count while preserving every pre-existing GPT entry byte-for-byte in the intended table model"
                .into(),
            "rediscover authoritative GPT geometry and prove all previous entries unchanged plus exactly one new partition before formatting"
                .into(),
            "format only the newly proven partition with the frozen ext4/XFS profile".into(),
            "defer mount and persistent configuration to the existing guarded mount/persistence activation path"
                .into(),
        ],
    };
    intent.intent_id = intent.expected_intent_id()?;
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{list_provisioning_opportunities, plan_create, CreateRequest, Growth};
    use serde_json::json;

    const MIB: u64 = 1024 * 1024;

    fn snapshot() -> HostSnapshot {
        let disk_bytes = 512 * MIB;
        let sector = 512_u64;
        let disk_sectors = disk_bytes / sector;
        let first_start = 2048_u64;
        let first_size_sectors = 64 * MIB / sector;
        serde_json::from_value(json!({
            "storage":{"block_devices":[{
                "name":"loop7","kernel_name":"loop7","path":"/dev/loop7","kind":"loop",
                "size_bytes":disk_bytes,"start_512_sector":null,"logical_sector_bytes":sector,
                "filesystem":null,"mountpoints":[],"parent_kernel_name":null,
                "model":"loop-test","serial":"fixture-001","uuid":null,"partition_uuid":null,
                "partition_table":"gpt","children":[{
                    "name":"loop7p1","kernel_name":"loop7p1","path":"/dev/loop7p1","kind":"partition",
                    "size_bytes":64*MIB,"start_512_sector":first_start,
                    "logical_sector_bytes":sector,"filesystem":{"fs_type":"ext4","version":null},
                    "mountpoints":[],"parent_kernel_name":"loop7","model":null,"serial":null,
                    "uuid":"11111111-1111-1111-1111-111111111111",
                    "partition_uuid":"22222222-2222-2222-2222-222222222222",
                    "partition_table":null,"children":[]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/loop7","label":"gpt",
                "id":"12345678-1234-1234-1234-123456789abc","unit":"sectors",
                "first_lba":34,"last_lba":disk_sectors-34,"sector_size_bytes":sector,
                "partitions":[{
                    "node":"/dev/loop7p1","start_sector":first_start,
                    "size_sectors":first_size_sectors,
                    "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                    "uuid":"22222222-2222-2222-2222-222222222222",
                    "name":null,"attrs":null,"bootable":null
                }]
            }],
            "mounts":[],"fstab":[],"swaps":[],"lvm":null,
            "filesystem_preflight":[],"diagnostics":[],
            "collectors":[
                {"component":"lsblk","state":"complete","detail":null},
                {"component":"partition_tables","state":"complete","detail":null}
            ]
        }))
        .unwrap()
    }

    fn plan(snapshot: &HostSnapshot, kind: ProvisioningSpaceKind) -> CreatePlanPreview {
        let source = list_provisioning_opportunities(snapshot)
            .into_iter()
            .find(|source| source.kind == kind)
            .expect("expected Create source");
        plan_create(
            snapshot,
            CreateRequest {
                source_id: source.id,
                size: Growth::ByBytes(64 * MIB),
                purpose: CreatePurpose::Filesystem,
                filesystem: Some("ext4".into()),
                mountpoint: None,
                partition_table: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_gpt_tail_preview_freezes_deterministically_without_partition_slot() {
        let snapshot = snapshot();
        let plan = plan(&snapshot, ProvisioningSpaceKind::DiskTail);
        assert_eq!(plan.status(), PlanStatus::Preview);

        let first = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();
        let second = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();

        assert!(first.ready());
        assert_eq!(first.intent_id, second.intent_id);
        assert!(first.integrity_matches().unwrap());
        assert_eq!(first.disk.path, "/dev/loop7");
        assert_eq!(first.gpt.label, "gpt");
        assert_eq!(first.gpt.existing_partition_count, 1);
        assert_eq!(first.filesystem, "ext4");
        assert!(first.partition_slot_deferred);
        assert!(!first.partition_table_write_authorized);
        assert!(!first.filesystem_format_authorized);
        assert_eq!(first.allocation.partition_size_bytes, 64 * MIB);
    }

    #[test]
    fn frozen_gpt_tail_intent_tampering_is_detected() {
        let snapshot = snapshot();
        let plan = plan(&snapshot, ProvisioningSpaceKind::DiskTail);
        let mut intent = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();
        intent.allocation.partition_sector_count += 1;
        assert!(!intent.integrity_matches().unwrap());
    }

    #[test]
    fn internal_gpt_gap_is_not_admitted_by_first_tail_profile() {
        let mut snapshot = snapshot();
        let sector = 512_u64;
        let second_start = 256 * MIB / sector;
        let second_size = 64 * MIB;
        snapshot.storage.block_devices[0].children.push(
            serde_json::from_value(json!({
                "name":"loop7p2","kernel_name":"loop7p2","path":"/dev/loop7p2","kind":"partition",
                "size_bytes":second_size,"start_512_sector":second_start,
                "logical_sector_bytes":sector,"filesystem":{"fs_type":"ext4","version":null},
                "mountpoints":[],"parent_kernel_name":"loop7","model":null,"serial":null,
                "uuid":"33333333-3333-3333-3333-333333333333",
                "partition_uuid":"44444444-4444-4444-4444-444444444444",
                "partition_table":null,"children":[]
            }))
            .unwrap(),
        );
        snapshot.partition_tables[0].partitions.push(
            serde_json::from_value(json!({
                "node":"/dev/loop7p2","start_sector":second_start,
                "size_sectors":second_size/sector,
                "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "uuid":"44444444-4444-4444-4444-444444444444",
                "name":null,"attrs":null,"bootable":null
            }))
            .unwrap(),
        );

        let plan = plan(&snapshot, ProvisioningSpaceKind::DiskGap);
        let intent = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();

        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "m2b1-source-not-gpt-tail"));
    }

    #[test]
    fn missing_gpt_disk_identifier_fails_closed() {
        let mut snapshot = snapshot();
        snapshot.partition_tables[0].id = None;
        let plan = plan(&snapshot, ProvisioningSpaceKind::DiskTail);

        let intent = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();

        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "m2b1-gpt-id-missing"));
    }

    #[test]
    fn unaligned_tail_start_fails_closed() {
        let mut snapshot = snapshot();
        snapshot.storage.block_devices[0].children[0].size_bytes += 512;
        snapshot.partition_tables[0].partitions[0].size_sectors += 1;
        let plan = plan(&snapshot, ProvisioningSpaceKind::DiskTail);

        let intent = freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap();

        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "m2b1-tail-start-unaligned"));
    }
}
