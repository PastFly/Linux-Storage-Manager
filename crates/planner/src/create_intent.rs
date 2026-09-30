use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind};
use serde::Serialize;
use sha2::Digest;

use crate::{
    Blocker, CreatePartitionTablePolicy, CreatePlanPreview, CreatePurpose, PlanStatus,
    PlannerError, ProvisioningSpaceKind,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenBlankDiskFilesystemIntent {
    pub schema_version: u32,
    pub intent_id: String,
    pub executable: bool,
    pub status: PlanStatus,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub disk_model: Option<String>,
    pub disk_serial: Option<String>,
    pub partition_table: CreatePartitionTablePolicy,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub mountpoint: Option<String>,
    pub blockers: Vec<Blocker>,
    pub ordered_future_steps: Vec<String>,
}

impl FrozenBlankDiskFilesystemIntent {
    pub fn ready(&self) -> bool {
        self.status == PlanStatus::Preview && self.blockers.is_empty() && !self.executable
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
            disk_size_bytes: self.disk_size_bytes,
            logical_sector_bytes: self.logical_sector_bytes,
            disk_model: &self.disk_model,
            disk_serial: &self.disk_serial,
            partition_table: self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            mountpoint: &self.mountpoint,
            blockers: &self.blockers,
            ordered_future_steps: &self.ordered_future_steps,
        };
        Ok(format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Serialize)]
struct IntentDigestPayload<'a> {
    schema_version: u32,
    executable: bool,
    status: PlanStatus,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    disk_model: &'a Option<String>,
    disk_serial: &'a Option<String>,
    partition_table: CreatePartitionTablePolicy,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    mountpoint: &'a Option<String>,
    blockers: &'a [Blocker],
    ordered_future_steps: &'a [String],
}

fn flatten<'a>(devices: &'a [BlockDevice], out: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        out.push(device);
        flatten(&device.children, out);
    }
}

fn push_blocker(blockers: &mut Vec<Blocker>, code: &str, message: &str) {
    blockers.push(Blocker {
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

/// Freeze the first M2 provisioning profile:
/// verified blank disk -> one partition -> ext4/XFS filesystem.
///
/// The result is deterministic and explicitly non-executable. It intentionally
/// does not yet authorize partition-table writes, mkfs, mounting or fstab edits.
pub fn freeze_blank_disk_filesystem_create_intent(
    snapshot: &HostSnapshot,
    plan: &CreatePlanPreview,
) -> Result<FrozenBlankDiskFilesystemIntent, PlannerError> {
    let mut blockers = Vec::new();

    if plan.status() != PlanStatus::Preview || plan.executable() || !plan.blockers().is_empty() {
        blockers.extend(plan.blockers().iter().cloned());
        push_blocker(
            &mut blockers,
            "create-preview-not-freezable",
            "only a successful non-executable create preview can be frozen",
        );
    }

    let request = plan.request();
    if request.purpose != CreatePurpose::Filesystem {
        push_blocker(
            &mut blockers,
            "m2a1-purpose-unsupported",
            "M2A1 freezes only filesystem provisioning; swap remains on its separate migration/create path",
        );
    }
    let filesystem = request.filesystem.clone().unwrap_or_default();
    if !matches!(filesystem.as_str(), "ext4" | "xfs") {
        push_blocker(
            &mut blockers,
            "m2a1-filesystem-unsupported",
            "M2A1 accepts only ext4 or XFS filesystem intent",
        );
    }
    if request.mountpoint.is_some() {
        push_blocker(
            &mut blockers,
            "m2a1-mount-intent-deferred",
            "M2A1 freezes storage creation only; mount/fstab activation is a later M2 gate",
        );
    }

    let source = plan.source();
    if source.is_none_or(|source| source.kind != ProvisioningSpaceKind::BlankDisk) {
        push_blocker(
            &mut blockers,
            "m2a1-source-not-blank-disk",
            "M2A1 supports only an exact verified blank-disk source",
        );
    }

    let allocation = plan.allocation();
    let partition_table = allocation.and_then(|allocation| allocation.partition_table);
    let start_sector = allocation.and_then(|allocation| allocation.start_sector);
    let sector_count = allocation.and_then(|allocation| allocation.sector_count);
    if partition_table.is_none() || start_sector.is_none() || sector_count.is_none() {
        push_blocker(
            &mut blockers,
            "m2a1-allocation-incomplete",
            "blank-disk partition policy and exact sector allocation must be frozen",
        );
    }

    let collector_matches = snapshot
        .collectors
        .iter()
        .filter(|collector| collector.component == "partition_tables")
        .collect::<Vec<_>>();
    if collector_matches.len() != 1 || collector_matches[0].state != CollectorState::Complete {
        push_blocker(
            &mut blockers,
            "partition-table-discovery-incomplete",
            "authoritative partition-table discovery must be complete before freezing provisioning",
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
        .filter(|device| device.path.as_deref() == Some(disk_path.as_str()))
        .collect::<Vec<_>>();
    let disk = if disk_matches.len() == 1 {
        Some(disk_matches[0])
    } else {
        push_blocker(
            &mut blockers,
            "blank-disk-identity-ambiguous",
            "selected blank disk is absent or ambiguous in the fresh snapshot",
        );
        None
    };

    if let Some(disk) = disk {
        if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
            || !disk.children.is_empty()
            || disk.filesystem.is_some()
            || disk.partition_table.is_some()
            || !disk.mountpoints.is_empty()
            || snapshot
                .partition_tables
                .iter()
                .any(|table| table.device == disk_path)
            || snapshot.swaps.iter().any(|swap| swap.name == disk_path)
        {
            push_blocker(
                &mut blockers,
                "blank-disk-state-changed",
                "selected source is no longer a plain unpartitioned, unmounted, non-swap disk",
            );
        }
    }

    let logical_sector_bytes = disk.and_then(|disk| disk.logical_sector_bytes).unwrap_or(0);
    let disk_size_bytes = disk.map(|disk| disk.size_bytes).unwrap_or(0);
    if logical_sector_bytes == 0
        || start_sector.is_some_and(|start| start == 0)
        || sector_count.is_some_and(|count| count == 0)
    {
        push_blocker(
            &mut blockers,
            "blank-disk-geometry-invalid",
            "fresh blank-disk sector geometry is incomplete",
        );
    }

    let partition_size_bytes = match (sector_count, logical_sector_bytes) {
        (Some(count), sector) if sector > 0 => count.checked_mul(sector).unwrap_or(0),
        _ => 0,
    };
    if partition_size_bytes == 0
        || allocation.is_some_and(|allocation| allocation.rounded_bytes != partition_size_bytes)
    {
        push_blocker(
            &mut blockers,
            "blank-disk-allocation-mismatch",
            "frozen allocation bytes no longer match exact sector geometry",
        );
    }

    let status = if blockers.is_empty() {
        PlanStatus::Preview
    } else {
        PlanStatus::Blocked
    };

    let mut intent = FrozenBlankDiskFilesystemIntent {
        schema_version: 1,
        intent_id: String::new(),
        executable: false,
        status,
        create_plan_id: plan.plan_id().to_owned(),
        source_id: source.map(|source| source.id.clone()).unwrap_or_default(),
        disk: disk_path,
        disk_size_bytes,
        logical_sector_bytes,
        disk_model: disk.and_then(|disk| disk.model.clone()),
        disk_serial: disk.and_then(|disk| disk.serial.clone()),
        partition_table: partition_table.unwrap_or(CreatePartitionTablePolicy::Gpt),
        partition_start_sector: start_sector.unwrap_or(0),
        partition_sector_count: sector_count.unwrap_or(0),
        partition_size_bytes,
        filesystem,
        mountpoint: request.mountpoint.clone(),
        blockers,
        ordered_future_steps: vec![
            "rediscover and require the exact same blank-disk identity and geometry".to_owned(),
            "capture and fsync a pre-mutation blank-disk/partition-table evidence record".to_owned(),
            "create the selected GPT or DOS partition table using fixed non-shell argv".to_owned(),
            "create exactly one partition at the frozen start/count without consuming any other range"
                .to_owned(),
            "rediscover authoritative partition geometry before filesystem formatting".to_owned(),
            "format only the newly proven partition with the frozen ext4/XFS profile".to_owned(),
            "rediscover and verify filesystem identity and capacity before any mount/persistence step"
                .to_owned(),
        ],
    };

    intent.intent_id = intent.expected_intent_id()?;

    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan_create, CreateRequest, Growth};
    use serde_json::json;

    fn snapshot() -> HostSnapshot {
        serde_json::from_value(json!({
            "storage": {"block_devices":[{
                "name":"loop7","kernel_name":"loop7","path":"/dev/loop7","kind":"loop",
                "size_bytes":536870912u64,"start_512_sector":null,"logical_sector_bytes":512,
                "filesystem":null,"mountpoints":[],"parent_kernel_name":null,
                "model":"loop-test","serial":"fixture-001","uuid":null,"partition_uuid":null,
                "partition_table":null,"children":[]
            }]},
            "partition_tables":[],
            "mounts":[],
            "fstab":[],
            "swaps":[],
            "lvm":null,
            "filesystem_preflight":[],
            "diagnostics":[],
            "collectors":[{"component":"partition_tables","state":"complete","detail":null}]
        }))
        .unwrap()
    }

    fn plan(snapshot: &HostSnapshot) -> CreatePlanPreview {
        let source = crate::list_provisioning_opportunities(snapshot)
            .into_iter()
            .find(|source| source.kind == ProvisioningSpaceKind::BlankDisk)
            .unwrap();
        plan_create(
            snapshot,
            CreateRequest {
                source_id: source.id,
                size: Growth::ByBytes(128 * 1024 * 1024),
                purpose: CreatePurpose::Filesystem,
                filesystem: Some("ext4".into()),
                mountpoint: None,
                partition_table: Some(CreatePartitionTablePolicy::Gpt),
            },
        )
        .unwrap()
    }

    #[test]
    fn exact_blank_disk_preview_freezes_deterministically() {
        let snapshot = snapshot();
        let plan = plan(&snapshot);
        let first = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap();
        let second = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap();

        assert!(first.ready());
        assert!(!first.executable);
        assert_eq!(first.intent_id, second.intent_id);
        assert!(first.integrity_matches().unwrap());
        assert_eq!(first.disk, "/dev/loop7");
        assert_eq!(first.filesystem, "ext4");
        assert_eq!(first.partition_size_bytes, 128 * 1024 * 1024);
    }

    #[test]
    fn frozen_intent_tampering_is_detected() {
        let snapshot = snapshot();
        let plan = plan(&snapshot);
        let mut intent = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap();
        intent.partition_sector_count += 1;
        assert!(!intent.integrity_matches().unwrap());
    }

    #[test]
    fn mount_intent_is_deferred_from_first_m2_profile() {
        let snapshot = snapshot();
        let source = crate::list_provisioning_opportunities(&snapshot)
            .into_iter()
            .find(|source| source.kind == ProvisioningSpaceKind::BlankDisk)
            .unwrap();
        let plan = plan_create(
            &snapshot,
            CreateRequest {
                source_id: source.id,
                size: Growth::ByBytes(64 * 1024 * 1024),
                purpose: CreatePurpose::Filesystem,
                filesystem: Some("xfs".into()),
                mountpoint: Some("/srv/new".into()),
                partition_table: Some(CreatePartitionTablePolicy::Gpt),
            },
        )
        .unwrap();
        let intent = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap();
        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "m2a1-mount-intent-deferred"));
    }

    #[test]
    fn changed_blank_disk_state_blocks_frozen_intent() {
        let mut snapshot = snapshot();
        let plan = plan(&snapshot);
        snapshot.storage.block_devices[0].partition_table = Some("gpt".into());
        let intent = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap();
        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "blank-disk-state-changed"));
    }
}
