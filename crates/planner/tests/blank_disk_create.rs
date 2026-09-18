use lsm_core::HostSnapshot;
use lsm_planner::{
    list_provisioning_opportunities, plan_create, CreatePartitionTablePolicy, CreatePurpose,
    CreateRequest, Growth, PlanStatus, ProvisioningSpaceKind,
};
use serde_json::json;

const GIB: u64 = 1 << 30;
const TIB: u64 = 1 << 40;

fn blank_snapshot(size_bytes: u64, sector_size: u64) -> HostSnapshot {
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"vdb",
            "kernel_name":"vdb",
            "path":"/dev/vdb",
            "kind":"disk",
            "size_bytes":size_bytes,
            "logical_sector_bytes":sector_size,
            "filesystem":null,
            "mountpoints":[],
            "children":[]
        }]},
        "partition_tables":[],
        "mounts":[],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[
            {"component":"partition_tables","state":"complete","detail":null}
        ]
    }))
    .unwrap()
}

fn blank_source(snapshot: &HostSnapshot) -> String {
    list_provisioning_opportunities(snapshot)
        .into_iter()
        .find(|source| source.kind == ProvisioningSpaceKind::BlankDisk)
        .expect("blank disk must be exposed as a Create source")
        .id
}

fn request(
    source_id: String,
    size: Growth,
    policy: Option<CreatePartitionTablePolicy>,
) -> CreateRequest {
    CreateRequest {
        source_id,
        size,
        purpose: CreatePurpose::Filesystem,
        filesystem: Some("ext4".into()),
        mountpoint: Some("/data".into()),
        partition_table: policy,
    }
}

#[test]
fn blank_gpt_512_max_reserves_metadata_and_one_mib_alignment() {
    let snapshot = blank_snapshot(10 * GIB, 512);
    let source_id = blank_source(&snapshot);

    let plan = plan_create(
        &snapshot,
        request(
            source_id,
            Growth::MaxFree,
            Some(CreatePartitionTablePolicy::Gpt),
        ),
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let allocation = plan.allocation().expect("blank-disk allocation must be frozen");

    let disk_sectors = (10 * GIB) / 512;
    let gpt_entry_sectors = (128_u64 * 128).div_ceil(512);
    let expected_start = 2048_u64;
    let expected_end_exclusive = disk_sectors - (gpt_entry_sectors + 1);
    let expected_sector_count = expected_end_exclusive - expected_start;
    let expected_bytes = expected_sector_count * 512;

    assert_eq!(allocation.partition_table, Some(CreatePartitionTablePolicy::Gpt));
    assert_eq!(allocation.allocation_unit_bytes, 512);
    assert_eq!(allocation.start_sector, Some(expected_start));
    assert_eq!(allocation.sector_count, Some(expected_sector_count));
    assert_eq!(allocation.available_bytes, expected_bytes);
    assert_eq!(allocation.rounded_bytes, expected_bytes);
    assert_eq!(allocation.remaining_bytes, 0);
    assert!(plan.steps().iter().any(|step| step.contains("GPT partition table")));
    assert!(plan
        .steps()
        .iter()
        .any(|step| step.contains("sector 2048")));
    assert!(plan.steps().iter().any(|step| step.contains("ext4")));
}

#[test]
fn blank_gpt_4kn_uses_sector_aware_metadata_and_alignment() {
    let snapshot = blank_snapshot(10 * GIB, 4096);
    let source_id = blank_source(&snapshot);

    let plan = plan_create(
        &snapshot,
        request(
            source_id,
            Growth::MaxFree,
            Some(CreatePartitionTablePolicy::Gpt),
        ),
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let allocation = plan.allocation().unwrap();

    let disk_sectors = (10 * GIB) / 4096;
    let gpt_entry_sectors = (128_u64 * 128).div_ceil(4096);
    let expected_start = 256_u64;
    let expected_end_exclusive = disk_sectors - (gpt_entry_sectors + 1);
    let expected_sector_count = expected_end_exclusive - expected_start;

    assert_eq!(gpt_entry_sectors, 4);
    assert_eq!(allocation.allocation_unit_bytes, 4096);
    assert_eq!(allocation.start_sector, Some(expected_start));
    assert_eq!(allocation.sector_count, Some(expected_sector_count));
    assert_eq!(allocation.rounded_bytes, expected_sector_count * 4096);
}

#[test]
fn blank_dos_caps_usable_range_at_mbr_lba_limit() {
    let snapshot = blank_snapshot(3 * TIB, 512);
    let source_id = blank_source(&snapshot);

    let plan = plan_create(
        &snapshot,
        request(
            source_id,
            Growth::MaxFree,
            Some(CreatePartitionTablePolicy::Dos),
        ),
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let allocation = plan.allocation().unwrap();

    let expected_start = 2048_u64;
    let expected_end_exclusive = u64::from(u32::MAX) + 1;
    let expected_sector_count = expected_end_exclusive - expected_start;

    assert_eq!(allocation.partition_table, Some(CreatePartitionTablePolicy::Dos));
    assert_eq!(allocation.start_sector, Some(expected_start));
    assert_eq!(allocation.sector_count, Some(expected_sector_count));
    assert_eq!(allocation.available_bytes, expected_sector_count * 512);
    assert!(allocation.available_bytes < 3 * TIB);
    assert!(plan.steps().iter().any(|step| step.contains("DOS/MBR")));
}

#[test]
fn blank_disk_without_explicit_table_policy_stays_blocked() {
    let snapshot = blank_snapshot(10 * GIB, 512);
    let source_id = blank_source(&snapshot);

    let plan = plan_create(&snapshot, request(source_id, Growth::MaxFree, None)).unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "blank-disk-policy-required"));
}

#[test]
fn tiny_blank_disk_fails_closed_after_metadata_and_alignment_reservation() {
    let snapshot = blank_snapshot(512 * 1024, 512);
    let source_id = blank_source(&snapshot);

    let plan = plan_create(
        &snapshot,
        request(
            source_id,
            Growth::MaxFree,
            Some(CreatePartitionTablePolicy::Gpt),
        ),
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "blank-disk-too-small"));
}

#[test]
fn partition_table_policy_is_rejected_for_nonblank_create_sources() {
    let snapshot: HostSnapshot = serde_json::from_value(json!({
        "storage":{"block_devices":[]},
        "partition_tables":[],
        "mounts":[],
        "fstab":[],
        "swaps":[],
        "lvm":{
            "physical_volumes":[],
            "volume_groups":[{
                "name":"vg0",
                "uuid":"vg-1",
                "size_bytes":8*GIB,
                "free_bytes":4*GIB,
                "pv_count":1,
                "lv_count":0,
                "extent_size_bytes":4194304u64,
                "free_extent_count":1024,
                "missing_pv_count":0,
                "attributes":"wz--n-"
            }],
            "logical_volumes":[]
        },
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap();
    let source = list_provisioning_opportunities(&snapshot)
        .into_iter()
        .find(|source| source.kind == ProvisioningSpaceKind::LvmFreeExtents)
        .unwrap();

    let plan = plan_create(
        &snapshot,
        request(
            source.id,
            Growth::ByBytes(GIB),
            Some(CreatePartitionTablePolicy::Gpt),
        ),
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "create-partition-table-unexpected"));
}
