use lsm_core::{
    CollectorState, CollectorStatus, DiagnosticSeverity, ExtendabilityStatus, HostSnapshot,
    MountEntry, StorageDiagnostic,
};
use lsm_discovery::{analyze_extendability, parse_lsblk_json, parse_sfdisk_json};
use serde_json::json;

fn fixture(sector: u64) -> HostSnapshot {
    let sectors = 67_108_864 / sector;
    let reserved = if sector == 512 { 34 } else { 6 };
    let lsblk = json!({"blockdevices":[{
        "name":"vdb", "kname":"vdb", "path":"/dev/vdb", "type":"disk",
        "size":67_108_864, "log-sec":sector, "pttype":"gpt", "children":[{
            "name":"vdb1", "kname":"vdb1", "path":"/dev/vdb1", "type":"part",
            "size":16_777_216, "start":2048, "log-sec":sector, "pkname":"vdb",
            "fstype":"ext4", "partuuid":"partition-one", "mountpoints":["/data"]
        }]
    }]});
    let table = json!({"partitiontable":{
        "device":"/dev/vdb", "label":"gpt", "unit":"sectors",
        "sectorsize":sector, "firstlba":reserved, "lastlba":sectors-reserved,
        "partitions":[{"node":"/dev/vdb1", "start":1_048_576/sector,
            "size":16_777_216/sector, "uuid":"PARTITION-ONE", "type":"linux"}]
    }});
    HostSnapshot {
        storage: parse_lsblk_json(&lsblk.to_string()).unwrap(),
        partition_tables: vec![parse_sfdisk_json(&table.to_string()).unwrap()],
        mounts: vec![MountEntry {
            source: Some("/dev/vdb1".into()),
            target: "/data".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: ["lsblk", "partition_tables", "mounts"]
            .into_iter()
            .map(|component| CollectorStatus {
                component: component.to_owned(),
                state: CollectorState::Complete,
                detail: None,
            })
            .collect(),
    }
}

fn capacity(snapshot: &HostSnapshot) -> Option<u64> {
    analyze_extendability(snapshot, "/data")
        .unwrap()
        .potential_underlying_growth_bytes
}

fn unknown(snapshot: &HostSnapshot) {
    let report = analyze_extendability(snapshot, "/data").unwrap();
    assert_eq!(report.status, ExtendabilityStatus::NeedsGeometry);
    assert_eq!(report.potential_underlying_growth_bytes, None);
}

// Independent table and kernel representations, with explicit unit conversion.
fn sibling(snapshot: &mut HostSnapshot, start_bytes: u64, size_bytes: u64) {
    let sector = snapshot.partition_tables[0].sector_size_bytes.unwrap();
    let mut node = snapshot.storage.block_devices[0].children[0].clone();
    node.name = "vdb2".into();
    node.kernel_name = Some("vdb2".into());
    node.path = Some("/dev/vdb2".into());
    node.partition_uuid = Some("partition-two".into());
    node.start_512_sector = Some(start_bytes / 512);
    node.size_bytes = size_bytes;
    node.mountpoints.clear();
    let mut record = snapshot.partition_tables[0].partitions[0].clone();
    record.node = "/dev/vdb2".into();
    record.uuid = Some("partition-two".into());
    record.start_sector = start_bytes / sector;
    record.size_sectors = size_bytes / sector;
    snapshot.storage.block_devices[0].children.push(node);
    snapshot.partition_tables[0].partitions.push(record);
}

#[test]
fn uses_inclusive_gpt_last_usable_lba() {
    assert_eq!(capacity(&fixture(512)), Some(49_266_176));
}

#[test]
fn four_k_sectors_keep_lsblk_start_in_512_byte_units() {
    assert_eq!(capacity(&fixture(4096)), Some(49_262_592));
}

#[test]
fn custom_gpt_boundary_is_not_replaced_with_a_tail_constant() {
    let mut snapshot = fixture(4096);
    snapshot.partition_tables[0].last_lba = Some(15_000);
    assert_eq!(capacity(&snapshot), Some(43_618_304));
}

#[test]
fn increased_disk_does_not_expand_the_reported_gpt_bounds() {
    let mut snapshot = fixture(512);
    snapshot.storage.block_devices[0].size_bytes *= 2;
    assert_eq!(capacity(&snapshot), Some(49_266_176));
}

#[test]
fn stops_before_the_next_partition() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 33_554_432, 8_388_608);
    assert_eq!(capacity(&snapshot), Some(15_728_640));
}

#[test]
fn adjacent_partition_reports_zero_not_unknown() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 17_825_792, 8_388_608);
    assert_eq!(capacity(&snapshot), Some(0));
}

#[test]
fn missing_sibling_start_is_not_free_space() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 33_554_432, 8_388_608);
    snapshot.storage.block_devices[0].children[1].start_512_sector = None;
    unknown(&snapshot);
}

#[test]
fn rejects_overlap_starting_before_target() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 524_288, 1_048_576);
    unknown(&snapshot);
}

#[test]
fn rejects_overlap_starting_inside_target() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 8_388_608, 16_777_216);
    unknown(&snapshot);
}

#[test]
fn rejects_partition_missing_from_kernel_tree() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 33_554_432, 8_388_608);
    snapshot.storage.block_devices[0].children.pop();
    unknown(&snapshot);
}

#[test]
fn rejects_partition_missing_from_table() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 33_554_432, 8_388_608);
    snapshot.partition_tables[0].partitions.pop();
    unknown(&snapshot);
}

#[test]
fn requires_unique_complete_collectors() {
    for state in [CollectorState::Failed, CollectorState::Unavailable] {
        let mut snapshot = fixture(512);
        snapshot.collectors[1].state = state;
        unknown(&snapshot);
    }
    let mut snapshot = fixture(512);
    snapshot
        .collectors
        .retain(|c| c.component != "partition_tables");
    unknown(&snapshot);
    let mut snapshot = fixture(512);
    snapshot.collectors.push(snapshot.collectors[1].clone());
    unknown(&snapshot);
}

#[test]
fn requires_one_partition_table_and_one_parent() {
    let mut snapshot = fixture(512);
    snapshot.partition_tables.clear();
    unknown(&snapshot);
    let mut snapshot = fixture(512);
    snapshot
        .partition_tables
        .push(snapshot.partition_tables[0].clone());
    unknown(&snapshot);
    let mut snapshot = fixture(512);
    snapshot
        .storage
        .block_devices
        .push(snapshot.storage.block_devices[0].clone());
    // Duplicate parents now fail at target resolution, before geometry is assessed.
    let report = analyze_extendability(&snapshot, "/data").unwrap();
    assert_eq!(report.status, ExtendabilityStatus::Unknown);
    assert!(report.device.is_none());
    assert!(report.potential_underlying_growth_bytes.is_none());
    assert!(report.steps.is_empty());
}

#[test]
fn rejects_inconsistent_units_and_ranges() {
    let mutations: [fn(&mut HostSnapshot); 8] = [
        |s| s.partition_tables[0].unit = Some("bytes".into()),
        |s| s.partition_tables[0].sector_size_bytes = Some(4096),
        |s| s.partition_tables[0].last_lba = None,
        |s| s.partition_tables[0].last_lba = Some(u64::MAX),
        |s| s.partition_tables[0].partitions[0].start_sector = u64::MAX,
        |s| s.partition_tables[0].partitions[0].size_sectors = 0,
        |s| s.partition_tables[0].partitions[0].uuid = Some("wrong".into()),
        |s| s.storage.block_devices[0].children[0].size_bytes += 512,
    ];
    for mutation in mutations {
        let mut snapshot = fixture(512);
        mutation(&mut snapshot);
        unknown(&snapshot);
    }
}

#[test]
fn rejects_duplicate_partition_identity() {
    let mut snapshot = fixture(512);
    sibling(&mut snapshot, 33_554_432, 8_388_608);
    snapshot.partition_tables[0].partitions[1].uuid = Some("PARTITION-ONE".into());
    snapshot.storage.block_devices[0].children[1].partition_uuid = Some("partition-one".into());
    unknown(&snapshot);
}

#[test]
fn preexisting_error_blocks_advisory_capacity() {
    let mut snapshot = fixture(512);
    snapshot.diagnostics.push(StorageDiagnostic {
        code: "geometry-conflict".into(),
        severity: DiagnosticSeverity::Error,
        message: "test conflict".into(),
        device: Some("/dev/vdb".into()),
    });
    let report = analyze_extendability(&snapshot, "/data").unwrap();
    assert_eq!(report.status, ExtendabilityStatus::Unknown);
    assert_eq!(report.potential_underlying_growth_bytes, None);
    assert!(report.steps.is_empty());
}

#[test]
fn supports_simple_primary_mbr_but_not_extended_or_protective() {
    let mut snapshot = fixture(512);
    snapshot.storage.block_devices[0].partition_table = Some("dos".into());
    snapshot.partition_tables[0].label = Some("dos".into());
    snapshot.partition_tables[0].partitions[0].partition_type = Some("83".into());
    assert_eq!(capacity(&snapshot), Some(49_283_072));
    for kind in ["5", "0f", "85", "ee"] {
        snapshot.partition_tables[0].partitions[0].partition_type = Some(kind.into());
        unknown(&snapshot);
    }
}
