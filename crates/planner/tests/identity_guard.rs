use lsm_core::HostSnapshot;
use lsm_planner::{capture_target_identity, revalidate_target_identity};
use serde_json::json;

const GIB: u64 = 1 << 30;

fn direct_snapshot() -> HostSnapshot {
    let sector = 512_u64;
    let partition_bytes = 10 * GIB;
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20*GIB,"logical_sector_bytes":sector,
            "model":"Virtual Disk","serial":"DISK-A","mountpoints":[],"children":[{
                "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                "size_bytes":partition_bytes,"start_512_sector":2048,
                "logical_sector_bytes":sector,"uuid":"fs-data","partition_uuid":"part-data",
                "partition_table":"gpt","filesystem":{"fs_type":"ext4","version":"1.0"},
                "mountpoints":["/data"],"parent_kernel_name":"sda","children":[]
            }]
        }]},
        "partition_tables":[{
            "device":"/dev/sda","label":"gpt","id":"gpt-a","unit":"sectors",
            "first_lba":34,"last_lba":(20*GIB/sector)-34,
            "sector_size_bytes":sector,
            "partitions":[{
                "node":"/dev/sda1","start_sector":2048,
                "size_sectors":partition_bytes/sector,
                "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "uuid":"part-data","name":null,"attrs":null,"bootable":null
            }]
        }],
        "mounts":[
            {"source":"/dev/sda1","target":"/data","fs_type":"ext4","options":["rw","relatime"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

fn lvm_snapshot() -> HostSnapshot {
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"vda","kernel_name":"vda","path":"/dev/vda","kind":"disk",
            "size_bytes":20*GIB,"logical_sector_bytes":512,
            "model":"Virtual Disk","serial":"LVM-DISK","mountpoints":[],"children":[{
                "name":"vda1","kernel_name":"vda1","path":"/dev/vda1","kind":"partition",
                "size_bytes":18*GIB,"start_512_sector":2048,"logical_sector_bytes":512,
                "uuid":"pv-1","partition_uuid":"pv-part","partition_table":"gpt",
                "filesystem":{"fs_type":"LVM2_member","version":"LVM2 001"},
                "mountpoints":[],"parent_kernel_name":"vda","children":[{
                    "name":"vg0-root","kernel_name":"dm-0","path":"/dev/mapper/vg0-root",
                    "kind":"lvm","size_bytes":10*GIB,"uuid":"fs-root",
                    "filesystem":{"fs_type":"xfs","version":"5"},
                    "mountpoints":["/"],"parent_kernel_name":"vda1","children":[]
                }]
            }]
        }]},
        "partition_tables":[{
            "device":"/dev/vda","label":"gpt","id":"gpt-lvm","unit":"sectors",
            "first_lba":34,"last_lba":(20*GIB/512)-34,"sector_size_bytes":512,
            "partitions":[{
                "node":"/dev/vda1","start_sector":2048,"size_sectors":18*GIB/512,
                "partition_type":"E6D6D379-F507-44C2-A23C-238F2A3DF928",
                "uuid":"pv-part","name":null,"attrs":null,"bootable":null
            }]
        }],
        "mounts":[
            {"source":"/dev/vg0/root","target":"/","fs_type":"xfs","options":["rw","relatime"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":{
            "physical_volumes":[{
                "name":"/dev/vda1","uuid":"pv-1","vg_name":"vg0",
                "size_bytes":18*GIB,"free_bytes":8*GIB
            }],
            "volume_groups":[{
                "name":"vg0","uuid":"vg-1","size_bytes":18*GIB,"free_bytes":8*GIB,
                "pv_count":1,"lv_count":1,"extent_size_bytes":4_194_304,
                "free_extent_count":2048,"missing_pv_count":0,"attributes":"wz--n-"
            }],
            "logical_volumes":[{
                "name":"root","path":"/dev/vg0/root","uuid":"lv-root","vg_name":"vg0",
                "size_bytes":10*GIB,"attributes":"-wi-ao----","layout":"linear","role":"public"
            }]
        },
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

#[test]
fn unchanged_target_revalidates_exactly() {
    let snapshot = direct_snapshot();
    let manifest = capture_target_identity(&snapshot, "/data").unwrap();

    let result = revalidate_target_identity(&manifest, &snapshot);

    assert!(result.matches);
    assert!(result.changes.is_empty());
    assert_eq!(
        result.fresh_digest.as_deref(),
        Some(manifest.manifest_digest.as_str())
    );
}

#[test]
fn unrelated_disk_change_does_not_invalidate_selected_target() {
    let snapshot = direct_snapshot();
    let manifest = capture_target_identity(&snapshot, "/data").unwrap();
    let mut fresh = snapshot.clone();
    let unrelated = serde_json::from_value(json!({
        "name":"sdb","kernel_name":"sdb","path":"/dev/sdb","kind":"disk",
        "size_bytes":500*GIB,"logical_sector_bytes":512,
        "model":"Other Disk","serial":"DISK-B","mountpoints":[],"children":[]
    }))
    .unwrap();
    fresh.storage.block_devices.push(unrelated);

    let result = revalidate_target_identity(&manifest, &fresh);

    assert!(result.matches);
    assert!(result.changes.is_empty());
}

#[test]
fn partition_geometry_change_invalidates_target_manifest() {
    let snapshot = direct_snapshot();
    let manifest = capture_target_identity(&snapshot, "/data").unwrap();
    let mut fresh = snapshot.clone();
    fresh.partition_tables[0].partitions[0].size_sectors += 2048;

    let result = revalidate_target_identity(&manifest, &fresh);

    assert!(!result.matches);
    assert!(result
        .changes
        .iter()
        .any(|change| change.code == "partition-geometry-changed"));
}

#[test]
fn target_disk_identity_change_invalidates_target_manifest() {
    let snapshot = direct_snapshot();
    let manifest = capture_target_identity(&snapshot, "/data").unwrap();
    let mut fresh = snapshot.clone();
    fresh.storage.block_devices[0].serial = Some("REPLACED-DISK".into());

    let result = revalidate_target_identity(&manifest, &fresh);

    assert!(!result.matches);
    assert!(result
        .changes
        .iter()
        .any(|change| change.code == "device-chain-changed"));
}

#[test]
fn lvm_uuid_or_capacity_change_invalidates_target_manifest() {
    let snapshot = lvm_snapshot();
    let manifest = capture_target_identity(&snapshot, "/").unwrap();

    let mut changed_uuid = snapshot.clone();
    changed_uuid.lvm.as_mut().unwrap().volume_groups[0].uuid = Some("vg-replaced".into());
    let uuid_result = revalidate_target_identity(&manifest, &changed_uuid);
    assert!(!uuid_result.matches);
    assert!(uuid_result
        .changes
        .iter()
        .any(|change| change.code == "lvm-identity-changed"));

    let mut changed_capacity = snapshot.clone();
    changed_capacity.lvm.as_mut().unwrap().volume_groups[0].free_bytes -= 4 * 1024 * 1024;
    let capacity_result = revalidate_target_identity(&manifest, &changed_capacity);
    assert!(!capacity_result.matches);
    assert!(capacity_result
        .changes
        .iter()
        .any(|change| change.code == "lvm-identity-changed"));
}

#[test]
fn disappearing_target_fails_revalidation_closed() {
    let snapshot = direct_snapshot();
    let manifest = capture_target_identity(&snapshot, "/data").unwrap();
    let mut fresh = snapshot.clone();
    fresh.mounts.clear();
    fresh.storage.block_devices[0].children.clear();

    let result = revalidate_target_identity(&manifest, &fresh);

    assert!(!result.matches);
    assert_eq!(result.fresh_digest, None);
    assert!(result
        .changes
        .iter()
        .any(|change| change.code == "fresh-target-unresolved"));
}
