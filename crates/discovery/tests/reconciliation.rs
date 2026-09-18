use lsm_core::{FstabEntry, HostSnapshot, LvmInventory, LvmPhysicalVolume, MountEntry, SwapEntry};
use lsm_discovery::{parse_lsblk_json, reconcile_snapshot};

#[test]
fn reports_missing_sources_across_collectors() {
    let storage = parse_lsblk_json(include_str!("../../../tests/fixtures/lsblk-lvm-ext4.json"))
        .expect("lsblk fixture should parse");

    let snapshot = HostSnapshot {
        storage,
        partition_tables: Vec::new(),
        mounts: vec![MountEntry {
            source: Some("/dev/missing-mount".to_owned()),
            target: "/mnt/missing".to_owned(),
            fs_type: Some("ext4".to_owned()),
            options: vec!["rw".to_owned()],
        }],
        fstab: vec![FstabEntry {
            source: "UUID=missing-uuid".to_owned(),
            target: "/srv".to_owned(),
            fs_type: "ext4".to_owned(),
            options: vec!["defaults".to_owned()],
            dump: 0,
            pass: 2,
        }],
        swaps: vec![SwapEntry {
            name: "/dev/missing-swap".to_owned(),
            kind: "partition".to_owned(),
            size_bytes: 4_294_967_296,
            used_bytes: 0,
            priority: -2,
        }],
        lvm: Some(LvmInventory {
            physical_volumes: vec![LvmPhysicalVolume {
                name: "/dev/missing-pv".to_owned(),
                uuid: Some("pv-missing".to_owned()),
                vg_name: Some("vg-missing".to_owned()),
                size_bytes: 10_737_418_240,
                free_bytes: 0,
            }],
            volume_groups: Vec::new(),
            logical_volumes: Vec::new(),
        }),
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: Vec::new(),
    };

    let diagnostics = reconcile_snapshot(&snapshot);
    let codes: Vec<&str> = diagnostics.iter().map(|item| item.code.as_str()).collect();

    assert!(codes.contains(&"lvm-pv-not-in-lsblk"));
    assert!(codes.contains(&"mounted-device-not-in-lsblk"));
    assert!(codes.contains(&"fstab-uuid-not-discovered"));
    assert!(codes.contains(&"swap-device-not-in-lsblk"));
}
