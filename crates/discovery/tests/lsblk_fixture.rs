use lsm_core::NodeKind;
use lsm_discovery::parse_lsblk_json;

#[test]
fn normalizes_lvm_ext4_topology() {
    let fixture = include_str!("../../../tests/fixtures/lsblk-lvm-ext4.json");
    let graph = parse_lsblk_json(fixture).expect("fixture should parse");

    assert_eq!(graph.block_devices.len(), 1);
    let disk = &graph.block_devices[0];
    assert_eq!(disk.kind, NodeKind::Disk);
    assert_eq!(disk.size_bytes, 214_748_364_800);
    assert_eq!(disk.children.len(), 2);

    let root_partition = &disk.children[1];
    assert_eq!(root_partition.kind, NodeKind::Partition);
    assert_eq!(root_partition.children.len(), 1);

    let root_lv = &root_partition.children[0];
    assert_eq!(root_lv.kind, NodeKind::Lvm);
    assert_eq!(root_lv.mountpoints, vec!["/"]);
    assert_eq!(root_lv.filesystem.as_ref().unwrap().fs_type, "ext4");
}
