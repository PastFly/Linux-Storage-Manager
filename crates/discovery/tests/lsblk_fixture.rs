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

#[test]
fn normalizes_multipath_device_without_collapsing_to_unknown() {
    let fixture = r#"{
      "blockdevices": [{
        "name":"mpatha","kname":"dm-0","path":"/dev/mapper/mpatha","type":"mpath",
        "size":107374182400,"start":null,"log-sec":512,
        "fstype":"ext4","fsver":"1.0","mountpoints":["/data"],
        "pkname":null,"model":"SAN LUN","serial":"3600508b400105e210000900000490000",
        "uuid":"fs-mpath","partuuid":null,"pttype":null,"children":[]
      }]
    }"#;

    let graph = parse_lsblk_json(fixture).expect("multipath fixture should parse");
    assert_eq!(graph.block_devices.len(), 1);
    let device = &graph.block_devices[0];
    assert_eq!(device.kind, NodeKind::Multipath);
    assert_eq!(device.path.as_deref(), Some("/dev/mapper/mpatha"));
    assert_eq!(device.mountpoints, vec!["/data"]);
}
