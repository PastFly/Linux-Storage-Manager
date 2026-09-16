use lsm_core::{BlockDevice, DiagnosticSeverity, NodeKind, StorageGraph};
use lsm_discovery::{diagnose_storage, parse_fstab};

#[test]
fn parses_fstab_without_mutating_it() {
    let input = r#"
# root filesystem
UUID=root-uuid / ext4 defaults 0 1
/dev/vg0/data /srv/data\040files xfs defaults,nofail 0 2
/swapfile none swap sw 0 0
"#;

    let entries = parse_fstab(input).expect("fstab fixture should parse");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].target, "/srv/data files");
    assert_eq!(entries[1].options, vec!["defaults", "nofail"]);
    assert_eq!(entries[2].fs_type, "swap");
}

#[test]
fn reports_partition_parent_mismatch() {
    let graph = StorageGraph {
        block_devices: vec![BlockDevice {
            name: "sda".to_owned(),
            kernel_name: Some("sda".to_owned()),
            path: Some("/dev/sda".to_owned()),
            kind: NodeKind::Disk,
            size_bytes: 100,
            start_sector: None,
            logical_sector_bytes: Some(512),
            filesystem: None,
            mountpoints: vec![],
            parent_kernel_name: None,
            model: None,
            serial: None,
            uuid: None,
            partition_uuid: None,
            partition_table: Some("gpt".to_owned()),
            children: vec![BlockDevice {
                name: "sda1".to_owned(),
                kernel_name: Some("sda1".to_owned()),
                path: Some("/dev/sda1".to_owned()),
                kind: NodeKind::Partition,
                size_bytes: 101,
                start_sector: Some(2048),
                logical_sector_bytes: Some(512),
                filesystem: None,
                mountpoints: vec![],
                parent_kernel_name: Some("sdb".to_owned()),
                model: None,
                serial: None,
                uuid: None,
                partition_uuid: None,
                partition_table: None,
                children: vec![],
            }],
        }],
    };

    let diagnostics = diagnose_storage(&graph);
    assert!(diagnostics
        .iter()
        .any(|item| item.code == "partition-larger-than-disk" && item.severity == DiagnosticSeverity::Error));
    assert!(diagnostics
        .iter()
        .any(|item| item.code == "partition-parent-mismatch"));
}
