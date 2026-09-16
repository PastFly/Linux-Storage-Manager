use lsm_core::{DiagnosticSeverity, HostSnapshot};
use lsm_discovery::{parse_lsblk_json, parse_sfdisk_json, reconcile_snapshot};

#[test]
fn parses_sfdisk_gpt_inventory() {
    let table = parse_sfdisk_json(include_str!("../../../tests/fixtures/sfdisk-gpt.json"))
        .expect("sfdisk fixture should parse");

    assert_eq!(table.device, "/dev/sda");
    assert_eq!(table.label.as_deref(), Some("gpt"));
    assert_eq!(table.sector_size_bytes, Some(512));
    assert_eq!(table.first_lba, Some(34));
    assert_eq!(table.partitions.len(), 2);
    assert_eq!(table.partitions[1].node, "/dev/sda2");
    assert_eq!(table.partitions[1].start_sector, 2_099_200);
    assert_eq!(table.partitions[1].size_sectors, 377_487_360);
}

#[test]
fn matching_sfdisk_and_lsblk_geometry_has_no_partition_table_errors() {
    let storage = parse_lsblk_json(include_str!(
        "../../../tests/fixtures/lsblk-lvm-ext4-tail.json"
    ))
    .expect("lsblk geometry fixture should parse");
    let table = parse_sfdisk_json(include_str!("../../../tests/fixtures/sfdisk-gpt.json"))
        .expect("sfdisk fixture should parse");

    let snapshot = HostSnapshot {
        storage,
        partition_tables: vec![table],
        mounts: Vec::new(),
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        diagnostics: Vec::new(),
        collectors: Vec::new(),
    };

    let diagnostics = reconcile_snapshot(&snapshot);
    assert!(!diagnostics.iter().any(|item| {
        item.severity == DiagnosticSeverity::Error
            && matches!(
                item.code.as_str(),
                "partition-table-label-mismatch"
                    | "logical-sector-size-mismatch"
                    | "partition-start-mismatch"
                    | "partition-size-mismatch"
                    | "partition-uuid-mismatch"
                    | "sfdisk-partition-not-in-lsblk"
                    | "lsblk-partition-not-in-sfdisk"
            )
    }));
}

#[test]
fn reports_authoritative_geometry_and_uuid_mismatch() {
    let storage = parse_lsblk_json(include_str!(
        "../../../tests/fixtures/lsblk-lvm-ext4-tail.json"
    ))
    .expect("lsblk geometry fixture should parse");
    let mut table = parse_sfdisk_json(include_str!("../../../tests/fixtures/sfdisk-gpt.json"))
        .expect("sfdisk fixture should parse");

    table.partitions[1].size_sectors += 8;
    table.partitions[1].uuid = Some("DIFFERENT-PARTUUID".to_owned());

    let snapshot = HostSnapshot {
        storage,
        partition_tables: vec![table],
        mounts: Vec::new(),
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        diagnostics: Vec::new(),
        collectors: Vec::new(),
    };

    let diagnostics = reconcile_snapshot(&snapshot);
    let codes: Vec<&str> = diagnostics.iter().map(|item| item.code.as_str()).collect();

    assert!(codes.contains(&"partition-size-mismatch"));
    assert!(codes.contains(&"partition-uuid-mismatch"));
}
