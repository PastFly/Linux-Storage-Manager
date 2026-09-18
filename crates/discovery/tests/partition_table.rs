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

#[test]
fn dos_extended_partition_container_does_not_trigger_false_size_mismatch() {
    let storage = parse_lsblk_json(
        r#"{
          "blockdevices": [{
            "name":"sda","kname":"sda","path":"/dev/sda","type":"disk",
            "size":10737418240,"fstype":null,"fsver":null,"mountpoints":[null],
            "pkname":null,"model":null,"serial":null,"uuid":null,"partuuid":null,
            "pttype":"dos","start":null,"log-sec":512,
            "children":[
              {
                "name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part",
                "size":9711910912,"fstype":"ext4","fsver":"1.0","mountpoints":["/"],
                "pkname":"sda","model":null,"serial":null,"uuid":"root-fs",
                "partuuid":"00000000-01","pttype":"dos","start":2048,"log-sec":512
              },
              {
                "name":"sda2","kname":"sda2","path":"/dev/sda2","type":"part",
                "size":1024,"fstype":null,"fsver":null,"mountpoints":[null],
                "pkname":"sda","model":null,"serial":null,"uuid":null,
                "partuuid":"00000000-02","pttype":"dos","start":18970624,"log-sec":512,
                "children":[{
                  "name":"sda5","kname":"sda5","path":"/dev/sda5","type":"part",
                  "size":1022361600,"fstype":"swap","fsver":"1","mountpoints":["[SWAP]"],
                  "pkname":"sda2","model":null,"serial":null,"uuid":"swap-id",
                  "partuuid":"00000000-05","pttype":"dos","start":18972672,"log-sec":512
                }]
              }
            ]
          }]
        }"#,
    )
    .expect("MBR lsblk fixture should parse");

    let table = parse_sfdisk_json(
        r#"{
          "partitiontable":{
            "label":"dos","id":"0x00000000","device":"/dev/sda","unit":"sectors",
            "sectorsize":512,
            "partitions":[
              {"node":"/dev/sda1","start":2048,"size":18968576,"type":"83"},
              {"node":"/dev/sda2","start":18970624,"size":1996802,"type":"5"},
              {"node":"/dev/sda5","start":18972672,"size":1996800,"type":"82"}
            ]
          }
        }"#,
    )
    .expect("MBR sfdisk fixture should parse");

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
        item.code == "partition-size-mismatch" && item.device.as_deref() == Some("/dev/sda2")
    }));
}
