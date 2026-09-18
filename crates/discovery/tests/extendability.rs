use lsm_core::{
    CollectorState, CollectorStatus, DiagnosticSeverity, ExtendabilityStatus, HostSnapshot,
    LvmInventory, MountEntry, StorageDiagnostic,
};
use lsm_discovery::{
    analyze_extendability, parse_lsblk_json, parse_lvs_json, parse_pvs_json, parse_sfdisk_json,
    parse_vgs_json,
};

#[test]
fn reports_immediate_lvm_capacity_for_root() {
    let snapshot = fixture_snapshot(21_474_836_480);
    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::Ready);
    assert_eq!(analysis.immediate_growth_bytes, Some(21_474_836_480));
    assert_eq!(analysis.filesystem.as_deref(), Some("ext4"));
    assert_eq!(analysis.device.as_deref(), Some("/dev/mapper/vg0-root"));
}

#[test]
fn reports_missing_geometry_when_vg_is_full() {
    let analysis = analyze_extendability(&fixture_snapshot(0), "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsGeometry);
    assert_eq!(analysis.immediate_growth_bytes, Some(0));
    assert_eq!(analysis.potential_underlying_growth_bytes, None);
}

#[test]
fn reports_adjacent_partition_capacity_below_full_vg() {
    let analysis = analyze_extendability(&tail_snapshot(), "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsUnderlyingResize);
    assert_eq!(analysis.immediate_growth_bytes, Some(0));
    // Last usable GPT LBA is inclusive: use the reported bound, not disk size - 34 sectors.
    assert_eq!(
        analysis.potential_underlying_growth_bytes,
        Some(41_874_865_664)
    );
}

#[test]
fn lsblk_start_remains_512_byte_based_on_4k_logical_sector_disk() {
    let storage = parse_lsblk_json(
        r#"{"blockdevices":[{
        "name":"vdb","kname":"vdb","path":"/dev/vdb","type":"disk",
        "size":10737418240,"log-sec":4096,"pttype":"gpt","children":[{
            "name":"vdb1","kname":"vdb1","path":"/dev/vdb1","type":"part",
            "size":5368709120,"start":2048,"log-sec":4096,"fstype":"ext4",
            "mountpoints":["/data"],"pkname":"vdb","partuuid":"PART-DATA"
        }]
    }]}"#,
    )
    .unwrap();
    let table = parse_sfdisk_json(
        r#"{"partitiontable":{
        "device":"/dev/vdb","label":"gpt","unit":"sectors","sectorsize":4096,
        "firstlba":6,"lastlba":2621434,"partitions":[{
            "node":"/dev/vdb1","start":256,"size":1310720,"uuid":"PART-DATA"
        }]
    }}"#,
    )
    .unwrap();
    let mut snapshot = fixture_snapshot(0);
    snapshot.storage = storage;
    snapshot.lvm = None;
    snapshot.partition_tables = vec![table];
    snapshot.collectors = geometry_collectors();
    snapshot.mounts = vec![MountEntry {
        source: Some("/dev/vdb1".into()),
        target: "/data".into(),
        fs_type: Some("ext4".into()),
        options: vec!["rw".into()],
    }];
    let analysis = analyze_extendability(&snapshot, "/data").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsUnderlyingResize);
    assert_eq!(
        analysis.potential_underlying_growth_bytes,
        Some(5_367_640_064)
    );
}

#[test]
fn partial_pv_geometry_never_exposes_a_partial_sum() {
    let mut snapshot = tail_snapshot();
    let lvm = snapshot.lvm.as_mut().unwrap();
    let mut missing = lvm.physical_volumes[0].clone();
    missing.name = "/dev/missing".into();
    missing.uuid = Some("missing-pv".into());
    lvm.physical_volumes.push(missing);
    lvm.volume_groups[0].pv_count = 2;
    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsGeometry);
    assert_eq!(analysis.potential_underlying_growth_bytes, None);
}

#[test]
fn duplicate_pv_records_are_not_double_counted() {
    let mut snapshot = tail_snapshot();
    let lvm = snapshot.lvm.as_mut().unwrap();
    lvm.physical_volumes.push(lvm.physical_volumes[0].clone());
    lvm.volume_groups[0].pv_count = 2;
    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsGeometry);
    assert_eq!(analysis.potential_underlying_growth_bytes, None);
}

#[test]
fn missing_pv_record_cannot_be_treated_as_complete() {
    let mut snapshot = tail_snapshot();
    snapshot.lvm.as_mut().unwrap().volume_groups[0].pv_count = 2;
    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsGeometry);
    assert_eq!(analysis.potential_underlying_growth_bytes, None);
}

#[test]
fn error_diagnostics_also_block_lvm_free_capacity_claims() {
    let mut snapshot = fixture_snapshot(21_474_836_480);
    snapshot.diagnostics.push(StorageDiagnostic {
        code: "partition-size-mismatch".into(),
        severity: DiagnosticSeverity::Error,
        message: "test error".into(),
        device: Some("/dev/sda2".into()),
    });
    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::Unknown);
    assert_eq!(analysis.immediate_growth_bytes, None);
    assert_eq!(analysis.potential_underlying_growth_bytes, None);
    assert!(analysis.steps.is_empty());
}

fn geometry_collectors() -> Vec<CollectorStatus> {
    ["lsblk", "partition_tables", "mounts", "lvm"]
        .into_iter()
        .map(|component| CollectorStatus {
            component: component.into(),
            state: CollectorState::Complete,
            detail: None,
        })
        .collect()
}

fn tail_snapshot() -> HostSnapshot {
    let mut snapshot = fixture_snapshot(0);
    snapshot.storage = parse_lsblk_json(include_str!(
        "../../../tests/fixtures/lsblk-lvm-ext4-tail.json"
    ))
    .unwrap();
    snapshot.partition_tables = vec![parse_sfdisk_json(
        r#"{"partitiontable":{
        "device":"/dev/sda","label":"gpt","unit":"sectors","sectorsize":512,
        "firstlba":34,"lastlba":461373406,"partitions":[
            {"node":"/dev/sda1","start":2048,"size":2097152,"uuid":"PART-EFI"},
            {"node":"/dev/sda2","start":2099200,"size":377487360,"uuid":"PART-LVM"}
        ]
    }}"#,
    )
    .unwrap()];
    snapshot.collectors = geometry_collectors();
    let lvm = snapshot.lvm.as_mut().unwrap();
    lvm.physical_volumes[0].size_bytes = 193_273_528_320;
    lvm.volume_groups[0].size_bytes = 193_273_528_320;
    snapshot
}

fn fixture_snapshot(vg_free: u64) -> HostSnapshot {
    let storage =
        parse_lsblk_json(include_str!("../../../tests/fixtures/lsblk-lvm-ext4.json")).unwrap();
    let pvs = format!(
        r#"{{"report":[{{"pv":[{{"pv_name":"/dev/sda2","pv_uuid":"PV-UUID","vg_name":"vg0","pv_size":"213674622976","pv_free":"{vg_free}"}}]}}]}}"#
    );
    let vgs = format!(
        r#"{{"report":[{{"vg":[{{"vg_name":"vg0","vg_uuid":"vg-1","vg_size":"213674622976","vg_free":"{vg_free}","pv_count":"1","lv_count":"1"}}]}}]}}"#
    );
    let lvs = r#"{"report":[{"lv":[{"lv_name":"root","lv_path":"/dev/vg0/root","lv_uuid":"lv-1","vg_name":"vg0","lv_size":"193273528320","lv_attr":"-wi-ao----"}]}]}"#;
    HostSnapshot {
        storage,
        partition_tables: Vec::new(),
        mounts: vec![MountEntry {
            source: Some("/dev/mapper/vg0-root".into()),
            target: "/".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: Some(LvmInventory {
            physical_volumes: parse_pvs_json(&pvs).unwrap(),
            volume_groups: parse_vgs_json(&vgs).unwrap(),
            logical_volumes: parse_lvs_json(lvs).unwrap(),
        }),
        diagnostics: Vec::new(),
        collectors: geometry_collectors(),
    }
}

#[test]
fn dos_primary_before_extended_container_has_known_zero_adjacent_capacity() {
    let storage = parse_lsblk_json(
        r#"{
          "blockdevices": [{
            "name":"sda","kname":"sda","path":"/dev/sda","type":"disk",
            "size":10737418240,"start":null,"log-sec":512,"fstype":null,"fsver":null,
            "mountpoints":[null],"pkname":null,"model":null,"serial":null,"uuid":null,
            "partuuid":null,"pttype":"dos","children":[
              {
                "name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part",
                "size":9711910912,"start":2048,"log-sec":512,"fstype":"ext4","fsver":"1.0",
                "mountpoints":["/"],"pkname":"sda","model":null,"serial":null,
                "uuid":"root-fs","partuuid":"00000000-01","pttype":"dos"
              },
              {
                "name":"sda2","kname":"sda2","path":"/dev/sda2","type":"part",
                "size":1024,"start":18970624,"log-sec":512,"fstype":null,"fsver":null,
                "mountpoints":[null],"pkname":"sda","model":null,"serial":null,
                "uuid":null,"partuuid":"00000000-02","pttype":"dos","children":[{
                  "name":"sda5","kname":"sda5","path":"/dev/sda5","type":"part",
                  "size":1022361600,"start":18972672,"log-sec":512,"fstype":"swap","fsver":"1",
                  "mountpoints":["[SWAP]"],"pkname":"sda2","model":null,"serial":null,
                  "uuid":"swap-id","partuuid":"00000000-05","pttype":"dos"
                }]
              }
            ]
          }]
        }"#,
    )
    .unwrap();

    let table = parse_sfdisk_json(
        r#"{"partitiontable":{
          "device":"/dev/sda","label":"dos","unit":"sectors","sectorsize":512,
          "partitions":[
            {"node":"/dev/sda1","start":2048,"size":18968576,"type":"83"},
            {"node":"/dev/sda2","start":18970624,"size":1996802,"type":"5"},
            {"node":"/dev/sda5","start":18972672,"size":1996800,"type":"82"}
          ]
        }}"#,
    )
    .unwrap();

    let snapshot = HostSnapshot {
        storage,
        partition_tables: vec![table],
        mounts: vec![MountEntry {
            source: Some("/dev/sda1".into()),
            target: "/".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        diagnostics: Vec::new(),
        collectors: geometry_collectors(),
    };

    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(
        analysis.status,
        ExtendabilityStatus::NeedsUnderlyingCapacity
    );
    assert_eq!(analysis.potential_underlying_growth_bytes, Some(0));
}

#[test]
fn debian12_dos_logical_sibling_reports_real_gap_before_extended_container() {
    let storage = parse_lsblk_json(
        r#"{
          "blockdevices": [{
            "name":"sda","kname":"sda","path":"/dev/sda","type":"disk",
            "size":10737418240,"start":null,"log-sec":512,"fstype":null,"fsver":null,
            "mountpoints":[null],"pkname":null,"model":null,"serial":null,"uuid":null,
            "partuuid":null,"pttype":"dos","children":[
              {
                "name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part",
                "size":9711910912,"start":2048,"log-sec":512,"fstype":"ext4","fsver":"1.0",
                "mountpoints":["/"],"pkname":"sda","model":null,"serial":null,
                "uuid":"042edc87-45f0-4634-ad09-7c228a600fbf","partuuid":"f5b1b569-01","pttype":"dos"
              },
              {
                "name":"sda2","kname":"sda2","path":"/dev/sda2","type":"part",
                "size":1024,"start":18972670,"log-sec":512,"fstype":null,"fsver":null,
                "mountpoints":[null],"pkname":"sda","model":null,"serial":null,
                "uuid":null,"partuuid":"f5b1b569-02","pttype":"dos"
              },
              {
                "name":"sda5","kname":"sda5","path":"/dev/sda5","type":"part",
                "size":1022361600,"start":18972672,"log-sec":512,"fstype":"swap","fsver":"1",
                "mountpoints":["[SWAP]"],"pkname":"sda","model":null,"serial":null,
                "uuid":"a2f7942e-9329-4367-a8cc-33b8a928aed0","partuuid":"f5b1b569-05","pttype":"dos"
              }
            ]
          }]
        }"#,
    )
    .unwrap();

    let table = parse_sfdisk_json(
        r#"{"partitiontable":{
          "label":"dos","id":"0xf5b1b569","device":"/dev/sda","unit":"sectors","sectorsize":512,
          "partitions":[
            {"node":"/dev/sda1","start":2048,"size":18968576,"type":"83","bootable":true},
            {"node":"/dev/sda2","start":18972670,"size":1996802,"type":"5"},
            {"node":"/dev/sda5","start":18972672,"size":1996800,"type":"82"}
          ]
        }}"#,
    )
    .unwrap();

    let snapshot = HostSnapshot {
        storage,
        partition_tables: vec![table],
        mounts: vec![MountEntry {
            source: Some("/dev/sda1".into()),
            target: "/".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        diagnostics: Vec::new(),
        collectors: geometry_collectors(),
    };

    let analysis = analyze_extendability(&snapshot, "/").unwrap();
    assert_eq!(analysis.status, ExtendabilityStatus::NeedsUnderlyingResize);
    assert_eq!(analysis.potential_underlying_growth_bytes, Some(1_047_552));
}
