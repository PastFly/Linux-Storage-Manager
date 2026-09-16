use lsm_core::{ExtendabilityStatus, HostSnapshot, LvmInventory};
use lsm_discovery::{
    analyze_extendability, parse_lsblk_json, parse_lvs_json, parse_pvs_json, parse_vgs_json,
};

#[test]
fn reports_immediate_lvm_capacity_for_root() {
    let snapshot = fixture_snapshot(21_474_836_480);
    let analysis = analyze_extendability(&snapshot, "/").expect("root target should resolve");

    assert_eq!(analysis.status, ExtendabilityStatus::Ready);
    assert_eq!(analysis.immediate_growth_bytes, Some(21_474_836_480));
    assert_eq!(analysis.filesystem.as_deref(), Some("ext4"));
    assert_eq!(analysis.device.as_deref(), Some("/dev/mapper/vg0-root"));
}

#[test]
fn reports_when_vg_has_no_free_extents() {
    let snapshot = fixture_snapshot(0);
    let analysis = analyze_extendability(&snapshot, "/").expect("root target should resolve");

    assert_eq!(
        analysis.status,
        ExtendabilityStatus::NeedsUnderlyingCapacity
    );
    assert_eq!(analysis.immediate_growth_bytes, Some(0));
}

fn fixture_snapshot(vg_free: u64) -> HostSnapshot {
    let storage = parse_lsblk_json(include_str!("../../../tests/fixtures/lsblk-lvm-ext4.json"))
        .expect("lsblk fixture should parse");

    let pvs = format!(
        r#"{{"report":[{{"pv":[{{"pv_name":"/dev/sda2","pv_uuid":"pv-1","vg_name":"vg0","pv_size":"213674622976","pv_free":"{vg_free}"}}]}}]}}"#
    );
    let vgs = format!(
        r#"{{"report":[{{"vg":[{{"vg_name":"vg0","vg_uuid":"vg-1","vg_size":"213674622976","vg_free":"{vg_free}","pv_count":"1","lv_count":"1"}}]}}]}}"#
    );
    let lvs = r#"{"report":[{"lv":[{"lv_name":"root","lv_path":"/dev/vg0/root","lv_uuid":"lv-1","vg_name":"vg0","lv_size":"193273528320","lv_attr":"-wi-ao----"}]}]}"#;

    HostSnapshot {
        storage,
        mounts: Vec::new(),
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: Some(LvmInventory {
            physical_volumes: parse_pvs_json(&pvs).expect("pvs fixture should parse"),
            volume_groups: parse_vgs_json(&vgs).expect("vgs fixture should parse"),
            logical_volumes: parse_lvs_json(lvs).expect("lvs fixture should parse"),
        }),
        diagnostics: Vec::new(),
        collectors: Vec::new(),
    }
}
