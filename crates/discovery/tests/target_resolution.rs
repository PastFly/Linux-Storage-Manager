use lsm_core::{
    CollectorState, CollectorStatus, ExtendabilityStatus, HostSnapshot, LvmInventory, MountEntry,
};
use lsm_discovery::{
    analyze_extendability, parse_lsblk_json, parse_lvs_json, parse_pvs_json, parse_vgs_json,
};

fn fixture() -> HostSnapshot {
    HostSnapshot {
        storage: parse_lsblk_json(include_str!(
            "../../../tests/fixtures/lsblk-lvm-ext4.json"
        ))
        .unwrap(),
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
            physical_volumes: parse_pvs_json(r#"{"report":[{"pv":[{"pv_name":"/dev/sda2","pv_uuid":"PV-UUID","vg_name":"vg0","pv_size":"193294499840","pv_free":"16777216"}]}]}"#).unwrap(),
            volume_groups: parse_vgs_json(r#"{"report":[{"vg":[{"vg_name":"vg0","vg_uuid":"VG-UUID","vg_size":"193290305536","vg_free":"16777216","pv_count":"1","lv_count":"1"}]}]}"#).unwrap(),
            logical_volumes: parse_lvs_json(r#"{"report":[{"lv":[{"lv_name":"root","lv_path":"/dev/vg0/root","lv_uuid":"LV-UUID","vg_name":"vg0","lv_size":"193273528320","lv_attr":"-wi-ao----"}]}]}"#).unwrap(),
        }),
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: ["lsblk", "mounts", "lvm"]
            .into_iter()
            .map(|component| CollectorStatus {
                component: component.into(),
                state: CollectorState::Complete,
                detail: None,
            })
            .collect(),
    }
}

fn refused(snapshot: &HostSnapshot, target: &str) {
    let report = analyze_extendability(snapshot, target).expect("refusal is an advisory report");
    assert_eq!(report.status, ExtendabilityStatus::Unknown);
    assert_eq!(report.immediate_growth_bytes, None);
    assert_eq!(report.potential_underlying_growth_bytes, None);
    assert!(report.steps.is_empty());
}

#[test]
fn resolves_mount_mapper_lvm_and_kernel_paths_to_one_lv() {
    let snapshot = fixture();
    for target in ["/", "/dev/mapper/vg0-root", "/dev/vg0/root", "/dev/dm-0"] {
        let report = analyze_extendability(&snapshot, target).unwrap();
        assert_eq!(report.status, ExtendabilityStatus::Ready, "{target}");
        assert_eq!(report.device.as_deref(), Some("/dev/mapper/vg0-root"));
        assert_eq!(report.immediate_growth_bytes, Some(16_777_216));
    }
}

#[test]
fn resolves_hyphenated_lvm_names_without_guessing_unescaped_mapper_paths() {
    let mut snapshot = fixture();
    let lv = &mut snapshot.lvm.as_mut().unwrap().logical_volumes[0];
    lv.name = "root-vol".into();
    lv.vg_name = "vg-data".into();
    lv.path = Some("/dev/vg-data/root-vol".into());
    snapshot.lvm.as_mut().unwrap().volume_groups[0].name = "vg-data".into();
    snapshot.lvm.as_mut().unwrap().physical_volumes[0].vg_name = Some("vg-data".into());
    let node = &mut snapshot.storage.block_devices[0].children[1].children[0];
    node.name = "vg--data-root--vol".into();
    node.path = Some("/dev/mapper/vg--data-root--vol".into());
    snapshot.mounts[0].source = Some("/dev/vg-data/root-vol".into());
    for target in [
        "/",
        "/dev/vg-data/root-vol",
        "/dev/mapper/vg--data-root--vol",
        "/dev/dm-0",
    ] {
        let report = analyze_extendability(&snapshot, target).unwrap();
        assert_eq!(report.status, ExtendabilityStatus::Ready);
        assert_eq!(
            report.device.as_deref(),
            Some("/dev/mapper/vg--data-root--vol")
        );
    }
    assert!(analyze_extendability(&snapshot, "/dev/mapper/vg-data-root-vol").is_err());
}

#[test]
fn does_not_invent_a_dev_path_from_display_name() {
    assert!(analyze_extendability(&fixture(), "/dev/vg0-root").is_err());
}

#[test]
fn duplicate_active_mounts_never_select_the_first_record() {
    let mut snapshot = fixture();
    let duplicate = snapshot.mounts[0].clone();
    snapshot.mounts.push(duplicate);
    for target in ["/", "/dev/vg0/root"] {
        refused(&snapshot, target);
    }
}

#[test]
fn conflicting_mount_sources_are_order_independent() {
    let mut snapshot = fixture();
    let mut other = snapshot.mounts[0].clone();
    other.source = Some("/dev/sda1".into());
    snapshot.mounts.push(other);
    refused(&snapshot, "/");
    snapshot.mounts.reverse();
    refused(&snapshot, "/");
}

#[test]
fn conflicting_lsblk_mount_claims_are_order_independent() {
    let mut snapshot = fixture();
    let mut other = snapshot.storage.block_devices[0].children[1].children[0].clone();
    other.path = Some("/dev/sdz1".into());
    other.kernel_name = Some("sdz1".into());
    other.name = "sdz1".into();
    snapshot.storage.block_devices.push(other);
    refused(&snapshot, "/");
    snapshot.storage.block_devices.reverse();
    refused(&snapshot, "/");
}

#[test]
fn missing_or_conflicting_mount_source_does_not_fall_back_to_lsblk() {
    for source in [
        None,
        Some("/dev/missing"),
        Some("/dev/sda1"),
        Some("/dev/root"),
    ] {
        let mut snapshot = fixture();
        snapshot.mounts[0].source = source.map(str::to_owned);
        refused(&snapshot, "/");
        refused(&snapshot, "/dev/dm-0");
    }
}

#[test]
fn missing_mount_row_is_not_proof_of_a_live_mount() {
    let mut snapshot = fixture();
    snapshot.mounts.clear();
    refused(&snapshot, "/");
    refused(&snapshot, "/dev/mapper/vg0-root");
}

#[test]
fn missing_lsblk_mount_claim_is_not_silently_accepted() {
    let mut snapshot = fixture();
    snapshot.storage.block_devices[0].children[1].children[0]
        .mountpoints
        .clear();
    refused(&snapshot, "/");
    refused(&snapshot, "/dev/vg0/root");
}

#[test]
fn incomplete_or_duplicated_collectors_cannot_supply_target_evidence() {
    for component in ["lsblk", "mounts", "lvm"] {
        for state in [CollectorState::Failed, CollectorState::Unavailable] {
            let mut snapshot = fixture();
            snapshot
                .collectors
                .iter_mut()
                .find(|c| c.component == component)
                .unwrap()
                .state = state;
            refused(&snapshot, "/");
            refused(&snapshot, "/dev/vg0/root");
        }
        let mut snapshot = fixture();
        snapshot.collectors.retain(|c| c.component != component);
        refused(&snapshot, "/");
        let mut snapshot = fixture();
        let duplicate = snapshot
            .collectors
            .iter()
            .find(|c| c.component == component)
            .unwrap()
            .clone();
        snapshot.collectors.push(duplicate);
        refused(&snapshot, "/");
    }
}

#[test]
fn duplicate_graph_paths_do_not_select_the_first_node() {
    let mut snapshot = fixture();
    let duplicate = snapshot.storage.block_devices[0].clone();
    snapshot.storage.block_devices.push(duplicate);
    let report = analyze_extendability(&snapshot, "/dev/mapper/vg0-root").unwrap();
    refused(&snapshot, "/dev/mapper/vg0-root");
    assert!(report.device.is_none());
    assert!(report.current_size_bytes.is_none());
}

#[test]
fn duplicate_kernel_identity_is_ambiguous_even_with_distinct_paths() {
    let mut snapshot = fixture();
    let mut other = snapshot.storage.block_devices[0].children[1].children[0].clone();
    other.path = Some("/dev/another-name".into());
    other.mountpoints.clear();
    snapshot.storage.block_devices.push(other);
    refused(&snapshot, "/dev/mapper/vg0-root");
}

#[test]
fn direct_alias_and_lvm_alias_cannot_point_to_different_nodes() {
    let mut snapshot = fixture();
    let mut other = snapshot.storage.block_devices[0].children[0].clone();
    other.path = Some("/dev/vg0/root".into());
    other.mountpoints.clear();
    snapshot.storage.block_devices.push(other);
    refused(&snapshot, "/dev/vg0/root");
}

#[test]
fn duplicate_lv_reports_cannot_select_a_uuid_by_order() {
    let mut snapshot = fixture();
    let lvm = snapshot.lvm.as_mut().unwrap();
    let mut other = lvm.logical_volumes[0].clone();
    other.uuid = Some("OTHER-LV-UUID".into());
    lvm.logical_volumes.push(other);
    refused(&snapshot, "/");
    snapshot.lvm.as_mut().unwrap().logical_volumes.reverse();
    refused(&snapshot, "/dev/dm-0");
}

#[test]
fn duplicate_vg_reports_cannot_select_free_capacity_by_order() {
    let mut snapshot = fixture();
    let lvm = snapshot.lvm.as_mut().unwrap();
    let mut other = lvm.volume_groups[0].clone();
    other.free_bytes = 0;
    lvm.volume_groups.push(other);
    refused(&snapshot, "/");
    snapshot.lvm.as_mut().unwrap().volume_groups.reverse();
    refused(&snapshot, "/");
}

#[test]
fn mount_filesystem_disagreement_blocks_advice() {
    let mut snapshot = fixture();
    snapshot.mounts[0].fs_type = Some("xfs".into());
    refused(&snapshot, "/");
    refused(&snapshot, "/dev/vg0/root");
}

#[test]
fn read_only_and_bind_mounts_do_not_receive_growth_steps() {
    for option in ["ro", "bind", "rbind"] {
        let mut snapshot = fixture();
        snapshot.mounts[0].options.push(option.into());
        refused(&snapshot, "/");
        refused(&snapshot, "/dev/vg0/root");
    }
}

#[test]
fn bracketed_subdirectory_sources_are_not_trimmed_into_device_paths() {
    let mut snapshot = fixture();
    snapshot.mounts[0].source = Some("/dev/mapper/vg0-root[/subdir]".into());
    refused(&snapshot, "/");
    refused(&snapshot, "/dev/dm-0");
}

#[test]
fn invalid_targets_have_no_capacity_and_do_not_echo_control_characters_in_reasons() {
    for target in ["", "root", "/dev/", "/dev/dm-0\n", "/\x1b[31m", "/\0"] {
        let report = analyze_extendability(&fixture(), target).unwrap();
        assert_eq!(report.status, ExtendabilityStatus::Unknown);
        assert!(report.device.is_none());
        assert!(report.steps.is_empty());
        assert!(report
            .reasons
            .iter()
            .all(|r| !r.chars().any(char::is_control)));
    }
}

#[test]
fn genuinely_absent_device_keeps_not_found_error() {
    let error = analyze_extendability(&fixture(), "/dev/does-not-exist").unwrap_err();
    assert!(error.to_string().contains("not found"));
}

#[test]
fn unmounted_device_is_distinct_from_a_failed_mount_collector() {
    let mut snapshot = fixture();
    let node = &mut snapshot.storage.block_devices[0].children[1].children[0];
    node.mountpoints.clear();
    node.filesystem.as_mut().unwrap().fs_type = "xfs".into();
    snapshot.mounts.clear();
    let report = analyze_extendability(&snapshot, "/dev/vg0/root").unwrap();
    assert_eq!(report.status, ExtendabilityStatus::RequiresMount);
    snapshot
        .collectors
        .iter_mut()
        .find(|c| c.component == "mounts")
        .unwrap()
        .state = CollectorState::Failed;
    refused(&snapshot, "/dev/vg0/root");
}
