use lsm_core::{
    CollectorState, DiagnosticSeverity, FilesystemPreflightEvidence, FilesystemProbeState,
    HostCapabilities, HostSnapshot, StorageDiagnostic,
};
use lsm_planner::{
    analyze_lvm_underlying_growth, list_extend_targets, list_provisioning_opportunities,
    parse_growth_size, plan_create, plan_extend, CreatePurpose, CreateRequest, ExtendRequest,
    ExtendTargetAvailability, ExtendTargetKind, Growth, Operation, PlanStatus, PreflightState,
    ProvisioningSpaceKind,
};
use serde_json::json;

const GIB: u64 = 1 << 30;
const EXTENT: u64 = 4 << 20;

fn input() -> (HostSnapshot, HostCapabilities) {
    let snapshot: HostSnapshot = serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"vda", "kernel_name":"vda", "path":"/dev/vda", "kind":"disk",
            "size_bytes":20*GIB, "mountpoints":[], "partition_table":"gpt", "children":[{
                "name":"vda1", "kernel_name":"vda1", "path":"/dev/vda1", "kind":"partition",
                "size_bytes":16*GIB+EXTENT, "start_512_sector":2048, "logical_sector_bytes":512,
                "uuid":"pv-1", "filesystem":{"fs_type":"LVM2_member"}, "mountpoints":[],
                "children":[{
                    "name":"vg0-root", "kernel_name":"dm-0", "path":"/dev/mapper/vg0-root",
                    "kind":"lvm", "size_bytes":8*GIB, "uuid":"fs-1",
                    "filesystem":{"fs_type":"ext4"}, "mountpoints":["/"], "children":[]
                }]
            }]
        }]},
        "partition_tables":[],
        "mounts":[{"source":"/dev/vg0/root","target":"/","fs_type":"ext4","options":["rw","relatime"]}],
        "fstab":[], "swaps":[], "diagnostics":[],
        "collectors":[
            {"component":"lsblk","state":"complete"},
            {"component":"partition_tables","state":"complete"},
            {"component":"mounts","state":"complete"},
            {"component":"fstab","state":"complete"},
            {"component":"swap","state":"complete"},
            {"component":"lvm","state":"complete"}
        ],
        "lvm":{
            "physical_volumes":[{"name":"/dev/vda1","uuid":"pv-1","vg_name":"vg0","size_bytes":16*GIB,"free_bytes":8*GIB}],
            "volume_groups":[{
                "name":"vg0","uuid":"vg-1","size_bytes":16*GIB,"free_bytes":8*GIB,
                "pv_count":1,"lv_count":1,"extent_size_bytes":EXTENT,"free_extent_count":2048,
                "missing_pv_count":0,"attributes":"wz--n-"
            }],
            "logical_volumes":[{
                "name":"root","path":"/dev/vg0/root","uuid":"lv-1","vg_name":"vg0",
                "size_bytes":8*GIB,"attributes":"-wi-ao----","layout":"linear","role":"public"
            }]
        }
    })).unwrap();
    let caps = serde_json::from_value(json!({"tools":[
        {"name":"vgcfgbackup","available":true}, {"name":"lvextend","available":true},
        {"name":"resize2fs","available":true}, {"name":"xfs_growfs","available":true}
    ]}))
    .unwrap();
    (snapshot, caps)
}

fn request(target: &str, growth: Growth) -> ExtendRequest {
    ExtendRequest {
        target: target.to_owned(),
        growth,
    }
}

#[test]
fn preview_is_immutable_input_and_never_executable() {
    let (snapshot, caps) = input();
    let before = snapshot.clone();
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::ByBytes(GIB))).unwrap();
    assert_eq!(snapshot, before);
    assert_eq!(plan.status(), PlanStatus::Preview);
    assert_eq!(plan.steps().len(), 5);
    assert_eq!(plan.size_change().unwrap().expected_lv_size_bytes, 9 * GIB);
    assert!(matches!(
        plan.steps()[1].operation,
        Operation::BackupLvmMetadata { .. }
    ));
    for (index, step) in plan.steps().iter().enumerate() {
        assert_eq!(step.id as usize, index + 1);
        assert_eq!(
            step.depends_on,
            if index == 0 {
                vec![]
            } else {
                vec![index as u32]
            }
        );
    }
    let output = serde_json::to_value(&plan).unwrap();
    assert_eq!(output["dry_run"], true);
    assert_eq!(output["executable"], false);
    assert!(plan.render_text().contains("no commands executed"));
}

#[test]
fn rounds_up_to_extents_transparently() {
    let (snapshot, caps) = input();
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::ByBytes(EXTENT + 1))).unwrap();
    let size = plan.size_change().unwrap();
    assert_eq!(size.requested_growth_bytes, EXTENT + 1);
    assert_eq!(size.rounded_growth_bytes, EXTENT * 2);
}

#[test]
fn max_is_frozen_to_observed_capacity() {
    let (snapshot, caps) = input();
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    assert_eq!(plan.size_change().unwrap().remaining_vg_free_bytes, 0);
    assert_eq!(plan.size_change().unwrap().expected_lv_size_bytes, 16 * GIB);
}

#[test]
fn recognizes_device_mapper_kernel_and_lvm_aliases() {
    let (snapshot, caps) = input();
    for target in ["/", "/dev/vg0/root", "/dev/mapper/vg0-root", "/dev/dm-0"] {
        assert_eq!(
            plan_extend(&snapshot, &caps, request(target, Growth::MaxFree))
                .unwrap()
                .status(),
            PlanStatus::Preview
        );
    }
}

#[test]
fn xfs_requires_matching_rw_mount() {
    let (mut snapshot, caps) = input();
    snapshot.storage.block_devices[0].children[0].children[0]
        .filesystem
        .as_mut()
        .unwrap()
        .fs_type = "xfs".into();
    snapshot.mounts[0].fs_type = Some("xfs".into());
    assert_eq!(
        plan_extend(&snapshot, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Preview
    );
    snapshot.mounts[0].options = vec!["ro".into()];
    assert_eq!(
        plan_extend(&snapshot, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Blocked
    );
}

#[test]
fn missing_and_failed_collectors_are_blockers() {
    let (snapshot, caps) = input();
    for state in [CollectorState::Unavailable, CollectorState::Failed] {
        let mut changed = snapshot.clone();
        changed.collectors[0].state = state;
        let plan = plan_extend(&changed, &caps, request("/", Growth::MaxFree)).unwrap();
        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan.steps().is_empty());
    }
    let mut changed = snapshot.clone();
    changed.collectors.clear();
    assert_eq!(
        plan_extend(&changed, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Blocked
    );
}

#[test]
fn errors_block_even_when_legacy_explain_would_be_ready() {
    let (mut snapshot, caps) = input();
    snapshot.diagnostics.push(StorageDiagnostic {
        code: "partition-size-mismatch".into(),
        severity: DiagnosticSeverity::Error,
        message: "contradictory geometry".into(),
        device: Some("/dev/vda1".into()),
    });
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert_eq!(plan.blockers()[0].code, "diagnostic-error");
    assert!(plan.steps().is_empty());
}

#[test]
fn duplicate_mount_targets_and_logical_volumes_are_rejected() {
    let (snapshot, caps) = input();
    let mut changed = snapshot.clone();
    changed.mounts.push(changed.mounts[0].clone());
    assert_eq!(
        plan_extend(&changed, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Blocked
    );
    let mut changed = snapshot.clone();
    let lvm = changed.lvm.as_mut().unwrap();
    lvm.logical_volumes.push(lvm.logical_volumes[0].clone());
    assert_eq!(
        plan_extend(&changed, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Blocked
    );
}

#[test]
fn missing_or_thin_or_raid_layouts_are_blocked() {
    let (snapshot, caps) = input();
    for layout in [
        None,
        Some("thin"),
        Some("raid,raid1"),
        Some("striped"),
        Some("linear,cache"),
    ] {
        let mut changed = snapshot.clone();
        changed.lvm.as_mut().unwrap().logical_volumes[0].layout = layout.map(str::to_owned);
        let plan = plan_extend(&changed, &caps, request("/", Growth::MaxFree)).unwrap();
        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan.steps().is_empty());
    }
}

#[test]
fn identity_and_capacity_disagreements_block() {
    let (snapshot, caps) = input();
    let cases: Vec<fn(&mut HostSnapshot)> = vec![
        |s| s.lvm.as_mut().unwrap().physical_volumes[0].uuid = Some("another-pv".into()),
        |s| s.lvm.as_mut().unwrap().logical_volumes[0].size_bytes += 1,
        |s| s.lvm.as_mut().unwrap().volume_groups[0].free_extent_count = Some(1),
        |s| s.lvm.as_mut().unwrap().volume_groups[0].missing_pv_count = Some(1),
        |s| s.lvm.as_mut().unwrap().volume_groups[0].pv_count = 2,
        |s| s.lvm.as_mut().unwrap().volume_groups[0].extent_size_bytes = None,
        |s| s.lvm.as_mut().unwrap().logical_volumes[0].uuid = None,
    ];
    for mutate in cases {
        let mut changed = snapshot.clone();
        mutate(&mut changed);
        assert_eq!(
            plan_extend(&changed, &caps, request("/", Growth::MaxFree))
                .unwrap()
                .status(),
            PlanStatus::Blocked
        );
    }
}

#[test]
fn missing_tools_zero_and_oversized_requests_block() {
    let (snapshot, mut caps) = input();
    for size in [0, 8 * GIB + 1, u64::MAX] {
        let plan = plan_extend(&snapshot, &caps, request("/", Growth::ByBytes(size))).unwrap();
        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan.steps().is_empty());
    }
    caps.tools[0].available = false;
    assert_eq!(
        plan_extend(&snapshot, &caps, request("/", Growth::MaxFree))
            .unwrap()
            .status(),
        PlanStatus::Blocked
    );
}

#[test]
fn plan_id_is_repeatable_and_basis_changes_invalidate() {
    let (snapshot, caps) = input();
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    let again = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    assert_eq!(plan.plan_id(), again.plan_id());
    assert!(plan.matches_basis(&snapshot, &caps).unwrap());
    let mut changed = snapshot.clone();
    changed.lvm.as_mut().unwrap().volume_groups[0].free_bytes -= EXTENT;
    assert!(!plan.matches_basis(&changed, &caps).unwrap());
    let mut changed_caps = caps.clone();
    changed_caps.tools[0].available = false;
    assert!(!plan.matches_basis(&snapshot, &changed_caps).unwrap());
}

#[test]
fn validates_explicit_binary_units_without_float_conversion() {
    assert_eq!(parse_growth_size("8GiB").unwrap(), 8 * GIB);
    assert_eq!(parse_growth_size("1B").unwrap(), 1);
    assert_eq!(
        parse_growth_size("18446744073709551615B").unwrap(),
        u64::MAX
    );
    for value in [
        "8",
        "8GB",
        "0B",
        "1.5GiB",
        "-1GiB",
        "+1GiB",
        "1e3B",
        " 8GiB",
        "8GiB ",
        "18446744073709551616B",
        "18446744073709551615TiB",
    ] {
        assert!(parse_growth_size(value).is_err(), "accepted {value}");
    }
}

#[test]
fn lvm_preview_exposes_profile_preflight_and_future_gates() {
    let (snapshot, caps) = input();
    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();

    let checks = plan.preflight_checks();
    for code in [
        "collectors-complete",
        "diagnostics-clean",
        "mount-rw",
        "tooling-available",
        "lvm-identity-consistent",
        "lvm-layout-supported",
        "capacity-verified",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| { check.code == code && check.state == PreflightState::Verified }),
            "missing verified preflight check: {code}"
        );
    }
    assert!(checks.iter().any(|check| {
        check.code == "filesystem-health" && check.state == PreflightState::Required
    }));
    for code in [
        "filesystem-metadata-probe",
        "filesystem-version-observed",
        "filesystem-features-observed",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| check.code == code && check.state == PreflightState::Required),
            "missing required filesystem evidence gate: {code}"
        );
    }
}

#[test]
fn ext4_filesystem_evidence_upgrades_observable_preflight_checks() {
    let (mut snapshot, caps) = input();
    snapshot
        .filesystem_preflight
        .push(FilesystemPreflightEvidence {
            device: "/dev/mapper/vg0-root".into(),
            mountpoint: Some("/".into()),
            fs_type: "ext4".into(),
            fs_version: Some("1.0".into()),
            state: FilesystemProbeState::Verified,
            filesystem_state: Some("clean".into()),
            revision: Some("1 (dynamic)".into()),
            features: vec![
                "has_journal".into(),
                "extent".into(),
                "64bit".into(),
                "metadata_csum".into(),
            ],
            grow_check_passed: None,
            detail: None,
        });

    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    let checks = plan.preflight_checks();

    for code in [
        "filesystem-metadata-probe",
        "filesystem-version-observed",
        "filesystem-features-observed",
        "ext4-superblock-state",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| check.code == code && check.state == PreflightState::Verified),
            "missing verified filesystem evidence check: {code}"
        );
    }
    assert!(checks.iter().any(|check| {
        check.code == "filesystem-health" && check.state == PreflightState::Required
    }));
}

#[test]
fn xfs_read_only_grow_probe_is_exposed_as_verified_preflight() {
    let (mut snapshot, caps) = input();
    snapshot.storage.block_devices[0].children[0].children[0]
        .filesystem
        .as_mut()
        .unwrap()
        .fs_type = "xfs".into();
    snapshot.mounts[0].fs_type = Some("xfs".into());
    snapshot
        .filesystem_preflight
        .push(FilesystemPreflightEvidence {
            device: "/dev/mapper/vg0-root".into(),
            mountpoint: Some("/".into()),
            fs_type: "xfs".into(),
            fs_version: Some("5".into()),
            state: FilesystemProbeState::Verified,
            filesystem_state: None,
            revision: None,
            features: vec!["crc=1".into(), "reflink=1".into(), "bigtime=1".into()],
            grow_check_passed: Some(true),
            detail: None,
        });

    let plan = plan_extend(&snapshot, &caps, request("/", Growth::MaxFree)).unwrap();
    let checks = plan.preflight_checks();

    assert!(checks.iter().any(|check| {
        check.code == "xfs-grow-dry-run" && check.state == PreflightState::Verified
    }));
    assert!(checks.iter().any(|check| {
        check.code == "filesystem-health" && check.state == PreflightState::Required
    }));
}

#[test]
fn catalog_exposes_selectable_growth_targets_without_mutation() {
    let (snapshot, caps) = input();
    let before = snapshot.clone();

    let targets = list_extend_targets(&snapshot, &caps);

    assert_eq!(snapshot, before);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].target, "/");
    assert_eq!(targets[0].device, "/dev/mapper/vg0-root");
    assert_eq!(targets[0].filesystem, "ext4");
    assert_eq!(targets[0].kind, ExtendTargetKind::LvmLogicalVolume);
    assert_eq!(
        targets[0].availability,
        ExtendTargetAvailability::PreviewReady
    );
    assert_eq!(targets[0].verified_growth_bytes, Some(8 * GIB));
}

#[test]
fn catalog_exposes_free_vg_space_for_future_create_workflows() {
    let (snapshot, _caps) = input();

    let spaces = list_provisioning_opportunities(&snapshot);

    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].kind, ProvisioningSpaceKind::LvmFreeExtents);
    assert_eq!(spaces[0].source, "VG vg0");
    assert_eq!(spaces[0].available_bytes, 8 * GIB);
    assert!(spaces[0].advisory_only);
    assert!(spaces[0]
        .future_actions
        .iter()
        .any(|action| action.contains("logical volume")));
}

fn with_gpt_tail(mut snapshot: HostSnapshot) -> HostSnapshot {
    let partition_size = 16 * GIB + EXTENT;
    let sector = 512_u64;
    let start = 2048_u64;
    let disk_sectors = snapshot.storage.block_devices[0].size_bytes / sector;
    snapshot.storage.block_devices[0].children[0].parent_kernel_name = Some("vda".into());
    snapshot.partition_tables = vec![lsm_core::PartitionTable {
        device: "/dev/vda".into(),
        label: Some("gpt".into()),
        id: Some("gpt-test".into()),
        unit: Some("sectors".into()),
        first_lba: Some(34),
        last_lba: Some(disk_sectors - 34),
        sector_size_bytes: Some(sector),
        partitions: vec![lsm_core::PartitionRecord {
            node: "/dev/vda1".into(),
            start_sector: start,
            size_sectors: partition_size / sector,
            partition_type: Some("E6D6D379-F507-44C2-A23C-238F2A3DF928".into()),
            uuid: Some("part-1".into()),
            name: None,
            attrs: None,
            bootable: None,
        }],
    }];
    snapshot
}

#[test]
fn chained_lvm_route_uses_partition_tail_when_vg_free_is_insufficient() {
    let (snapshot, caps) = input();
    let snapshot = with_gpt_tail(snapshot);
    let request = request("/", Growth::ByBytes(10 * GIB));

    let route = analyze_lvm_underlying_growth(&snapshot, &request)
        .expect("expected chained LVM growth opportunity");

    assert_eq!(route.partition.as_deref(), Some("/dev/vda1"));
    assert_eq!(route.physical_volume, "/dev/vda1");
    assert_eq!(route.volume_group, "vg0");
    assert_eq!(route.logical_volume, "/dev/vg0/root");
    assert_eq!(route.existing_vg_free_bytes, 8 * GIB);
    assert!(route.pv_device_slack_bytes >= EXTENT);
    assert!(route.adjacent_partition_free_bytes > 2 * GIB);
    assert!(route.max_growth_bytes >= 10 * GIB);
    assert!(route.required_partition_growth_bytes > 0);
    assert!(route
        .steps
        .iter()
        .any(|step| step.contains("resize LVM PV")));

    let plan = plan_extend(&snapshot, &caps, request).unwrap();
    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert_eq!(plan.growth_route_alternatives().len(), 1);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "insufficient-capacity"));
}

#[test]
fn max_target_catalog_includes_verified_lvm_underlying_route_capacity() {
    let (snapshot, caps) = input();
    let snapshot = with_gpt_tail(snapshot);

    let targets = list_extend_targets(&snapshot, &caps);

    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].availability,
        ExtendTargetAvailability::PreviewReady
    );
    assert_eq!(targets[0].verified_growth_bytes, Some(8 * GIB));
    assert!(targets[0].layout_growth_bytes.unwrap() > 8 * GIB);
}

#[test]
fn chained_lvm_route_handles_pv_directly_on_an_enlarged_disk() {
    let (mut snapshot, caps) = input();
    let lv_device = snapshot.storage.block_devices[0].children[0]
        .children
        .remove(0);
    let disk = &mut snapshot.storage.block_devices[0];
    disk.children = vec![lv_device];
    disk.filesystem = Some(lsm_core::Filesystem {
        fs_type: "LVM2_member".into(),
        version: None,
    });
    disk.uuid = Some("pv-1".into());

    let lvm = snapshot.lvm.as_mut().unwrap();
    lvm.physical_volumes[0].name = "/dev/vda".into();
    lvm.physical_volumes[0].size_bytes = 18 * GIB;
    lvm.physical_volumes[0].free_bytes = 10 * GIB;
    lvm.volume_groups[0].size_bytes = 18 * GIB;
    lvm.volume_groups[0].free_bytes = 10 * GIB;
    lvm.volume_groups[0].free_extent_count = Some((10 * GIB) / EXTENT);

    let request = request("/", Growth::ByBytes(11 * GIB));
    let route = analyze_lvm_underlying_growth(&snapshot, &request)
        .expect("expected direct-disk PV growth opportunity");

    assert_eq!(route.disk, "/dev/vda");
    assert_eq!(route.partition, None);
    assert_eq!(route.physical_volume, "/dev/vda");
    assert_eq!(route.pv_device_slack_bytes, 2 * GIB);
    assert_eq!(route.required_partition_growth_bytes, 0);
    assert!(route.max_growth_bytes >= 11 * GIB);
    assert_eq!(route.code, "grow-pv-lv-filesystem");

    let plan = plan_extend(&snapshot, &caps, request).unwrap();
    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert_eq!(plan.growth_route_alternatives().len(), 1);
}

#[test]
fn create_catalog_reports_internal_gpt_gap_with_exact_geometry() {
    let (mut snapshot, _caps) = input();
    let sector = 512_u64;
    let disk_sectors = snapshot.storage.block_devices[0].size_bytes / sector;
    let first_start = 2048_u64;
    let first_size = 2 * GIB / sector;
    let second_start = 8 * GIB / sector;
    let second_size = 2 * GIB / sector;
    let expected_gap_start = first_start + first_size;
    let expected_gap_sectors = second_start - expected_gap_start;

    snapshot.partition_tables = vec![lsm_core::PartitionTable {
        device: "/dev/vda".into(),
        label: Some("gpt".into()),
        id: Some("gpt-gap-test".into()),
        unit: Some("sectors".into()),
        first_lba: Some(34),
        last_lba: Some(disk_sectors - 34),
        sector_size_bytes: Some(sector),
        partitions: vec![
            lsm_core::PartitionRecord {
                node: "/dev/vda1".into(),
                start_sector: first_start,
                size_sectors: first_size,
                partition_type: Some("8300".into()),
                uuid: Some("part-1".into()),
                name: None,
                attrs: None,
                bootable: None,
            },
            lsm_core::PartitionRecord {
                node: "/dev/vda2".into(),
                start_sector: second_start,
                size_sectors: second_size,
                partition_type: Some("8300".into()),
                uuid: Some("part-2".into()),
                name: None,
                attrs: None,
                bootable: None,
            },
        ],
    }];

    let spaces = list_provisioning_opportunities(&snapshot);
    let gap = spaces
        .iter()
        .find(|space| {
            space.kind == ProvisioningSpaceKind::DiskGap
                && space.start_sector == Some(expected_gap_start)
        })
        .expect("expected internal GPT free range");

    assert_eq!(gap.sector_size_bytes, Some(sector));
    assert_eq!(gap.sector_count, Some(expected_gap_sectors));
    assert_eq!(gap.available_bytes, expected_gap_sectors * sector);
    assert!(gap.advisory_only);
    assert!(gap
        .blockers
        .iter()
        .any(|blocker| blocker.contains("alignment")));

    let tail = spaces
        .iter()
        .find(|space| space.kind == ProvisioningSpaceKind::DiskTail)
        .expect("expected GPT tail range");
    assert!(tail.start_sector.unwrap() > second_start);
}

#[test]
fn create_catalog_exposes_empty_gpt_usable_range_without_calling_it_blank() {
    let (mut snapshot, _caps) = input();
    let sector = 512_u64;
    let disk_sectors = snapshot.storage.block_devices[0].size_bytes / sector;
    snapshot.storage.block_devices[0].children.clear();
    snapshot.lvm = None;
    snapshot.partition_tables = vec![lsm_core::PartitionTable {
        device: "/dev/vda".into(),
        label: Some("gpt".into()),
        id: Some("gpt-empty-test".into()),
        unit: Some("sectors".into()),
        first_lba: Some(34),
        last_lba: Some(disk_sectors - 34),
        sector_size_bytes: Some(sector),
        partitions: vec![],
    }];

    let spaces = list_provisioning_opportunities(&snapshot);

    assert_eq!(spaces.len(), 1);
    assert_eq!(spaces[0].kind, ProvisioningSpaceKind::DiskGap);
    assert_eq!(spaces[0].start_sector, Some(34));
    assert_eq!(spaces[0].sector_count, Some((disk_sectors - 33) - 34));
}

#[test]
fn dos_extended_container_hides_its_internal_logical_space_from_generic_create() {
    let (mut snapshot, _caps) = input();
    let sector = 512_u64;
    let primary_start = 2048_u64;
    let primary_size = 2 * GIB / sector;
    let extended_start = 6 * GIB / sector;
    let extended_size = 8 * GIB / sector;
    let logical_start = extended_start + 2048;
    let logical_size = 2 * GIB / sector;

    snapshot.partition_tables = vec![lsm_core::PartitionTable {
        device: "/dev/vda".into(),
        label: Some("dos".into()),
        id: Some("0x12345678".into()),
        unit: Some("sectors".into()),
        first_lba: None,
        last_lba: None,
        sector_size_bytes: Some(sector),
        partitions: vec![
            lsm_core::PartitionRecord {
                node: "/dev/vda1".into(),
                start_sector: primary_start,
                size_sectors: primary_size,
                partition_type: Some("83".into()),
                uuid: None,
                name: None,
                attrs: None,
                bootable: Some(false),
            },
            lsm_core::PartitionRecord {
                node: "/dev/vda2".into(),
                start_sector: extended_start,
                size_sectors: extended_size,
                partition_type: Some("5".into()),
                uuid: None,
                name: None,
                attrs: None,
                bootable: Some(false),
            },
            lsm_core::PartitionRecord {
                node: "/dev/vda5".into(),
                start_sector: logical_start,
                size_sectors: logical_size,
                partition_type: Some("82".into()),
                uuid: None,
                name: None,
                attrs: None,
                bootable: Some(false),
            },
        ],
    }];

    let extended_end = extended_start + extended_size;
    let primary_end = primary_start + primary_size;
    let spaces = list_provisioning_opportunities(&snapshot);

    assert!(!spaces.iter().any(|space| {
        space.kind == ProvisioningSpaceKind::DiskGap
            && space.start_sector.is_some_and(|start| start < primary_end)
    }));
    assert!(!spaces.iter().any(|space| {
        space.kind == ProvisioningSpaceKind::DiskGap
            && space
                .start_sector
                .is_some_and(|start| start >= extended_start && start < extended_end)
    }));
    assert!(spaces
        .iter()
        .filter(|space| {
            matches!(
                space.kind,
                ProvisioningSpaceKind::DiskGap | ProvisioningSpaceKind::DiskTail
            )
        })
        .all(|space| {
            space
                .blockers
                .iter()
                .any(|blocker| blocker.contains("DOS/MBR"))
        }));
}

#[test]
fn scenario_contract_keeps_multiple_filesystem_targets_selectable() {
    let (mut snapshot, mut caps) = input();
    let sector = 512_u64;
    let first_start = 2048_u64;
    let first_size = 16 * GIB + EXTENT;
    let first_size_sectors = first_size / sector;
    let second_start = first_start + first_size_sectors + 2048;
    let second_size = GIB;
    let second_size_sectors = second_size / sector;
    let disk_sectors = snapshot.storage.block_devices[0].size_bytes / sector;

    let var_device: lsm_core::BlockDevice = serde_json::from_value(json!({
        "name":"vda2", "kernel_name":"vda2", "path":"/dev/vda2", "kind":"partition",
        "size_bytes":second_size, "start_512_sector":second_start,
        "logical_sector_bytes":sector, "uuid":"var-fs", "partition_uuid":"var-part",
        "partition_table":"gpt",
        "filesystem":{"fs_type":"ext4","version":"1.0"},
        "mountpoints":["/var"], "parent_kernel_name":"vda", "children":[]
    }))
    .unwrap();
    snapshot.storage.block_devices[0].children.push(var_device);
    snapshot.mounts.push(
        serde_json::from_value(json!({
            "source":"/dev/vda2","target":"/var","fs_type":"ext4","options":["rw","relatime"]
        }))
        .unwrap(),
    );
    snapshot.partition_tables = vec![lsm_core::PartitionTable {
        device: "/dev/vda".into(),
        label: Some("gpt".into()),
        id: Some("multi-target-gpt".into()),
        unit: Some("sectors".into()),
        first_lba: Some(34),
        last_lba: Some(disk_sectors - 34),
        sector_size_bytes: Some(sector),
        partitions: vec![
            lsm_core::PartitionRecord {
                node: "/dev/vda1".into(),
                start_sector: first_start,
                size_sectors: first_size_sectors,
                partition_type: Some("E6D6D379-F507-44C2-A23C-238F2A3DF928".into()),
                uuid: Some("pv-part".into()),
                name: None,
                attrs: None,
                bootable: None,
            },
            lsm_core::PartitionRecord {
                node: "/dev/vda2".into(),
                start_sector: second_start,
                size_sectors: second_size_sectors,
                partition_type: Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4".into()),
                uuid: Some("var-part".into()),
                name: None,
                attrs: None,
                bootable: None,
            },
        ],
    }];
    caps.tools.push(lsm_core::ToolCapability {
        name: "sfdisk".into(),
        available: true,
    });

    let targets = list_extend_targets(&snapshot, &caps);

    assert_eq!(targets.len(), 2);
    assert!(targets.iter().any(|target| {
        target.target == "/"
            && target.kind == ExtendTargetKind::LvmLogicalVolume
            && target.availability == ExtendTargetAvailability::PreviewReady
    }));
    assert!(targets.iter().any(|target| {
        target.target == "/var"
            && target.kind == ExtendTargetKind::DirectPartition
            && target.availability == ExtendTargetAvailability::PreviewReady
    }));
}

#[test]
fn scenario_contract_keeps_unknown_filesystem_visible_but_blocked() {
    let (mut snapshot, caps) = input();
    snapshot.storage.block_devices[0].children[0].children[0]
        .filesystem
        .as_mut()
        .unwrap()
        .fs_type = "mysteryfs".into();
    snapshot.mounts[0].fs_type = Some("mysteryfs".into());

    let targets = list_extend_targets(&snapshot, &caps);

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].target, "/");
    assert_eq!(targets[0].filesystem, "mysteryfs");
    assert_eq!(targets[0].availability, ExtendTargetAvailability::Blocked);
    assert!(targets[0].reason.contains("filesystem"));
}

#[test]
fn create_plan_accepts_unique_source_id_prefix() {
    let (snapshot, _caps) = input();
    let source = list_provisioning_opportunities(&snapshot)
        .into_iter()
        .find(|space| space.kind == ProvisioningSpaceKind::LvmFreeExtents)
        .unwrap();
    let prefix = source.id[..16].to_owned();

    let plan = plan_create(
        &snapshot,
        CreateRequest {
            source_id: prefix,
            size: Growth::ByBytes(GIB),
            purpose: CreatePurpose::Filesystem,
            filesystem: Some("ext4".into()),
            mountpoint: None,
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    assert_eq!(plan.source().unwrap().id, source.id);
}

#[test]
fn create_plan_builds_extent_aligned_filesystem_volume_from_vg_free_space() {
    let (snapshot, _caps) = input();
    let source = list_provisioning_opportunities(&snapshot)
        .into_iter()
        .find(|space| space.kind == ProvisioningSpaceKind::LvmFreeExtents)
        .expect("expected VG free source");

    let plan = plan_create(
        &snapshot,
        CreateRequest {
            source_id: source.id,
            size: Growth::ByBytes(GIB),
            purpose: CreatePurpose::Filesystem,
            filesystem: Some("ext4".into()),
            mountpoint: Some("/data".into()),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let allocation = plan.allocation().expect("allocation must be frozen");
    assert_eq!(allocation.requested_bytes, GIB);
    assert_eq!(allocation.rounded_bytes, GIB);
    assert_eq!(allocation.allocation_unit_bytes, EXTENT);
    assert_eq!(allocation.volume_group.as_deref(), Some("vg0"));
    assert!(plan
        .steps()
        .iter()
        .any(|step| step.contains("logical volume")));
    assert!(plan.steps().iter().any(|step| step.contains("ext4")));
    assert!(plan.steps().iter().any(|step| step.contains("/data")));
}

#[test]
fn create_plan_builds_sector_aligned_partition_filesystem_from_gpt_tail() {
    let (snapshot, _caps) = input();
    let snapshot = with_gpt_tail(snapshot);
    let source = list_provisioning_opportunities(&snapshot)
        .into_iter()
        .find(|space| space.kind == ProvisioningSpaceKind::DiskTail)
        .expect("expected GPT tail source");

    let plan = plan_create(
        &snapshot,
        CreateRequest {
            source_id: source.id,
            size: Growth::ByBytes(GIB + 1),
            purpose: CreatePurpose::Filesystem,
            filesystem: Some("xfs".into()),
            mountpoint: Some("/srv/data".into()),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let allocation = plan.allocation().unwrap();
    assert_eq!(allocation.allocation_unit_bytes, 512);
    assert_eq!(allocation.rounded_bytes, GIB + 512);
    assert!(allocation.start_sector.is_some());
    assert!(allocation.sector_count.is_some());
    assert!(plan
        .steps()
        .iter()
        .any(|step| step.contains("new partition")));
    assert!(plan.steps().iter().any(|step| step.contains("xfs")));
}

#[test]
fn create_plan_blocks_conflicting_mountpoint_and_invalid_swap_options() {
    let (snapshot, _caps) = input();
    let source = list_provisioning_opportunities(&snapshot)
        .into_iter()
        .find(|space| space.kind == ProvisioningSpaceKind::LvmFreeExtents)
        .unwrap();

    let conflict = plan_create(
        &snapshot,
        CreateRequest {
            source_id: source.id.clone(),
            size: Growth::ByBytes(GIB),
            purpose: CreatePurpose::Filesystem,
            filesystem: Some("ext4".into()),
            mountpoint: Some("/".into()),
        },
    )
    .unwrap();
    assert_eq!(conflict.status(), PlanStatus::Blocked);
    assert!(conflict
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "create-mountpoint-invalid"));

    let swap = plan_create(
        &snapshot,
        CreateRequest {
            source_id: source.id,
            size: Growth::ByBytes(512 * 1024 * 1024),
            purpose: CreatePurpose::Swap,
            filesystem: Some("ext4".into()),
            mountpoint: None,
        },
    )
    .unwrap();
    assert_eq!(swap.status(), PlanStatus::Blocked);
    assert!(swap
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "create-swap-options-invalid"));
}
