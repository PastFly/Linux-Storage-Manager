use lsm_core::{
    BlockDevice, CollectorState, CollectorStatus, Filesystem, HostCapabilities, HostSnapshot,
    MountEntry, NodeKind, PartitionRecord, PartitionTable, StorageGraph, ToolCapability,
};
use lsm_planner::{
    analyze_layout_opportunity, list_extend_targets, plan_extend, ExtendRequest,
    ExtendTargetAvailability, ExtendTargetKind, Growth, PlanStatus, PreflightState,
};

fn device(
    name: &str,
    kind: NodeKind,
    size_bytes: u64,
    start_512_sector: Option<u64>,
    parent: Option<&str>,
) -> BlockDevice {
    BlockDevice {
        name: name.into(),
        kernel_name: Some(name.into()),
        path: Some(format!("/dev/{name}")),
        kind,
        size_bytes,
        start_512_sector,
        logical_sector_bytes: Some(512),
        filesystem: None,
        mountpoints: Vec::new(),
        parent_kernel_name: parent.map(str::to_owned),
        model: None,
        serial: None,
        uuid: None,
        partition_uuid: None,
        partition_table: Some("dos".into()),
        children: Vec::new(),
    }
}

fn live_debian_snapshot() -> HostSnapshot {
    let mut disk = device("sda", NodeKind::Disk, 10_737_418_240, None, None);

    let mut root = device(
        "sda1",
        NodeKind::Partition,
        9_711_910_912,
        Some(2_048),
        Some("sda"),
    );
    root.filesystem = Some(Filesystem {
        fs_type: "ext4".into(),
        version: Some("1.0".into()),
    });
    root.mountpoints = vec!["/".into()];
    root.uuid = Some("042edc87-45f0-4634-ad09-7c228a600fbf".into());
    root.partition_uuid = Some("f5b1b569-01".into());

    let mut extended = device(
        "sda2",
        NodeKind::Partition,
        1_024,
        Some(18_972_670),
        Some("sda"),
    );
    extended.partition_uuid = Some("f5b1b569-02".into());

    let mut swap = device(
        "sda5",
        NodeKind::Partition,
        1_022_361_600,
        Some(18_972_672),
        Some("sda"),
    );
    swap.filesystem = Some(Filesystem {
        fs_type: "swap".into(),
        version: Some("1".into()),
    });
    swap.mountpoints = vec!["[SWAP]".into()];
    swap.uuid = Some("a2f7942e-9329-4367-a8cc-33b8a928aed0".into());
    swap.partition_uuid = Some("f5b1b569-05".into());

    disk.children = vec![root, extended, swap];

    HostSnapshot {
        storage: StorageGraph {
            block_devices: vec![disk],
        },
        partition_tables: vec![PartitionTable {
            device: "/dev/sda".into(),
            label: Some("dos".into()),
            id: Some("0xf5b1b569".into()),
            unit: Some("sectors".into()),
            first_lba: None,
            last_lba: None,
            sector_size_bytes: Some(512),
            partitions: vec![
                PartitionRecord {
                    node: "/dev/sda1".into(),
                    start_sector: 2_048,
                    size_sectors: 18_968_576,
                    partition_type: Some("83".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: Some(true),
                },
                PartitionRecord {
                    node: "/dev/sda2".into(),
                    start_sector: 18_972_670,
                    size_sectors: 1_996_802,
                    partition_type: Some("5".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
                PartitionRecord {
                    node: "/dev/sda5".into(),
                    start_sector: 18_972_672,
                    size_sectors: 1_996_800,
                    partition_type: Some("82".into()),
                    uuid: None,
                    name: None,
                    attrs: None,
                    bootable: None,
                },
            ],
        }],
        mounts: vec![MountEntry {
            source: Some("/dev/sda1".into()),
            target: "/".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into(), "relatime".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: vec![
            complete("lsblk"),
            complete("partition_tables"),
            complete("mounts"),
            complete("fstab"),
            complete("swap"),
            CollectorStatus {
                component: "lvm".into(),
                state: CollectorState::Unavailable,
                detail: Some("LVM tools unavailable".into()),
            },
        ],
    }
}

fn with_second_nvme_disk(mut snapshot: HostSnapshot) -> HostSnapshot {
    const MIB: u64 = 1024 * 1024;
    let sector = 512_u64;
    let mut disk = device("nvme1n1", NodeKind::Disk, 64 * MIB, None, None);
    disk.partition_table = Some("gpt".into());

    let mut data = device(
        "nvme1n1p1",
        NodeKind::Partition,
        32 * MIB,
        Some(2_048),
        Some("nvme1n1"),
    );
    data.partition_table = Some("gpt".into());
    data.filesystem = Some(Filesystem {
        fs_type: "ext4".into(),
        version: Some("1.0".into()),
    });
    data.mountpoints = vec!["/data".into()];
    data.uuid = Some("nvme-data-fs".into());
    data.partition_uuid = Some("nvme-data-part".into());
    disk.children = vec![data];

    let disk_sectors = disk.size_bytes / sector;
    snapshot.storage.block_devices.push(disk);
    snapshot.partition_tables.push(PartitionTable {
        device: "/dev/nvme1n1".into(),
        label: Some("gpt".into()),
        id: Some("nvme-multi-disk-gpt".into()),
        unit: Some("sectors".into()),
        first_lba: Some(34),
        last_lba: Some(disk_sectors - 34),
        sector_size_bytes: Some(sector),
        partitions: vec![PartitionRecord {
            node: "/dev/nvme1n1p1".into(),
            start_sector: 2_048,
            size_sectors: (32 * MIB) / sector,
            partition_type: Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4".into()),
            uuid: Some("nvme-data-part".into()),
            name: None,
            attrs: None,
            bootable: None,
        }],
    });
    snapshot.mounts.push(MountEntry {
        source: Some("/dev/nvme1n1p1".into()),
        target: "/data".into(),
        fs_type: Some("ext4".into()),
        options: vec!["rw".into(), "relatime".into()],
    });
    snapshot
}

fn gpt_ext4_snapshot(partition_type: Option<&str>) -> HostSnapshot {
    const MIB: u64 = 1024 * 1024;
    let sector = 512_u64;
    let mut disk = device("vdb", NodeKind::Disk, 64 * MIB, None, None);
    disk.partition_table = Some("gpt".into());

    let mut boot = device(
        "vdb1",
        NodeKind::Partition,
        32 * MIB,
        Some(2_048),
        Some("vdb"),
    );
    boot.partition_table = Some("gpt".into());
    boot.filesystem = Some(Filesystem {
        fs_type: "ext4".into(),
        version: Some("1.0".into()),
    });
    boot.mountpoints = vec!["/boot-test".into()];
    boot.uuid = Some("boot-test-fs".into());
    boot.partition_uuid = Some("boot-test-part".into());
    disk.children = vec![boot];

    let disk_sectors = disk.size_bytes / sector;
    HostSnapshot {
        storage: StorageGraph {
            block_devices: vec![disk],
        },
        partition_tables: vec![PartitionTable {
            device: "/dev/vdb".into(),
            label: Some("gpt".into()),
            id: Some("boot-role-gpt".into()),
            unit: Some("sectors".into()),
            first_lba: Some(34),
            last_lba: Some(disk_sectors - 34),
            sector_size_bytes: Some(sector),
            partitions: vec![PartitionRecord {
                node: "/dev/vdb1".into(),
                start_sector: 2_048,
                size_sectors: (32 * MIB) / sector,
                partition_type: partition_type.map(str::to_owned),
                uuid: Some("boot-test-part".into()),
                name: None,
                attrs: None,
                bootable: None,
            }],
        }],
        mounts: vec![MountEntry {
            source: Some("/dev/vdb1".into()),
            target: "/boot-test".into(),
            fs_type: Some("ext4".into()),
            options: vec!["rw".into(), "relatime".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: vec![
            complete("lsblk"),
            complete("partition_tables"),
            complete("mounts"),
            complete("fstab"),
            complete("swap"),
        ],
    }
}

fn complete(component: &str) -> CollectorStatus {
    CollectorStatus {
        component: component.into(),
        state: CollectorState::Complete,
        detail: None,
    }
}

fn capabilities() -> HostCapabilities {
    HostCapabilities {
        tools: vec![
            ToolCapability {
                name: "sfdisk".into(),
                available: true,
            },
            ToolCapability {
                name: "resize2fs".into(),
                available: true,
            },
            ToolCapability {
                name: "xfs_growfs".into(),
                available: false,
            },
        ],
    }
}

#[test]
fn direct_dos_partition_max_free_builds_nonexecutable_preview() {
    let plan = plan_extend(
        &live_debian_snapshot(),
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let change = plan
        .partition_size_change()
        .expect("direct partition preview must expose partition size change");
    assert_eq!(change.device, "/dev/sda1");
    assert_eq!(change.requested_growth_bytes, 1_047_552);
    assert_eq!(change.rounded_growth_bytes, 1_047_552);
    assert_eq!(change.expected_partition_size_bytes, 9_712_958_464);
    assert_eq!(change.remaining_adjacent_free_bytes, 0);
    assert_eq!(plan.steps().len(), 5);
}

#[test]
fn direct_partition_device_alias_matches_mountpoint_geometry() {
    let snapshot = live_debian_snapshot();
    let caps = capabilities();

    let by_mount = plan_extend(
        &snapshot,
        &caps,
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();
    let by_device = plan_extend(
        &snapshot,
        &caps,
        ExtendRequest {
            target: "/dev/sda1".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(by_mount.status(), PlanStatus::Preview);
    assert_eq!(by_device.status(), PlanStatus::Preview);
    assert_eq!(
        by_mount.partition_size_change(),
        by_device.partition_size_change()
    );
    assert_eq!(by_mount.steps(), by_device.steps());
}

#[test]
fn multi_disk_catalog_keeps_sata_and_nvme_targets_isolated() {
    let snapshot = with_second_nvme_disk(live_debian_snapshot());
    let caps = capabilities();

    let targets = list_extend_targets(&snapshot, &caps);

    assert_eq!(targets.len(), 2);
    assert!(targets.iter().any(|target| {
        target.target == "/"
            && target.device == "/dev/sda1"
            && target.kind == ExtendTargetKind::DirectPartition
            && target.availability == ExtendTargetAvailability::PreviewReady
    }));
    assert!(targets.iter().any(|target| {
        target.target == "/data"
            && target.device == "/dev/nvme1n1p1"
            && target.kind == ExtendTargetKind::DirectPartition
            && target.availability == ExtendTargetAvailability::PreviewReady
    }));
}

#[test]
fn unrelated_nvme_disk_does_not_change_selected_sata_growth_geometry() {
    let baseline = live_debian_snapshot();
    let multi_disk = with_second_nvme_disk(baseline.clone());
    let caps = capabilities();

    let before = plan_extend(
        &baseline,
        &caps,
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();
    let after = plan_extend(
        &multi_disk,
        &caps,
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(before.status(), PlanStatus::Preview);
    assert_eq!(after.status(), PlanStatus::Preview);
    assert_eq!(
        before.partition_size_change(),
        after.partition_size_change()
    );
    assert_eq!(before.steps(), after.steps());
}

#[test]
fn nvme_target_resolves_identically_by_mountpoint_and_partition_path() {
    let snapshot = with_second_nvme_disk(live_debian_snapshot());
    let caps = capabilities();

    let by_mount = plan_extend(
        &snapshot,
        &caps,
        ExtendRequest {
            target: "/data".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();
    let by_device = plan_extend(
        &snapshot,
        &caps,
        ExtendRequest {
            target: "/dev/nvme1n1p1".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(by_mount.status(), PlanStatus::Preview);
    assert_eq!(by_device.status(), PlanStatus::Preview);
    assert_eq!(
        by_mount
            .partition_size_change()
            .expect("NVMe target must expose partition growth")
            .device,
        "/dev/nvme1n1p1"
    );
    assert_eq!(
        by_mount.partition_size_change(),
        by_device.partition_size_change()
    );
    assert_eq!(by_mount.steps(), by_device.steps());
}

#[test]
fn protected_gpt_boot_partition_types_never_enter_generic_growth() {
    for partition_type in [
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        "21686148-6449-6E6F-744E-656564454649",
        "BC13C2FF-59E6-4262-A352-B275FD6F7172",
    ] {
        let plan = plan_extend(
            &gpt_ext4_snapshot(Some(partition_type)),
            &capabilities(),
            ExtendRequest {
                target: "/boot-test".into(),
                growth: Growth::MaxFree,
            },
        )
        .unwrap();

        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan
            .blockers()
            .iter()
            .any(|blocker| blocker.code == "protected-partition-role"));
        assert!(plan.partition_size_change().is_none());
    }
}

#[test]
fn protected_mbr_boot_partition_types_never_enter_generic_growth() {
    for partition_type in ["ea", "ef"] {
        let mut snapshot = live_debian_snapshot();
        snapshot.partition_tables[0].partitions[0].partition_type = Some(partition_type.to_owned());

        let plan = plan_extend(
            &snapshot,
            &capabilities(),
            ExtendRequest {
                target: "/".into(),
                growth: Growth::MaxFree,
            },
        )
        .unwrap();

        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan
            .blockers()
            .iter()
            .any(|blocker| blocker.code == "protected-partition-role"));
        assert!(plan.partition_size_change().is_none());
    }
}

#[test]
fn gpt_partition_type_must_be_present_and_well_formed_before_growth() {
    for partition_type in [None, Some("not-a-guid")] {
        let plan = plan_extend(
            &gpt_ext4_snapshot(partition_type),
            &capabilities(),
            ExtendRequest {
                target: "/boot-test".into(),
                growth: Growth::MaxFree,
            },
        )
        .unwrap();

        assert_eq!(plan.status(), PlanStatus::Blocked);
        assert!(plan.blockers().iter().any(|blocker| {
            matches!(
                blocker.code.as_str(),
                "partition-type-missing" | "invalid-partition-type"
            )
        }));
        assert!(plan.partition_size_change().is_none());
    }
}

#[test]
fn ordinary_linux_gpt_partition_remains_growable_after_role_guard() {
    let plan = plan_extend(
        &gpt_ext4_snapshot(Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4")),
        &capabilities(),
        ExtendRequest {
            target: "/boot-test".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    assert_eq!(
        plan.partition_size_change()
            .expect("ordinary Linux GPT partition must remain growable")
            .device,
        "/dev/vdb1"
    );
}

#[test]
fn unknown_partition_table_label_blocks_direct_growth_with_explicit_reason() {
    let mut snapshot = gpt_ext4_snapshot(Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4"));
    snapshot.partition_tables[0].label = Some("sun".into());

    let plan = plan_extend(
        &snapshot,
        &capabilities(),
        ExtendRequest {
            target: "/boot-test".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "unsupported-partition-table"));
    assert!(plan.partition_size_change().is_none());
}

#[test]
fn direct_partition_request_larger_than_verified_gap_is_blocked() {
    let plan = plan_extend(
        &live_debian_snapshot(),
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::ByBytes(2 * 1024 * 1024),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "insufficient-adjacent-capacity"));
    assert!(plan.partition_size_change().is_none());
}

#[test]
fn direct_gpt_xfs_4k_partition_rounds_growth_to_logical_sector() {
    let mut disk = device("nvme0n1", NodeKind::Disk, 64 * 1024 * 1024, None, None);
    disk.logical_sector_bytes = Some(4096);
    disk.partition_table = Some("gpt".into());

    let mut data = device(
        "nvme0n1p1",
        NodeKind::Partition,
        32 * 1024 * 1024,
        Some(2_048),
        Some("nvme0n1"),
    );
    data.logical_sector_bytes = Some(4096);
    data.partition_table = Some("gpt".into());
    data.filesystem = Some(Filesystem {
        fs_type: "xfs".into(),
        version: Some("5".into()),
    });
    data.mountpoints = vec!["/data".into()];
    data.uuid = Some("xfs-fs-uuid".into());
    data.partition_uuid = Some("gpt-part-uuid".into());
    disk.children = vec![data];

    let snapshot = HostSnapshot {
        storage: StorageGraph {
            block_devices: vec![disk],
        },
        partition_tables: vec![PartitionTable {
            device: "/dev/nvme0n1".into(),
            label: Some("gpt".into()),
            id: Some("gpt-disk-id".into()),
            unit: Some("sectors".into()),
            first_lba: Some(6),
            last_lba: Some(16_378),
            sector_size_bytes: Some(4096),
            partitions: vec![PartitionRecord {
                node: "/dev/nvme0n1p1".into(),
                start_sector: 256,
                size_sectors: 8_192,
                partition_type: Some("0FC63DAF-8483-4772-8E79-3D69D8477DE4".into()),
                uuid: Some("gpt-part-uuid".into()),
                name: None,
                attrs: None,
                bootable: None,
            }],
        }],
        mounts: vec![MountEntry {
            source: Some("/dev/nvme0n1p1".into()),
            target: "/data".into(),
            fs_type: Some("xfs".into()),
            options: vec!["rw".into()],
        }],
        fstab: Vec::new(),
        swaps: Vec::new(),
        lvm: None,
        filesystem_preflight: Vec::new(),
        diagnostics: Vec::new(),
        collectors: vec![
            complete("lsblk"),
            complete("partition_tables"),
            complete("mounts"),
            complete("fstab"),
            complete("swap"),
            CollectorStatus {
                component: "lvm".into(),
                state: CollectorState::Unavailable,
                detail: None,
            },
        ],
    };
    let caps = HostCapabilities {
        tools: vec![
            ToolCapability {
                name: "sfdisk".into(),
                available: true,
            },
            ToolCapability {
                name: "resize2fs".into(),
                available: false,
            },
            ToolCapability {
                name: "xfs_growfs".into(),
                available: true,
            },
        ],
    };

    let plan = plan_extend(
        &snapshot,
        &caps,
        ExtendRequest {
            target: "/data".into(),
            growth: Growth::ByBytes(1_000_000),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Preview);
    let change = plan.partition_size_change().unwrap();
    assert_eq!(change.sector_size_bytes, 4096);
    assert_eq!(change.requested_growth_bytes, 1_000_000);
    assert_eq!(change.rounded_growth_bytes, 1_003_520);
    assert_eq!(change.expected_partition_size_bytes, 34_557_952);
    assert_eq!(change.remaining_adjacent_free_bytes, 31_481_856);
}

#[test]
fn direct_partition_preview_exposes_verified_and_required_preflight() {
    let plan = plan_extend(
        &live_debian_snapshot(),
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    let checks = plan.preflight_checks();
    assert!(checks.iter().any(|check| {
        check.code == "partition-geometry-consistent" && check.state == PreflightState::Verified
    }));
    assert!(checks.iter().any(|check| {
        check.code == "adjacent-capacity-verified" && check.state == PreflightState::Verified
    }));
    for code in [
        "runtime-identity-recheck",
        "filesystem-health",
        "exclusive-lock",
        "metadata-backup",
        "execution-approval",
    ] {
        assert!(
            checks
                .iter()
                .any(|check| { check.code == code && check.state == PreflightState::Required }),
            "missing required preflight check: {code}"
        );
    }
}

#[test]
fn bind_mount_is_visible_but_blocked_from_generic_growth() {
    let mut snapshot = live_debian_snapshot();
    snapshot.mounts[0].options.push("bind".into());

    let plan = plan_extend(
        &snapshot,
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::MaxFree,
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "mount-state-mismatch"));
    assert!(plan.partition_size_change().is_none());
}

#[test]
fn blocked_direct_partition_plan_has_no_success_preflight() {
    let plan = plan_extend(
        &live_debian_snapshot(),
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::ByBytes(2 * 1024 * 1024),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan.preflight_checks().is_empty());
}

fn grown_live_debian_snapshot() -> HostSnapshot {
    let mut snapshot = live_debian_snapshot();
    snapshot.storage.block_devices[0].size_bytes = 11 * 1024 * 1024 * 1024;
    snapshot.swaps = vec![lsm_core::SwapEntry {
        name: "/dev/sda5".into(),
        kind: "partition".into(),
        size_bytes: 1_022_361_600,
        used_bytes: 0,
        priority: -2,
    }];
    snapshot
}

#[test]
fn one_gib_request_reports_tail_swap_layout_alternative() {
    let plan = plan_extend(
        &grown_live_debian_snapshot(),
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::ByBytes(1024 * 1024 * 1024),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan
        .blockers()
        .iter()
        .any(|blocker| blocker.code == "insufficient-adjacent-capacity"));

    let alternatives = plan.layout_alternatives();
    assert_eq!(alternatives.len(), 1);
    let alternative = &alternatives[0];
    assert_eq!(alternative.code, "migrate-tail-swap");
    assert_eq!(alternative.disk, "/dev/sda");
    assert_eq!(alternative.target, "/dev/sda1");
    assert_eq!(alternative.requested_growth_bytes, 1_073_741_824);
    assert_eq!(alternative.disk_tail_free_bytes, 1_074_790_400);
    assert_eq!(alternative.swap_bytes, 1_022_361_600);
    assert_eq!(alternative.required_partition_growth_bytes, 2_096_103_424);
    assert_eq!(alternative.remaining_raw_tail_bytes, 2_097_152);
    assert_eq!(
        alternative.blocking_devices,
        vec!["/dev/sda2".to_owned(), "/dev/sda5".to_owned()]
    );
    assert!(alternative
        .steps
        .iter()
        .any(|step| step.contains("swapfile")));
    assert!(alternative
        .steps
        .iter()
        .any(|step| step.contains("hibernation")));
}

#[test]
fn mixed_payload_inside_extended_container_blocks_swap_migration_advisory() {
    let mut snapshot = grown_live_debian_snapshot();

    let swap_record = snapshot.partition_tables[0]
        .partitions
        .iter_mut()
        .find(|record| record.node == "/dev/sda5")
        .unwrap();
    swap_record.size_sectors = 1_000_000;
    snapshot.swaps[0].size_bytes = 1_000_000 * 512;
    snapshot.storage.block_devices[0].children[2].size_bytes = 1_000_000 * 512;

    snapshot.partition_tables[0].partitions.push(PartitionRecord {
        node: "/dev/sda6".into(),
        start_sector: 19_972_672,
        size_sectors: 500_000,
        partition_type: Some("83".into()),
        uuid: None,
        name: Some("payload".into()),
        attrs: None,
        bootable: None,
    });

    assert!(analyze_layout_opportunity(&snapshot, "/").is_none());

    let plan = plan_extend(
        &snapshot,
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::ByBytes(1024 * 1024 * 1024),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan.layout_alternatives().is_empty());
}

#[test]
fn layout_alternative_is_not_emitted_when_tail_cannot_preserve_swap_and_growth() {
    let mut snapshot = grown_live_debian_snapshot();
    snapshot.storage.block_devices[0].size_bytes = 10_500_000_000;

    let plan = plan_extend(
        &snapshot,
        &capabilities(),
        ExtendRequest {
            target: "/".into(),
            growth: Growth::ByBytes(1024 * 1024 * 1024),
        },
    )
    .unwrap();

    assert_eq!(plan.status(), PlanStatus::Blocked);
    assert!(plan.layout_alternatives().is_empty());
}

#[test]
fn layout_opportunity_exposes_max_target_growth_for_selector() {
    let snapshot = grown_live_debian_snapshot();
    let opportunity = analyze_layout_opportunity(&snapshot, "/")
        .expect("grown DOS/swap layout should expose a safe advisory opportunity");

    assert_eq!(opportunity.code, "migrate-tail-swap");
    assert_eq!(opportunity.disk, "/dev/sda");
    assert_eq!(opportunity.target, "/dev/sda1");
    assert_eq!(opportunity.sector_size_bytes, 512);
    assert_eq!(opportunity.disk_tail_free_bytes, 1_074_790_400);
    assert_eq!(opportunity.swap_bytes, 1_022_361_600);
    assert!(opportunity.max_target_growth_bytes >= 1024 * 1024 * 1024);
    assert!(opportunity.max_target_growth_bytes < 2 * 1024 * 1024 * 1024);
}
