use lsm_core::{
    BlockDevice, CollectorState, CollectorStatus, Filesystem, HostCapabilities, HostSnapshot,
    MountEntry, NodeKind, PartitionRecord, PartitionTable, StorageGraph, ToolCapability,
};
use lsm_planner::{
    analyze_layout_opportunity, plan_extend, ExtendRequest, Growth, PlanStatus, PreflightState,
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
