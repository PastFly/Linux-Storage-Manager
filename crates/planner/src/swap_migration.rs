use lsm_core::{BlockDevice, HibernationResumeEvidence, HostSnapshot};
use serde::Serialize;

use crate::{analyze_layout_opportunity, Blocker};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapMigrationSafetyStatus {
    ClearForPlanning,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwapMigrationSafety {
    pub status: SwapMigrationSafetyStatus,
    pub target: String,
    pub disk: Option<String>,
    pub swap_device: Option<String>,
    pub swap_bytes: Option<u64>,
    pub active_swap_used_bytes: Option<u64>,
    pub persistent_swap_source: Option<String>,
    pub blockers: Vec<Blocker>,
    pub future_checks: Vec<String>,
}

impl SwapMigrationSafety {
    pub fn clear_for_planning(&self) -> bool {
        self.status == SwapMigrationSafetyStatus::ClearForPlanning
    }
}

fn flatten<'a>(devices: &'a [BlockDevice], out: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        out.push(device);
        flatten(&device.children, out);
    }
}

fn source_matches_device(source: &str, device: &BlockDevice) -> bool {
    device.path.as_deref() == Some(source)
        || source == device.name
        || device
            .uuid
            .as_deref()
            .is_some_and(|uuid| source == format!("UUID={uuid}"))
        || device
            .partition_uuid
            .as_deref()
            .is_some_and(|uuid| source == format!("PARTUUID={uuid}"))
}

fn push_blocker(blockers: &mut Vec<Blocker>, code: &str, message: &str) {
    blockers.push(Blocker {
        code: code.to_owned(),
        message: message.to_owned(),
    });
}

/// Assess whether the already-detected DOS tail-swap layout is safe to advance
/// into a future swap-partition -> swapfile migration plan.
///
/// This is deliberately read-only. It does not choose a swapfile location,
/// deactivate swap, edit fstab/resume configuration or modify partitions.
pub fn analyze_swap_migration_safety(
    snapshot: &HostSnapshot,
    resume: &HibernationResumeEvidence,
    target: &str,
) -> SwapMigrationSafety {
    let Some(opportunity) = analyze_layout_opportunity(snapshot, target) else {
        return SwapMigrationSafety {
            status: SwapMigrationSafetyStatus::Blocked,
            target: target.to_owned(),
            disk: None,
            swap_device: None,
            swap_bytes: None,
            active_swap_used_bytes: None,
            persistent_swap_source: None,
            blockers: vec![Blocker {
                code: "swap-tail-layout-not-proven".to_owned(),
                message: "the exact DOS extended/logical active-swap tail layout is not proven"
                    .to_owned(),
            }],
            future_checks: Vec::new(),
        };
    };

    let swap_device = opportunity.blocking_devices.get(1).cloned();
    let mut blockers = Vec::new();

    if !resume.kernel_resume_targets.is_empty() {
        push_blocker(
            &mut blockers,
            "kernel-resume-target-configured",
            "kernel command line contains resume=; swap migration is blocked until the resume target is explicitly reconciled",
        );
    }
    if !resume.kernel_resume_offsets.is_empty() {
        push_blocker(
            &mut blockers,
            "kernel-resume-offset-configured",
            "kernel command line contains resume_offset=; swapfile migration must not proceed without an explicit hibernation resume-offset design",
        );
    }
    if resume.sysfs_resume.is_some() {
        push_blocker(
            &mut blockers,
            "sysfs-resume-device-configured",
            "the running kernel reports a nonzero /sys/power/resume device",
        );
    }
    if resume.sysfs_resume_offset.is_some() {
        push_blocker(
            &mut blockers,
            "sysfs-resume-offset-configured",
            "the running kernel reports a nonzero /sys/power/resume_offset",
        );
    }

    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let swap_node = swap_device.as_deref().and_then(|swap_device| {
        let matches = nodes
            .iter()
            .copied()
            .filter(|device| source_matches_device(swap_device, device))
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    });

    let persistent_matches = match swap_node {
        Some(device) => snapshot
            .fstab
            .iter()
            .filter(|entry| entry.fs_type == "swap" && source_matches_device(&entry.source, device))
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    let persistent_swap_source = if persistent_matches.len() == 1 {
        Some(persistent_matches[0].source.clone())
    } else {
        if persistent_matches.is_empty() {
            push_blocker(
                &mut blockers,
                "persistent-swap-entry-not-proven",
                "no unique fstab swap entry can be bound to the active tail swap partition",
            );
        } else {
            push_blocker(
                &mut blockers,
                "persistent-swap-entry-ambiguous",
                "multiple fstab swap entries bind to the active tail swap partition",
            );
        }
        None
    };

    let active_swap_used_bytes = swap_device.as_deref().and_then(|device| {
        snapshot
            .swaps
            .iter()
            .find(|entry| entry.name == device)
            .map(|entry| entry.used_bytes)
    });

    let future_checks = vec![
        "choose a swapfile filesystem with explicitly verified free capacity and swapfile support"
            .to_owned(),
        "create, mkswap and swapon the replacement before deactivating the partition".to_owned(),
        "prove current memory/swap pressure permits safe swapoff of the old partition".to_owned(),
        "atomically rewrite and verify persistent swap configuration before partition removal"
            .to_owned(),
        "back up partition-table, fstab and boot/resume configuration before any mutation".to_owned(),
    ];

    SwapMigrationSafety {
        status: if blockers.is_empty() {
            SwapMigrationSafetyStatus::ClearForPlanning
        } else {
            SwapMigrationSafetyStatus::Blocked
        },
        target: target.to_owned(),
        disk: Some(opportunity.disk),
        swap_device,
        swap_bytes: Some(opportunity.swap_bytes),
        active_swap_used_bytes,
        persistent_swap_source,
        blockers,
        future_checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::HostSnapshot;
    use serde_json::json;

    fn snapshot() -> HostSnapshot {
        serde_json::from_value(json!({
            "storage": {"block_devices": [{
                "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
                "size_bytes":1073741824u64,"start_512_sector":null,"logical_sector_bytes":512,
                "filesystem":null,"mountpoints":[],"parent_kernel_name":null,"model":null,
                "serial":null,"uuid":null,"partition_uuid":null,"partition_table":"dos",
                "children":[
                    {"name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                     "size_bytes":512000000u64,"start_512_sector":2048,"logical_sector_bytes":512,
                     "filesystem":{"fs_type":"ext4","version":"1.0"},"mountpoints":["/data"],
                     "parent_kernel_name":"sda","model":null,"serial":null,"uuid":"fs-data",
                     "partition_uuid":"part-data","partition_table":null,"children":[]},
                    {"name":"sda5","kernel_name":"sda5","path":"/dev/sda5","kind":"partition",
                     "size_bytes":102400000u64,"start_512_sector":1004096,"logical_sector_bytes":512,
                     "filesystem":{"fs_type":"swap","version":"1"},"mountpoints":["[SWAP]"],
                     "parent_kernel_name":"sda","model":null,"serial":null,"uuid":"swap-uuid",
                     "partition_uuid":"swap-partuuid","partition_table":null,"children":[]}
                ]
            }]},
            "partition_tables":[{
                "device":"/dev/sda","label":"dos","id":"0x12345678","unit":"sectors",
                "first_lba":null,"last_lba":null,"sector_size_bytes":512,
                "partitions":[
                    {"node":"/dev/sda1","start_sector":2048,"size_sectors":1000000,
                     "partition_type":"83","uuid":null,"name":null,"attrs":null,"bootable":false},
                    {"node":"/dev/sda2","start_sector":1002048,"size_sectors":600000,
                     "partition_type":"0f","uuid":null,"name":null,"attrs":null,"bootable":false},
                    {"node":"/dev/sda5","start_sector":1004096,"size_sectors":200000,
                     "partition_type":"82","uuid":null,"name":null,"attrs":null,"bootable":false}
                ]
            }],
            "mounts":[{"source":"/dev/sda1","target":"/data","fs_type":"ext4","options":["rw"]}],
            "fstab":[
                {"source":"UUID=fs-data","target":"/data","fs_type":"ext4","options":["defaults"],"dump":0,"pass":2},
                {"source":"UUID=swap-uuid","target":"none","fs_type":"swap","options":["sw"],"dump":0,"pass":0}
            ],
            "swaps":[{"name":"/dev/sda5","kind":"partition","size_bytes":102400000u64,"used_bytes":4096u64,"priority":-2}],
            "lvm":null,
            "filesystem_preflight":[],
            "diagnostics":[],
            "collectors":[]
        }))
        .unwrap()
    }

    #[test]
    fn clear_resume_state_and_unique_fstab_swap_allow_future_planning() {
        let result = analyze_swap_migration_safety(
            &snapshot(),
            &HibernationResumeEvidence::default(),
            "/data",
        );
        assert!(result.clear_for_planning());
        assert_eq!(result.swap_device.as_deref(), Some("/dev/sda5"));
        assert_eq!(result.persistent_swap_source.as_deref(), Some("UUID=swap-uuid"));
        assert_eq!(result.active_swap_used_bytes, Some(4096));
        assert!(!result.future_checks.is_empty());
    }

    #[test]
    fn kernel_resume_configuration_blocks_swap_partition_retirement() {
        let resume = HibernationResumeEvidence {
            kernel_resume_targets: vec!["UUID=swap-uuid".into()],
            ..HibernationResumeEvidence::default()
        };
        let result = analyze_swap_migration_safety(&snapshot(), &resume, "/data");
        assert!(!result.clear_for_planning());
        assert!(result
            .blockers
            .iter()
            .any(|blocker| blocker.code == "kernel-resume-target-configured"));
    }

    #[test]
    fn sysfs_resume_offset_blocks_swapfile_migration_planning() {
        let resume = HibernationResumeEvidence {
            sysfs_resume_offset: Some(8192),
            ..HibernationResumeEvidence::default()
        };
        let result = analyze_swap_migration_safety(&snapshot(), &resume, "/data");
        assert!(result
            .blockers
            .iter()
            .any(|blocker| blocker.code == "sysfs-resume-offset-configured"));
    }

    #[test]
    fn missing_persistent_swap_binding_fails_closed() {
        let mut snapshot = snapshot();
        snapshot.fstab.retain(|entry| entry.fs_type != "swap");
        let result = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        assert!(result
            .blockers
            .iter()
            .any(|blocker| blocker.code == "persistent-swap-entry-not-proven"));
    }
}
