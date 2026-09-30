use lsm_core::{
    BlockDevice, FilesystemSpaceEvidence, HibernationResumeEvidence, HostCapabilities,
    HostSnapshot, PathOccupancyEvidence,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{analyze_layout_opportunity, Blocker, PlanStatus, PlannerError};

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
        "back up partition-table, fstab and boot/resume configuration before any mutation"
            .to_owned(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapfileDestinationStatus {
    ReadyForPlanning,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwapfileDestinationReadiness {
    pub status: SwapfileDestinationStatus,
    pub destination_mount: String,
    pub swapfile_path: String,
    pub filesystem_type: Option<String>,
    pub available_bytes: u64,
    pub replacement_swap_bytes: Option<u64>,
    pub blockers: Vec<Blocker>,
    pub ordered_future_steps: Vec<String>,
}

impl SwapfileDestinationReadiness {
    pub fn ready_for_planning(&self) -> bool {
        self.status == SwapfileDestinationStatus::ReadyForPlanning
    }
}

fn required_tool_available(capabilities: &HostCapabilities, name: &str) -> bool {
    let matches = capabilities
        .tools
        .iter()
        .filter(|tool| tool.name == name)
        .collect::<Vec<_>>();
    matches.len() == 1 && matches[0].available
}

fn swapfile_path_for_mount(mountpoint: &str) -> String {
    if mountpoint == "/" {
        "/.linux-storage-manager.swap".to_owned()
    } else {
        format!(
            "{}/.linux-storage-manager.swap",
            mountpoint.trim_end_matches('/')
        )
    }
}

/// Prove a concrete replacement-swapfile destination has enough currently
/// available space and a deliberately supported filesystem/mount profile.
///
/// This remains read-only. The initial automatic profile is ext4 only; XFS
/// swapfile constraints are left blocked until a separate filesystem-specific
/// contract is implemented.
pub fn analyze_swapfile_destination(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    safety: &SwapMigrationSafety,
    space: &FilesystemSpaceEvidence,
    destination_mount: &str,
) -> SwapfileDestinationReadiness {
    let mut blockers = Vec::new();
    if !safety.clear_for_planning() {
        blockers.extend(safety.blockers.iter().cloned());
    }

    if space.path != destination_mount {
        push_blocker(
            &mut blockers,
            "swapfile-space-evidence-mismatch",
            "filesystem-space evidence does not match the selected swapfile destination mount",
        );
    }

    let mounts = snapshot
        .mounts
        .iter()
        .filter(|mount| mount.target == destination_mount)
        .collect::<Vec<_>>();
    let mount = if mounts.len() == 1 {
        Some(mounts[0])
    } else {
        push_blocker(
            &mut blockers,
            "swapfile-mount-not-unique",
            "replacement swapfile destination must resolve to exactly one current mount",
        );
        None
    };

    let filesystem_type = mount.and_then(|mount| mount.fs_type.clone());
    if filesystem_type.as_deref() != Some("ext4") {
        push_blocker(
            &mut blockers,
            "swapfile-filesystem-unsupported",
            "the first automatic swapfile migration profile requires an ext4 destination",
        );
    }
    if let Some(mount) = mount {
        if !mount.options.iter().any(|option| option == "rw")
            || mount.options.iter().any(|option| option == "ro")
        {
            push_blocker(
                &mut blockers,
                "swapfile-destination-not-rw",
                "replacement swapfile destination must be mounted read-write",
            );
        }
        if mount.source.as_deref() == safety.swap_device.as_deref() {
            push_blocker(
                &mut blockers,
                "swapfile-destination-is-retiring-swap",
                "replacement swapfile destination cannot be the swap partition being retired",
            );
        }
    }

    let replacement_swap_bytes = safety.swap_bytes;
    if let Some(required) = replacement_swap_bytes {
        if space.available_bytes < required {
            push_blocker(
                &mut blockers,
                "swapfile-capacity-insufficient",
                "selected destination does not have enough currently available bytes for an equal-sized replacement swapfile",
            );
        }
    } else {
        push_blocker(
            &mut blockers,
            "swapfile-required-size-unknown",
            "exact replacement swap size is not available from the migration safety proof",
        );
    }

    for tool in ["mkswap", "swapon", "swapoff"] {
        if !required_tool_available(capabilities, tool) {
            push_blocker(
                &mut blockers,
                "swapfile-tool-unavailable",
                &format!("required tool {tool} is unavailable or ambiguous"),
            );
        }
    }

    let swapfile_path = swapfile_path_for_mount(destination_mount);
    let ordered_future_steps = vec![
        format!(
            "create a non-sparse root-owned 0600 file at {swapfile_path} with the exact replacement size"
        ),
        format!("run mkswap on {swapfile_path} and verify the resulting swap signature"),
        format!("swapon {swapfile_path} before any attempt to deactivate the old swap partition"),
        "rediscover active swap and require the replacement to be active at the intended priority"
            .to_owned(),
        "attempt swapoff of the old partition; if it fails, keep both swaps and abort partition changes"
            .to_owned(),
        "rewrite persistent swap configuration atomically only after the runtime replacement is proven"
            .to_owned(),
        "remove the old swap/extended partitions only after all runtime and persistence checks pass"
            .to_owned(),
    ];

    SwapfileDestinationReadiness {
        status: if blockers.is_empty() {
            SwapfileDestinationStatus::ReadyForPlanning
        } else {
            SwapfileDestinationStatus::Blocked
        },
        destination_mount: destination_mount.to_owned(),
        swapfile_path,
        filesystem_type,
        available_bytes: space.available_bytes,
        replacement_swap_bytes,
        blockers,
        ordered_future_steps,
    }
}

#[derive(Serialize)]
struct SwapReplacementIntentDigestPayload<'a> {
    schema_version: u32,
    executable: bool,
    status: PlanStatus,
    target: &'a str,
    disk: &'a Option<String>,
    retiring_swap_device: &'a Option<String>,
    retiring_swap_bytes: Option<u64>,
    retiring_swap_used_bytes: Option<u64>,
    retiring_swap_priority: Option<i32>,
    persistent_swap_source: &'a Option<String>,
    persistent_swap_target: &'a Option<String>,
    persistent_swap_options: &'a [String],
    persistent_swap_dump: Option<u32>,
    persistent_swap_pass: Option<u32>,
    destination_mount: &'a str,
    swapfile_path: &'a str,
    destination_filesystem: &'a Option<String>,
    destination_available_bytes: u64,
    swapfile_mode: u32,
    blockers: &'a [Blocker],
    ordered_steps: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwapReplacementIntent {
    pub schema_version: u32,
    pub intent_id: String,
    pub executable: bool,
    pub status: PlanStatus,
    pub target: String,
    pub disk: Option<String>,
    pub retiring_swap_device: Option<String>,
    pub retiring_swap_bytes: Option<u64>,
    pub retiring_swap_used_bytes: Option<u64>,
    pub retiring_swap_priority: Option<i32>,
    pub persistent_swap_source: Option<String>,
    pub persistent_swap_target: Option<String>,
    pub persistent_swap_options: Vec<String>,
    pub persistent_swap_dump: Option<u32>,
    pub persistent_swap_pass: Option<u32>,
    pub destination_mount: String,
    pub swapfile_path: String,
    pub destination_filesystem: Option<String>,
    pub destination_available_bytes: u64,
    pub swapfile_mode: u32,
    pub blockers: Vec<Blocker>,
    pub ordered_steps: Vec<String>,
}

impl SwapReplacementIntent {
    pub fn ready(&self) -> bool {
        self.status == PlanStatus::Preview && self.blockers.is_empty() && !self.executable
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.intent_id == self.expected_intent_id()?)
    }

    pub fn expected_intent_id(&self) -> Result<String, serde_json::Error> {
        let payload = SwapReplacementIntentDigestPayload {
            schema_version: self.schema_version,
            executable: self.executable,
            status: self.status,
            target: &self.target,
            disk: &self.disk,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_bytes: self.retiring_swap_bytes,
            retiring_swap_used_bytes: self.retiring_swap_used_bytes,
            retiring_swap_priority: self.retiring_swap_priority,
            persistent_swap_source: &self.persistent_swap_source,
            persistent_swap_target: &self.persistent_swap_target,
            persistent_swap_options: &self.persistent_swap_options,
            persistent_swap_dump: self.persistent_swap_dump,
            persistent_swap_pass: self.persistent_swap_pass,
            destination_mount: &self.destination_mount,
            swapfile_path: &self.swapfile_path,
            destination_filesystem: &self.destination_filesystem,
            destination_available_bytes: self.destination_available_bytes,
            swapfile_mode: self.swapfile_mode,
            blockers: &self.blockers,
            ordered_steps: &self.ordered_steps,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

/// Freeze the exact read-only swap-replacement evidence into a deterministic,
/// non-executing intent. This does not create the swapfile or authorize any
/// runtime/persistent mutation.
pub fn build_swap_replacement_intent(
    snapshot: &HostSnapshot,
    safety: &SwapMigrationSafety,
    readiness: &SwapfileDestinationReadiness,
    path_state: &PathOccupancyEvidence,
) -> Result<SwapReplacementIntent, PlannerError> {
    let mut blockers = Vec::new();
    if !safety.clear_for_planning() {
        blockers.extend(safety.blockers.iter().cloned());
    }
    if !readiness.ready_for_planning() {
        blockers.extend(readiness.blockers.iter().cloned());
    }

    if path_state.path != readiness.swapfile_path {
        push_blocker(
            &mut blockers,
            "swapfile-path-evidence-mismatch",
            "path occupancy evidence does not match the frozen replacement swapfile path",
        );
    }
    if path_state.exists {
        push_blocker(
            &mut blockers,
            "swapfile-path-occupied",
            "replacement swapfile path already exists; automatic migration refuses to replace or reuse it",
        );
    }

    if readiness.replacement_swap_bytes != safety.swap_bytes {
        push_blocker(
            &mut blockers,
            "swapfile-size-binding-mismatch",
            "destination readiness no longer matches the exact retiring swap-partition size",
        );
    }

    let swap_matches = safety
        .swap_device
        .as_deref()
        .map(|device| {
            snapshot
                .swaps
                .iter()
                .filter(|entry| entry.name == device)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let swap_entry = if swap_matches.len() == 1 {
        Some(swap_matches[0])
    } else {
        push_blocker(
            &mut blockers,
            "retiring-swap-runtime-identity-mismatch",
            "the retiring active swap entry is absent or ambiguous",
        );
        None
    };

    let persistent_matches = safety
        .persistent_swap_source
        .as_deref()
        .map(|source| {
            snapshot
                .fstab
                .iter()
                .filter(|entry| entry.fs_type == "swap" && entry.source == source)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let persistent = if persistent_matches.len() == 1 {
        Some(persistent_matches[0])
    } else {
        push_blocker(
            &mut blockers,
            "retiring-swap-persistence-identity-mismatch",
            "the persistent swap entry changed or became ambiguous after safety analysis",
        );
        None
    };

    if let (Some(entry), Some(expected_bytes)) = (swap_entry, safety.swap_bytes) {
        if entry.size_bytes == 0
            || entry.size_bytes > expected_bytes
            || Some(entry.used_bytes) != safety.active_swap_used_bytes
        {
            push_blocker(
                &mut blockers,
                "retiring-swap-runtime-state-changed",
                "active swap reported size exceeds the frozen partition geometry or usage changed after the migration safety proof",
            );
        }
    }

    let status = if blockers.is_empty() {
        PlanStatus::Preview
    } else {
        PlanStatus::Blocked
    };

    let mut intent = SwapReplacementIntent {
        schema_version: 1,
        intent_id: String::new(),
        executable: false,
        status,
        target: safety.target.clone(),
        disk: safety.disk.clone(),
        retiring_swap_device: safety.swap_device.clone(),
        retiring_swap_bytes: safety.swap_bytes,
        retiring_swap_used_bytes: swap_entry.map(|entry| entry.used_bytes),
        retiring_swap_priority: swap_entry.map(|entry| entry.priority),
        persistent_swap_source: persistent.map(|entry| entry.source.clone()),
        persistent_swap_target: persistent.map(|entry| entry.target.clone()),
        persistent_swap_options: persistent
            .map(|entry| entry.options.clone())
            .unwrap_or_default(),
        persistent_swap_dump: persistent.map(|entry| entry.dump),
        persistent_swap_pass: persistent.map(|entry| entry.pass),
        destination_mount: readiness.destination_mount.clone(),
        swapfile_path: readiness.swapfile_path.clone(),
        destination_filesystem: readiness.filesystem_type.clone(),
        destination_available_bytes: readiness.available_bytes,
        swapfile_mode: 0o600,
        blockers,
        ordered_steps: vec![
            "revalidate hibernation/resume, active swap, fstab, destination mount, free space and swapfile-path vacancy".to_owned(),
            "create the replacement swapfile with create-new semantics, exact size, no holes and mode 0600".to_owned(),
            "run mkswap and verify the replacement signature before activation".to_owned(),
            "activate the replacement with the frozen priority while keeping the old swap partition active".to_owned(),
            "rediscover active swap and require both old and new swap areas before any swapoff attempt".to_owned(),
            "attempt swapoff of the old partition; on failure leave the replacement active and make no partition-table changes".to_owned(),
            "after successful swapoff, atomically replace the persistent swap entry and verify the parsed result".to_owned(),
            "only after runtime and persistent replacement are proven may a later executor remove the old swap/extended partitions".to_owned(),
        ],
    };

    intent.intent_id = intent.expected_intent_id()?;
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{
        FilesystemSpaceEvidence, HostCapabilities, HostSnapshot, PathObjectKind,
        PathOccupancyEvidence, ToolCapability,
    };
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

    fn capabilities() -> HostCapabilities {
        HostCapabilities {
            tools: ["mkswap", "swapon", "swapoff"]
                .into_iter()
                .map(|name| ToolCapability {
                    name: name.to_owned(),
                    available: true,
                })
                .collect(),
        }
    }

    fn space(available_bytes: u64) -> FilesystemSpaceEvidence {
        FilesystemSpaceEvidence {
            path: "/data".into(),
            block_size_bytes: 4096,
            total_bytes: 512_000_000,
            available_bytes,
        }
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
        assert_eq!(
            result.persistent_swap_source.as_deref(),
            Some("UUID=swap-uuid")
        );
        assert_eq!(result.active_swap_used_bytes, Some(4096));
        assert!(!result.future_checks.is_empty());
    }

    #[test]
    fn loop_fixture_and_header_reduced_active_swap_are_supported() {
        let mut snapshot = snapshot();
        snapshot.storage.block_devices[0].kind = lsm_core::NodeKind::Loop;
        snapshot.swaps[0].size_bytes -= 4096;

        let result = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        assert!(result.clear_for_planning());
        assert_eq!(result.swap_bytes, Some(102_400_000));
        assert_eq!(result.swap_device.as_deref(), Some("/dev/sda5"));
    }

    #[test]
    fn intent_accepts_header_reduced_active_swap_size_with_exact_geometry() {
        let mut snapshot = snapshot();
        snapshot.storage.block_devices[0].kind = lsm_core::NodeKind::Loop;
        snapshot.swaps[0].size_bytes -= 4096;
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(150_000_000),
            "/data",
        );
        let intent = build_swap_replacement_intent(
            &snapshot,
            &safety,
            &readiness,
            &vacant_swapfile_path(),
        )
        .unwrap();
        assert!(intent.ready());
        assert_eq!(intent.retiring_swap_bytes, Some(102_400_000));
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
    fn ext4_destination_with_exact_capacity_and_tools_is_ready() {
        let snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(150_000_000),
            "/data",
        );
        assert!(readiness.ready_for_planning());
        assert_eq!(readiness.swapfile_path, "/data/.linux-storage-manager.swap");
        assert_eq!(readiness.replacement_swap_bytes, Some(102_400_000));
    }

    #[test]
    fn insufficient_destination_capacity_blocks_before_any_mutation() {
        let snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(64_000_000),
            "/data",
        );
        assert!(readiness
            .blockers
            .iter()
            .any(|blocker| blocker.code == "swapfile-capacity-insufficient"));
    }

    #[test]
    fn missing_swap_tool_blocks_destination_readiness() {
        let snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let mut capabilities = capabilities();
        capabilities
            .tools
            .iter_mut()
            .find(|tool| tool.name == "swapoff")
            .unwrap()
            .available = false;
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities,
            &safety,
            &space(150_000_000),
            "/data",
        );
        assert!(readiness
            .blockers
            .iter()
            .any(|blocker| blocker.code == "swapfile-tool-unavailable"));
    }

    fn vacant_swapfile_path() -> PathOccupancyEvidence {
        PathOccupancyEvidence {
            path: "/data/.linux-storage-manager.swap".into(),
            exists: false,
            kind: None,
            uid: None,
            mode: None,
            size_bytes: None,
        }
    }

    #[test]
    fn exact_readiness_and_vacant_path_freeze_nonexecuting_intent() {
        let snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(150_000_000),
            "/data",
        );
        let first =
            build_swap_replacement_intent(&snapshot, &safety, &readiness, &vacant_swapfile_path())
                .unwrap();
        let second =
            build_swap_replacement_intent(&snapshot, &safety, &readiness, &vacant_swapfile_path())
                .unwrap();

        assert!(first.ready());
        assert!(!first.executable);
        assert_eq!(first.intent_id, second.intent_id);
        assert_eq!(first.retiring_swap_priority, Some(-2));
        assert_eq!(
            first.persistent_swap_source.as_deref(),
            Some("UUID=swap-uuid")
        );
        assert_eq!(first.swapfile_mode, 0o600);
    }

    #[test]
    fn existing_or_symlink_swapfile_path_blocks_intent() {
        let snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(150_000_000),
            "/data",
        );
        let occupied = PathOccupancyEvidence {
            path: readiness.swapfile_path.clone(),
            exists: true,
            kind: Some(PathObjectKind::Symlink),
            uid: Some(1000),
            mode: Some(0o120777),
            size_bytes: Some(4),
        };

        let intent =
            build_swap_replacement_intent(&snapshot, &safety, &readiness, &occupied).unwrap();
        assert!(!intent.ready());
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "swapfile-path-occupied"));
    }

    #[test]
    fn runtime_swap_drift_after_safety_analysis_blocks_intent() {
        let mut snapshot = snapshot();
        let safety = analyze_swap_migration_safety(
            &snapshot,
            &HibernationResumeEvidence::default(),
            "/data",
        );
        let readiness = analyze_swapfile_destination(
            &snapshot,
            &capabilities(),
            &safety,
            &space(150_000_000),
            "/data",
        );
        snapshot.swaps[0].used_bytes += 4096;

        let intent =
            build_swap_replacement_intent(&snapshot, &safety, &readiness, &vacant_swapfile_path())
                .unwrap();
        assert!(intent
            .blockers
            .iter()
            .any(|blocker| blocker.code == "retiring-swap-runtime-state-changed"));
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
