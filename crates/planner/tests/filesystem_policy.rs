use lsm_core::{
    DiagnosticSeverity, FilesystemPreflightEvidence, FilesystemProbeState, HostCapabilities,
    HostSnapshot, StorageDiagnostic, ToolCapability,
};
use lsm_planner::{decide_filesystem_growth, FilesystemCheckKind, FilesystemDecisionState};
use serde_json::json;

const GIB: u64 = 1 << 30;

fn snapshot(fs_type: &str, mounted: bool, mount_options: &[&str]) -> HostSnapshot {
    let mountpoints = if mounted { json!(["/data"]) } else { json!([]) };
    let mounts = if mounted {
        json!([{
            "source":"/dev/sda1",
            "target":"/data",
            "fs_type":fs_type,
            "options":mount_options
        }])
    } else {
        json!([])
    };

    serde_json::from_value(json!({
        "storage":{"block_devices":[{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20*GIB,"logical_sector_bytes":512,"mountpoints":[],
            "children":[{
                "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                "size_bytes":10*GIB,"start_512_sector":2048,"logical_sector_bytes":512,
                "uuid":"fs-data","partition_uuid":"part-data","partition_table":"gpt",
                "filesystem":{"fs_type":fs_type,"version":"1.0"},
                "mountpoints":mountpoints,"parent_kernel_name":"sda","children":[]
            }]
        }]},
        "partition_tables":[],
        "mounts":mounts,
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "filesystem_preflight":[],
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

fn capabilities() -> HostCapabilities {
    HostCapabilities {
        tools: vec![
            tool("resize2fs", true),
            tool("e2fsck", true),
            tool("xfs_growfs", true),
            tool("xfs_scrub", true),
        ],
    }
}

fn tool(name: &str, available: bool) -> ToolCapability {
    ToolCapability {
        name: name.to_owned(),
        available,
    }
}

fn ext4_evidence(state: &str) -> FilesystemPreflightEvidence {
    FilesystemPreflightEvidence {
        device: "/dev/sda1".into(),
        mountpoint: Some("/data".into()),
        fs_type: "ext4".into(),
        fs_version: Some("1.0".into()),
        state: FilesystemProbeState::Verified,
        filesystem_state: Some(state.into()),
        revision: Some("1 (dynamic)".into()),
        features: vec![
            "has_journal".into(),
            "extent".into(),
            "64bit".into(),
            "metadata_csum".into(),
        ],
        block_size_bytes: None,
        block_count: None,
        size_bytes: None,
        grow_check_passed: None,
        detail: None,
    }
}

fn xfs_evidence(grow_check_passed: Option<bool>) -> FilesystemPreflightEvidence {
    FilesystemPreflightEvidence {
        device: "/dev/sda1".into(),
        mountpoint: Some("/data".into()),
        fs_type: "xfs".into(),
        fs_version: Some("5".into()),
        state: FilesystemProbeState::Verified,
        filesystem_state: None,
        revision: None,
        features: vec!["crc=1".into(), "reflink=1".into(), "bigtime=1".into()],
        block_size_bytes: None,
        block_count: None,
        size_bytes: None,
        grow_check_passed,
        detail: None,
    }
}

#[test]
fn clean_mounted_ext4_is_online_grow_candidate_without_mounted_e2fsck() {
    let mut snapshot = snapshot("ext4", true, &["rw", "relatime"]);
    snapshot.filesystem_preflight.push(ext4_evidence("clean"));

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::ReadyOnlineGrow);
    assert!(decision.execution_ready());
    assert_eq!(decision.read_only_check, None);
    assert!(decision
        .required_actions
        .iter()
        .any(|action| action.contains("do not run e2fsck")));
}

#[test]
fn missing_mounted_ext4_evidence_blocks_without_panicking() {
    let snapshot = snapshot("ext4", true, &["rw", "relatime"]);

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::Blocked);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("metadata evidence is missing")));
    assert!(decision
        .required_actions
        .iter()
        .any(|action| action.contains("tune2fs")));
}

#[test]
fn questionable_mounted_ext4_requires_explicit_offline_read_only_check() {
    let mut snapshot = snapshot("ext4", true, &["rw"]);
    snapshot
        .filesystem_preflight
        .push(ext4_evidence("clean with errors"));

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(
        decision.state,
        FilesystemDecisionState::OfflineHealthCheckRequired
    );
    let check = decision.read_only_check.unwrap();
    assert_eq!(check.kind, FilesystemCheckKind::Ext4OfflineE2fsckNoModify);
    assert_eq!(check.tool, "e2fsck");
    assert_eq!(check.args, vec!["-f", "-n", "/dev/sda1"]);
    assert!(check.requires_unmounted);
    assert!(!check.requires_mounted);
    assert!(!check.run_automatically_on_refresh);
}

#[test]
fn unmounted_ext4_requires_offline_health_check_before_resize() {
    let snapshot = snapshot("ext4", false, &[]);

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/dev/sda1");

    assert_eq!(
        decision.state,
        FilesystemDecisionState::OfflineHealthCheckRequired
    );
    assert_eq!(
        decision.read_only_check.unwrap().kind,
        FilesystemCheckKind::Ext4OfflineE2fsckNoModify
    );
}

#[test]
fn verified_offline_ext4_state_is_execution_ready_only_after_explicit_promotion() {
    let snapshot = snapshot("ext4", false, &[]);
    let mut decision = decide_filesystem_growth(&snapshot, &capabilities(), "/dev/sda1");

    assert_eq!(
        decision.state,
        FilesystemDecisionState::OfflineHealthCheckRequired
    );
    assert!(!decision.execution_ready());

    decision.state = FilesystemDecisionState::ReadyOfflineGrow;
    decision.read_only_check = None;
    decision.required_actions.clear();

    assert!(decision.execution_ready());
}

#[test]
fn read_only_ext4_mount_is_blocked() {
    let mut snapshot = snapshot("ext4", true, &["ro"]);
    snapshot.filesystem_preflight.push(ext4_evidence("clean"));

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::Blocked);
    assert!(!decision.execution_ready());
}

#[test]
fn xfs_requires_explicit_no_modify_scrub_after_grow_dry_run_passes() {
    let mut snapshot = snapshot("xfs", true, &["rw", "relatime"]);
    snapshot.filesystem_preflight.push(xfs_evidence(Some(true)));

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(
        decision.state,
        FilesystemDecisionState::ReadOnlyHealthCheckRequired
    );
    let check = decision.read_only_check.unwrap();
    assert_eq!(check.kind, FilesystemCheckKind::XfsMountedScrubNoModify);
    assert_eq!(check.tool, "xfs_scrub");
    assert_eq!(check.args, vec!["-n", "-k", "/data"]);
    assert!(check.requires_mounted);
    assert!(!check.requires_unmounted);
    assert!(!check.run_automatically_on_refresh);
}

#[test]
fn unmounted_xfs_requires_mount_before_growth() {
    let snapshot = snapshot("xfs", false, &[]);

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/dev/sda1");

    assert_eq!(decision.state, FilesystemDecisionState::MountRequired);
    assert!(decision.read_only_check.is_none());
}

#[test]
fn failed_xfs_grow_dry_run_blocks_health_promotion() {
    let mut snapshot = snapshot("xfs", true, &["rw"]);
    snapshot
        .filesystem_preflight
        .push(xfs_evidence(Some(false)));

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::Blocked);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("xfs_growfs -n")));
}

#[test]
fn missing_xfs_scrub_capability_blocks_executor_grade_health_decision() {
    let mut snapshot = snapshot("xfs", true, &["rw"]);
    snapshot.filesystem_preflight.push(xfs_evidence(Some(true)));
    let mut caps = capabilities();
    caps.tools
        .iter_mut()
        .find(|tool| tool.name == "xfs_scrub")
        .unwrap()
        .available = false;

    let decision = decide_filesystem_growth(&snapshot, &caps, "/data");

    assert_eq!(decision.state, FilesystemDecisionState::Blocked);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("xfs_scrub")));
}

#[test]
fn unknown_filesystem_requires_dedicated_adapter() {
    let snapshot = snapshot("mysteryfs", true, &["rw"]);

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::AdapterRequired);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("mysteryfs")));
}

#[test]
fn target_error_diagnostic_blocks_filesystem_execution_decision() {
    let mut snapshot = snapshot("ext4", true, &["rw"]);
    snapshot.filesystem_preflight.push(ext4_evidence("clean"));
    snapshot.diagnostics.push(StorageDiagnostic {
        code: "target-geometry-error".into(),
        severity: DiagnosticSeverity::Error,
        message: "target geometry is inconsistent".into(),
        device: Some("/dev/sda1".into()),
    });

    let decision = decide_filesystem_growth(&snapshot, &capabilities(), "/data");

    assert_eq!(decision.state, FilesystemDecisionState::Blocked);
    assert!(decision
        .reasons
        .iter()
        .any(|reason| reason.contains("error-level diagnostic")));
}
