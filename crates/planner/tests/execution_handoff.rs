use lsm_core::{FilesystemPreflightEvidence, FilesystemProbeState, HostCapabilities, HostSnapshot};
use lsm_planner::{
    build_frozen_execution_handoff, plan_extend, ExecutionHandoffError, ExecutionHandoffStatus,
    ExtendRequest, FilesystemDecisionState, Growth, GuardGateKind, PlanStatus,
};
use serde_json::json;

const GIB: u64 = 1 << 30;

fn snapshot(with_filesystem_evidence: bool) -> HostSnapshot {
    let sector = 512_u64;
    let partition_bytes = 10 * GIB;
    let mut snapshot: HostSnapshot = serde_json::from_value(json!({
        "storage":{"block_devices":[{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20*GIB,"logical_sector_bytes":sector,
            "model":"Virtual Disk","serial":"HANDOFF-TEST","mountpoints":[],"children":[{
                "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                "size_bytes":partition_bytes,"start_512_sector":2048,
                "logical_sector_bytes":sector,"uuid":"fs-data","partition_uuid":"part-data",
                "partition_table":"gpt","filesystem":{"fs_type":"ext4","version":"1.0"},
                "mountpoints":["/data"],"parent_kernel_name":"sda","children":[]
            }]
        }]},
        "partition_tables":[{
            "device":"/dev/sda","label":"gpt","id":"gpt-handoff","unit":"sectors",
            "first_lba":34,"last_lba":(20*GIB/sector)-34,
            "sector_size_bytes":sector,
            "partitions":[{
                "node":"/dev/sda1","start_sector":2048,
                "size_sectors":partition_bytes/sector,
                "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "uuid":"part-data","name":null,"attrs":null,"bootable":null
            }]
        }],
        "mounts":[{
            "source":"/dev/sda1","target":"/data","fs_type":"ext4","options":["rw","relatime"]
        }],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "filesystem_preflight":[],
        "diagnostics":[],
        "collectors":[
            {"component":"lsblk","state":"complete"},
            {"component":"partition_tables","state":"complete"},
            {"component":"mounts","state":"complete"},
            {"component":"fstab","state":"complete"},
            {"component":"swap","state":"complete"}
        ]
    }))
    .unwrap();

    if with_filesystem_evidence {
        snapshot
            .filesystem_preflight
            .push(FilesystemPreflightEvidence {
                device: "/dev/sda1".into(),
                mountpoint: Some("/data".into()),
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
                block_size_bytes: Some(4096),
                block_count: Some(partition_bytes / 4096),
                size_bytes: Some(partition_bytes),
                grow_check_passed: None,
                detail: None,
            });
    }

    snapshot
}

fn capabilities() -> HostCapabilities {
    serde_json::from_value(json!({"tools":[
        {"name":"sfdisk","available":true},
        {"name":"resize2fs","available":true},
        {"name":"e2fsck","available":true}
    ]}))
    .unwrap()
}

fn preview(snapshot: &HostSnapshot, capabilities: &HostCapabilities) -> lsm_planner::PlanPreview {
    let plan = plan_extend(
        snapshot,
        capabilities,
        ExtendRequest {
            target: "/data".into(),
            growth: Growth::ByBytes(GIB),
        },
    )
    .unwrap();
    assert_eq!(plan.status(), PlanStatus::Preview);
    plan
}

#[test]
fn fresh_preview_builds_repeatable_non_mutating_handoff() {
    let snapshot = snapshot(true);
    let capabilities = capabilities();
    let plan = preview(&snapshot, &capabilities);

    let first = build_frozen_execution_handoff(&snapshot, &capabilities, &plan).unwrap();
    let second = build_frozen_execution_handoff(&snapshot, &capabilities, &plan).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first.status,
        ExecutionHandoffStatus::FutureExecutorGatesRequired
    );
    assert!(!first.mutation_enabled);
    assert!(first.owner_acceptance_required);
    assert_eq!(first.plan.plan_id(), plan.plan_id());
    assert_eq!(first.plan.target(), "/data");
    assert_eq!(first.plan_basis_digest, plan.basis_digest());
    assert!(!first.capabilities_digest.is_empty());
    assert_eq!(first.target_identity.target, "/data");
    assert_eq!(
        first.guard.baseline_manifest_digest,
        first.target_identity.manifest_digest
    );
    assert_eq!(
        first.filesystem_decision.state,
        FilesystemDecisionState::ReadyOnlineGrow
    );
    assert!(first.blockers.is_empty());
    assert!(!first.handoff_id.is_empty());
    assert!(first
        .guard
        .gates
        .iter()
        .any(|gate| gate.kind == GuardGateKind::RecordExactPlanApproval));
    assert!(first
        .guard
        .gates
        .iter()
        .any(|gate| gate.kind == GuardGateKind::CreateDurableJournal));
}

#[test]
fn stale_preview_basis_cannot_enter_execution_handoff() {
    let snapshot = snapshot(true);
    let capabilities = capabilities();
    let plan = preview(&snapshot, &capabilities);
    let mut changed = snapshot.clone();
    changed.storage.block_devices[0].size_bytes += GIB;

    let error = build_frozen_execution_handoff(&changed, &capabilities, &plan).unwrap_err();

    assert!(matches!(error, ExecutionHandoffError::StalePlan));
}

#[test]
fn blocked_preview_cannot_enter_execution_handoff() {
    let snapshot = snapshot(true);
    let capabilities = capabilities();
    let plan = plan_extend(
        &snapshot,
        &capabilities,
        ExtendRequest {
            target: "/data".into(),
            growth: Growth::ByBytes(20 * GIB),
        },
    )
    .unwrap();
    assert_eq!(plan.status(), PlanStatus::Blocked);

    let error = build_frozen_execution_handoff(&snapshot, &capabilities, &plan).unwrap_err();

    assert!(matches!(error, ExecutionHandoffError::PlanNotPreview));
}

#[test]
fn missing_filesystem_preflight_evidence_keeps_handoff_blocked() {
    let snapshot = snapshot(false);
    let capabilities = capabilities();
    let plan = preview(&snapshot, &capabilities);

    let handoff = build_frozen_execution_handoff(&snapshot, &capabilities, &plan).unwrap();

    assert_eq!(handoff.status, ExecutionHandoffStatus::Blocked);
    assert!(!handoff.mutation_enabled);
    assert!(handoff.owner_acceptance_required);
    assert_eq!(
        handoff.filesystem_decision.state,
        FilesystemDecisionState::Blocked
    );
    assert!(handoff
        .blockers
        .iter()
        .any(|blocker| blocker.contains("metadata evidence")));
}
