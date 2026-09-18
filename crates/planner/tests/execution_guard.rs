use lsm_core::HostSnapshot;
use lsm_planner::{
    build_execution_guard_plan, capture_target_identity, GuardPlanStatus, JournalError,
    JournalPhase, JournalTransition, LayerRouteStatus, LockScope, OperationJournal,
    ResumeDisposition, HOST_STORAGE_LOCK_PATH,
};
use serde_json::json;

const GIB: u64 = 1 << 30;

fn snapshot() -> HostSnapshot {
    let sector = 512_u64;
    let partition_bytes = 10 * GIB;
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20*GIB,"logical_sector_bytes":sector,
            "model":"Virtual Disk","serial":"LOCK-TEST","mountpoints":[],"children":[{
                "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                "size_bytes":partition_bytes,"start_512_sector":2048,
                "logical_sector_bytes":sector,"uuid":"fs-root","partition_uuid":"part-root",
                "partition_table":"gpt","filesystem":{"fs_type":"ext4","version":"1.0"},
                "mountpoints":["/"],"parent_kernel_name":"sda","children":[]
            }]
        }]},
        "partition_tables":[{
            "device":"/dev/sda","label":"gpt","id":"gpt-lock-test","unit":"sectors",
            "first_lba":34,"last_lba":(20*GIB/sector)-34,
            "sector_size_bytes":sector,
            "partitions":[{
                "node":"/dev/sda1","start_sector":2048,
                "size_sectors":partition_bytes/sector,
                "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                "uuid":"part-root","name":null,"attrs":null,"bootable":null
            }]
        }],
        "mounts":[
            {"source":"/dev/sda1","target":"/","fs_type":"ext4","options":["rw","relatime"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

fn guard() -> lsm_planner::ExecutionGuardPlan {
    let manifest = capture_target_identity(&snapshot(), "/").unwrap();
    assert_eq!(manifest.route_status, LayerRouteStatus::SupportedProfile);
    build_execution_guard_plan("plan-test-001", &manifest).unwrap()
}

#[test]
fn guard_uses_one_nonblocking_host_exclusive_storage_lock() {
    let guard = guard();

    assert_eq!(guard.status, GuardPlanStatus::FutureExecutorGatesRequired);
    assert_eq!(guard.lock.scope, LockScope::HostExclusive);
    assert_eq!(guard.lock.lock_path, HOST_STORAGE_LOCK_PATH);
    assert!(!guard.lock.blocking);
    assert!(guard
        .lock
        .resource_keys
        .iter()
        .any(|key| key == "device:/dev/sda"));
    assert!(guard
        .lock
        .resource_keys
        .iter()
        .any(|key| key == "partition:/dev/sda1"));
    assert!(guard
        .lock
        .resource_keys
        .iter()
        .any(|key| key == "filesystem:/dev/sda1"));
    assert!(guard
        .lock
        .resource_keys
        .iter()
        .any(|key| key == "mount:/"));
    assert!(guard.journal_path.ends_with(".json"));
    assert_eq!(guard.gates.len(), 8);
}

#[test]
fn journal_happy_path_requires_exact_order_and_exact_identity() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);

    journal.apply(JournalTransition::HostLockAcquired).unwrap();
    journal
        .apply(JournalTransition::IdentityRevalidated {
            fresh_manifest_digest: &guard.baseline_manifest_digest,
        })
        .unwrap();
    journal
        .apply(JournalTransition::PreconditionsVerified)
        .unwrap();
    journal
        .apply(JournalTransition::ExactPlanApproved {
            approved_plan_id: &guard.plan_id,
        })
        .unwrap();

    assert_eq!(journal.phase, JournalPhase::Approved);
    assert_eq!(
        journal.resume_disposition(),
        ResumeDisposition::RestartFromFreshPlan
    );

    journal.apply(JournalTransition::ExecutionStarted).unwrap();
    assert!(journal.mutation_may_have_started);
    assert_eq!(
        journal.resume_disposition(),
        ResumeDisposition::RecoveryRequired
    );

    journal
        .apply(JournalTransition::VerificationStarted)
        .unwrap();
    journal.apply(JournalTransition::Completed).unwrap();

    assert_eq!(journal.phase, JournalPhase::Completed);
    assert_eq!(journal.resume_disposition(), ResumeDisposition::Complete);
    assert_eq!(
        journal
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7]
    );
}

#[test]
fn stale_identity_is_rejected_before_preconditions_or_execution() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);
    journal.apply(JournalTransition::HostLockAcquired).unwrap();

    let error = journal
        .apply(JournalTransition::IdentityRevalidated {
            fresh_manifest_digest: "different-manifest",
        })
        .unwrap_err();

    assert_eq!(error, JournalError::IdentityMismatch);
    assert_eq!(journal.phase, JournalPhase::HostLockHeld);
    assert!(!journal.mutation_may_have_started);
}

#[test]
fn approval_for_another_plan_is_rejected() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);
    journal.apply(JournalTransition::HostLockAcquired).unwrap();
    journal
        .apply(JournalTransition::IdentityRevalidated {
            fresh_manifest_digest: &guard.baseline_manifest_digest,
        })
        .unwrap();
    journal
        .apply(JournalTransition::PreconditionsVerified)
        .unwrap();

    let error = journal
        .apply(JournalTransition::ExactPlanApproved {
            approved_plan_id: "older-plan-id",
        })
        .unwrap_err();

    assert_eq!(error, JournalError::ApprovalMismatch);
    assert_eq!(journal.phase, JournalPhase::PreconditionsVerified);
}

#[test]
fn interruption_before_execution_can_only_restart_from_a_fresh_plan() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);
    journal.apply(JournalTransition::HostLockAcquired).unwrap();

    journal
        .apply(JournalTransition::Interrupted {
            reason: "operator terminated preview-to-execution handoff",
        })
        .unwrap();

    assert_eq!(journal.phase, JournalPhase::Aborted);
    assert!(!journal.mutation_may_have_started);
    assert_eq!(
        journal.resume_disposition(),
        ResumeDisposition::RestartFromFreshPlan
    );
}

#[test]
fn interruption_after_execution_boundary_requires_reconciliation_not_replay() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);
    journal.apply(JournalTransition::HostLockAcquired).unwrap();
    journal
        .apply(JournalTransition::IdentityRevalidated {
            fresh_manifest_digest: &guard.baseline_manifest_digest,
        })
        .unwrap();
    journal
        .apply(JournalTransition::PreconditionsVerified)
        .unwrap();
    journal
        .apply(JournalTransition::ExactPlanApproved {
            approved_plan_id: &guard.plan_id,
        })
        .unwrap();
    journal.apply(JournalTransition::ExecutionStarted).unwrap();

    journal
        .apply(JournalTransition::Interrupted {
            reason: "power loss",
        })
        .unwrap();

    assert_eq!(journal.phase, JournalPhase::RecoveryRequired);
    assert!(journal.mutation_may_have_started);
    assert_eq!(
        journal.resume_disposition(),
        ResumeDisposition::RecoveryRequired
    );
    assert_eq!(
        journal
            .apply(JournalTransition::ExecutionStarted)
            .unwrap_err(),
        JournalError::Terminal
    );
}

#[test]
fn abort_after_execution_boundary_is_recovery_required() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);
    journal.apply(JournalTransition::HostLockAcquired).unwrap();
    journal
        .apply(JournalTransition::IdentityRevalidated {
            fresh_manifest_digest: &guard.baseline_manifest_digest,
        })
        .unwrap();
    journal
        .apply(JournalTransition::PreconditionsVerified)
        .unwrap();
    journal
        .apply(JournalTransition::ExactPlanApproved {
            approved_plan_id: &guard.plan_id,
        })
        .unwrap();
    journal.apply(JournalTransition::ExecutionStarted).unwrap();

    journal
        .apply(JournalTransition::Abort {
            reason: "unexpected subprocess result",
        })
        .unwrap();

    assert_eq!(journal.phase, JournalPhase::RecoveryRequired);
    assert_eq!(
        journal.resume_disposition(),
        ResumeDisposition::RecoveryRequired
    );
}

#[test]
fn invalid_phase_transition_fails_closed() {
    let guard = guard();
    let mut journal = OperationJournal::new(&guard);

    let error = journal
        .apply(JournalTransition::PreconditionsVerified)
        .unwrap_err();

    assert!(matches!(
        error,
        JournalError::InvalidTransition {
            phase: JournalPhase::Planned,
            ..
        }
    ));
    assert_eq!(journal.phase, JournalPhase::Planned);
}

#[test]
fn guard_id_is_repeatable_for_the_same_plan_and_target_manifest() {
    let snapshot = snapshot();
    let manifest = capture_target_identity(&snapshot, "/").unwrap();

    let first = build_execution_guard_plan("plan-test-001", &manifest).unwrap();
    let second = build_execution_guard_plan("plan-test-001", &manifest).unwrap();

    assert_eq!(first.guard_id, second.guard_id);
    assert_eq!(first.journal_path, second.journal_path);
}
