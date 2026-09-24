use lsm_core::{HostCapabilities, HostSnapshot};
use lsm_planner::{
    decide_filesystem_growth, revalidate_target_identity, FilesystemCheckKind,
    FilesystemDecisionState, FilesystemGrowthDecision, JournalPhase, PlannerError,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    filesystem_health::receipt_matches_exact_check, BackupReceiptRevalidation,
    ExplicitFilesystemHealthReceipt, LockedExecutionSession, MUTATION_ENABLED,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreMutationEvidenceStatus {
    EvidenceComplete,
    FutureChecksRequired,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreMutationEvidenceBundle {
    schema_version: u32,
    bundle_id: String,
    locked_session_id: String,
    handoff_id: String,
    plan_id: String,
    target_manifest_digest: String,
    backup_manifest_id: String,
    backup_receipt_id: String,
    backup_receipt_revalidated: bool,
    filesystem_health_receipt_id: Option<String>,
    filesystem_decision: FilesystemGrowthDecision,
    status: PreMutationEvidenceStatus,
    owner_acceptance_required: bool,
    mutation_enabled: bool,
    blockers: Vec<String>,
    future_gates: Vec<String>,
}

impl PreMutationEvidenceBundle {
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn locked_session_id(&self) -> &str {
        &self.locked_session_id
    }

    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.target_manifest_digest
    }

    pub fn backup_manifest_id(&self) -> &str {
        &self.backup_manifest_id
    }

    pub fn backup_receipt_id(&self) -> &str {
        &self.backup_receipt_id
    }

    pub fn backup_receipt_revalidated(&self) -> bool {
        self.backup_receipt_revalidated
    }

    pub fn filesystem_health_receipt_id(&self) -> Option<&str> {
        self.filesystem_health_receipt_id.as_deref()
    }

    pub fn filesystem_decision(&self) -> &FilesystemGrowthDecision {
        &self.filesystem_decision
    }

    pub fn status(&self) -> PreMutationEvidenceStatus {
        self.status
    }

    pub fn owner_acceptance_required(&self) -> bool {
        self.owner_acceptance_required
    }

    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }

    pub fn blockers(&self) -> &[String] {
        &self.blockers
    }

    pub fn future_gates(&self) -> &[String] {
        &self.future_gates
    }
}

#[derive(Debug, Error)]
pub enum PreMutationEvidenceError {
    #[error("pre-mutation evidence requires an identity-revalidated locked session")]
    SessionNotRevalidated,
    #[error("mutation-enabled state is forbidden in the pre-mutation evidence foundation")]
    MutationEnabled,
    #[error("backup receipt revalidation is not bound to the exact locked handoff")]
    BackupBindingMismatch,
    #[error("explicit filesystem health receipt does not match the exact pending check")]
    FilesystemHealthReceiptMismatch,
    #[error("planner capability verification failed: {0}")]
    Planner(#[from] PlannerError),
    #[error("could not serialize pre-mutation evidence basis: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn build_pre_mutation_evidence(
    session: &LockedExecutionSession<'_>,
    fresh_snapshot: &HostSnapshot,
    fresh_capabilities: &HostCapabilities,
    backup_revalidation: &BackupReceiptRevalidation,
) -> Result<PreMutationEvidenceBundle, PreMutationEvidenceError> {
    build_pre_mutation_evidence_inner(
        session,
        fresh_snapshot,
        fresh_capabilities,
        backup_revalidation,
        None,
    )
}

pub fn build_pre_mutation_evidence_with_filesystem_health(
    session: &LockedExecutionSession<'_>,
    fresh_snapshot: &HostSnapshot,
    fresh_capabilities: &HostCapabilities,
    backup_revalidation: &BackupReceiptRevalidation,
    filesystem_health_receipt: &ExplicitFilesystemHealthReceipt,
) -> Result<PreMutationEvidenceBundle, PreMutationEvidenceError> {
    build_pre_mutation_evidence_inner(
        session,
        fresh_snapshot,
        fresh_capabilities,
        backup_revalidation,
        Some(filesystem_health_receipt),
    )
}

fn build_pre_mutation_evidence_inner(
    session: &LockedExecutionSession<'_>,
    fresh_snapshot: &HostSnapshot,
    fresh_capabilities: &HostCapabilities,
    backup_revalidation: &BackupReceiptRevalidation,
    filesystem_health_receipt: Option<&ExplicitFilesystemHealthReceipt>,
) -> Result<PreMutationEvidenceBundle, PreMutationEvidenceError> {
    if session.journal().phase != JournalPhase::IdentityRevalidated {
        return Err(PreMutationEvidenceError::SessionNotRevalidated);
    }
    if MUTATION_ENABLED || session.mutation_enabled() || session.handoff().mutation_enabled() {
        return Err(PreMutationEvidenceError::MutationEnabled);
    }

    let handoff = session.handoff();
    if backup_revalidation.handoff_id() != handoff.handoff_id()
        || backup_revalidation.plan_id() != handoff.plan().plan_id()
        || backup_revalidation.target_manifest_digest() != handoff.target_identity().manifest_digest
    {
        return Err(PreMutationEvidenceError::BackupBindingMismatch);
    }

    let identity = revalidate_target_identity(handoff.target_identity(), fresh_snapshot);
    let capabilities_match = handoff.matches_capabilities(fresh_capabilities)?;
    let mut filesystem_decision =
        decide_filesystem_growth(fresh_snapshot, fresh_capabilities, handoff.plan().target());
    let filesystem_health_receipt_id = if let Some(receipt) = filesystem_health_receipt {
        let check = filesystem_decision
            .read_only_check
            .as_ref()
            .ok_or(PreMutationEvidenceError::FilesystemHealthReceiptMismatch)?;
        if filesystem_decision.state != FilesystemDecisionState::ReadOnlyHealthCheckRequired
            || check.kind != FilesystemCheckKind::XfsMountedScrubNoModify
            || !receipt_matches_exact_check(receipt, session, check)?
        {
            return Err(PreMutationEvidenceError::FilesystemHealthReceiptMismatch);
        }
        let receipt_id = receipt.receipt_id().to_owned();
        filesystem_decision.state = FilesystemDecisionState::ReadyOnlineGrow;
        filesystem_decision.read_only_check = None;
        filesystem_decision.required_actions.clear();
        filesystem_decision.reasons.push(
            "explicit read-only XFS health receipt matched the exact locked session and check"
                .to_owned(),
        );
        Some(receipt_id)
    } else {
        None
    };

    let mut blockers = identity
        .changes
        .iter()
        .map(|change| format!("{}: {}", change.code, change.message))
        .collect::<Vec<_>>();
    if !capabilities_match {
        blockers.push(
            "capability-inventory-changed: storage tool capability inventory changed after locked revalidation"
                .to_owned(),
        );
    }
    if !backup_revalidation.matches() {
        blockers.extend(
            backup_revalidation
                .blockers()
                .iter()
                .map(|blocker| format!("backup-evidence: {blocker}")),
        );
        if backup_revalidation.blockers().is_empty() {
            blockers.push("backup-evidence: receipt revalidation did not match".to_owned());
        }
    }
    if matches!(
        filesystem_decision.state,
        FilesystemDecisionState::Blocked | FilesystemDecisionState::AdapterRequired
    ) {
        blockers.extend(
            filesystem_decision
                .reasons
                .iter()
                .map(|reason| format!("filesystem-precondition: {reason}")),
        );
        if filesystem_decision.reasons.is_empty() {
            blockers.push("filesystem-precondition: filesystem decision is blocked".to_owned());
        }
    }

    blockers.sort();
    blockers.dedup();

    let mut future_gates = vec![
        "explicit owner acceptance of the completed M0/M1A baseline is still required before mutation-capable rollout"
            .to_owned(),
        "exact fresh plan approval has not been recorded".to_owned(),
        "the durable journal remains at identity_revalidated; this bundle does not advance preconditions_verified"
            .to_owned(),
        "storage mutation remains disabled".to_owned(),
    ];
    if !matches!(
        filesystem_decision.state,
        FilesystemDecisionState::ReadyOnlineGrow
            | FilesystemDecisionState::Blocked
            | FilesystemDecisionState::AdapterRequired
    ) {
        future_gates.extend(
            filesystem_decision
                .required_actions
                .iter()
                .map(|action| format!("filesystem: {action}")),
        );
        if let Some(check) = &filesystem_decision.read_only_check {
            future_gates.push(format!(
                "filesystem check required: {} {}",
                check.tool,
                check.args.join(" ")
            ));
        }
    }
    future_gates.sort();
    future_gates.dedup();

    let status = if !blockers.is_empty() {
        PreMutationEvidenceStatus::Blocked
    } else if filesystem_decision.state == FilesystemDecisionState::ReadyOnlineGrow {
        PreMutationEvidenceStatus::EvidenceComplete
    } else {
        PreMutationEvidenceStatus::FutureChecksRequired
    };

    let mut bundle = PreMutationEvidenceBundle {
        schema_version: 3,
        bundle_id: String::new(),
        locked_session_id: session.session_id().to_owned(),
        handoff_id: handoff.handoff_id().to_owned(),
        plan_id: handoff.plan().plan_id().to_owned(),
        target_manifest_digest: handoff.target_identity().manifest_digest.clone(),
        backup_manifest_id: backup_revalidation.manifest_id().to_owned(),
        backup_receipt_id: backup_revalidation.receipt_id().to_owned(),
        backup_receipt_revalidated: backup_revalidation.matches(),
        filesystem_health_receipt_id,
        filesystem_decision,
        status,
        owner_acceptance_required: true,
        mutation_enabled: false,
        blockers,
        future_gates,
    };
    bundle.bundle_id = bundle.compute_bundle_id()?;
    Ok(bundle)
}

impl PreMutationEvidenceBundle {
    fn compute_bundle_id(&self) -> Result<String, serde_json::Error> {
        fingerprint(&(
            self.schema_version,
            &self.locked_session_id,
            &self.handoff_id,
            &self.plan_id,
            &self.target_manifest_digest,
            &self.backup_manifest_id,
            &self.backup_receipt_id,
            self.backup_receipt_revalidated,
            &self.filesystem_health_receipt_id,
            &self.filesystem_decision,
            self.status,
            self.owner_acceptance_required,
            self.mutation_enabled,
            &self.blockers,
            &self.future_gates,
        ))
    }

    pub(crate) fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.bundle_id == self.compute_bundle_id()?)
    }

    #[cfg(test)]
    pub(crate) fn test_with_handoff_id(mut self, value: String) -> Self {
        self.handoff_id = value;
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }

    #[cfg(test)]
    pub(crate) fn test_with_plan_id(mut self, value: String) -> Self {
        self.plan_id = value;
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }

    #[cfg(test)]
    pub(crate) fn test_with_target_manifest_digest(mut self, value: String) -> Self {
        self.target_manifest_digest = value;
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }

    #[cfg(test)]
    pub(crate) fn test_without_backup(mut self) -> Self {
        self.backup_manifest_id.clear();
        self.backup_receipt_id.clear();
        self.backup_receipt_revalidated = false;
        self.status = PreMutationEvidenceStatus::EvidenceComplete;
        self.blockers.clear();
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }

    #[cfg(test)]
    pub(crate) fn test_with_mutation_enabled(mut self) -> Self {
        self.mutation_enabled = true;
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }

    #[cfg(test)]
    pub(crate) fn test_with_filesystem_state(mut self, state: FilesystemDecisionState) -> Self {
        self.filesystem_decision.state = state;
        self.status = PreMutationEvidenceStatus::EvidenceComplete;
        self.blockers.clear();
        self.bundle_id = self.compute_bundle_id().unwrap();
        self
    }
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{FilesystemPreflightEvidence, FilesystemProbeState};
    use lsm_planner::{
        build_frozen_execution_handoff, plan_extend, ExtendRequest, Growth, PlanStatus,
    };
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    fn fixture(filesystem_state: &str) -> (HostSnapshot, HostCapabilities) {
        const GIB: u64 = 1 << 30;
        let sector = 512_u64;
        let partition_bytes = 10 * GIB;
        let mut snapshot: HostSnapshot = serde_json::from_value(json!({
            "storage":{"block_devices":[{
                "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
                "size_bytes":20*GIB,"logical_sector_bytes":sector,
                "model":"Virtual Disk","serial":"PRECONDITION-EVIDENCE","mountpoints":[],"children":[{
                    "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                    "size_bytes":partition_bytes,"start_512_sector":2048,
                    "logical_sector_bytes":sector,"uuid":"fs-data","partition_uuid":"part-data",
                    "partition_table":"gpt","filesystem":{"fs_type":"ext4","version":"1.0"},
                    "mountpoints":["/data"],"parent_kernel_name":"sda","children":[]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/sda","label":"gpt","id":"gpt-preconditions","unit":"sectors",
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
        snapshot
            .filesystem_preflight
            .push(FilesystemPreflightEvidence {
                device: "/dev/sda1".into(),
                mountpoint: Some("/data".into()),
                fs_type: "ext4".into(),
                fs_version: Some("1.0".into()),
                state: FilesystemProbeState::Verified,
                filesystem_state: Some(filesystem_state.into()),
                revision: Some("1".into()),
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
        let capabilities = serde_json::from_value(json!({"tools":[
            {"name":"sfdisk","available":true},
            {"name":"resize2fs","available":true},
            {"name":"e2fsck","available":true}
        ]}))
        .unwrap();
        (snapshot, capabilities)
    }

    fn handoff(
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> lsm_planner::FrozenExecutionHandoff {
        const GIB: u64 = 1 << 30;
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
        build_frozen_execution_handoff(snapshot, capabilities, &plan).unwrap()
    }

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lsm-pre-mutation-evidence-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn clean_ext4_and_matching_backup_evidence_is_complete_but_non_mutating() {
        let (snapshot, capabilities) = fixture("clean");
        let handoff = handoff(&snapshot, &capabilities);
        let lock = test_path("complete").join("storage.lock");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        let locked = session.revalidate(&snapshot, &capabilities).unwrap();
        assert_eq!(locked.status, crate::LockedRevalidationStatus::Revalidated);
        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            true,
            Vec::new(),
        );

        let bundle =
            build_pre_mutation_evidence(&session, &snapshot, &capabilities, &backup).unwrap();

        assert_eq!(bundle.status(), PreMutationEvidenceStatus::EvidenceComplete);
        assert!(bundle.blockers().is_empty());
        assert!(bundle.owner_acceptance_required());
        assert!(!bundle.mutation_enabled());
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
    }

    #[test]
    fn failed_backup_evidence_blocks_bundle() {
        let (snapshot, capabilities) = fixture("clean");
        let handoff = handoff(&snapshot, &capabilities);
        let lock = test_path("backup-block").join("storage.lock");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            false,
            vec!["artifact SHA-256 changed".into()],
        );

        let bundle =
            build_pre_mutation_evidence(&session, &snapshot, &capabilities, &backup).unwrap();

        assert_eq!(bundle.status(), PreMutationEvidenceStatus::Blocked);
        assert!(bundle
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("SHA-256")));
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
    }

    #[test]
    fn dirty_ext4_remains_future_check_required() {
        let (snapshot, capabilities) = fixture("not clean");
        let handoff = handoff(&snapshot, &capabilities);
        let lock = test_path("future-check").join("storage.lock");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            true,
            Vec::new(),
        );

        let bundle =
            build_pre_mutation_evidence(&session, &snapshot, &capabilities, &backup).unwrap();

        assert_eq!(
            bundle.status(),
            PreMutationEvidenceStatus::FutureChecksRequired
        );
        assert!(bundle
            .future_gates()
            .iter()
            .any(|gate| gate.contains("e2fsck")));
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
    }

    #[test]
    fn target_change_after_locked_revalidation_blocks_evidence() {
        let (snapshot, capabilities) = fixture("clean");
        let handoff = handoff(&snapshot, &capabilities);
        let lock = test_path("stale").join("storage.lock");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            true,
            Vec::new(),
        );
        let mut changed = snapshot.clone();
        changed.storage.block_devices[0].serial = Some("CHANGED".into());

        let bundle =
            build_pre_mutation_evidence(&session, &changed, &capabilities, &backup).unwrap();

        assert_eq!(bundle.status(), PreMutationEvidenceStatus::Blocked);
        assert!(bundle
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("device-chain-changed")));
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
    }
}
