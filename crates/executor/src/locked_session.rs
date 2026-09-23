use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use lsm_core::{HostCapabilities, HostSnapshot};
use lsm_planner::{
    revalidate_target_identity, ExactApprovalBinding, ExecutionHandoffStatus,
    ExecutionStartBinding, FrozenExecutionHandoff, IdentityRevalidation, JournalError,
    JournalPhase, JournalTransition, OperationJournal, PlannerError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DurableJournalStore, HostLockError, HostStorageLock, JournalStoreError, MUTATION_ENABLED,
};

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedRevalidationStatus {
    Revalidated,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedRevalidation {
    pub status: LockedRevalidationStatus,
    pub identity: IdentityRevalidation,
    pub capabilities_match: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug)]
pub struct LockedExecutionSession<'a> {
    lock: HostStorageLock,
    session_id: String,
    handoff: &'a FrozenExecutionHandoff,
    journal: OperationJournal,
    journal_store: Option<&'a DurableJournalStore>,
    revalidation_attempted: bool,
}

#[derive(Debug, Error)]
pub enum LockedSessionError {
    #[error("frozen handoff is blocked and cannot enter a locked executor session")]
    HandoffBlocked,
    #[error("a mutation-enabled handoff is forbidden in the M1B pre-executor session")]
    MutationEnabled,
    #[error(
        "locked revalidation has already been attempted; release the lock and build a fresh plan"
    )]
    RevalidationAlreadyAttempted,
    #[error("host lock acquisition failed: {0}")]
    Lock(#[from] HostLockError),
    #[error("planner capability revalidation failed: {0}")]
    Planner(#[from] PlannerError),
    #[error("in-memory journal transition failed: {0}")]
    Journal(#[from] JournalError),
    #[error("preconditions verification requires a durable journal store")]
    DurableJournalRequired,
    #[error("durable journal state does not match the current locked session")]
    DurableJournalMismatch,
    #[error("durable journal persistence failed: {0}")]
    DurableJournal(#[from] JournalStoreError),
}

impl<'a> LockedExecutionSession<'a> {
    pub fn begin(handoff: &'a FrozenExecutionHandoff) -> Result<Self, LockedSessionError> {
        validate_handoff(handoff)?;
        Self::begin_with_lock(handoff, HostStorageLock::try_acquire_default()?, None)
    }

    pub fn begin_durable(
        handoff: &'a FrozenExecutionHandoff,
        journal_store: &'a DurableJournalStore,
    ) -> Result<Self, LockedSessionError> {
        validate_handoff(handoff)?;
        Self::begin_with_lock(
            handoff,
            HostStorageLock::try_acquire_default()?,
            Some(journal_store),
        )
    }

    pub fn lock_path(&self) -> &Path {
        self.lock.path()
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn journal(&self) -> &OperationJournal {
        &self.journal
    }

    pub fn handoff(&self) -> &FrozenExecutionHandoff {
        self.handoff
    }

    pub fn mutation_enabled(&self) -> bool {
        MUTATION_ENABLED
    }

    pub fn durable_journal_enabled(&self) -> bool {
        self.journal_store.is_some()
    }

    pub fn revalidate(
        &mut self,
        fresh_snapshot: &HostSnapshot,
        fresh_capabilities: &HostCapabilities,
    ) -> Result<LockedRevalidation, LockedSessionError> {
        if self.revalidation_attempted {
            return Err(LockedSessionError::RevalidationAlreadyAttempted);
        }
        self.revalidation_attempted = true;

        let identity = revalidate_target_identity(self.handoff.target_identity(), fresh_snapshot);
        let capabilities_match = self.handoff.matches_capabilities(fresh_capabilities)?;

        let mut blockers = identity
            .changes
            .iter()
            .map(|change| format!("{}: {}", change.code, change.message))
            .collect::<Vec<_>>();
        if !capabilities_match {
            blockers.push(
                "capability-inventory-changed: storage tool capability inventory changed since the frozen handoff"
                    .to_owned(),
            );
        }

        let status = if identity.matches && capabilities_match {
            let fresh_digest = identity
                .fresh_digest
                .as_deref()
                .unwrap_or(self.handoff.target_identity().manifest_digest.as_str());
            self.journal.apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: fresh_digest,
            })?;
            self.persist_journal_if_configured()?;
            LockedRevalidationStatus::Revalidated
        } else {
            LockedRevalidationStatus::Blocked
        };

        Ok(LockedRevalidation {
            status,
            identity,
            capabilities_match,
            blockers,
        })
    }

    fn begin_with_lock(
        handoff: &'a FrozenExecutionHandoff,
        lock: HostStorageLock,
        journal_store: Option<&'a DurableJournalStore>,
    ) -> Result<Self, LockedSessionError> {
        validate_handoff(handoff)?;

        let mut journal = OperationJournal::new(handoff.guard());
        journal.apply(JournalTransition::HostLockAcquired)?;
        debug_assert_eq!(journal.phase, JournalPhase::HostLockHeld);
        if let Some(store) = journal_store {
            store.persist(&journal)?;
        }

        let session_id = build_session_id(handoff, lock.path());

        Ok(Self {
            lock,
            session_id,
            handoff,
            journal,
            journal_store,
            revalidation_attempted: false,
        })
    }

    fn persist_journal_if_configured(&self) -> Result<(), LockedSessionError> {
        if let Some(store) = self.journal_store {
            store.persist(&self.journal)?;
        }
        Ok(())
    }

    pub(crate) fn require_current_durable_journal(&self) -> Result<(), LockedSessionError> {
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;
        let persisted = store.load(&self.journal.journal_id)?;
        if persisted != self.journal {
            return Err(LockedSessionError::DurableJournalMismatch);
        }
        Ok(())
    }

    pub(crate) fn persist_preconditions_verified(&mut self) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::PreconditionsVerified)?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub(crate) fn persist_exact_plan_approved(
        &mut self,
        approved_plan_id: &str,
        approval: &ExactApprovalBinding,
    ) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::ExactPlanApproved {
            approved_plan_id,
            approval,
        })?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub fn persist_execution_started(
        &mut self,
        binding: &ExecutionStartBinding,
    ) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::ExecutionStarted { binding })?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub fn persist_verification_started(&mut self) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::VerificationStarted)?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub fn persist_verification_passed_continue(
        &mut self,
        completed_step_id: u32,
        next_step_id: u32,
        fresh_identity_digest: &str,
    ) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::VerificationPassedContinue {
            completed_step_id,
            next_step_id,
            fresh_identity_digest,
        })?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub fn persist_completed(&mut self) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::Completed)?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    pub fn persist_interrupted(&mut self, reason: &str) -> Result<(), LockedSessionError> {
        self.require_current_durable_journal()?;
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;

        let mut next = self.journal.clone();
        next.apply(JournalTransition::Interrupted { reason })?;
        store.persist(&next)?;
        self.journal = next;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn begin_at_path(
        handoff: &'a FrozenExecutionHandoff,
        path: &Path,
    ) -> Result<Self, LockedSessionError> {
        validate_handoff(handoff)?;
        Self::begin_with_lock(handoff, HostStorageLock::try_acquire_path(path)?, None)
    }

    #[cfg(test)]
    fn begin_durable_at_paths(
        handoff: &'a FrozenExecutionHandoff,
        lock_path: &Path,
        journal_store: &'a DurableJournalStore,
    ) -> Result<Self, LockedSessionError> {
        validate_handoff(handoff)?;
        Self::begin_with_lock(
            handoff,
            HostStorageLock::try_acquire_path(lock_path)?,
            Some(journal_store),
        )
    }
}

fn build_session_id(handoff: &FrozenExecutionHandoff, lock_path: &Path) -> String {
    let sequence = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(b"linux-storage-manager:locked-session:v1\0");
    hasher.update(handoff.handoff_id().as_bytes());
    hasher.update([0_u8]);
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(sequence.to_le_bytes());
    hasher.update(lock_path.as_os_str().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn validate_handoff(handoff: &FrozenExecutionHandoff) -> Result<(), LockedSessionError> {
    if handoff.status() == ExecutionHandoffStatus::Blocked {
        return Err(LockedSessionError::HandoffBlocked);
    }
    if handoff.mutation_enabled() || MUTATION_ENABLED {
        return Err(LockedSessionError::MutationEnabled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{HostCapabilities, HostSnapshot};
    use lsm_planner::{
        build_execution_start_binding, build_frozen_execution_handoff, plan_extend, ExtendRequest,
        Growth, JournalPhase, PlanStatus,
    };
    use serde_json::json;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const GIB: u64 = 1024 * 1024 * 1024;
    const EXTENT: u64 = 4 * 1024 * 1024;
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn lock_path() -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "linux-storage-manager-session-test-{}-{unique}",
                std::process::id()
            ))
            .join("storage.lock")
    }

    fn journal_root(name: &str) -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "linux-storage-manager-session-journal-test-{}-{unique}-{name}",
            std::process::id()
        ))
    }

    fn fixture() -> (HostSnapshot, HostCapabilities) {
        let snapshot: HostSnapshot = serde_json::from_value(json!({
            "storage": {"block_devices": [{
                "name":"vda", "kernel_name":"vda", "path":"/dev/vda", "kind":"disk",
                "size_bytes":20*GIB, "mountpoints":[], "partition_table":"gpt", "children":[{
                    "name":"vda1", "kernel_name":"vda1", "path":"/dev/vda1", "kind":"partition",
                    "size_bytes":16*GIB, "start_512_sector":2048, "logical_sector_bytes":512,
                    "uuid":"pv-1", "partition_uuid":"part-1",
                    "filesystem":{"fs_type":"LVM2_member"}, "mountpoints":[],
                    "parent_kernel_name":"vda", "children":[{
                        "name":"vg0-root", "kernel_name":"dm-0", "path":"/dev/mapper/vg0-root",
                        "kind":"lvm", "size_bytes":8*GIB, "uuid":"fs-1",
                        "filesystem":{"fs_type":"ext4","version":"1.0"}, "mountpoints":["/"],
                        "parent_kernel_name":"vda1", "children":[]
                    }]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/vda","label":"gpt","id":"gpt-test","unit":"sectors",
                "first_lba":34,"last_lba":41943006,"sector_size_bytes":512,
                "partitions":[{
                    "node":"/dev/vda1","start_sector":2048,"size_sectors":33554432,
                    "partition_type":"E6D6D379-F507-44C2-A23C-238F2A3DF928",
                    "uuid":"part-1"
                }]
            }],
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
            },
            "filesystem_preflight":[{
                "device":"/dev/mapper/vg0-root","mountpoint":"/","fs_type":"ext4",
                "fs_version":"1.0","state":"verified","filesystem_state":"clean",
                "revision":"1","features":["has_journal","extent","64bit","metadata_csum"],
                "block_size_bytes":4096,
                "block_count":2097152,"size_bytes":8*GIB,"grow_check_passed":null,
                "detail":"fixture"
            }]
        }))
        .unwrap();

        let capabilities: HostCapabilities = serde_json::from_value(json!({"tools":[
            {"name":"vgcfgbackup","available":true},
            {"name":"lvextend","available":true},
            {"name":"resize2fs","available":true},
            {"name":"e2fsck","available":true}
        ]}))
        .unwrap();
        (snapshot, capabilities)
    }

    fn handoff(snapshot: &HostSnapshot, capabilities: &HostCapabilities) -> FrozenExecutionHandoff {
        let plan = plan_extend(
            snapshot,
            capabilities,
            ExtendRequest {
                target: "/".into(),
                growth: Growth::ByBytes(GIB),
            },
        )
        .unwrap();
        assert_eq!(plan.status(), PlanStatus::Preview);
        build_frozen_execution_handoff(snapshot, capabilities, &plan).unwrap()
    }

    fn evidence(
        session: &LockedExecutionSession<'_>,
        handoff: &FrozenExecutionHandoff,
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
        backup_matches: bool,
        backup_blockers: Vec<String>,
    ) -> crate::PreMutationEvidenceBundle {
        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            backup_matches,
            backup_blockers,
        );
        crate::build_pre_mutation_evidence(session, snapshot, capabilities, &backup).unwrap()
    }

    fn xfs_fixture() -> (HostSnapshot, HostCapabilities) {
        let (mut snapshot, _) = fixture();
        let filesystem = snapshot.storage.block_devices[0].children[0].children[0]
            .filesystem
            .as_mut()
            .unwrap();
        filesystem.fs_type = "xfs".into();
        filesystem.version = Some("5".into());
        snapshot.mounts[0].fs_type = Some("xfs".into());

        let preflight = &mut snapshot.filesystem_preflight[0];
        preflight.fs_type = "xfs".into();
        preflight.fs_version = Some("5".into());
        preflight.filesystem_state = None;
        preflight.features = vec!["crc".into(), "finobt".into()];
        preflight.grow_check_passed = Some(true);

        let capabilities: HostCapabilities = serde_json::from_value(json!({"tools":[
            {"name":"vgcfgbackup","available":true},
            {"name":"lvextend","available":true},
            {"name":"xfs_growfs","available":true},
            {"name":"xfs_scrub","available":true}
        ]}))
        .unwrap();
        (snapshot, capabilities)
    }

    fn assert_identity_revalidated_is_durable(
        session: &LockedExecutionSession<'_>,
        store: &DurableJournalStore,
    ) {
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted, *session.journal());
    }

    fn verified_preconditions(
        session: &mut LockedExecutionSession<'_>,
        handoff: &FrozenExecutionHandoff,
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> (
        crate::PreMutationEvidenceBundle,
        crate::PreconditionsVerification,
    ) {
        let evidence = evidence(session, handoff, snapshot, capabilities, true, Vec::new());
        let verified = crate::verify_preconditions(session, &evidence).unwrap();
        (evidence, verified)
    }

    fn approved_session<'a>(
        session: &mut LockedExecutionSession<'a>,
        handoff: &FrozenExecutionHandoff,
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> crate::ExactPlanApproval {
        session.revalidate(snapshot, capabilities).unwrap();
        let (evidence, verified) = verified_preconditions(session, handoff, snapshot, capabilities);
        crate::approve_exact_plan(
            session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        )
        .unwrap()
    }

    fn assert_preconditions_verified_is_durable(
        session: &LockedExecutionSession<'_>,
        store: &DurableJournalStore,
    ) {
        assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted, *session.journal());
    }

    #[test]
    fn unchanged_fresh_state_revalidates_while_lock_is_held() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();

        assert_eq!(session.journal().phase, JournalPhase::HostLockHeld);
        let result = session.revalidate(&snapshot, &capabilities).unwrap();

        assert_eq!(result.status, LockedRevalidationStatus::Revalidated);
        assert!(result.identity.matches);
        assert!(result.capabilities_match);
        assert!(result.blockers.is_empty());
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        assert!(!session.mutation_enabled());
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn target_change_fails_closed_without_advancing_journal() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        let mut changed = snapshot.clone();
        changed.storage.block_devices[0].children[0].size_bytes += EXTENT;

        let result = session.revalidate(&changed, &capabilities).unwrap();

        assert_eq!(result.status, LockedRevalidationStatus::Blocked);
        assert!(!result.identity.matches);
        assert_eq!(session.journal().phase, JournalPhase::HostLockHeld);
        assert!(result
            .blockers
            .iter()
            .any(|blocker| blocker.contains("device-chain-changed")));
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn capability_change_fails_closed_without_advancing_journal() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        let mut changed_capabilities = capabilities.clone();
        changed_capabilities.tools[0].available = false;

        let result = session
            .revalidate(&snapshot, &changed_capabilities)
            .unwrap();

        assert_eq!(result.status, LockedRevalidationStatus::Blocked);
        assert!(result.identity.matches);
        assert!(!result.capabilities_match);
        assert_eq!(session.journal().phase, JournalPhase::HostLockHeld);
        assert!(result
            .blockers
            .iter()
            .any(|blocker| blocker.starts_with("capability-inventory-changed")));
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn unrelated_disk_does_not_invalidate_target_identity() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        let mut fresh = snapshot.clone();
        fresh.storage.block_devices.push(
            serde_json::from_value(json!({
                "name":"vdb","kernel_name":"vdb","path":"/dev/vdb","kind":"disk",
                "size_bytes":4*GIB,"mountpoints":[],"children":[]
            }))
            .unwrap(),
        );

        let result = session.revalidate(&fresh, &capabilities).unwrap();

        assert_eq!(result.status, LockedRevalidationStatus::Revalidated);
        assert!(result.identity.matches);
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn second_locked_session_is_busy_until_first_is_dropped() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let first = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();

        let second = LockedExecutionSession::begin_at_path(&handoff, &path);

        assert!(matches!(
            second,
            Err(LockedSessionError::Lock(HostLockError::Busy))
        ));
        drop(first);
        let replacement = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        drop(replacement);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn one_session_cannot_retry_after_failed_revalidation() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        let mut changed = snapshot.clone();
        changed.storage.block_devices[0].size_bytes += GIB;

        let first = session.revalidate(&changed, &capabilities).unwrap();
        assert_eq!(first.status, LockedRevalidationStatus::Blocked);

        let second = session.revalidate(&snapshot, &capabilities);
        assert!(matches!(
            second,
            Err(LockedSessionError::RevalidationAlreadyAttempted)
        ));
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn durable_session_persists_lock_and_identity_revalidation() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("round-trip");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();

        assert!(session.durable_journal_enabled());
        let locked = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(locked.phase, JournalPhase::HostLockHeld);
        assert_eq!(locked.events.len(), 1);

        let result = session.revalidate(&snapshot, &capabilities).unwrap();
        assert_eq!(result.status, LockedRevalidationStatus::Revalidated);

        let revalidated = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(revalidated.phase, JournalPhase::IdentityRevalidated);
        assert_eq!(revalidated.events.len(), 2);
        assert_eq!(revalidated, *session.journal());

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_precondition_evidence_advances_durable_journal() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("preconditions");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let result = session.revalidate(&snapshot, &capabilities).unwrap();
        assert_eq!(result.status, LockedRevalidationStatus::Revalidated);

        let second = LockedExecutionSession::begin_at_path(&handoff, &path);
        assert!(matches!(
            second,
            Err(LockedSessionError::Lock(HostLockError::Busy))
        ));

        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        assert_eq!(
            evidence.status(),
            crate::PreMutationEvidenceStatus::EvidenceComplete
        );
        assert_eq!(evidence.locked_session_id(), session.session_id());
        assert!(evidence.owner_acceptance_required());

        let verified = crate::verify_preconditions(&mut session, &evidence).unwrap();

        assert_eq!(verified.bundle_id(), evidence.bundle_id());
        assert_eq!(verified.locked_session_id(), session.session_id());
        assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);
        assert!(!session.journal().mutation_may_have_started);
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted.phase, JournalPhase::PreconditionsVerified);
        assert_eq!(persisted, *session.journal());

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_operator_approval_advances_and_binds_durable_journal() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("exact-approval");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();

        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        let verified = crate::verify_preconditions(&mut session, &evidence).unwrap();
        assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);

        let second = LockedExecutionSession::begin_at_path(&handoff, &path);
        assert!(matches!(
            second,
            Err(LockedSessionError::Lock(HostLockError::Busy))
        ));

        let approval = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        )
        .unwrap();

        assert_eq!(session.journal().phase, JournalPhase::Approved);
        assert!(!session.journal().mutation_may_have_started);
        assert_eq!(approval.plan_id(), handoff.plan().plan_id());
        assert_eq!(approval.evidence_bundle_id(), evidence.bundle_id());
        assert_eq!(
            approval.target_manifest_digest(),
            handoff.target_identity().manifest_digest
        );
        assert_eq!(approval.locked_session_id(), session.session_id());
        assert!(approval.owner_acceptance_required());
        assert!(!approval.mutation_enabled());
        assert_eq!(approval.approval_id().len(), 64);
        assert_eq!(approval.preconditions_journal_digest().len(), 64);

        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted.phase, JournalPhase::Approved);
        assert!(!persisted.mutation_may_have_started);
        let binding = persisted.approval.as_ref().unwrap();
        assert_eq!(binding.approval_id, approval.approval_id());
        assert_eq!(binding.plan_id, approval.plan_id());
        assert_eq!(binding.evidence_bundle_id, approval.evidence_bundle_id());
        assert_eq!(
            binding.target_manifest_digest,
            approval.target_manifest_digest()
        );
        assert_eq!(
            binding.preconditions_journal_digest,
            approval.preconditions_journal_digest()
        );

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_execution_start_binding_advances_durable_journal_atomically() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("execution-start");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities);

        let frozen = crate::freeze_execution_intent(&session, &approval).unwrap();
        let compiled = crate::compile_native_manifest(&frozen);
        let validated = crate::validate_and_bind_native_manifest(compiled).unwrap();
        let mutation_step_ids = validated
            .manifest()
            .steps
            .iter()
            .filter(|step| step.role == crate::FrozenIntentRole::MutationCandidate)
            .map(|step| step.plan_step_id)
            .collect::<Vec<_>>();
        let binding = build_execution_start_binding(
            session.journal(),
            frozen.manifest_id(),
            validated.digest(),
            &handoff.target_identity().manifest_digest,
            &mutation_step_ids,
        )
        .unwrap();

        let approved = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(approved.phase, JournalPhase::Approved);
        assert!(!approved.mutation_may_have_started);
        assert!(approved.execution.is_none());

        session.persist_execution_started(&binding).unwrap();

        assert_eq!(session.journal().phase, JournalPhase::Executing);
        assert!(session.journal().mutation_may_have_started);
        assert_eq!(session.journal().execution.as_ref(), Some(&binding));
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted, *session.journal());
        assert_eq!(persisted.execution.as_ref(), Some(&binding));

        session.persist_verification_started().unwrap();
        assert_eq!(session.journal().phase, JournalPhase::Verifying);
        assert!(session.journal().mutation_may_have_started);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        let verified_identity_digest = "7".repeat(64);
        session
            .persist_verification_passed_continue(
                mutation_step_ids[0],
                mutation_step_ids[1],
                &verified_identity_digest,
            )
            .unwrap();
        assert_eq!(session.journal().phase, JournalPhase::Executing);
        assert_eq!(
            session
                .journal()
                .verified_boundary
                .as_ref()
                .unwrap()
                .fresh_identity_digest,
            verified_identity_digest
        );
        assert!(session.journal().mutation_may_have_started);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        session.persist_verification_started().unwrap();
        assert_eq!(session.journal().phase, JournalPhase::Verifying);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        session.persist_completed().unwrap();
        assert_eq!(session.journal().phase, JournalPhase::Completed);
        assert!(session.journal().mutation_may_have_started);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn terminal_disposable_verification_completes_only_after_fresh_filesystem_growth() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("terminal-disposable-verification");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities);

        let frozen = crate::freeze_execution_intent(&session, &approval).unwrap();
        let compiled = crate::compile_native_manifest(&frozen);
        let validated = crate::validate_and_bind_native_manifest(compiled).unwrap();
        let mutation_step_ids = validated
            .manifest()
            .steps
            .iter()
            .filter(|step| step.role == crate::FrozenIntentRole::MutationCandidate)
            .map(|step| step.plan_step_id)
            .collect::<Vec<_>>();
        assert_eq!(mutation_step_ids.len(), 2);

        let binding = build_execution_start_binding(
            session.journal(),
            frozen.manifest_id(),
            validated.digest(),
            &handoff.target_identity().manifest_digest,
            &mutation_step_ids,
        )
        .unwrap();
        session.persist_execution_started(&binding).unwrap();
        session.persist_verification_started().unwrap();
        let verified_identity_digest = "b".repeat(64);
        session
            .persist_verification_passed_continue(
                mutation_step_ids[0],
                mutation_step_ids[1],
                &verified_identity_digest,
            )
            .unwrap();
        let verified_boundary = session.journal().verified_boundary.as_ref().unwrap();
        assert_eq!(verified_boundary.completed_step_id, mutation_step_ids[0]);
        assert_eq!(verified_boundary.next_step_id, mutation_step_ids[1]);
        assert_eq!(
            verified_boundary.fresh_identity_digest,
            verified_identity_digest
        );
        session.persist_verification_started().unwrap();
        assert_eq!(session.journal().phase, JournalPhase::Verifying);

        let expected_lv_size = validated
            .manifest()
            .steps
            .iter()
            .find_map(|step| match &step.operation {
                crate::NativeOperationSpec::ExtendLogicalVolume {
                    expected_lv_size_bytes,
                    ..
                } => Some(*expected_lv_size_bytes),
                _ => None,
            })
            .unwrap();

        let mut before_growth = handoff.target_identity().clone();
        before_growth.manifest_digest = verified_identity_digest.clone();
        for entry in &mut before_growth.lvm {
            if entry.kind == lsm_planner::LvmIdentityKind::LogicalVolume {
                entry.size_bytes = expected_lv_size;
            }
        }
        let before_filesystem = before_growth.filesystem.as_mut().unwrap();
        let original_filesystem_size = before_filesystem.observed_filesystem_size_bytes.unwrap();
        before_filesystem.backing_device_size_bytes = expected_lv_size;

        let mut fresh = before_growth.clone();
        fresh.manifest_digest = "c".repeat(64);

        let blocked = crate::verify_and_complete_disposable_execution(
            &mut session,
            &validated,
            &before_growth,
            &fresh,
            mutation_step_ids[1],
        );
        assert!(matches!(
            blocked,
            Err(crate::DisposableBoundaryVerificationError::FilesystemSizeDidNotGrow)
        ));
        assert_eq!(session.journal().phase, JournalPhase::Verifying);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        let grown_filesystem_size =
            original_filesystem_size + (expected_lv_size - original_filesystem_size) / 2;
        fresh
            .filesystem
            .as_mut()
            .unwrap()
            .observed_filesystem_size_bytes = Some(grown_filesystem_size);

        let mut forged_before_growth = before_growth.clone();
        forged_before_growth.manifest_digest = "d".repeat(64);
        let forged = crate::verify_and_complete_disposable_execution(
            &mut session,
            &validated,
            &forged_before_growth,
            &fresh,
            mutation_step_ids[1],
        );
        assert!(matches!(
            forged,
            Err(crate::DisposableBoundaryVerificationError::VerifiedBoundaryIdentityMismatch)
        ));
        assert_eq!(session.journal().phase, JournalPhase::Verifying);

        let completion = crate::verify_and_complete_disposable_execution(
            &mut session,
            &validated,
            &before_growth,
            &fresh,
            mutation_step_ids[1],
        )
        .unwrap();

        assert_eq!(completion.execution_id(), binding.execution_id);
        assert_eq!(completion.completed_step_id(), mutation_step_ids[1]);
        assert_eq!(completion.fresh_identity_digest(), fresh.manifest_digest);
        assert_eq!(session.journal().phase, JournalPhase::Completed);
        assert_eq!(
            store.load(&session.journal().journal_id).unwrap(),
            *session.journal()
        );

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn exact_approved_session_freezes_non_executable_intent() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("execution-intent");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities);
        let before = session.journal().clone();

        let second = LockedExecutionSession::begin_at_path(&handoff, &path);
        assert!(matches!(
            second,
            Err(LockedSessionError::Lock(HostLockError::Busy))
        ));

        let manifest = crate::freeze_execution_intent(&session, &approval).unwrap();
        let repeated = crate::freeze_execution_intent(&session, &approval).unwrap();

        assert_eq!(manifest, repeated);
        assert_eq!(manifest.manifest_id(), repeated.manifest_id());
        assert_eq!(
            manifest.status(),
            crate::ExecutionIntentManifestStatus::FrozenNonExecutable
        );
        assert_eq!(manifest.approval_id(), approval.approval_id());
        assert_eq!(manifest.plan_id(), handoff.plan().plan_id());
        assert_eq!(manifest.evidence_bundle_id(), approval.evidence_bundle_id());
        assert_eq!(
            manifest.target_manifest_digest(),
            handoff.target_identity().manifest_digest
        );
        assert_eq!(manifest.locked_session_id(), session.session_id());
        assert_eq!(manifest.approved_journal_id(), session.journal().journal_id);
        assert_eq!(manifest.steps().len(), handoff.plan().steps().len());
        assert_eq!(
            manifest.verification_barriers().len(),
            manifest
                .steps()
                .iter()
                .filter(|step| step.role == crate::FrozenIntentRole::MutationCandidate)
                .count()
        );
        assert!(manifest.owner_acceptance_required());
        assert!(!manifest.mutation_enabled());
        assert_eq!(session.journal(), &before);
        assert_eq!(session.journal().phase, JournalPhase::Approved);
        assert!(!session.journal().mutation_may_have_started);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_approval_id_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-approval");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities);
        let before = session.journal().clone();
        let foreign = approval.clone().test_with_approval_id("f".repeat(64));

        let result = crate::freeze_execution_intent(&session, &foreign);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_approval_from_another_locked_session() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);

        let first_path = lock_path();
        let first_root = journal_root("intent-first-session");
        let first_store = DurableJournalStore::at(&first_root);
        let mut first =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &first_path, &first_store)
                .unwrap();
        let first_approval = approved_session(&mut first, &handoff, &snapshot, &capabilities);
        drop(first);
        let _ = std::fs::remove_dir_all(first_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("intent-second-session");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let _current = approved_session(&mut session, &handoff, &snapshot, &capabilities);
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &first_approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(first_root);
    }

    #[test]
    fn intent_rejects_wrong_plan_id_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-plan");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_plan_id("a".repeat(64));
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_evidence_bundle_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-evidence");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_evidence_bundle_id("b".repeat(64));
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_target_manifest_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-target");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_target_manifest_digest("c".repeat(64));
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_approval_journal_id_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-journal");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_journal_id("d".repeat(64));
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_mutation_enabled_approval_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-mutation-enabled");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_mutation_enabled();
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::MutationEnabled)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_preconditions_digest_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-wrong-preconditions-digest");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities)
            .test_with_preconditions_journal_digest("e".repeat(64));
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::ApprovalBindingMismatch)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_approved_journal_divergence_is_rejected() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-durable-divergence");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);
        let preconditions = session.journal().clone();
        let approval = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        )
        .unwrap();
        let approved = session.journal().clone();
        store.persist(&preconditions).unwrap();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::DurableJournalMismatch)
        ));
        assert_eq!(session.journal(), &approved);
        assert_eq!(store.load(&approved.journal_id).unwrap(), preconditions);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn intent_rejects_wrong_journal_phase() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);

        let approval_path = lock_path();
        let approval_root = journal_root("intent-phase-approval");
        let approval_store = DurableJournalStore::at(&approval_root);
        let mut approval_session = LockedExecutionSession::begin_durable_at_paths(
            &handoff,
            &approval_path,
            &approval_store,
        )
        .unwrap();
        let approval = approved_session(&mut approval_session, &handoff, &snapshot, &capabilities);
        drop(approval_session);
        let _ = std::fs::remove_dir_all(approval_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("intent-wrong-phase");
        let store = DurableJournalStore::at(&root);
        let session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let before = session.journal().clone();

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::SessionNotApproved)
        ));
        assert_eq!(session.journal(), &before);
        assert_eq!(store.load(&before.journal_id).unwrap(), before);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(approval_root);
    }

    #[test]
    fn intent_rejects_mutation_may_have_started() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("intent-mutation-started");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let approval = approved_session(&mut session, &handoff, &snapshot, &capabilities);
        let persisted = session.journal().clone();
        session.journal.mutation_may_have_started = true;

        let result = crate::freeze_execution_intent(&session, &approval);

        assert!(matches!(
            result,
            Err(crate::ExecutionIntentError::MutationMayHaveStarted)
        ));
        assert!(session.journal().mutation_may_have_started);
        assert_eq!(store.load(&persisted.journal_id).unwrap(), persisted);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn approval_rejects_foreign_explicit_plan_id() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-foreign-plan");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            &"a".repeat(64),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::ApprovedPlanMismatch)
        ));
        assert_preconditions_verified_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn approval_rejects_foreign_explicit_evidence_bundle() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-foreign-evidence");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (_evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            &"b".repeat(64),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::ApprovedEvidenceMismatch)
        ));
        assert_preconditions_verified_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn approval_rejects_foreign_explicit_target_manifest() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-foreign-target");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &"c".repeat(64),
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::ApprovedTargetMismatch)
        ));
        assert_preconditions_verified_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn approval_rejects_stale_preconditions_journal_digest() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-stale-journal");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);
        let stale = verified.test_with_journal_digest("d".repeat(64));

        let result = crate::approve_exact_plan(
            &mut session,
            &stale,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::VerificationJournalStale)
        ));
        assert_preconditions_verified_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn approval_rejects_preconditions_verification_from_another_locked_session() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);

        let first_path = lock_path();
        let first_root = journal_root("approval-first-session");
        let first_store = DurableJournalStore::at(&first_root);
        let mut first =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &first_path, &first_store)
                .unwrap();
        first.revalidate(&snapshot, &capabilities).unwrap();
        let (first_evidence, first_verified) =
            verified_preconditions(&mut first, &handoff, &snapshot, &capabilities);
        drop(first);
        let _ = std::fs::remove_dir_all(first_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("approval-second-session");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (_evidence, _verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);

        let result = crate::approve_exact_plan(
            &mut session,
            &first_verified,
            handoff.plan().plan_id(),
            first_evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::VerificationSessionMismatch)
        ));
        assert_preconditions_verified_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(first_root);
    }

    #[test]
    fn approval_rejects_wrong_journal_phase() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);

        let source_path = lock_path();
        let source_root = journal_root("approval-source");
        let source_store = DurableJournalStore::at(&source_root);
        let mut source =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &source_path, &source_store)
                .unwrap();
        source.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut source, &handoff, &snapshot, &capabilities);
        drop(source);
        let _ = std::fs::remove_dir_all(source_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("approval-wrong-phase");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::SessionNotPreconditionsVerified)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(source_root);
    }

    #[test]
    fn repeated_exact_approval_is_rejected_without_second_transition() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-repeat");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);

        crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        )
        .unwrap();
        let approved = session.journal().clone();

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::SessionNotPreconditionsVerified)
        ));
        assert_eq!(*session.journal(), approved);
        assert_eq!(store.load(&approved.journal_id).unwrap(), approved);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_journal_divergence_blocks_exact_approval() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("approval-durable-mismatch");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let stale = session.journal().clone();
        let (evidence, verified) =
            verified_preconditions(&mut session, &handoff, &snapshot, &capabilities);
        store.persist(&stale).unwrap();

        let result = crate::approve_exact_plan(
            &mut session,
            &verified,
            handoff.plan().plan_id(),
            evidence.bundle_id(),
            &handoff.target_identity().manifest_digest,
        );

        assert!(matches!(
            result,
            Err(crate::ExactPlanApprovalError::Session(
                LockedSessionError::DurableJournalMismatch
            ))
        ));
        assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);
        assert_eq!(store.load(&stale.journal_id).unwrap(), stale);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn foreign_plan_id_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("foreign-plan");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_plan_id("c".repeat(64));

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::PlanBindingMismatch)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn foreign_handoff_id_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("foreign-handoff");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_handoff_id("d".repeat(64));

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::HandoffBindingMismatch)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn changed_target_manifest_binding_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("foreign-target");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_target_manifest_digest("e".repeat(64));

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::TargetBindingMismatch)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_backup_receipt_evidence_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("tampered-backup");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            false,
            vec!["artifact SHA-256 changed".into()],
        );

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::BackupReceiptNotRevalidated)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_backup_binding_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("missing-backup");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_without_backup();

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::BackupBindingInvalid)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_enabled_evidence_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("mutation-flag");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_mutation_enabled();

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::MutationEnabled)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn filesystem_blocked_state_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("filesystem-blocked");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_filesystem_state(lsm_planner::FilesystemDecisionState::Blocked);

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::FilesystemNotReady)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn filesystem_adapter_required_state_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("filesystem-adapter");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        )
        .test_with_filesystem_state(lsm_planner::FilesystemDecisionState::AdapterRequired);

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::FilesystemNotReady)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn stale_capabilities_evidence_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("stale-capabilities");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let mut changed = capabilities.clone();
        changed.tools[0].available = false;
        let evidence = evidence(&session, &handoff, &snapshot, &changed, true, Vec::new());

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::EvidenceIncomplete)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn changed_filesystem_identity_evidence_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("changed-filesystem");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let mut changed = snapshot.clone();
        changed.storage.block_devices[0].children[0].children[0].uuid = Some("fs-2".into());
        let evidence = evidence(
            &session,
            &handoff,
            &changed,
            &capabilities,
            true,
            Vec::new(),
        );

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::EvidenceIncomplete)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_offline_ext4_check_is_rejected_without_journal_advance() {
        let (mut snapshot, capabilities) = fixture();
        snapshot.filesystem_preflight[0].filesystem_state = Some("not clean".into());
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("ext4-offline-check");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        assert_eq!(
            evidence.status(),
            crate::PreMutationEvidenceStatus::FutureChecksRequired
        );
        assert!(evidence.filesystem_decision().read_only_check.is_some());

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::EvidenceIncomplete)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn required_xfs_check_is_rejected_without_journal_advance() {
        let (snapshot, capabilities) = xfs_fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("xfs-check");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        assert_eq!(
            evidence.status(),
            crate::PreMutationEvidenceStatus::FutureChecksRequired
        );
        assert!(evidence.filesystem_decision().read_only_check.is_some());

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::EvidenceIncomplete)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_journal_phase_is_rejected() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let source_path = lock_path();
        let mut source = LockedExecutionSession::begin_at_path(&handoff, &source_path).unwrap();
        source.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &source,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        drop(source);
        let _ = std::fs::remove_dir_all(source_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("wrong-phase");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::SessionNotIdentityRevalidated)
        ));
        assert_eq!(session.journal().phase, JournalPhase::HostLockHeld);
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted, *session.journal());
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn repeated_precondition_transition_is_rejected() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("repeat");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );
        crate::verify_preconditions(&mut session, &evidence).unwrap();
        let first = session.journal().clone();

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::SessionNotIdentityRevalidated)
        ));
        assert_eq!(*session.journal(), first);
        assert_eq!(store.load(&first.journal_id).unwrap(), first);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn evidence_from_previous_locked_session_is_rejected() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let first_path = lock_path();
        let mut first = LockedExecutionSession::begin_at_path(&handoff, &first_path).unwrap();
        first.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(&first, &handoff, &snapshot, &capabilities, true, Vec::new());
        let first_session_id = first.session_id().to_owned();
        drop(first);
        let _ = std::fs::remove_dir_all(first_path.parent().unwrap());

        let path = lock_path();
        let root = journal_root("session-replay");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        assert_ne!(session.session_id(), first_session_id);

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::SessionBindingMismatch)
        ));
        assert_identity_revalidated_is_durable(&session, &store);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn non_durable_session_cannot_verify_preconditions() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let mut session = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::DurableJournalRequired)
        ));
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn durable_journal_mismatch_is_rejected_without_memory_advance() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("durable-mismatch");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let evidence = evidence(
            &session,
            &handoff,
            &snapshot,
            &capabilities,
            true,
            Vec::new(),
        );

        let mut stale = lsm_planner::OperationJournal::new(handoff.guard());
        stale
            .apply(lsm_planner::JournalTransition::HostLockAcquired)
            .unwrap();
        store.persist(&stale).unwrap();

        let result = crate::verify_preconditions(&mut session, &evidence);

        assert!(matches!(
            result,
            Err(crate::PreconditionsVerificationError::Session(
                LockedSessionError::DurableJournalMismatch
            ))
        ));
        assert_eq!(session.journal().phase, JournalPhase::IdentityRevalidated);
        assert_eq!(store.load(&stale.journal_id).unwrap(), stale);
        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn blocked_revalidation_does_not_advance_durable_journal() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("blocked");
        let store = DurableJournalStore::at(&root);
        let mut session =
            LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store).unwrap();
        let mut changed = snapshot.clone();
        changed.storage.block_devices[0].children[0].size_bytes += EXTENT;

        let result = session.revalidate(&changed, &capabilities).unwrap();
        assert_eq!(result.status, LockedRevalidationStatus::Blocked);

        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted.phase, JournalPhase::HostLockHeld);
        assert_eq!(persisted.events.len(), 1);
        assert_eq!(persisted, *session.journal());

        drop(session);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn durable_journal_failure_releases_host_lock() {
        let (snapshot, capabilities) = fixture();
        let handoff = handoff(&snapshot, &capabilities);
        let path = lock_path();
        let root = journal_root("unsafe");
        let real = root.with_extension("real");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&real, &root).unwrap();
        let store = DurableJournalStore::at(&root);

        let result = LockedExecutionSession::begin_durable_at_paths(&handoff, &path, &store);
        assert!(matches!(
            result,
            Err(LockedSessionError::DurableJournal(
                JournalStoreError::UnsafeDirectory(_)
            ))
        ));

        let replacement = LockedExecutionSession::begin_at_path(&handoff, &path).unwrap();
        drop(replacement);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let _ = std::fs::remove_file(root);
        let _ = std::fs::remove_dir_all(real);
    }
}
