use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use lsm_core::{HostCapabilities, HostSnapshot};
use lsm_planner::{
    revalidate_target_identity, ExecutionHandoffStatus, FrozenExecutionHandoff,
    IdentityRevalidation, JournalError, JournalPhase, JournalTransition, OperationJournal,
    PlannerError,
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

    pub(crate) fn persist_preconditions_verified(&mut self) -> Result<(), LockedSessionError> {
        let store = self
            .journal_store
            .ok_or(LockedSessionError::DurableJournalRequired)?;
        let persisted = store.load(&self.journal.journal_id)?;
        if persisted != self.journal {
            return Err(LockedSessionError::DurableJournalMismatch);
        }

        let mut next = self.journal.clone();
        next.apply(JournalTransition::PreconditionsVerified)?;
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
        build_frozen_execution_handoff, plan_extend, ExtendRequest, Growth, JournalPhase,
        PlanStatus,
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

        let backup = crate::backup_capture::test_backup_receipt_revalidation(
            handoff.handoff_id(),
            handoff.plan().plan_id(),
            &handoff.target_identity().manifest_digest,
            true,
            Vec::new(),
        );
        let evidence =
            crate::build_pre_mutation_evidence(&session, &snapshot, &capabilities, &backup).unwrap();
        assert_eq!(
            evidence.status(),
            crate::PreMutationEvidenceStatus::EvidenceComplete
        );

        crate::verify_preconditions(&mut session, &evidence).unwrap();

        assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);
        let persisted = store.load(&session.journal().journal_id).unwrap();
        assert_eq!(persisted.phase, JournalPhase::PreconditionsVerified);
        assert_eq!(persisted, *session.journal());

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
