use std::path::Path;

use lsm_planner::{
    JournalError, JournalPhase, JournalTransition, OperationJournal, HOST_STORAGE_LOCK_PATH,
};
use thiserror::Error;

use crate::{
    DurableJournalStore, HostLockError, HostStorageLock, JournalFileIdentity, JournalStoreError,
};

#[derive(Debug, Error)]
pub enum ReconciliationError {
    #[error("host storage lock acquisition failed: {0}")]
    Lock(#[from] HostLockError),
    #[error("journal access failed: {0}")]
    Store(#[from] JournalStoreError),
    #[error("journal transition failed: {0}")]
    Journal(#[from] JournalError),
    #[error("the exact journal-specific confirmation did not match")]
    ConfirmationMismatch,
    #[error("the journal changed since it was shown; inspect it again")]
    JournalChanged,
    #[error("mutation may have started; manual investigation is required and this procedure cannot resolve it")]
    AmbiguousMutation,
    #[error("the journal is already terminal")]
    Terminal,
}

/// Abort an abandoned journal only if its durable history proves no write began.
/// Ambiguous operations remain blocked and are never retried by this procedure.
pub fn reconcile_abandoned_prewrite(
    store: &DurableJournalStore,
    shown_journal: &OperationJournal,
    confirmation: &str,
) -> Result<OperationJournal, ReconciliationError> {
    reconcile_prewrite_at(
        store,
        shown_journal,
        confirmation,
        Path::new(HOST_STORAGE_LOCK_PATH),
    )
}

/// Remove only a second name for the exact displayed durable journal inode.
/// This never executes or resumes any storage operation.
pub fn reconcile_duplicate_staging(
    store: &DurableJournalStore,
    staging: &Path,
    shown_journal: &OperationJournal,
    identity: JournalFileIdentity,
    confirmation: &str,
) -> Result<(), ReconciliationError> {
    reconcile_duplicate_at(
        store,
        staging,
        shown_journal,
        identity,
        confirmation,
        Path::new(HOST_STORAGE_LOCK_PATH),
    )
}

fn reconcile_duplicate_at(
    store: &DurableJournalStore,
    staging: &Path,
    shown_journal: &OperationJournal,
    identity: JournalFileIdentity,
    confirmation: &str,
    lock_path: &Path,
) -> Result<(), ReconciliationError> {
    let _lock = HostStorageLock::try_acquire_path(lock_path)?;
    if confirmation != format!("REMOVE DUPLICATE {}", shown_journal.journal_id) {
        return Err(ReconciliationError::ConfirmationMismatch);
    }
    store.remove_linked_staging_duplicate(staging, shown_journal, identity)?;
    Ok(())
}

fn reconcile_prewrite_at(
    store: &DurableJournalStore,
    shown_journal: &OperationJournal,
    confirmation: &str,
    lock_path: &Path,
) -> Result<OperationJournal, ReconciliationError> {
    let _lock = HostStorageLock::try_acquire_path(lock_path)?;
    // An interrupted durable replacement may contain a newer mutation state.
    // Any unclassified entry must block even a seemingly pre-write abort.
    let _ = store.all()?;
    let mut journal = store.load(&shown_journal.journal_id)?;
    if &journal != shown_journal {
        return Err(ReconciliationError::JournalChanged);
    }
    if confirmation != format!("ABORT {}", journal.journal_id) {
        return Err(ReconciliationError::ConfirmationMismatch);
    }
    if journal.mutation_may_have_started
        || matches!(
            journal.phase,
            JournalPhase::Executing | JournalPhase::Verifying | JournalPhase::RecoveryRequired
        )
    {
        return Err(ReconciliationError::AmbiguousMutation);
    }
    if matches!(
        journal.phase,
        JournalPhase::Completed | JournalPhase::Aborted
    ) {
        return Err(ReconciliationError::Terminal);
    }
    journal.apply(JournalTransition::Abort {
        reason:
            "operator reconciled abandoned pre-write operation; no mutation boundary was crossed",
    })?;
    store.persist(&journal)?;
    Ok(journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_planner::{JournalPhase, OperationJournal};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn identity(path: &Path) -> JournalFileIdentity {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).unwrap();
        JournalFileIdentity {
            device_id: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (std::path::PathBuf, DurableJournalStore, OperationJournal) {
        let root = std::env::temp_dir().join(format!(
            "lsm-reconcile-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let store = DurableJournalStore::at(root.join("journals"));
        let journal = OperationJournal {
            schema_version: 1,
            journal_id: "a".repeat(64),
            plan_id: "b".repeat(64),
            target: "/data".into(),
            baseline_manifest_digest: "c".repeat(64),
            phase: JournalPhase::Planned,
            mutation_may_have_started: false,
            approval: None,
            execution: None,
            verified_boundary: None,
            events: Vec::new(),
        };
        store.persist_new(&journal).unwrap();
        (root, store, journal)
    }

    #[test]
    fn abandoned_prewrite_journal_is_aborted_only_with_exact_confirmation() {
        let (root, store, journal) = fixture();
        let lock = root.join("lock/storage.lock");
        assert!(reconcile_prewrite_at(&store, &journal, "yes", &lock).is_err());
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        let result = reconcile_prewrite_at(
            &store,
            &journal,
            &format!("ABORT {}", journal.journal_id),
            &lock,
        )
        .unwrap();
        assert_eq!(result.phase, JournalPhase::Aborted);
        assert!(!result.mutation_may_have_started);
        assert_eq!(store.load(&journal.journal_id).unwrap(), result);
        assert_eq!(result.events.last().unwrap().code, "aborted");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_refuses_when_another_operation_holds_host_lock() {
        let (root, store, journal) = fixture();
        let path = root.join("lock/storage.lock");
        let guard = HostStorageLock::try_acquire_path(&path).unwrap();
        assert!(matches!(
            reconcile_prewrite_at(
                &store,
                &journal,
                &format!("ABORT {}", journal.journal_id),
                &path
            ),
            Err(ReconciliationError::Lock(HostLockError::Busy))
        ));
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_rejects_journal_changed_after_confirmation_was_shown() {
        let (root, store, shown) = fixture();
        let mut changed = shown.clone();
        changed.apply(JournalTransition::HostLockAcquired).unwrap();
        store.persist(&changed).unwrap();
        let result = reconcile_prewrite_at(
            &store,
            &shown,
            &format!("ABORT {}", shown.journal_id),
            &root.join("lock/storage.lock"),
        );
        assert!(matches!(result, Err(ReconciliationError::JournalChanged)));
        assert_eq!(store.load(&shown.journal_id).unwrap(), changed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_preserves_and_rejects_unclassified_staging_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let (root, store, journal) = fixture();
        let staging = store
            .root()
            .join(format!(".{}.tmp-123-1", journal.journal_id));
        fs::write(&staging, b"unclassified possible execution state").unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
        let result = reconcile_prewrite_at(
            &store,
            &journal,
            &format!("ABORT {}", journal.journal_id),
            &root.join("lock/storage.lock"),
        );
        assert!(matches!(
            result,
            Err(ReconciliationError::Store(
                JournalStoreError::InvalidRecord(_)
            ))
        ));
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        assert!(staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_staging_reconciliation_retains_exact_durable_journal() {
        let (root, store, journal) = fixture();
        let final_path = store.root().join(format!("{}.json", journal.journal_id));
        let staging = store
            .root()
            .join(format!(".{}.tmp-123-1", journal.journal_id));
        fs::hard_link(&final_path, &staging).unwrap();
        let shown_identity = identity(&staging);
        let lock = root.join("lock/storage.lock");
        assert!(
            reconcile_duplicate_at(&store, &staging, &journal, shown_identity, "yes", &lock)
                .is_err()
        );
        assert!(staging.exists());
        reconcile_duplicate_at(
            &store,
            &staging,
            &journal,
            shown_identity,
            &format!("REMOVE DUPLICATE {}", journal.journal_id),
            &lock,
        )
        .unwrap();
        assert!(!staging.exists());
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_staging_reconciliation_never_removes_a_distinct_file() {
        let (root, store, journal) = fixture();
        let final_path = store.root().join(format!("{}.json", journal.journal_id));
        let staging = store
            .root()
            .join(format!(".{}.tmp-123-1", journal.journal_id));
        fs::copy(&final_path, &staging).unwrap();
        let shown_identity = identity(&staging);
        let result = reconcile_duplicate_at(
            &store,
            &staging,
            &journal,
            shown_identity,
            &format!("REMOVE DUPLICATE {}", journal.journal_id),
            &root.join("lock/storage.lock"),
        );
        assert!(result.is_err());
        assert!(staging.exists());
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_staging_rejects_replacement_pair_after_display() {
        use std::os::unix::fs::PermissionsExt;
        let (root, store, journal) = fixture();
        let final_path = store.root().join(format!("{}.json", journal.journal_id));
        let staging = store
            .root()
            .join(format!(".{}.tmp-123-1", journal.journal_id));
        fs::hard_link(&final_path, &staging).unwrap();
        let shown_identity = identity(&staging);
        let old_file = fs::File::open(&final_path).unwrap();
        let bytes = fs::read(&final_path).unwrap();
        fs::remove_file(&staging).unwrap();
        fs::remove_file(&final_path).unwrap();
        fs::write(&final_path, &bytes).unwrap();
        fs::set_permissions(&final_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&final_path, &staging).unwrap();
        let result = reconcile_duplicate_at(
            &store,
            &staging,
            &journal,
            shown_identity,
            &format!("REMOVE DUPLICATE {}", journal.journal_id),
            &root.join("lock/storage.lock"),
        );
        assert!(result.is_err());
        assert!(staging.exists());
        drop(old_file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_never_aborts_a_possibly_executed_operation() {
        use lsm_planner::{build_execution_start_binding, ExactApprovalBinding};
        let (root, store, mut journal) = fixture();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: journal.plan_id.clone(),
            evidence_bundle_id: "d".repeat(64),
            target_manifest_digest: baseline.clone(),
            locked_session_id: "e".repeat(64),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        let plan_id = journal.plan_id.clone();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();
        let binding = build_execution_start_binding(
            &journal,
            &"f".repeat(64),
            &"1".repeat(64),
            &baseline,
            &[5, 6],
        )
        .unwrap();
        journal
            .apply(JournalTransition::ExecutionStarted { binding: &binding })
            .unwrap();
        store.persist(&journal).unwrap();
        let result = reconcile_prewrite_at(
            &store,
            &journal,
            &format!("ABORT {}", journal.journal_id),
            &root.join("lock/storage.lock"),
        );
        assert!(matches!(
            result,
            Err(ReconciliationError::AmbiguousMutation)
        ));
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        fs::remove_dir_all(root).unwrap();
    }
}
