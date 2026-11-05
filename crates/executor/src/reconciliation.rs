use std::path::Path;

use lsm_planner::{
    JournalError, JournalPhase, JournalTransition, OperationJournal, HOST_STORAGE_LOCK_PATH,
};
use thiserror::Error;

use crate::{DurableJournalStore, HostLockError, HostStorageLock, JournalStoreError};

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
    #[error("mutation may have started; manual investigation is required and this procedure cannot resolve it")]
    AmbiguousMutation,
    #[error("the journal is already terminal")]
    Terminal,
}

/// Abort an abandoned journal only if its durable history proves no write began.
/// Ambiguous operations remain blocked and are never retried by this procedure.
pub fn reconcile_abandoned_prewrite(
    store: &DurableJournalStore,
    journal_id: &str,
    confirmation: &str,
) -> Result<OperationJournal, ReconciliationError> {
    reconcile_prewrite_at(
        store,
        journal_id,
        confirmation,
        Path::new(HOST_STORAGE_LOCK_PATH),
    )
}

fn reconcile_prewrite_at(
    store: &DurableJournalStore,
    journal_id: &str,
    confirmation: &str,
    lock_path: &Path,
) -> Result<OperationJournal, ReconciliationError> {
    let _lock = HostStorageLock::try_acquire_path(lock_path)?;
    let mut journal = store.load(journal_id)?;
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
        assert!(reconcile_prewrite_at(&store, &journal.journal_id, "yes", &lock).is_err());
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        let result = reconcile_prewrite_at(
            &store,
            &journal.journal_id,
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
                &journal.journal_id,
                &format!("ABORT {}", journal.journal_id),
                &path
            ),
            Err(ReconciliationError::Lock(HostLockError::Busy))
        ));
        assert_eq!(store.load(&journal.journal_id).unwrap(), journal);
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }
}
