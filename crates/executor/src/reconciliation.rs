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
