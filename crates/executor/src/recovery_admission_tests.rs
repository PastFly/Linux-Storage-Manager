use super::*;
use crate::sealed_recovery::{
    tests::{disposable_mount, with_fixture},
    SealedRecovery,
};
use crate::sealed_recovery_store::PublishedRecovery;
use std::fs::{self, File};
use std::path::Path;

fn skip() -> bool {
    !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some()
}
fn fixture_store(session: &LockedExecutionSession<'_>) -> DurableJournalStore {
    DurableJournalStore::at(session.lock_path().parent().unwrap().join("journal"))
}

#[test]
fn admits_only_proven_aborted_prewrite_and_invalidates_on_new_evidence() {
    if skip() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let record_id = sealed.record().record_id().to_owned();
        let primary = Path::new(manifest.artifact_directory());
        let mut name = primary.file_name().unwrap().to_os_string();
        name.push(".record");
        let record_dir = primary.with_file_name(name);
        fs::create_dir(&record_dir).unwrap();
        drop(
            PublishedRecovery::publish(session, sealed, File::open(&record_dir).unwrap()).unwrap(),
        );
        let store = fixture_store(session);
        let mut verified = session.journal().clone();
        let binding = lsm_planner::JournalRecoveryBinding {
            record_id,
            session_id: session.session_id().into(),
            handoff_id: session.handoff().handoff_id().into(),
        };
        verified
            .apply(
                lsm_planner::JournalTransition::PreconditionsVerifiedWithRecovery {
                    binding: &binding,
                },
            )
            .unwrap();
        store
            .persist_if_matches(session.journal(), &verified)
            .unwrap();
        let mut aborted = verified.clone();
        aborted
            .apply(lsm_planner::JournalTransition::Abort {
                reason: "fixture prewrite",
            })
            .unwrap();
        store.persist_if_matches(&verified, &aborted).unwrap();
        let mut gate =
            admit_for_test(session, &store).expect("verified aborted prewrite is admissible");
        gate.revalidate().unwrap();
        let orphan = primary
            .parent()
            .unwrap()
            .join(format!("{}.record", "e".repeat(64)));
        fs::create_dir(&orphan).unwrap();
        assert!(gate.revalidate().is_err());
        assert!(orphan.exists());
        drop(gate);
        fs::remove_dir(orphan).unwrap();
        fs::remove_dir_all(record_dir).unwrap();
    });
}

#[test]
fn blocks_unbound_prewrite_and_preserves_candidate() {
    if skip() {
        return;
    }
    with_fixture(|session, manifest, _receipt, copies| {
        drop(copies);
        let root = Path::new(manifest.artifact_directory());
        let mut name = root.file_name().unwrap().to_os_string();
        name.push(".record");
        let orphan = root.with_file_name(name);
        fs::create_dir(&orphan).unwrap();
        fs::write(orphan.join("evidence"), b"preserve").unwrap();
        assert!(admit_for_test(session, &fixture_store(session)).is_err());
        assert_eq!(fs::read(orphan.join("evidence")).unwrap(), b"preserve");
        fs::remove_dir_all(orphan).unwrap();
    });
}
