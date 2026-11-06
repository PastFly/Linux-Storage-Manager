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
fn record_dir(manifest: &crate::MetadataBackupManifest) -> PathBuf {
    let root = Path::new(manifest.artifact_directory());
    let mut name = root.file_name().unwrap().to_os_string();
    name.push(".record");
    root.with_file_name(name)
}
fn fixture_store(session: &LockedExecutionSession<'_>) -> DurableJournalStore {
    DurableJournalStore::at(session.lock_path().parent().unwrap().join("journal"))
}

#[test]
fn inspector_classifies_unbound_prewrite_paths_as_untrusted() {
    if skip() {
        return;
    }
    with_fixture(|session, manifest, _receipt, copies| {
        drop(copies);
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        fs::write(root.join("unknown-orphan"), b"untrusted").unwrap();
        let store = fixture_store(session);
        let inspected = inspect_for_test(session, &store).unwrap();
        match inspected {
            Inspection::UnboundPrewrite { candidates } => {
                assert!(candidates.contains(&root));
                assert!(candidates.contains(&PathBuf::from(manifest.artifact_directory())));
            }
            _ => panic!("unbound candidates must not be trusted"),
        }
        assert_eq!(fs::read(root.join("unknown-orphan")).unwrap(), b"untrusted");
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn inspector_reopens_only_record_and_copies_bound_to_durable_journal() {
    if skip() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let id = sealed.record().record_id().to_owned();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let published =
            PublishedRecovery::publish(session, sealed, File::open(&root).unwrap()).unwrap();
        drop(published);
        let store = fixture_store(session);
        let mut next = session.journal().clone();
        let binding = lsm_planner::JournalRecoveryBinding {
            record_id: id.clone(),
            session_id: session.session_id().into(),
            handoff_id: session.handoff().handoff_id().into(),
        };
        next.apply(
            lsm_planner::JournalTransition::PreconditionsVerifiedWithRecovery { binding: &binding },
        )
        .unwrap();
        store.persist_if_matches(session.journal(), &next).unwrap();
        let inspected = inspect_for_test(session, &store).unwrap();
        assert!(matches!(inspected, Inspection::Bound { record_id } if record_id == id));
        fs::remove_dir_all(root).unwrap();
    });
}
