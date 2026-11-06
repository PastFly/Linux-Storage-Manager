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
        fs::remove_dir(orphan).unwrap();
        assert!(
            gate.revalidate().is_err(),
            "invalidation must remain sticky after restoration"
        );
        drop(gate);
        let mut legacy = lsm_planner::OperationJournal::new(session.handoff().guard());
        legacy.journal_id = "d".repeat(64);
        legacy
            .apply(lsm_planner::JournalTransition::HostLockAcquired)
            .unwrap();
        legacy
            .apply(lsm_planner::JournalTransition::Abort {
                reason: "legacy prewrite",
            })
            .unwrap();
        store.persist_new(&legacy).unwrap();
        assert!(
            admit_for_test(session, &store).is_err(),
            "legacy prewrite without binding must block"
        );
        assert_eq!(store.load(&legacy.journal_id).unwrap(), legacy);
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

#[test]
fn blocks_unbound_orphan_after_sigkill_and_lock_reacquisition() {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    const CHILD: &str = "LSM_TEST_ADMISSION_ORPHAN_CHILD";
    if skip() {
        return;
    }
    if std::env::var(CHILD).as_deref() == Ok("1") {
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let id = sealed.record().record_id().to_owned();
            let primary = Path::new(manifest.artifact_directory());
            let mut record_name = primary.file_name().unwrap().to_os_string();
            record_name.push(".record");
            let record_root = primary.with_file_name(record_name);
            fs::create_dir(&record_root).unwrap();
            drop(
                PublishedRecovery::publish(session, sealed, File::open(&record_root).unwrap())
                    .unwrap(),
            );
            let mut recovery_name = primary.file_name().unwrap().to_os_string();
            recovery_name.push(".recovery");
            let recovery = primary.with_file_name(recovery_name);
            println!(
                "LSM_ADMISSION_FIXTURE|{}|{}|{}|{}|{}",
                primary.display(),
                recovery.display(),
                record_root.display(),
                session.lock_path().parent().unwrap().display(),
                id
            );
            std::io::stdout().flush().unwrap();
            unsafe {
                libc::kill(libc::getpid(), libc::SIGKILL);
            }
            panic!("test child did not terminate");
        });
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "recovery_inspector::admission_tests::blocks_unbound_orphan_after_sigkill_and_lock_reacquisition", "--nocapture"])
        .env(CHILD, "1").output().unwrap();
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGKILL),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find_map(|line| {
            line.split_once("LSM_ADMISSION_FIXTURE|")
                .map(|(_, suffix)| suffix)
        })
        .unwrap();
    let fields = line.split('|').collect::<Vec<_>>();
    assert_eq!(fields.len(), 5);
    let primary = PathBuf::from(fields[0]);
    let recovery = PathBuf::from(fields[1]);
    let root = PathBuf::from(fields[2]);
    let outer = PathBuf::from(fields[3]);
    let id = fields[4];
    assert!(primary.starts_with(crate::BACKUP_DIRECTORY));
    assert_eq!(primary.parent(), recovery.parent());
    assert_eq!(primary.parent(), root.parent());
    let lock = crate::HostStorageLock::try_acquire_path(&outer.join("lock")).unwrap();
    let store = DurableJournalStore::at(outer.join("journal"));
    assert!(admit_after_restart_for_test(lock, &store).is_err());
    assert!(root.join(format!("{id}.json")).is_file());
    assert!(root.join(format!(".{id}.pending")).is_file());
    fs::remove_dir_all(&primary).unwrap();
    fs::remove_dir_all(&recovery).unwrap();
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir(primary.parent().unwrap()).unwrap();
    fs::remove_dir_all(outer).unwrap();
}
