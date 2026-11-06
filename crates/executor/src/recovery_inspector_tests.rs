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
        let unknown = Path::new(manifest.artifact_directory())
            .parent()
            .unwrap()
            .join("unrecognized-entry");
        fs::write(&unknown, b"preserve").unwrap();
        let store = fixture_store(session);
        let inspected = inspect_for_test(session, &store).unwrap();
        match inspected {
            Inspection::UnboundPrewrite {
                candidates,
                unrecognized,
            } => {
                assert!(candidates.contains(&root));
                assert!(candidates.contains(&PathBuf::from(manifest.artifact_directory())));
                assert!(unrecognized.contains(&unknown));
            }
            _ => panic!("unbound candidates must not be trusted"),
        }
        assert_eq!(fs::read(root.join("unknown-orphan")).unwrap(), b"untrusted");
        assert_eq!(fs::read(&unknown).unwrap(), b"preserve");
        fs::remove_file(unknown).unwrap();
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
        assert!(matches!(inspected, Inspection::Bound { record_id, .. } if record_id == id));
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn inspector_rejects_wrong_anchor_missing_link_and_replaced_backup() {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if skip() {
        return;
    }
    for attack in ["missing-link", "replaced-backup", "wrong-anchor"] {
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let id = sealed.record().record_id().to_owned();
            let recovery_path = PathBuf::from(&sealed.record().artifacts()[0].recovery_path);
            let root = record_dir(manifest);
            fs::create_dir(&root).unwrap();
            let published =
                PublishedRecovery::publish(session, sealed, File::open(&root).unwrap()).unwrap();
            drop(published);
            let store = fixture_store(session);
            let mut next = session.journal().clone();
            let binding = lsm_planner::JournalRecoveryBinding {
                record_id: if attack == "wrong-anchor" {
                    "f".repeat(64)
                } else {
                    id.clone()
                },
                session_id: session.session_id().into(),
                handoff_id: session.handoff().handoff_id().into(),
            };
            next.apply(
                lsm_planner::JournalTransition::PreconditionsVerifiedWithRecovery {
                    binding: &binding,
                },
            )
            .unwrap();
            store.persist_if_matches(session.journal(), &next).unwrap();
            if attack == "missing-link" {
                fs::remove_file(root.join(format!(".{id}.pending"))).unwrap();
            } else if attack == "replaced-backup" {
                let bytes = fs::read(&recovery_path).unwrap();
                fs::remove_file(&recovery_path).unwrap();
                let mut writer = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&recovery_path)
                    .unwrap();
                writer.write_all(&bytes).unwrap();
                writer.sync_all().unwrap();
            }
            assert!(inspect_for_test(session, &store).is_err());
            assert!(root.join(format!("{id}.json")).exists());
            fs::remove_dir_all(root).unwrap();
        });
    }
}

#[test]
fn inspector_reopens_durable_journal_and_copies_after_sigkill() {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    const CHILD: &str = "LSM_TEST_INSPECTOR_CRASH_CHILD";
    if skip() {
        return;
    }
    if let Ok(mode) = std::env::var(CHILD) {
        assert!(mode == "bound" || mode == "unbound");
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let id = sealed.record().record_id().to_owned();
            let root = record_dir(manifest);
            fs::create_dir(&root).unwrap();
            let published =
                PublishedRecovery::publish(session, sealed, File::open(&root).unwrap()).unwrap();
            drop(published);
            if mode == "bound" {
                let store = fixture_store(session);
                let mut next = session.journal().clone();
                let binding = lsm_planner::JournalRecoveryBinding {
                    record_id: id.clone(),
                    session_id: session.session_id().into(),
                    handoff_id: session.handoff().handoff_id().into(),
                };
                next.apply(
                    lsm_planner::JournalTransition::PreconditionsVerifiedWithRecovery {
                        binding: &binding,
                    },
                )
                .unwrap();
                store.persist_if_matches(session.journal(), &next).unwrap();
            }
            let primary = Path::new(manifest.artifact_directory());
            let mut name = primary.file_name().unwrap().to_os_string();
            name.push(".recovery");
            let recovery = primary.with_file_name(name);
            println!(
                "LSM_INSPECTOR_FIXTURE|{}|{}|{}|{}|{}|{}",
                primary.display(),
                recovery.display(),
                root.display(),
                session.lock_path().parent().unwrap().display(),
                session.journal().journal_id,
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
    for mode in ["bound", "unbound"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery_inspector::tests::inspector_reopens_durable_journal_and_copies_after_sigkill",
                "--nocapture",
            ])
            .env(CHILD, mode)
            .output()
            .unwrap();
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGKILL),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let line = text
            .lines()
            .find_map(|line| {
                line.split_once("LSM_INSPECTOR_FIXTURE|")
                    .map(|(_, suffix)| suffix)
            })
            .unwrap();
        let parts = line.split('|').collect::<Vec<_>>();
        assert_eq!(parts.len(), 6);
        let primary = PathBuf::from(parts[0]);
        let recovery = PathBuf::from(parts[1]);
        let root = PathBuf::from(parts[2]);
        let outer = PathBuf::from(parts[3]);
        let journal_id = parts[4];
        let record_id = parts[5];
        assert!(primary.starts_with(crate::BACKUP_DIRECTORY));
        assert_eq!(primary.parent(), recovery.parent());
        assert_eq!(primary.parent(), root.parent());
        let lock = crate::HostStorageLock::try_acquire_path(&outer.join("lock")).unwrap();
        let store = DurableJournalStore::at(outer.join("journal"));
        let inspected = inspect_in_store(&store, journal_id).unwrap();
        if mode == "bound" {
            assert!(
                matches!(inspected, Inspection::Bound { record_id: found, phase: lsm_planner::JournalPhase::PreconditionsVerified, mutation_may_have_started: false, .. } if found == record_id)
            );
        } else {
            assert!(
                matches!(inspected, Inspection::UnboundPrewrite { candidates, .. } if candidates.contains(&root))
            );
            assert!(root.join(format!("{record_id}.json")).exists());
            assert!(root.join(format!(".{record_id}.pending")).exists());
        }
        drop(lock);
        fs::remove_dir_all(&primary).unwrap();
        fs::remove_dir_all(&recovery).unwrap();
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir(primary.parent().unwrap()).unwrap();
        fs::remove_dir_all(outer).unwrap();
    }
}

#[test]
fn borrowed_inspection_holds_host_lock_until_owner_is_dropped() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "lsm-inspection-lock-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let path = root.join("lock");
    let lock = crate::HostStorageLock::try_acquire_path(&path).unwrap();
    let inspection = SystemInspection {
        result: Inspection::UnboundPrewrite {
            candidates: Vec::new(),
            unrecognized: Vec::new(),
        },
        _lock: lock,
    };
    assert!(matches!(
        inspection.result(),
        Inspection::UnboundPrewrite { .. }
    ));
    assert!(matches!(
        crate::HostStorageLock::try_acquire_path(&path),
        Err(crate::HostLockError::Busy)
    ));
    drop(inspection);
    drop(crate::HostStorageLock::try_acquire_path(&path).unwrap());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn inspector_rejects_self_consistent_noncanonical_recovery_name() {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    if skip() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let mut value = serde_json::to_value(sealed.record()).unwrap();
        let original = PathBuf::from(&sealed.record().artifacts()[0].recovery_path);
        let alternate = original.with_file_name("noncanonical-recovery-name");
        drop(sealed);
        fs::rename(&original, &alternate).unwrap();
        value["payload"]["artifacts"][0]["recovery_path"] =
            serde_json::Value::String(alternate.to_str().unwrap().into());
        let payload: crate::backup_recovery_record::RecoveryPayload =
            serde_json::from_value(value["payload"].clone()).unwrap();
        let forged = crate::backup_recovery_record::BackupRecoveryRecord::new(payload).unwrap();
        let id = forged.record_id().to_owned();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let pending = root.join(format!(".{id}.pending"));
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .unwrap();
        writer.write_all(&forged.encode().unwrap()).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        let record = File::open(&pending).unwrap();
        crate::backup_verity::enable(&record).unwrap();
        record.sync_all().unwrap();
        let dir = File::open(&root).unwrap();
        let final_name = CString::new(format!("{id}.json")).unwrap();
        assert_eq!(
            unsafe {
                libc::linkat(
                    record.as_raw_fd(),
                    c"".as_ptr(),
                    dir.as_raw_fd(),
                    final_name.as_ptr(),
                    libc::AT_EMPTY_PATH,
                )
            },
            0
        );
        dir.sync_all().unwrap();
        let store = fixture_store(session);
        let mut next = session.journal().clone();
        let binding = lsm_planner::JournalRecoveryBinding {
            record_id: id,
            session_id: session.session_id().into(),
            handoff_id: session.handoff().handoff_id().into(),
        };
        next.apply(
            lsm_planner::JournalTransition::PreconditionsVerifiedWithRecovery { binding: &binding },
        )
        .unwrap();
        store.persist_if_matches(session.journal(), &next).unwrap();
        assert!(
            inspect_for_test(session, &store).is_err(),
            "noncanonical recovery basename must not be accepted"
        );
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn inspector_detects_transient_change_in_earlier_handoff_during_scan() {
    if skip() {
        return;
    }
    with_fixture(|session, _manifest, _receipt, copies| {
        drop(copies);
        let first = Path::new(crate::BACKUP_DIRECTORY).join("0".repeat(64));
        assert!(!first.exists());
        fs::create_dir(&first).unwrap();
        let mut fired = false;
        let result = inspect_unbound_with_hook(session.journal(), |path| {
            if path == first && !fired {
                fired = true;
                let transient = first.join("transient");
                fs::write(&transient, b"event").unwrap();
                fs::remove_file(transient).unwrap();
            }
        });
        assert!(fired);
        assert!(
            result.is_err(),
            "a change in an already visited handoff must invalidate the scan"
        );
        fs::remove_dir(first).unwrap();
    });
}
