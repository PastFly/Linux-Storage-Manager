use super::*;
use crate::sealed_recovery::{
    tests::{disposable_mount, with_fixture},
    SealedRecovery,
};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn record_dir(manifest: &crate::MetadataBackupManifest) -> PathBuf {
    let root = Path::new(manifest.artifact_directory());
    let mut name = root.file_name().unwrap().to_os_string();
    name.push(".record");
    root.with_file_name(name)
}
fn skip_supported() -> bool {
    !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some()
}

#[test]
fn publishes_sealed_record_at_real_attempt_path() {
    if skip_supported() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let expected_record = sealed.record().clone();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let result =
            PublishedRecovery::publish(session, sealed, File::open(&root).unwrap()).unwrap();
        let path = root.join(format!("{}.json", expected_record.record_id()));
        let pending = root.join(format!(".{}.pending", expected_record.record_id()));
        let final_meta = fs::metadata(&path).unwrap();
        let pending_meta = fs::metadata(&pending).unwrap();
        assert_eq!(
            (final_meta.dev(), final_meta.ino()),
            (pending_meta.dev(), pending_meta.ino())
        );
        assert_eq!(final_meta.nlink(), 2);
        assert_eq!(result.record_path, path);
        let measurement = result.measurement;
        drop(result);
        let file = File::open(&path).unwrap();
        assert_eq!(crate::backup_verity::measure(&file).unwrap(), measurement);
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        let bytes = fs::read(&path).unwrap();
        let decoded = crate::backup_recovery_record::decode_v3_with_trusted_context(
            &bytes,
            expected_record.record_id(),
            expected_record.binding(),
        )
        .unwrap();
        assert_eq!(decoded, expected_record);
        assert_eq!(
            session.journal().phase,
            lsm_planner::JournalPhase::IdentityRevalidated
        );
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn publication_rejects_wrong_dirfd_and_existing_name_without_overwriting() {
    if skip_supported() {
        return;
    }
    for existing in [false, true] {
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let root = record_dir(manifest);
            fs::create_dir(&root).unwrap();
            let final_path = root.join(format!("{}.json", sealed.record().record_id()));
            if existing {
                fs::write(&final_path, b"keep-existing").unwrap();
            }
            let fd = if existing {
                File::open(&root).unwrap()
            } else {
                File::open(manifest.artifact_directory()).unwrap()
            };
            assert!(PublishedRecovery::publish(session, sealed, fd).is_err());
            if existing {
                assert_eq!(fs::read(final_path).unwrap(), b"keep-existing");
            } else {
                assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
            }
            fs::remove_dir_all(root).unwrap();
        });
    }
}

#[test]
fn publication_failures_preserve_staging_or_final_record() {
    if skip_supported() {
        return;
    }
    for stage in [
        PublicationStage::Created,
        PublicationStage::ReservationSynced,
        PublicationStage::WrittenAndSynced,
        PublicationStage::SealedAndSynced,
        PublicationStage::Linked,
        PublicationStage::LinkedInodeSynced,
        PublicationStage::DirectorySynced,
    ] {
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let id = sealed.record().record_id().to_owned();
            let root = record_dir(manifest);
            fs::create_dir(&root).unwrap();
            let result = PublishedRecovery::publish_inner(
                session,
                sealed,
                File::open(&root).unwrap(),
                |current| {
                    if current == stage {
                        return Err(io::Error::other("injected failure"));
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            let name = if matches!(
                stage,
                PublicationStage::Linked
                    | PublicationStage::LinkedInodeSynced
                    | PublicationStage::DirectorySynced
            ) {
                format!("{id}.json")
            } else {
                format!(".{id}.pending")
            };
            let path = root.join(name);
            assert!(path.is_file());
            let published = matches!(
                stage,
                PublicationStage::Linked
                    | PublicationStage::LinkedInodeSynced
                    | PublicationStage::DirectorySynced
            );
            assert_eq!(
                fs::read_dir(&root).unwrap().count(),
                if published { 2 } else { 1 }
            );
            if published {
                let pending = fs::metadata(root.join(format!(".{id}.pending"))).unwrap();
                let final_meta = fs::metadata(root.join(format!("{id}.json"))).unwrap();
                assert_eq!(
                    (pending.dev(), pending.ino(), pending.nlink()),
                    (final_meta.dev(), final_meta.ino(), 2)
                );
            }
            if matches!(
                stage,
                PublicationStage::SealedAndSynced
                    | PublicationStage::Linked
                    | PublicationStage::LinkedInodeSynced
                    | PublicationStage::DirectorySynced
            ) {
                assert!(crate::backup_verity::measure(&File::open(path).unwrap()).is_ok());
            }
            assert_eq!(
                session.journal().phase,
                lsm_planner::JournalPhase::IdentityRevalidated
            );
            fs::remove_dir_all(root).unwrap();
        });
    }
}

#[test]
fn publication_rejects_writer_inherited_by_forked_child() {
    if skip_supported() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let id = sealed.record().record_id().to_owned();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let mut child = -1;
        let result = PublishedRecovery::publish_inner(
            session,
            sealed,
            File::open(&root).unwrap(),
            |stage| {
                if stage == PublicationStage::WrittenAndSynced {
                    let pid = unsafe { libc::fork() };
                    if pid < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if pid == 0 {
                        // The only child operations after fork are libc calls.
                        // Its inherited writable record FD remains open until EOF.
                        unsafe {
                            libc::close(pipe[1]);
                            let mut byte = 0_u8;
                            loop {
                                let count = libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                                if count >= 0 || *libc::__errno_location() != libc::EINTR {
                                    break;
                                }
                            }
                            libc::_exit(0);
                        }
                    }
                    child = pid;
                    unsafe {
                        libc::close(pipe[0]);
                    }
                    pipe[0] = -1;
                }
                Ok(())
            },
        );
        unsafe {
            libc::close(pipe[1]);
        }
        if pipe[0] >= 0 {
            unsafe {
                libc::close(pipe[0]);
            }
        }
        assert!(child > 0, "child must have inherited the writer");
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert!(
            matches!(result, Err(PublicationError::Io(ref error)) if error.raw_os_error() == Some(libc::ETXTBSY))
        );
        assert!(root.join(format!(".{id}.pending")).is_file());
        assert!(!root.join(format!("{id}.json")).exists());
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn publication_never_publishes_substituted_staging_inode() {
    if skip_supported() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let id = sealed.record().record_id().to_owned();
        let expected = sealed.record().encode().unwrap();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let staging = root.join(format!(".{id}.pending"));
        let final_path = root.join(format!("{id}.json"));
        let displaced = root.join("displaced-record");
        let _result = PublishedRecovery::publish_inner(
            session,
            sealed,
            File::open(&root).unwrap(),
            |stage| {
                if stage == PublicationStage::BeforePublish {
                    fs::rename(&staging, &displaced)?;
                    fs::write(&staging, b"substituted record")?;
                }
                Ok(())
            },
        );
        if final_path.exists() {
            assert_eq!(fs::read(&final_path).unwrap(), expected);
        }
        assert_eq!(fs::read(displaced).unwrap(), expected);
        fs::remove_dir_all(root).unwrap();
    });
}

#[test]
fn publication_rejects_record_filesystem_without_verity() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    const OPT_IN: &str = "LSM_TEST_SEALED_RECORD_TMPFS";
    const CHILD: &str = "LSM_TEST_SEALED_RECORD_TMPFS_CHILD";
    if skip_supported() || std::env::var(OPT_IN).as_deref() != Ok("1") {
        return;
    }
    if std::env::var(CHILD).as_deref() != Ok("1") {
        // The mount is made only in this freshly created private namespace.
        let output = std::process::Command::new("unshare")
            .args(["--mount", "--propagation", "private", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sealed_recovery_store::tests::publication_rejects_record_filesystem_without_verity",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_ne!(
        fs::read_link("/proc/self/ns/mnt").unwrap(),
        fs::read_link(format!("/proc/{}/ns/mnt", unsafe { libc::getppid() })).unwrap(),
        "the disposable mount must be in a namespace separate from its parent"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    let target_mount = mountinfo
        .lines()
        .find(|line| {
            line.split_once(" - ").is_some_and(|(before, _)| {
                before.split_whitespace().nth(4) == Some(crate::BACKUP_DIRECTORY)
            })
        })
        .unwrap();
    let before = target_mount.split_once(" - ").unwrap().0;
    assert!(!before
        .split_whitespace()
        .any(|field| field.starts_with("shared:")
            || field.starts_with("master:")
            || field.starts_with("propagate_from:")
            || field == "unbindable"));

    struct TmpfsMount {
        target: CString,
        active: bool,
    }
    impl TmpfsMount {
        fn unmount(&mut self) {
            assert_eq!(unsafe { libc::umount2(self.target.as_ptr(), 0) }, 0);
            self.active = false;
        }
    }
    impl Drop for TmpfsMount {
        fn drop(&mut self) {
            if self.active {
                // Namespace teardown also removes the mount if this fails.
                unsafe {
                    libc::umount2(self.target.as_ptr(), libc::MNT_DETACH);
                }
            }
        }
    }

    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let id = sealed.record().record_id().to_owned();
        let root = record_dir(manifest);
        fs::create_dir(&root).unwrap();
        let target = CString::new(root.as_os_str().as_bytes()).unwrap();
        let rc = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                c"mode=0700,size=4m".as_ptr().cast(),
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        let mut mount = TmpfsMount {
            target,
            active: true,
        };
        let mut wrote = false;
        let result = PublishedRecovery::publish_inner(
            session,
            sealed,
            File::open(&root).unwrap(),
            |stage| {
                if stage == PublicationStage::WrittenAndSynced {
                    wrote = true;
                }
                Ok(())
            },
        );
        assert!(wrote, "failure must occur at or after the written record");
        assert!(
            matches!(result, Err(PublicationError::Io(ref error)) if matches!(error.raw_os_error(), Some(libc::ENOTTY | libc::EOPNOTSUPP)))
        );
        assert!(root.join(format!(".{id}.pending")).is_file());
        assert!(!root.join(format!("{id}.json")).exists());
        mount.unmount();
        fs::remove_dir(root).unwrap();
    });
}

#[test]
fn publication_tmpfs_child_flag_cannot_bypass_namespace_check() {
    if skip_supported() {
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sealed_recovery_store::tests::publication_rejects_record_filesystem_without_verity",
            "--nocapture",
        ])
        .env("LSM_TEST_SEALED_RECORD_TMPFS", "1")
        .env("LSM_TEST_SEALED_RECORD_TMPFS_CHILD", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("namespace separate from its parent"));
}

#[test]
fn publication_preserves_orphans_after_sigkill() {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    const CHILD: &str = "LSM_TEST_RECORD_KILL_STAGE";
    if skip_supported() {
        return;
    }
    if let Ok(stage) = std::env::var(CHILD) {
        with_fixture(|session, manifest, receipt, copies| {
            let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
            let root = record_dir(manifest);
            fs::create_dir(&root).unwrap();
            let primary = Path::new(manifest.artifact_directory());
            let mut name = primary.file_name().unwrap().to_os_string();
            name.push(".recovery");
            let recovery = primary.with_file_name(name);
            println!(
                "LSM_RECORD_FIXTURE|{}|{}|{}|{}|{}",
                primary.display(),
                recovery.display(),
                root.display(),
                session.lock_path().parent().unwrap().display(),
                sealed.record().record_id()
            );
            std::io::stdout().flush().unwrap();
            let _ = PublishedRecovery::publish_inner(
                session,
                sealed,
                File::open(&root).unwrap(),
                |current| {
                    let matched = matches!(
                        (stage.as_str(), current),
                        ("created", PublicationStage::Created)
                            | ("reserved", PublicationStage::ReservationSynced)
                            | ("written", PublicationStage::WrittenAndSynced)
                            | ("sealed", PublicationStage::SealedAndSynced)
                            | ("linked", PublicationStage::Linked)
                            | ("inode-synced", PublicationStage::LinkedInodeSynced)
                            | ("synced", PublicationStage::DirectorySynced)
                    );
                    if matched {
                        unsafe {
                            libc::kill(libc::getpid(), libc::SIGKILL);
                        }
                    }
                    Ok(())
                },
            );
            panic!("test child did not reach SIGKILL");
        });
        return;
    }
    for stage in [
        "created",
        "reserved",
        "written",
        "sealed",
        "linked",
        "inode-synced",
        "synced",
    ] {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sealed_recovery_store::tests::publication_preserves_orphans_after_sigkill",
                "--nocapture",
            ])
            .env(CHILD, stage)
            .output()
            .unwrap();
        assert_eq!(
            result.status.signal(),
            Some(libc::SIGKILL),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let stdout = String::from_utf8(result.stdout).unwrap();
        let line = stdout
            .lines()
            .find_map(|line| line.split_once("LSM_RECORD_FIXTURE|").map(|(_, rest)| rest))
            .unwrap();
        let parts = line.split('|').collect::<Vec<_>>();
        assert_eq!(parts.len(), 5);
        let primary = PathBuf::from(parts[0]);
        let recovery = PathBuf::from(parts[1]);
        let record_root = PathBuf::from(parts[2]);
        let outer = PathBuf::from(parts[3]);
        let id = parts[4];
        assert!(primary.starts_with(crate::BACKUP_DIRECTORY));
        assert_eq!(recovery.parent(), primary.parent());
        assert_eq!(record_root.parent(), primary.parent());
        let published = matches!(stage, "linked" | "inode-synced" | "synced");
        let record_name = if !published {
            format!(".{id}.pending")
        } else {
            format!("{id}.json")
        };
        let record_path = record_root.join(record_name);
        assert_eq!(
            fs::read_dir(&record_root).unwrap().count(),
            if published { 2 } else { 1 }
        );
        if published {
            let pending = fs::metadata(record_root.join(format!(".{id}.pending"))).unwrap();
            let final_meta = fs::metadata(record_root.join(format!("{id}.json"))).unwrap();
            assert_eq!(
                (pending.dev(), pending.ino(), pending.nlink()),
                (final_meta.dev(), final_meta.ino(), 2)
            );
        }
        if matches!(stage, "sealed" | "linked" | "inode-synced" | "synced") {
            let bytes = fs::read(&record_path).unwrap();
            let record = crate::backup_recovery_record::decode(&bytes, id).unwrap();
            assert_eq!(record.schema_version(), 3);
            assert!(crate::backup_verity::measure(&File::open(record_path).unwrap()).is_ok());
        } else {
            assert!(crate::backup_verity::measure(&File::open(record_path).unwrap()).is_err());
        }
        fs::remove_dir_all(&primary).unwrap();
        fs::remove_dir_all(&recovery).unwrap();
        fs::remove_dir_all(&record_root).unwrap();
        fs::remove_dir(primary.parent().unwrap()).unwrap();
        fs::remove_dir_all(outer).unwrap();
    }
}
