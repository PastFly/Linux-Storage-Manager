use super::*;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Nothing under the actual backup directory is touched before all checks pass.
fn disposable_mount() -> bool {
    if std::env::var("LSM_TEST_SEALED_DISPOSABLE").as_deref() != Ok("1") {
        return false;
    }
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let uuid = std::env::var("LSM_TEST_SEALED_UUID").expect("test filesystem UUID required");
    assert!(!uuid.is_empty() && uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    let root = Path::new(crate::BACKUP_DIRECTORY);
    let root_meta = fs::metadata(root).unwrap();
    assert_eq!(root_meta.uid(), 0);
    assert_eq!(
        libc::major(root_meta.dev()),
        7,
        "test image must be a loop device"
    );
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").unwrap();
    let mount = mountinfo
        .lines()
        .find(|line| {
            line.split_once(" - ").is_some_and(|(before, _)| {
                before.split_whitespace().nth(4) == Some(crate::BACKUP_DIRECTORY)
            })
        })
        .expect("BACKUP_DIRECTORY must be a mountpoint");
    let mut after = mount.split_once(" - ").unwrap().1.split_whitespace();
    assert_eq!(after.next(), Some("ext4"));
    let source = after.next().unwrap();
    assert_eq!(fs::metadata(source).unwrap().rdev(), root_meta.dev());
    let output = std::process::Command::new("blkid")
        .args(["-s", "UUID", "-o", "value", source])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), uuid);
    let marker = root.join(".lsm-sealed-disposable");
    let meta = fs::symlink_metadata(&marker).unwrap();
    assert!(meta.is_file() && meta.uid() == 0 && meta.nlink() == 1 && meta.mode() & 0o077 == 0);
    assert_eq!(fs::read_to_string(marker).unwrap().trim(), uuid);
    true
}

fn with_fixture(
    f: impl FnOnce(
        &crate::LockedExecutionSession<'_>,
        &crate::MetadataBackupManifest,
        &crate::MetadataBackupReceipt,
        PinnedCopies,
    ),
) {
    let (mut snapshot, capabilities) = crate::backup_capture::tests::direct_fixture();
    let unique = format!(
        "sealed-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    snapshot.storage.block_devices[0].serial = Some(unique.clone());
    let handoff = crate::backup_capture::tests::direct_handoff(&snapshot, &capabilities);
    let outer = std::env::temp_dir().join(format!("lsm-{unique}"));
    fs::create_dir(&outer).unwrap();
    let store = crate::DurableJournalStore::at(outer.join("journal"));
    let mut session = crate::LockedExecutionSession::begin_durable_recovery_at_paths(
        &handoff,
        &outer.join("lock"),
        &store,
    )
    .unwrap();
    session.revalidate(&snapshot, &capabilities).unwrap();
    let manifest = crate::build_metadata_backup_manifest_for_session(&session).unwrap();
    let root = PathBuf::from(manifest.artifact_directory());
    let handoff_root = root.parent().unwrap().to_path_buf();
    assert!(
        !handoff_root.exists(),
        "fixture must not reuse an existing backup directory"
    );
    let receipt = crate::backup_capture::tests::capture_fake_at_manifest_path(&session, &manifest);
    let recovery_root = root.with_file_name(format!(
        "{}.recovery",
        root.file_name().unwrap().to_str().unwrap()
    ));
    fs::create_dir(&recovery_root).unwrap();
    let mut pairs = Vec::new();
    for artifact in receipt.artifacts() {
        let path = Path::new(&artifact.artifact_path);
        let name = format!("{}.recovery", path.file_name().unwrap().to_str().unwrap());
        let recovery = recovery_root.join(name);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&recovery)
            .unwrap();
        output.write_all(&fs::read(path).unwrap()).unwrap();
        output.sync_all().unwrap();
        drop(output);
        pairs.push((File::open(path).unwrap(), File::open(recovery).unwrap()));
    }
    let copies = PinnedCopies {
        primary_dir: File::open(&root).unwrap(),
        recovery_dir: File::open(&recovery_root).unwrap(),
        pairs,
    };
    f(&session, &manifest, &receipt, copies);
    drop(session);
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&recovery_root).unwrap();
    fs::remove_dir(&handoff_root).unwrap();
    fs::remove_dir_all(outer).unwrap();
}

#[test]
fn sealed_recovery_accepts_real_pinned_copies_on_disposable_ext4() {
    if !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        assert_eq!(sealed.record().schema_version(), 3);
        assert_eq!(sealed.record().binding().receipt_id, receipt.receipt_id());
        assert_eq!(
            sealed.record().binding().journal_id,
            session.journal().journal_id
        );
        let artifact = &sealed.record().artifacts()[0];
        assert_eq!(artifact.primary_path, receipt.artifacts()[0].artifact_path);
        assert!(artifact.verity.is_some());
        for path in [&artifact.primary_path, &artifact.recovery_path] {
            assert!(OpenOptions::new().write(true).open(path).is_err());
        }
    });
}

#[test]
fn sealed_recovery_rejects_retained_primary_and_recovery_writers() {
    if !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some() {
        return;
    }
    for recovery_writer in [false, true] {
        with_fixture(|session, manifest, receipt, copies| {
            let primary = PathBuf::from(&receipt.artifacts()[0].artifact_path);
            let mut recovery_name = primary.file_name().unwrap().to_os_string();
            recovery_name.push(".recovery");
            let root = Path::new(manifest.artifact_directory());
            let recovery_root = root.with_file_name(format!(
                "{}.recovery",
                root.file_name().unwrap().to_str().unwrap()
            ));
            let recovery = recovery_root.join(recovery_name);
            let writer = OpenOptions::new()
                .write(true)
                .open(if recovery_writer { &recovery } else { &primary })
                .unwrap();
            let result = SealedRecovery::seal(session, manifest, receipt, copies);
            assert!(
                matches!(result, Err(SealError::Io(ref error)) if error.raw_os_error() == Some(libc::ETXTBSY))
            );
            if recovery_writer {
                // Failure on the second copy can leave the first one sealed.
                assert!(OpenOptions::new().write(true).open(&primary).is_err());
            }
            drop(writer);
        });
    }
}

#[test]
fn sealed_recovery_rejects_transient_name_replacement_and_wrong_dirfd() {
    if !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let path = PathBuf::from(&receipt.artifacts()[0].artifact_path);
        let moved = path.with_extension("fixture-moved");
        let result = SealedRecovery::seal_inner(session, manifest, receipt, copies, || {
            fs::rename(&path, &moved).unwrap();
            fs::rename(&moved, &path).unwrap();
        });
        assert!(result.is_err());
    });
    with_fixture(|session, manifest, receipt, mut copies| {
        copies.primary_dir = File::open("/tmp").unwrap();
        assert!(matches!(
            SealedRecovery::seal(session, manifest, receipt, copies),
            Err(SealError::InvalidEvidence)
        ));
    });
}

#[test]
fn sealed_recovery_fails_closed_on_unsupported_filesystem() {
    if !disposable_mount() || std::env::var("LSM_TEST_SEALED_UNSUPPORTED").as_deref() != Ok("1") {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        assert!(matches!(
            SealedRecovery::seal(session, manifest, receipt, copies),
            Err(SealError::Io(_))
        ));
    });
}
