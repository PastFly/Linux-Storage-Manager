//! Test-only reopening experiment. The caller must authenticate the anchor
//! and supply trusted roots. It does not defend against arbitrary root or
//! prove that both copies survive loss of their shared filesystem.

use crate::backup_recovery_record::{decode_v3_with_trusted_context, RecoveryBinding};
use crate::journal_fd::{DirectoryWatch, JournalDir};
use crate::journal_store::{trusted_journal_file, JournalStoreError};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

/// These values must come from an independently authenticated source.
/// This test-only type does not authenticate them or prevent rollback.
#[derive(Clone)]
struct TrustedRecoveryAnchor {
    record_id: String,
    binding: RecoveryBinding,
}

#[derive(Debug, thiserror::Error)]
enum ReopenError {
    #[error("record, paths, or file identity did not match the trusted anchor")]
    Invalid,
    #[error("recovery directory check failed: {0}")]
    Directory(#[from] JournalStoreError),
    #[error("recovery file I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// A snapshot of successfully checked files, not an authorization or an
/// ongoing namespace/observer guarantee. Kept descriptors pin those inodes.
struct ReopenedRecovery {
    pairs: Vec<(File, File)>,
    _primary_dir: JournalDir,
    _recovery_dir: JournalDir,
    _primary_watch: DirectoryWatch,
    _recovery_watch: DirectoryWatch,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn same_version(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn reopen_copy(
    directory: &JournalDir,
    name: &OsStr,
    expected_size: u64,
    expected_sha256: &str,
    expected_verity: &str,
) -> Result<(File, Metadata), ReopenError> {
    let mut file = directory.open_file(name)?;
    let before = file.metadata()?;
    if !trusted_journal_file(&before)
        || expected_size == 0
        || expected_size > MAX_ARTIFACT_BYTES
        || before.len() != expected_size
        || hex(&crate::backup_verity::measure(&file)?) != expected_verity
    {
        return Err(ReopenError::Invalid);
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = match file.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(ReopenError::Invalid)?;
        if total > expected_size {
            return Err(ReopenError::Invalid);
        }
        hasher.update(&buffer[..count]);
    }
    let held = file.metadata()?;
    let live = directory.open_file(name)?.metadata()?;
    if total != expected_size
        || format!("{:x}", hasher.finalize()) != expected_sha256
        || !same_version(&before, &held)
        || !same_version(&held, &live)
    {
        return Err(ReopenError::Invalid);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((file, held))
}

fn reopen(
    encoded: &[u8],
    anchor: &TrustedRecoveryAnchor,
    primary_root: &Path,
    recovery_root: &Path,
) -> Result<ReopenedRecovery, ReopenError> {
    let record = decode_v3_with_trusted_context(encoded, &anchor.record_id, &anchor.binding)
        .map_err(|_| ReopenError::Invalid)?;
    let primary_dir = JournalDir::open(primary_root)?;
    let recovery_dir = JournalDir::open(recovery_root)?;
    let p_root = primary_dir.file().metadata()?;
    let r_root = recovery_dir.file().metadata()?;
    if (p_root.dev(), p_root.ino()) == (r_root.dev(), r_root.ino()) {
        return Err(ReopenError::Invalid);
    }
    let mut primary_watch = primary_dir.watch_namespace()?;
    let mut recovery_watch = recovery_dir.watch_namespace()?;
    primary_dir.verify_namespace()?;
    recovery_dir.verify_namespace()?;
    let mut primary_names = Vec::<OsString>::new();
    let mut recovery_names = Vec::<OsString>::new();
    for artifact in record.artifacts() {
        let primary = Path::new(&artifact.primary_path);
        let recovery = Path::new(&artifact.recovery_path);
        if primary.parent() != Some(primary_root) || recovery.parent() != Some(recovery_root) {
            return Err(ReopenError::Invalid);
        }
        primary_names.push(
            primary
                .file_name()
                .ok_or(ReopenError::Invalid)?
                .to_os_string(),
        );
        recovery_names.push(
            recovery
                .file_name()
                .ok_or(ReopenError::Invalid)?
                .to_os_string(),
        );
    }
    primary_names.sort();
    recovery_names.sort();
    if primary_dir.names()? != primary_names || recovery_dir.names()? != recovery_names {
        return Err(ReopenError::Invalid);
    }
    let mut identities = BTreeSet::new();
    let mut pairs = Vec::with_capacity(record.artifacts().len());
    for artifact in record.artifacts() {
        let primary_path = Path::new(&artifact.primary_path);
        let recovery_path = Path::new(&artifact.recovery_path);
        if primary_path.parent() != Some(primary_root)
            || recovery_path.parent() != Some(recovery_root)
        {
            return Err(ReopenError::Invalid);
        }
        let primary_name = primary_path.file_name().ok_or(ReopenError::Invalid)?;
        let recovery_name = recovery_path.file_name().ok_or(ReopenError::Invalid)?;
        let verity = artifact.verity.as_ref().ok_or(ReopenError::Invalid)?;
        let (primary, p_metadata) = reopen_copy(
            &primary_dir,
            primary_name,
            artifact.size_bytes,
            &artifact.sha256,
            &verity.primary_sha256,
        )?;
        let (recovery, r_metadata) = reopen_copy(
            &recovery_dir,
            recovery_name,
            artifact.size_bytes,
            &artifact.sha256,
            &verity.recovery_sha256,
        )?;
        if !identities.insert((p_metadata.dev(), p_metadata.ino()))
            || !identities.insert((r_metadata.dev(), r_metadata.ino()))
        {
            return Err(ReopenError::Invalid);
        }
        pairs.push((primary, recovery));
    }
    primary_dir.verify_namespace()?;
    recovery_dir.verify_namespace()?;
    if primary_dir.names()? != primary_names || recovery_dir.names()? != recovery_names {
        return Err(ReopenError::Invalid);
    }
    primary_watch.require_unchanged()?;
    recovery_watch.require_unchanged()?;
    Ok(ReopenedRecovery {
        pairs,
        _primary_dir: primary_dir,
        _recovery_dir: recovery_dir,
        _primary_watch: primary_watch,
        _recovery_watch: recovery_watch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_recovery_record::{
        BackupRecoveryRecord, RecoveryArtifact, RecoveryBinding, RecoveryIdentity, RecoveryPayload,
        VerityPair,
    };
    use crate::{BackupArtifactReceipt, BackupExpectedIdentity, MetadataBackupKind};
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const DATA: &[u8] = b"sealed recovery fixture\n";

    struct Fixture {
        root: PathBuf,
        primary: PathBuf,
        recovery: PathBuf,
        encoded: Vec<u8>,
        anchor: TrustedRecoveryAnchor,
    }

    impl Fixture {
        fn new() -> Self {
            assert_eq!(
                std::env::var("LSM_TEST_DISPOSABLE_VERITY").as_deref(),
                Ok("1")
            );
            let base = PathBuf::from(
                std::env::var_os("LSM_TEST_DISPOSABLE_VERITY_DIR")
                    .expect("disposable ext4 fs-verity filesystem required"),
            );
            assert!(base.is_absolute());
            let base_file = File::open(&base).unwrap();
            let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::fstatfs(base_file.as_raw_fd(), &mut stat) },
                0
            );
            assert_eq!(stat.f_type as u64, 0xef53, "test root must be ext4");
            let root = base.join(format!(
                "lsm-reopen-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let primary = root.join("primary");
            let recovery = root.join("recovery");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&primary).unwrap();
            fs::create_dir(&recovery).unwrap();
            for path in [primary.join("backup"), recovery.join("backup.recovery")] {
                let mut writer = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path)
                    .unwrap();
                writer.write_all(DATA).unwrap();
                writer.sync_all().unwrap();
            }
            let p = File::open(primary.join("backup")).unwrap();
            let r = File::open(recovery.join("backup.recovery")).unwrap();
            crate::backup_verity::enable(&p).unwrap();
            crate::backup_verity::enable(&r).unwrap();
            p.sync_all().unwrap();
            r.sync_all().unwrap();
            let verity = VerityPair {
                primary_sha256: hex(&crate::backup_verity::measure(&p).unwrap()),
                recovery_sha256: hex(&crate::backup_verity::measure(&r).unwrap()),
            };
            drop((p, r));
            File::open(&primary).unwrap().sync_all().unwrap();
            File::open(&recovery).unwrap().sync_all().unwrap();
            let mut binding = RecoveryBinding {
                journal_id: "a".repeat(64),
                session_id: "b".repeat(64),
                handoff_id: "c".repeat(64),
                plan_id: "d".repeat(64),
                target_manifest_digest: "e".repeat(64),
                manifest_id: "f".repeat(64),
                receipt_id: String::new(),
            };
            let primary_path = primary.join("backup").to_str().unwrap().to_owned();
            let recovery_path = recovery
                .join("backup.recovery")
                .to_str()
                .unwrap()
                .to_owned();
            let identity = BackupExpectedIdentity::PartitionTable {
                disk: "/dev/vda".into(),
                table_label: "gpt".into(),
                table_id: Some("123".into()),
            };
            let sha256 = format!("{:x}", Sha256::digest(DATA));
            let captured = BackupArtifactReceipt {
                ordinal: 1,
                kind: MetadataBackupKind::PartitionTable,
                artifact_path: primary_path.clone(),
                expected_identity: identity,
                // Historical capture identity is intentionally unrelated to
                // the files reopened in this test.
                device_id: u64::MAX,
                inode: u64::MAX,
                size_bytes: DATA.len() as u64,
                sha256: sha256.clone(),
            };
            let receipt_bytes = serde_json::to_vec(&(
                2_u32,
                &binding.manifest_id,
                &binding.handoff_id,
                &binding.plan_id,
                &binding.target_manifest_digest,
                &binding.session_id,
                &binding.journal_id,
                false,
                &[captured],
            ))
            .unwrap();
            binding.receipt_id = format!("{:x}", Sha256::digest(receipt_bytes));
            let record = BackupRecoveryRecord::new(RecoveryPayload {
                schema_version: 3,
                binding: binding.clone(),
                artifacts: vec![RecoveryArtifact {
                    ordinal: 1,
                    identity: RecoveryIdentity::PartitionTable {
                        disk: "/dev/vda".into(),
                        table_label: "gpt".into(),
                        table_id: Some("123".into()),
                    },
                    primary_path,
                    recovery_path,
                    size_bytes: DATA.len() as u64,
                    sha256,
                    capture_device_id: Some(u64::MAX),
                    capture_inode: Some(u64::MAX),
                    verity: Some(verity),
                }],
            })
            .unwrap();
            Self {
                root,
                primary,
                recovery,
                encoded: record.encode().unwrap(),
                anchor: TrustedRecoveryAnchor {
                    record_id: record.record_id().into(),
                    binding,
                },
            }
        }

        fn reopen(&self) -> Result<ReopenedRecovery, ReopenError> {
            reopen(&self.encoded, &self.anchor, &self.primary, &self.recovery)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn reopens_both_sealed_files_without_trusting_capture_inode() {
        let fixture = Fixture::new();
        let mut opened = fixture.reopen().unwrap();
        assert_eq!(opened.pairs.len(), 1);
        assert_ne!(opened.pairs[0].0.metadata().unwrap().ino(), u64::MAX);
        assert_ne!(opened.pairs[0].1.metadata().unwrap().ino(), u64::MAX);
        let mut contents = Vec::new();
        opened.pairs[0].1.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, DATA);
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_removed_or_unsealed_replacement() {
        for replace in [false, true] {
            let fixture = Fixture::new();
            let path = fixture.recovery.join("backup.recovery");
            fs::remove_file(&path).unwrap();
            if replace {
                let mut writer = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                writer.write_all(DATA).unwrap();
                writer.sync_all().unwrap();
            }
            assert!(fixture.reopen().is_err());
        }
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_sealed_different_content_and_symlink_replacement() {
        for symlink in [false, true] {
            let fixture = Fixture::new();
            let path = fixture.recovery.join("backup.recovery");
            fs::remove_file(&path).unwrap();
            if symlink {
                std::os::unix::fs::symlink(fixture.primary.join("backup"), &path).unwrap();
            } else {
                let mut writer = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                writer.write_all(&vec![b'x'; DATA.len()]).unwrap();
                writer.sync_all().unwrap();
                drop(writer);
                crate::backup_verity::enable(&File::open(&path).unwrap()).unwrap();
            }
            assert!(fixture.reopen().is_err());
        }
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn identical_sealed_replacement_is_not_distinguishable_by_measurement() {
        let fixture = Fixture::new();
        let path = fixture.recovery.join("backup.recovery");
        fs::remove_file(&path).unwrap();
        let mut writer = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        writer.write_all(DATA).unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        crate::backup_verity::enable(&File::open(&path).unwrap()).unwrap();
        assert!(fixture.reopen().is_ok());
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_wrong_record_id_or_context() {
        let fixture = Fixture::new();
        let mut wrong = fixture.anchor.clone();
        wrong.record_id = "9".repeat(64);
        assert!(reopen(
            &fixture.encoded,
            &wrong,
            &fixture.primary,
            &fixture.recovery
        )
        .is_err());
        wrong = fixture.anchor.clone();
        wrong.binding.session_id = "9".repeat(64);
        assert!(reopen(
            &fixture.encoded,
            &wrong,
            &fixture.primary,
            &fixture.recovery
        )
        .is_err());
        assert!(reopen(
            &fixture.encoded,
            &fixture.anchor,
            &fixture.recovery,
            &fixture.primary
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_v2_even_with_its_own_matching_id_and_context() {
        let fixture = Fixture::new();
        let envelope: serde_json::Value = serde_json::from_slice(&fixture.encoded).unwrap();
        let mut payload: RecoveryPayload =
            serde_json::from_value(envelope["payload"].clone()).unwrap();
        payload.schema_version = 2;
        payload.artifacts[0].verity = None;
        let legacy = BackupRecoveryRecord::new(payload).unwrap();
        let anchor = TrustedRecoveryAnchor {
            record_id: legacy.record_id().to_owned(),
            binding: fixture.anchor.binding.clone(),
        };
        assert!(reopen(
            &legacy.encode().unwrap(),
            &anchor,
            &fixture.primary,
            &fixture.recovery
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_two_names_for_the_same_inode() {
        let fixture = Fixture::new();
        let path = fixture.recovery.join("backup.recovery");
        fs::remove_file(&path).unwrap();
        fs::hard_link(fixture.primary.join("backup"), &path).unwrap();
        assert!(fixture.reopen().is_err());
    }

    #[test]
    #[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
    fn rejects_and_preserves_unclassified_evidence_in_copy_directory() {
        let fixture = Fixture::new();
        let extra = fixture.recovery.join("unknown-staging");
        fs::write(&extra, b"preserve evidence").unwrap();
        assert!(fixture.reopen().is_err());
        assert_eq!(fs::read(extra).unwrap(), b"preserve evidence");
    }
}
