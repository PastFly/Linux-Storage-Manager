//! Test-only prototype; this does not authorize backup recovery.

use crate::backup_recovery_record::{
    decode_with_trusted_context, BackupRecoveryRecord, RecordError, RecoveryBinding,
};
use crate::journal_fd::JournalDir;
use crate::journal_store::{trusted_journal_file, JournalStoreError};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECORD_BYTES: u64 = 64 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
enum StorageError {
    #[error("recovery record validation failed: {0:?}")]
    Record(RecordError),
    #[error("journal directory failed: {0}")]
    Journal(#[from] JournalStoreError),
    #[error("recovery storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("recovery storage changed or was invalid")]
    Changed,
    #[error("injected pre-publication failure")]
    Injected,
}

impl From<RecordError> for StorageError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn read_pinned(
    directory: &JournalDir,
    name: &OsStr,
    expected_id: &str,
    trusted: &RecoveryBinding,
) -> Result<(BackupRecoveryRecord, File, Metadata), StorageError> {
    let mut file = directory.open_file(name)?;
    let initial = file.metadata()?;
    if !trusted_journal_file(&initial) || initial.len() > MAX_RECORD_BYTES {
        return Err(StorageError::Changed);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(StorageError::Changed);
    }
    let held = file.metadata()?;
    let live = directory.open_file(name)?.metadata()?;
    if !same_version(&initial, &held) || !same_version(&held, &live) {
        return Err(StorageError::Changed);
    }
    let record = decode_with_trusted_context(&bytes, expected_id, trusted)?;
    Ok((record, file, held))
}

fn load(
    root: &Path,
    expected_id: &str,
    trusted: &RecoveryBinding,
) -> Result<BackupRecoveryRecord, StorageError> {
    if !valid_id(expected_id) {
        return Err(StorageError::Changed);
    }
    let directory = JournalDir::open(root)?;
    let mut watch = directory.watch_namespace()?;
    let name = format!("{expected_id}.json");
    let (record, pinned, metadata) =
        read_pinned(&directory, OsStr::new(&name), expected_id, trusted)?;
    directory.verify_namespace()?;
    let live = directory.open_file(OsStr::new(&name))?.metadata()?;
    if !same_version(&metadata, &pinned.metadata()?) || !same_version(&metadata, &live) {
        return Err(StorageError::Changed);
    }
    watch.require_unchanged()?;
    Ok(record)
}

fn store(
    root: &Path,
    record: &BackupRecoveryRecord,
    trusted: &RecoveryBinding,
) -> Result<(), StorageError> {
    store_with_hook(root, record, trusted, || Ok(()))
}

fn store_with_hook(
    root: &Path,
    record: &BackupRecoveryRecord,
    trusted: &RecoveryBinding,
    before_publication: impl FnOnce() -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    let id = record.record_id();
    if !valid_id(id) {
        return Err(StorageError::Changed);
    }
    let bytes = record.encode()?;
    if decode_with_trusted_context(&bytes, id, trusted)? != *record {
        return Err(StorageError::Changed);
    }
    let directory = JournalDir::open(root)?;
    let staging = format!(
        ".{id}.tmp-{}-{}",
        std::process::id(),
        STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let final_name = format!("{id}.json");
    let created = directory.write_staged_file(OsStr::new(&staging), &bytes)?;
    let created_metadata = created.metadata()?;
    directory.sync()?;
    let mut watch = directory.watch()?;
    let (staged_record, staged, staged_metadata) =
        read_pinned(&directory, OsStr::new(&staging), id, trusted)?;
    if staged_record != *record || !same_version(&created_metadata, &staged_metadata) {
        return Err(StorageError::Changed);
    }
    before_publication()?;
    directory.verify_namespace()?;
    watch.require_unchanged()?;
    if !same_version(&staged_metadata, &staged.metadata()?) {
        return Err(StorageError::Changed);
    }
    directory.publish_new(OsStr::new(&staging), OsStr::new(&final_name))?;
    directory.sync()?;
    let mut published_watch = directory.watch_namespace()?;
    let (published, pinned, published_metadata) =
        read_pinned(&directory, OsStr::new(&final_name), id, trusted)?;
    if published != *record
        || published_metadata.dev() != created_metadata.dev()
        || published_metadata.ino() != created_metadata.ino()
        || !same_version(&published_metadata, &pinned.metadata()?)
    {
        return Err(StorageError::Changed);
    }
    directory.verify_namespace()?;
    published_watch.require_unchanged()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_recovery_record::{RecoveryArtifact, RecoveryIdentity, RecoveryPayload};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (BackupRecoveryRecord, RecoveryBinding) {
        let binding = RecoveryBinding {
            journal_id: "a".repeat(64),
            session_id: "b".repeat(64),
            handoff_id: "c".repeat(64),
            plan_id: "d".repeat(64),
            target_manifest_digest: "e".repeat(64),
            manifest_id: "f".repeat(64),
            receipt_id: "573c963f221eeb5287715a6dd620a3f7b3f84f31facbccdb4de567f8c32001fe".into(),
        };
        let record = BackupRecoveryRecord::new(RecoveryPayload {
            schema_version: 2,
            binding: binding.clone(),
            artifacts: vec![RecoveryArtifact {
                ordinal: 1,
                identity: RecoveryIdentity::PartitionTable {
                    disk: "/dev/vda".into(),
                    table_label: "gpt".into(),
                    table_id: Some("123".into()),
                },
                primary_path: "/var/lib/lsm/backups/primary".into(),
                recovery_path: "/var/lib/lsm/backups/recovery".into(),
                size_bytes: 42,
                sha256: "2".repeat(64),
                capture_device_id: Some(123),
                capture_inode: Some(456),
            }],
        })
        .unwrap();
        (record, binding)
    }

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "lsm-recovery-storage-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn writes_and_reads_back_exact_record_with_trusted_context() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        store(&root, &record, &trusted).unwrap();
        assert_eq!(load(&root, record.record_id(), &trusted).unwrap(), record);
        let mut wrong = trusted.clone();
        wrong.session_id = "9".repeat(64);
        assert!(load(&root, record.record_id(), &wrong).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_record_is_never_replaced() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        store(&root, &record, &trusted).unwrap();
        let before = fs::read(root.join(format!("{}.json", record.record_id()))).unwrap();
        assert!(store(&root, &record, &trusted).is_err());
        assert_eq!(
            fs::read(root.join(format!("{}.json", record.record_id()))).unwrap(),
            before
        );
        assert!(
            fs::read_dir(&root).unwrap().count() > 1,
            "failed publication retains staging evidence"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_record_bytes_are_rejected() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        store(&root, &record, &trusted).unwrap();
        let path = root.join(format!("{}.json", record.record_id()));
        let mut bytes = fs::read(&path).unwrap();
        let index = bytes.iter().position(|byte| *byte == b'v').unwrap();
        bytes[index] = b'x';
        fs::write(path, bytes).unwrap();
        assert!(load(&root, record.record_id(), &trusted).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failure_before_publication_retains_stage_and_has_no_final_record() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        assert!(store_with_hook(&root, &record, &trusted, || Err(StorageError::Injected)).is_err());
        assert!(!root.join(format!("{}.json", record.record_id())).exists());
        let names = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 1);
        assert!(names[0].to_string_lossy().starts_with('.'));
        fs::remove_dir_all(root).unwrap();
    }
}
