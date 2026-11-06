//! Test-only prototype; this does not authorize backup recovery.

use crate::backup_recovery_record::{
    decode_with_trusted_context, BackupRecoveryRecord, RecordError, RecoveryBinding,
};
use crate::journal_fd::JournalDir;
use crate::journal_store::{trusted_journal_file, JournalStoreError};
use std::ffi::{CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_WATCH_EVENTS: usize = 32;
const MAX_WATCH_READ_ATTEMPTS: usize = 16;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// Experimental event checks can reject observed interference, but inotify
// coalescing does not establish which process produced an event. This is not
// sufficient evidence for production recovery or protection from privileged
// writers.
struct NamespaceWatch {
    file: File,
    leaf: libc::c_int,
}

struct ObservedEvent {
    wd: libc::c_int,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}

impl NamespaceWatch {
    fn new(directory: &JournalDir) -> Result<Self, StorageError> {
        let raw = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let nodes = directory.test_namespace_fds();
        let mut descriptors = Vec::new();
        for (index, fd) in nodes.iter().enumerate() {
            let path =
                CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| StorageError::Changed)?;
            let mask = if index + 1 == nodes.len() {
                libc::IN_CREATE
                    | libc::IN_DELETE
                    | libc::IN_MOVED_FROM
                    | libc::IN_MOVED_TO
                    | libc::IN_MODIFY
                    | libc::IN_ATTRIB
                    | libc::IN_CLOSE_WRITE
                    | libc::IN_DELETE_SELF
                    | libc::IN_MOVE_SELF
                    | libc::IN_UNMOUNT
            } else {
                libc::IN_ATTRIB | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_UNMOUNT
            };
            use std::os::fd::AsRawFd;
            let wd = unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), mask) };
            if wd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if descriptors.contains(&wd) {
                return Err(StorageError::Changed);
            }
            descriptors.push(wd);
        }
        let leaf = *descriptors.last().ok_or(StorageError::Changed)?;
        Ok(Self { file, leaf })
    }

    fn events(&mut self) -> Result<Vec<ObservedEvent>, StorageError> {
        collect_events(&mut self.file)
    }

    fn expect_empty(&mut self) -> Result<(), StorageError> {
        if self.events()?.is_empty() {
            Ok(())
        } else {
            Err(StorageError::Changed)
        }
    }

    fn expect_staging(&mut self, staging: &str) -> Result<(), StorageError> {
        let events = self.events()?;
        let masks = [libc::IN_CREATE, libc::IN_MODIFY, libc::IN_CLOSE_WRITE];
        if events.len() != masks.len()
            || events.iter().zip(masks).any(|(event, mask)| {
                event.wd != self.leaf
                    || event.mask != mask
                    || event.cookie != 0
                    || event.name.as_slice() != staging.as_bytes()
            })
        {
            return Err(StorageError::Changed);
        }
        Ok(())
    }

    fn expect_publication(&mut self, staging: &str, final_name: &str) -> Result<(), StorageError> {
        let events = self.events()?;
        if events.len() != 2
            || events[0].wd != self.leaf
            || events[1].wd != self.leaf
            || events[0].mask != libc::IN_MOVED_FROM
            || events[1].mask != libc::IN_MOVED_TO
            || events[0].cookie == 0
            || events[0].cookie != events[1].cookie
            || events[0].name.as_slice() != staging.as_bytes()
            || events[1].name.as_slice() != final_name.as_bytes()
        {
            return Err(StorageError::Changed);
        }
        Ok(())
    }
}

fn collect_events(reader: &mut impl Read) -> Result<Vec<ObservedEvent>, StorageError> {
    let mut events = Vec::new();
    let mut bytes = [0_u8; 8192];
    for _ in 0..MAX_WATCH_READ_ATTEMPTS {
        let length = match reader.read(&mut bytes) {
            Ok(0) => return Err(StorageError::Changed),
            Ok(length) => length,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(events),
            Err(error) => return Err(error.into()),
        };
        let header_size = std::mem::size_of::<libc::inotify_event>();
        let mut offset = 0;
        while offset < length {
            if length - offset < header_size {
                return Err(StorageError::Changed);
            }
            let event = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<libc::inotify_event>())
            };
            let end = offset
                .checked_add(header_size)
                .and_then(|value| value.checked_add(event.len as usize))
                .filter(|end| *end <= length)
                .ok_or(StorageError::Changed)?;
            let name = &bytes[offset + header_size..end];
            let name_len = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            if events.len() == MAX_WATCH_EVENTS {
                return Err(StorageError::EventLimit);
            }
            events.push(ObservedEvent {
                wd: event.wd,
                mask: event.mask,
                cookie: event.cookie,
                name: name[..name_len].to_vec(),
            });
            offset = end;
        }
    }
    Err(StorageError::EventLimit)
}

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
    #[error("recovery storage event observation exceeded its limit")]
    EventLimit,
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
    let initial_names = directory.names()?;
    if initial_names.len() != 1 || initial_names[0].as_os_str() != OsStr::new(&name) {
        return Err(StorageError::Changed);
    }
    let (record, pinned, metadata) =
        read_pinned(&directory, OsStr::new(&name), expected_id, trusted)?;
    directory.verify_namespace()?;
    let live = directory.open_file(OsStr::new(&name))?.metadata()?;
    if !same_version(&metadata, &pinned.metadata()?)
        || !same_version(&metadata, &live)
        || initial_names != directory.names()?
    {
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
    store_with_hooks(root, record, trusted, before_publication, |_, _| Ok(()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HookPoint {
    BeforeStaging,
    AfterStagingBeforeWatch,
    AfterPrePublicationCheck,
    AfterPublicationBeforeWatch,
}

fn store_with_hooks(
    root: &Path,
    record: &BackupRecoveryRecord,
    trusted: &RecoveryBinding,
    before_publication: impl FnOnce() -> Result<(), StorageError>,
    mut hook: impl FnMut(HookPoint, &str) -> Result<(), StorageError>,
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
    let mut watch = NamespaceWatch::new(&directory)?;
    directory.verify_namespace()?;
    watch.expect_empty()?;
    let staging = format!(
        ".{id}.tmp-{}-{}",
        std::process::id(),
        STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let final_name = format!("{id}.json");
    if directory
        .names()?
        .iter()
        .any(|name| name.as_os_str() != OsStr::new(&final_name))
    {
        return Err(StorageError::Changed);
    }
    watch.expect_empty()?;
    hook(HookPoint::BeforeStaging, &staging)?;
    let created = directory.write_staged_file(OsStr::new(&staging), &bytes)?;
    let created_metadata = created.metadata()?;
    directory.sync()?;
    hook(HookPoint::AfterStagingBeforeWatch, &staging)?;
    watch.expect_staging(&staging)?;
    let (staged_record, staged, staged_metadata) =
        read_pinned(&directory, OsStr::new(&staging), id, trusted)?;
    if staged_record != *record || !same_version(&created_metadata, &staged_metadata) {
        return Err(StorageError::Changed);
    }
    before_publication()?;
    directory.verify_namespace()?;
    watch.expect_empty()?;
    if !same_version(&staged_metadata, &staged.metadata()?) {
        return Err(StorageError::Changed);
    }
    hook(HookPoint::AfterPrePublicationCheck, &staging)?;
    watch.expect_empty()?;
    directory.publish_new(OsStr::new(&staging), OsStr::new(&final_name))?;
    directory.sync()?;
    hook(HookPoint::AfterPublicationBeforeWatch, &staging)?;
    watch.expect_publication(&staging, &final_name)?;
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
    watch.expect_empty()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup_recovery_record::{RecoveryArtifact, RecoveryIdentity, RecoveryPayload};
    use std::cell::Cell;
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
                verity: None,
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

    fn nested_directory() -> (PathBuf, PathBuf) {
        let outer = temporary_directory();
        let ancestor = outer.join("ancestor");
        let root = ancestor.join("records");
        fs::create_dir(&ancestor).unwrap();
        fs::create_dir(&root).unwrap();
        (outer, root)
    }

    fn rename_and_restore_ancestor(outer: &Path) {
        let ancestor = outer.join("ancestor");
        let moved = outer.join("ancestor-moved");
        fs::rename(&ancestor, &moved).unwrap();
        fs::rename(&moved, &ancestor).unwrap();
    }

    #[test]
    fn excessive_observed_events_fail_closed() {
        let root = temporary_directory();
        let directory = JournalDir::open(&root).unwrap();
        let mut watch = NamespaceWatch::new(&directory).unwrap();
        for index in 0..=MAX_WATCH_EVENTS {
            fs::write(root.join(format!("event-{index}")), b"data").unwrap();
        }
        let result = watch.events();
        drop(watch);
        drop(directory);
        fs::remove_dir_all(root).unwrap();
        assert!(matches!(result, Err(StorageError::EventLimit)));
    }

    #[test]
    fn repeated_interrupted_reads_fail_closed_after_bounded_attempts() {
        struct InterruptedReader(usize);
        impl Read for InterruptedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
        }

        let mut reader = InterruptedReader(0);
        let result = collect_events(&mut reader);
        assert!(matches!(result, Err(StorageError::EventLimit)));
        assert_eq!(reader.0, MAX_WATCH_READ_ATTEMPTS);
    }

    #[test]
    fn transient_ancestor_rename_before_staging_is_rejected() {
        let (outer, root) = nested_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hooks(
            &root,
            &record,
            &trusted,
            || Ok(()),
            |point, _| {
                if point == HookPoint::BeforeStaging {
                    reached.set(true);
                    rename_and_restore_ancestor(&outer);
                }
                Ok(())
            },
        );
        fs::remove_dir_all(outer).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(result.is_err(), "transient ancestor change was accepted");
    }

    #[test]
    fn transient_ancestor_rename_before_publication_is_rejected() {
        let (outer, root) = nested_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hook(&root, &record, &trusted, || {
            reached.set(true);
            rename_and_restore_ancestor(&outer);
            Ok(())
        });
        fs::remove_dir_all(outer).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(result.is_err(), "transient ancestor change was accepted");
    }

    #[test]
    fn transient_ancestor_rename_after_staging_before_watch_is_rejected() {
        let (outer, root) = nested_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hooks(
            &root,
            &record,
            &trusted,
            || Ok(()),
            |point, _| {
                if point == HookPoint::AfterStagingBeforeWatch {
                    reached.set(true);
                    rename_and_restore_ancestor(&outer);
                }
                Ok(())
            },
        );
        fs::remove_dir_all(outer).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(result.is_err(), "transient ancestor change was accepted");
    }

    #[test]
    fn unrelated_create_write_and_close_are_not_accepted_as_own_staging_events() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hooks(
            &root,
            &record,
            &trusted,
            || Ok(()),
            |point, _| {
                if point == HookPoint::AfterStagingBeforeWatch {
                    reached.set(true);
                    let foreign = root.join("foreign");
                    fs::write(&foreign, b"foreign write").unwrap();
                    fs::remove_file(foreign).unwrap();
                }
                Ok(())
            },
        );
        fs::remove_dir_all(root).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(result.is_err(), "foreign create/write/close was accepted");
    }

    #[test]
    fn transient_staging_replacement_after_watch_check_is_rejected() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hooks(
            &root,
            &record,
            &trusted,
            || Ok(()),
            |point, staging| {
                if point == HookPoint::AfterPrePublicationCheck {
                    reached.set(true);
                    let path = root.join(staging);
                    let saved = root.join("saved-staging");
                    fs::rename(&path, &saved).unwrap();
                    fs::write(&path, b"foreign evidence").unwrap();
                    fs::remove_file(&path).unwrap();
                    fs::rename(&saved, &path).unwrap();
                }
                Ok(())
            },
        );
        fs::remove_dir_all(root).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(
            result.is_err(),
            "transient staging replacement was accepted"
        );
    }

    #[test]
    fn transient_ancestor_rename_after_publication_is_rejected() {
        let (outer, root) = nested_directory();
        let (record, trusted) = fixture();
        let reached = Cell::new(false);
        let result = store_with_hooks(
            &root,
            &record,
            &trusted,
            || Ok(()),
            |point, _| {
                if point == HookPoint::AfterPublicationBeforeWatch {
                    reached.set(true);
                    rename_and_restore_ancestor(&outer);
                }
                Ok(())
            },
        );
        fs::remove_dir_all(outer).unwrap();
        assert!(reached.get(), "the intended gap was not reached");
        assert!(result.is_err(), "transient ancestor change was accepted");
    }

    #[test]
    fn load_rejects_and_preserves_orphan_staging_next_to_final_record() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        store(&root, &record, &trusted).unwrap();
        let orphan = root.join(format!(".{}.tmp-999-1", record.record_id()));
        fs::write(&orphan, b"unknown staging evidence").unwrap();
        let result = load(&root, record.record_id(), &trusted);
        let evidence = fs::read(&orphan).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(evidence, b"unknown staging evidence");
        assert!(result.is_err(), "load accepted unresolved staging evidence");
    }

    #[test]
    fn store_rejects_and_preserves_preexisting_orphan_staging() {
        let root = temporary_directory();
        let (record, trusted) = fixture();
        let orphan = root.join(format!(".{}.tmp-999-1", record.record_id()));
        fs::write(&orphan, b"unknown staging evidence").unwrap();
        let result = store(&root, &record, &trusted);
        let evidence = fs::read(&orphan).unwrap();
        let final_exists = root.join(format!("{}.json", record.record_id())).exists();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(evidence, b"unknown staging evidence");
        assert!(
            !final_exists,
            "store published despite unresolved staging evidence"
        );
        assert!(
            result.is_err(),
            "store accepted unresolved staging evidence"
        );
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
