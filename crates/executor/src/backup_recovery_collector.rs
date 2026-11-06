//! Experimental pre-approval backup-copy preparation, not authorization.
//!
//! Copying, checksums and fsync do not rule out a retained writer or a later
//! namespace change. No record is returned without an observer proof, which
//! this module does not yet have; `seal` deliberately always fails closed.
#![allow(dead_code)]
use crate::backup_recovery_record::{
    validate_capture_binding, BackupRecoveryRecord, RecoveryBinding,
};
use crate::journal_fd::{DirectoryWatch, JournalDir};
use crate::journal_store::{trusted_journal_file, JournalStoreError};
use crate::{MetadataBackupManifest, MetadataBackupReceipt};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Optional parallel watcher used only to diagnose test failures. Its watch
/// descriptors are independent of `DirectoryWatch`; it never grants safety.
struct WatchDiagnostics {
    file: File,
    paths: Vec<(libc::c_int, std::path::PathBuf)>,
}

impl WatchDiagnostics {
    fn maybe_new(directory: &JournalDir) -> Result<Option<Self>, CollectorError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        if std::env::var_os("LSM_COLLECTOR_WATCH_DIAGNOSTICS").is_none() {
            return Ok(None);
        }
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let nodes = directory.test_namespace_fds();
        let mut paths = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let proc_path = format!("/proc/self/fd/{node}");
            let path = std::fs::read_link(&proc_path)?;
            let c_path = std::ffi::CString::new(proc_path).map_err(|_| CollectorError::Changed)?;
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
            let wd = unsafe { libc::inotify_add_watch(file.as_raw_fd(), c_path.as_ptr(), mask) };
            if wd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            paths.push((wd, path));
        }
        Ok(Some(Self { file, paths }))
    }

    fn drain(&mut self, phase: &str, report: bool) -> Result<(), CollectorError> {
        let mut bytes = [0u8; 8192];
        loop {
            let length = match self.file.read(&mut bytes) {
                Ok(0) => return Err(CollectorError::Changed),
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            let header_size = std::mem::size_of::<libc::inotify_event>();
            let mut offset = 0;
            while offset < length {
                if length - offset < header_size {
                    return Err(CollectorError::Changed);
                }
                let event = unsafe {
                    std::ptr::read_unaligned(
                        bytes.as_ptr().add(offset).cast::<libc::inotify_event>(),
                    )
                };
                let end = offset
                    .checked_add(header_size)
                    .and_then(|n| n.checked_add(event.len as usize))
                    .filter(|n| *n <= length)
                    .ok_or(CollectorError::Changed)?;
                let name = &bytes[offset + header_size..end];
                if report {
                    let path = self
                        .paths
                        .iter()
                        .find(|(wd, _)| *wd == event.wd)
                        .map(|(_, path)| path.as_path());
                    eprintln!("collector watch: phase={phase} wd={} mask={:#x} cookie={} path={path:?} name={:?}", event.wd, event.mask, event.cookie, String::from_utf8_lossy(name).trim_end_matches('\0'));
                }
                offset = end;
            }
        }
    }
}

fn check_watch(
    watch: &mut DirectoryWatch,
    diagnostics: &mut Option<WatchDiagnostics>,
    phase: &str,
) -> Result<(), CollectorError> {
    let result = watch.require_unchanged();
    if let Some(diagnostics) = diagnostics {
        diagnostics.drain(phase, result.is_err())?;
        if result.is_err() {
            eprintln!("collector watch failure: phase={phase}");
        }
    }
    result.map_err(CollectorError::from)
}

fn trace_journal<T>(
    phase: &str,
    result: Result<T, JournalStoreError>,
) -> Result<T, CollectorError> {
    result.map_err(|error| {
        if std::env::var_os("LSM_COLLECTOR_WATCH_DIAGNOSTICS").is_some() {
            eprintln!("collector journal failure: phase={phase} error={error:?}");
        }
        error.into()
    })
}

fn trace_collector<T>(phase: &str, result: Result<T, CollectorError>) -> Result<T, CollectorError> {
    result.map_err(|error| {
        if std::env::var_os("LSM_COLLECTOR_WATCH_DIAGNOSTICS").is_some() {
            eprintln!("collector failure: phase={phase} error={error:?}");
        }
        error
    })
}

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum CollectorError {
    ObserverProofUnavailable,
    InvalidEvidence,
    Changed,
    Io(io::Error),
    Journal(JournalStoreError),
}

impl From<io::Error> for CollectorError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<JournalStoreError> for CollectorError {
    fn from(error: JournalStoreError) -> Self {
        Self::Journal(error)
    }
}

struct PinnedPair {
    _primary: File,
    _recovery: File,
}

pub(crate) struct PendingCopies {
    _primary_dir: JournalDir,
    _recovery_dir: JournalDir,
    _primary_watch: DirectoryWatch,
    _recovery_watch: DirectoryWatch,
    _pairs: Vec<PinnedPair>,
}

impl PendingCopies {
    /// Intentionally never issues a record: no observer/semantic proof exists.
    pub(crate) fn seal(self) -> Result<BackupRecoveryRecord, CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }

    // Red-phase stub: never reports a successful observer.
    fn observe_at(
        self,
        _root: &Path,
        _executable: &OsStr,
    ) -> Result<ObservedPending, CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }
}

struct ObservedPending;

impl ObservedPending {
    fn observer_pidfd_for_test(&self) -> Result<File, CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }
    fn observer_alive(&self) -> Result<(), CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }
    fn seal(self) -> Result<BackupRecoveryRecord, CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
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

fn read_checked(
    directory: &JournalDir,
    name: &OsStr,
    expected_size: u64,
    expected_hash: &str,
    expected_identity: Option<(u64, u64)>,
) -> Result<(File, Metadata, Vec<u8>), CollectorError> {
    let mut file = directory.open_file(name)?;
    let before = file.metadata()?;
    if !trusted_journal_file(&before)
        || expected_size == 0
        || expected_size > MAX_ARTIFACT_BYTES
        || before.len() != expected_size
        || expected_identity.is_some_and(|identity| identity != (before.dev(), before.ino()))
    {
        return Err(CollectorError::InvalidEvidence);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_size
        || format!("{:x}", Sha256::digest(&bytes)) != expected_hash
    {
        return Err(CollectorError::InvalidEvidence);
    }
    let held = file.metadata()?;
    let live = directory.open_file(name)?.metadata()?;
    if !same_file(&before, &held) || !same_file(&held, &live) {
        return Err(CollectorError::Changed);
    }
    Ok((file, held, bytes))
}

/// All paths are explicitly test-only overrides. Both protected directories
/// must already exist; this routine never creates or removes directories.
pub(crate) fn prepare_at(
    manifest: &MetadataBackupManifest,
    receipt: &MetadataBackupReceipt,
    trusted: &RecoveryBinding,
    primary_root: &Path,
    recovery_root: &Path,
) -> Result<PendingCopies, CollectorError> {
    prepare_with_hook(
        manifest,
        receipt,
        trusted,
        primary_root,
        recovery_root,
        || Ok(()),
    )
}

fn prepare_with_hook(
    manifest: &MetadataBackupManifest,
    receipt: &MetadataBackupReceipt,
    trusted: &RecoveryBinding,
    primary_root: &Path,
    recovery_root: &Path,
    after_copy: impl FnOnce() -> Result<(), CollectorError>,
) -> Result<PendingCopies, CollectorError> {
    validate_capture_binding(manifest, receipt, trusted)
        .map_err(|_| CollectorError::InvalidEvidence)?;
    let primary_dir = JournalDir::open(primary_root)?;
    let recovery_dir = JournalDir::open(recovery_root)?;
    let primary_root_metadata = primary_dir.file().metadata()?;
    let recovery_root_metadata = recovery_dir.file().metadata()?;
    if (primary_root_metadata.dev(), primary_root_metadata.ino())
        == (recovery_root_metadata.dev(), recovery_root_metadata.ino())
    {
        return Err(CollectorError::InvalidEvidence);
    }
    let mut primary_diagnostics = WatchDiagnostics::maybe_new(&primary_dir)?;
    let mut primary_watch = trace_journal("primary-watch-install", primary_dir.watch_namespace())?;
    trace_journal("primary-initial-verify", primary_dir.verify_namespace())?;
    check_watch(
        &mut primary_watch,
        &mut primary_diagnostics,
        "primary-initial-check",
    )?;
    trace_journal("recovery-initial-verify", recovery_dir.verify_namespace())?;
    if !recovery_dir.names()?.is_empty() {
        return Err(CollectorError::Changed);
    }
    let mut pairs = Vec::with_capacity(receipt.artifacts().len());
    let mut expected_names = Vec::<OsString>::new();
    for artifact in receipt.artifacts() {
        let name = Path::new(&artifact.artifact_path)
            .file_name()
            .ok_or(CollectorError::InvalidEvidence)?;
        let (primary, original, bytes) = trace_collector(
            "primary-initial-read",
            read_checked(
                &primary_dir,
                name,
                artifact.size_bytes,
                &artifact.sha256,
                Some((artifact.device_id, artifact.inode)),
            ),
        )?;
        primary.sync_all()?;
        trace_journal("primary-before-copy", primary_dir.verify_namespace())?;
        check_watch(
            &mut primary_watch,
            &mut primary_diagnostics,
            "primary-before-copy",
        )?;
        let mut recovery_name = name.to_os_string();
        recovery_name.push(".recovery");
        // O_EXCL is implemented by the isolated journal writer: never reuse,
        // overwrite, or delete an existing/partially written recovery file.
        let created = trace_journal(
            "recovery-write",
            recovery_dir.write_staged_file(&recovery_name, &bytes),
        )?;
        let created_metadata = created.metadata()?;
        if !trusted_journal_file(&created_metadata) {
            return Err(CollectorError::InvalidEvidence);
        }
        recovery_dir.sync()?;
        trace_journal("recovery-after-copy", recovery_dir.verify_namespace())?;
        let (recovery, recovered, _) = trace_collector(
            "recovery-initial-read",
            read_checked(
                &recovery_dir,
                &recovery_name,
                artifact.size_bytes,
                &artifact.sha256,
                None,
            ),
        )?;
        if !same_file(&created_metadata, &recovered)
            || (original.dev(), original.ino()) == (recovered.dev(), recovered.ino())
        {
            return Err(CollectorError::Changed);
        }
        expected_names.push(recovery_name);
        pairs.push(PinnedPair {
            _primary: primary,
            _recovery: recovery,
        });
    }
    after_copy()?;
    expected_names.sort();
    if recovery_dir.names()? != expected_names {
        return Err(CollectorError::Changed);
    }
    // New copies were written by us. Arm the watcher after publication, then
    // re-read pinned evidence. This is diagnostics, not a substitute for leases.
    let mut recovery_diagnostics = WatchDiagnostics::maybe_new(&recovery_dir)?;
    let mut recovery_watch =
        trace_journal("recovery-watch-install", recovery_dir.watch_namespace())?;
    for (artifact, pair) in receipt.artifacts().iter().zip(&pairs) {
        let name = Path::new(&artifact.artifact_path)
            .file_name()
            .ok_or(CollectorError::InvalidEvidence)?;
        let mut recovery_name = name.to_os_string();
        recovery_name.push(".recovery");
        let (_, primary_metadata, _) = trace_collector(
            "primary-final-read",
            read_checked(
                &primary_dir,
                name,
                artifact.size_bytes,
                &artifact.sha256,
                Some((artifact.device_id, artifact.inode)),
            ),
        )?;
        let (_, recovery_metadata, _) = trace_collector(
            "recovery-final-read",
            read_checked(
                &recovery_dir,
                &recovery_name,
                artifact.size_bytes,
                &artifact.sha256,
                None,
            ),
        )?;
        if !same_file(&primary_metadata, &pair._primary.metadata()?)
            || !same_file(&recovery_metadata, &pair._recovery.metadata()?)
        {
            return Err(CollectorError::Changed);
        }
    }
    primary_dir.sync()?;
    recovery_dir.sync()?;
    trace_journal("primary-final-verify", primary_dir.verify_namespace())?;
    trace_journal("recovery-final-verify", recovery_dir.verify_namespace())?;
    check_watch(
        &mut primary_watch,
        &mut primary_diagnostics,
        "primary-final-check",
    )?;
    check_watch(
        &mut recovery_watch,
        &mut recovery_diagnostics,
        "recovery-final-check",
    )?;
    if recovery_dir.names()? != expected_names {
        return Err(CollectorError::Changed);
    }
    Ok(PendingCopies {
        _primary_dir: primary_dir,
        _recovery_dir: recovery_dir,
        _primary_watch: primary_watch,
        _recovery_watch: recovery_watch,
        _pairs: pairs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::{FileExt, PermissionsExt};

    fn fixture(
        suffix: &str,
    ) -> (
        MetadataBackupManifest,
        MetadataBackupReceipt,
        RecoveryBinding,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let (_handoff, manifest, receipt, lock, primary) =
            crate::backup_capture::tests::captured_direct_fixture(suffix);
        let trusted = RecoveryBinding {
            journal_id: receipt.recovery_journal_id().into(),
            session_id: receipt.recovery_session_id().into(),
            handoff_id: manifest.handoff_id().into(),
            plan_id: manifest.plan_id().into(),
            target_manifest_digest: manifest.target_manifest_digest().into(),
            manifest_id: manifest.manifest_id().into(),
            receipt_id: receipt.receipt_id().into(),
        };
        let recovery = primary.with_extension("recovery");
        std::fs::create_dir(&recovery).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        (manifest, receipt, trusted, lock, primary, recovery)
    }

    fn paths(
        receipt: &MetadataBackupReceipt,
        primary: &Path,
        recovery: &Path,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let name = Path::new(&receipt.artifacts()[0].artifact_path)
            .file_name()
            .unwrap();
        let mut recovery_name = name.to_os_string();
        recovery_name.push(".recovery");
        (primary.join(name), recovery.join(recovery_name))
    }

    fn cleanup(lock: &Path, primary: &Path, recovery: &Path) {
        let _ = std::fs::remove_dir_all(lock.parent().unwrap());
        let _ = std::fs::remove_dir_all(recovery);
        let _ = std::fs::remove_dir_all(primary);
    }

    fn disposable_observer() -> (std::path::PathBuf, OsString) {
        let root = std::path::PathBuf::from(
            std::env::var_os("LSM_TEST_DISPOSABLE_CGROUP")
                .expect("explicit disposable cgroup required"),
        );
        let executable =
            std::env::var_os("LSM_TEST_OBSERVER_EXE").expect("observer executable required");
        assert!(root.starts_with("/sys/fs/cgroup") && root != Path::new("/sys/fs/cgroup"));
        assert!(root.components().all(|part| matches!(
            part,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        (root, executable)
    }

    fn wait_pidfd(pidfd: &File) {
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut pollfd, 1, 10_000) },
            1,
            "observer did not exit"
        );
        assert_ne!(pollfd.revents & libc::POLLIN, 0);
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    fn observer_preparation_holds_both_copies_but_seal_stays_closed() {
        let (root, executable) = disposable_observer();
        let (manifest, receipt, trusted, lock, primary, recovery) =
            fixture("collector-observer-ready");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).unwrap();
        let observed = pending
            .observe_at(&root, &executable)
            .expect("observer must acquire leases for both pinned files");
        observed.observer_alive().unwrap();
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&copy).unwrap()
        );
        let pidfd = observed.observer_pidfd_for_test().unwrap();
        assert!(matches!(
            observed.seal(),
            Err(CollectorError::ObserverProofUnavailable)
        ));
        wait_pidfd(&pidfd);
        assert!(source.exists() && copy.exists());
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    fn observer_refuses_retained_writer_before_ready() {
        let (root, executable) = disposable_observer();
        let (manifest, receipt, trusted, lock, primary, recovery) =
            fixture("collector-observer-writer");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap();
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).unwrap();
        assert!(pending.observe_at(&root, &executable).is_err());
        assert!(source.exists() && copy.exists());
        drop(writer);
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    fn observer_stops_after_lease_break_and_cannot_seal() {
        use std::os::unix::fs::OpenOptionsExt;
        let (root, executable) = disposable_observer();
        let (manifest, receipt, trusted, lock, primary, recovery) =
            fixture("collector-observer-break");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).unwrap();
        let observed = pending.observe_at(&root, &executable).unwrap();
        let pidfd = observed.observer_pidfd_for_test().unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&source);
        assert!(matches!(writer, Err(ref error) if error.raw_os_error() == Some(libc::EAGAIN)));
        wait_pidfd(&pidfd);
        assert!(observed.observer_alive().is_err());
        assert!(matches!(
            observed.seal(),
            Err(CollectorError::ObserverProofUnavailable)
        ));
        assert!(source.exists() && copy.exists());
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    #[ignore = "requires an explicitly delegated disposable Linux cgroup and observer executable"]
    fn observer_death_cannot_authorize_seal() {
        let (root, executable) = disposable_observer();
        let (manifest, receipt, trusted, lock, primary, recovery) =
            fixture("collector-observer-death");
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).unwrap();
        let observed = pending.observe_at(&root, &executable).unwrap();
        let pidfd = observed.observer_pidfd_for_test().unwrap();
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
        wait_pidfd(&pidfd);
        assert!(observed.observer_alive().is_err());
        assert!(matches!(
            observed.seal(),
            Err(CollectorError::ObserverProofUnavailable)
        ));
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    fn collector_prepares_independent_copy_but_refuses_to_seal_without_observer() {
        let (_handoff, manifest, receipt, lock_path, primary_root) =
            crate::backup_capture::tests::captured_direct_fixture("collector-preflight");
        let trusted = RecoveryBinding {
            journal_id: receipt.recovery_journal_id().into(),
            session_id: receipt.recovery_session_id().into(),
            handoff_id: manifest.handoff_id().into(),
            plan_id: manifest.plan_id().into(),
            target_manifest_digest: manifest.target_manifest_digest().into(),
            manifest_id: manifest.manifest_id().into(),
            receipt_id: receipt.receipt_id().into(),
        };
        let recovery_root = primary_root.with_extension("recovery");
        std::fs::create_dir(&recovery_root).unwrap();
        std::fs::set_permissions(
            &recovery_root,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let source = primary_root.join(
            Path::new(&receipt.artifacts()[0].artifact_path)
                .file_name()
                .unwrap(),
        );
        let mut recovery_name = source.file_name().unwrap().to_os_string();
        recovery_name.push(".recovery");
        let recovery = recovery_root.join(recovery_name);
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary_root, &recovery_root)
            .expect("verified copies should be prepared");
        let primary_metadata = std::fs::metadata(&source).unwrap();
        let recovery_metadata = std::fs::metadata(&recovery).unwrap();
        assert_ne!(
            (primary_metadata.dev(), primary_metadata.ino()),
            (recovery_metadata.dev(), recovery_metadata.ino())
        );
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&recovery).unwrap()
        );
        assert!(matches!(
            pending.seal(),
            Err(CollectorError::ObserverProofUnavailable)
        ));
        assert!(source.exists() && recovery.exists());
        drop(receipt);
        let _ = std::fs::remove_dir_all(lock_path.parent().unwrap());
        let _ = std::fs::remove_dir_all(recovery_root);
        let _ = std::fs::remove_dir_all(primary_root);
    }

    #[test]
    fn retained_writer_can_change_original_but_never_authorizes_seal() {
        let (manifest, receipt, trusted, lock, primary, recovery) = fixture("collector-writer");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap();
        let pending = prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).unwrap();
        assert_eq!(writer.write_at(b"X", 0).unwrap(), 1);
        assert_ne!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&copy).unwrap()
        );
        assert!(matches!(
            pending.seal(),
            Err(CollectorError::ObserverProofUnavailable)
        ));
        drop(writer);
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    fn substituted_primary_symlink_is_rejected_and_preserved() {
        let (manifest, receipt, trusted, lock, primary, recovery) = fixture("collector-symlink");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let saved = primary.join("saved-original");
        std::fs::rename(&source, &saved).unwrap();
        std::os::unix::fs::symlink(&saved, &source).unwrap();
        assert!(prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).is_err());
        assert!(saved.exists());
        assert!(!copy.exists());
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    fn existing_recovery_evidence_is_never_overwritten() {
        let (manifest, receipt, trusted, lock, primary, recovery) = fixture("collector-existing");
        let (_, copy) = paths(&receipt, &primary, &recovery);
        std::fs::write(&copy, b"preserve existing evidence").unwrap();
        assert!(prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).is_err());
        assert_eq!(std::fs::read(&copy).unwrap(), b"preserve existing evidence");
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    fn interrupted_after_copy_preserves_recovery_evidence() {
        let (manifest, receipt, trusted, lock, primary, recovery) = fixture("collector-failure");
        let (source, copy) = paths(&receipt, &primary, &recovery);
        let result = prepare_with_hook(&manifest, &receipt, &trusted, &primary, &recovery, || {
            Err(CollectorError::Changed)
        });
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(&source).unwrap(),
            std::fs::read(&copy).unwrap()
        );
        assert!(prepare_at(&manifest, &receipt, &trusted, &primary, &recovery).is_err());
        drop(receipt);
        cleanup(&lock, &primary, &recovery);
    }

    #[test]
    fn crash_after_copy_preserves_recovery_evidence() {
        use std::io::Write;
        const CHILD: &str = "LSM_RECOVERY_COLLECTOR_CRASH_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let (manifest, receipt, trusted, lock, primary, recovery) = fixture("collector-crash");
            let (source, copy) = paths(&receipt, &primary, &recovery);
            println!(
                "LSM_PATHS={}\t{}\t{}\t{}\t{}",
                lock.display(),
                primary.display(),
                recovery.display(),
                source.display(),
                copy.display()
            );
            std::io::stdout().flush().unwrap();
            let _ = prepare_with_hook(
                &manifest,
                &receipt,
                &trusted,
                &primary,
                &recovery,
                || unsafe { libc::_exit(86) },
            );
            std::process::exit(87);
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("backup_recovery_collector::tests::crash_after_copy_preserves_recovery_evidence")
            .arg("--nocapture")
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(86),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout
            .lines()
            .find_map(|line| line.split_once("LSM_PATHS=").map(|(_, paths)| paths))
            .unwrap();
        let items = line
            .split('\t')
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        assert_eq!(items.len(), 5);
        assert_eq!(
            std::fs::read(&items[3]).unwrap(),
            std::fs::read(&items[4]).unwrap()
        );
        cleanup(&items[0], &items[1], &items[2]);
    }
}
