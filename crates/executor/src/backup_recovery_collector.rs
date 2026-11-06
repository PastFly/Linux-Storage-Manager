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
    primary_dir.verify_namespace()?;
    recovery_dir.verify_namespace()?;
    let mut primary_watch = primary_dir.watch_namespace()?;
    if !recovery_dir.names()?.is_empty() {
        return Err(CollectorError::Changed);
    }
    let mut pairs = Vec::with_capacity(receipt.artifacts().len());
    let mut expected_names = Vec::<OsString>::new();
    for artifact in receipt.artifacts() {
        let name = Path::new(&artifact.artifact_path)
            .file_name()
            .ok_or(CollectorError::InvalidEvidence)?;
        let (primary, original, bytes) = read_checked(
            &primary_dir,
            name,
            artifact.size_bytes,
            &artifact.sha256,
            Some((artifact.device_id, artifact.inode)),
        )?;
        primary.sync_all()?;
        primary_dir.verify_namespace()?;
        primary_watch.require_unchanged()?;
        let mut recovery_name = name.to_os_string();
        recovery_name.push(".recovery");
        // O_EXCL is implemented by the isolated journal writer: never reuse,
        // overwrite, or delete an existing/partially written recovery file.
        let created = recovery_dir.write_staged_file(&recovery_name, &bytes)?;
        let created_metadata = created.metadata()?;
        if !trusted_journal_file(&created_metadata) {
            return Err(CollectorError::InvalidEvidence);
        }
        recovery_dir.sync()?;
        recovery_dir.verify_namespace()?;
        let (recovery, recovered, _) = read_checked(
            &recovery_dir,
            &recovery_name,
            artifact.size_bytes,
            &artifact.sha256,
            None,
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
    let mut recovery_watch = recovery_dir.watch_namespace()?;
    for (artifact, pair) in receipt.artifacts().iter().zip(&pairs) {
        let name = Path::new(&artifact.artifact_path)
            .file_name()
            .ok_or(CollectorError::InvalidEvidence)?;
        let mut recovery_name = name.to_os_string();
        recovery_name.push(".recovery");
        let (_, primary_metadata, _) = read_checked(
            &primary_dir,
            name,
            artifact.size_bytes,
            &artifact.sha256,
            Some((artifact.device_id, artifact.inode)),
        )?;
        let (_, recovery_metadata, _) = read_checked(
            &recovery_dir,
            &recovery_name,
            artifact.size_bytes,
            &artifact.sha256,
            None,
        )?;
        if !same_file(&primary_metadata, &pair._primary.metadata()?)
            || !same_file(&recovery_metadata, &pair._recovery.metadata()?)
        {
            return Err(CollectorError::Changed);
        }
    }
    primary_dir.sync()?;
    recovery_dir.sync()?;
    primary_dir.verify_namespace()?;
    recovery_dir.verify_namespace()?;
    primary_watch.require_unchanged()?;
    recovery_watch.require_unchanged()?;
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
