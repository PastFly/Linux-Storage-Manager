//! Opt-in experimental sealing of already captured backup copies.
//!
//! This pins and measures bytes, but does not authorize mutation or approval.
//! It does not establish capture provenance, durable record publication, a
//! separate failure domain, or continuous namespace protection. In particular,
//! another privileged process can remove or replace paths after validation.
//! A failed partial seal is not retryable on the same inode: preserve the
//! files and durably abort the prewrite attempt before starting a new attempt.
//! This module does not yet perform that durable abort itself.
#![allow(dead_code)]

use crate::backup_recovery_record::{
    experimental_bind_verity, from_experimental_verified_metadata, validate_capture_binding,
    BackupRecoveryRecord, ExperimentalCopyPair, ExperimentalCopyView, RecoveryBinding,
};
use crate::journal_fd::{DirectoryWatch, JournalDir};
use crate::{LockedExecutionSession, MetadataBackupManifest, MetadataBackupReceipt};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACTS: usize = 16;

/// Caller-supplied handles are only candidates; the constructor checks each
/// against the exact, independently opened attempt path and receipt.
pub(crate) struct PinnedCopies {
    pub(crate) primary_dir: File,
    pub(crate) recovery_dir: File,
    pub(crate) pairs: Vec<(File, File)>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError {
    #[error("sealed recovery inputs or identity do not match the locked attempt")]
    InvalidEvidence,
    #[error("backup path or inode changed during sealing")]
    Changed,
    #[error("backup I/O or fs-verity failed: {0}")]
    Io(#[from] io::Error),
    #[error("backup directory check failed: {0}")]
    Directory(#[from] crate::JournalStoreError),
    #[error("locked session is not current: {0}")]
    Session(#[from] crate::LockedSessionError),
}

/// This type is deliberately not a durable recovery or approval authority.
pub(crate) struct SealedRecovery {
    record: BackupRecoveryRecord,
    _copies: PinnedCopies,
    _primary_dir: JournalDir,
    _recovery_dir: JournalDir,
    _primary_watch: DirectoryWatch,
    _recovery_watch: DirectoryWatch,
}

pub(crate) fn same_inode(left: &Metadata, right: &Metadata) -> bool {
    (left.dev(), left.ino()) == (right.dev(), right.ino())
}

pub(crate) fn same_file_version(left: &Metadata, right: &Metadata) -> bool {
    same_inode(left, right)
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(crate) fn require_directory(candidate: &File, directory: &JournalDir) -> Result<(), SealError> {
    let flags = unsafe { libc::fcntl(candidate.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let candidate_meta = candidate.metadata()?;
    if flags & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY
        || !candidate_meta.is_dir()
        || !same_inode(&candidate_meta, &directory.file().metadata()?)
    {
        return Err(SealError::InvalidEvidence);
    }
    Ok(())
}

pub(crate) fn bounded_names(directory: &JournalDir) -> Result<Vec<OsString>, SealError> {
    let raw = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let fresh = unsafe { File::from_raw_fd(raw) };
    if !same_inode(&fresh.metadata()?, &directory.file().metadata()?) {
        return Err(SealError::Changed);
    }
    // Read from this fresh open-file description directly; never trust a
    // /proc mount for enumeration or share a directory offset with the caller.
    let mut names = Vec::with_capacity(MAX_ARTIFACTS);
    let mut buffer = [0_u8; 8192];
    let mut interrupted = 0_usize;
    let mut reads = 0_usize;
    loop {
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                fresh.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted && interrupted < 64 {
                interrupted += 1;
                continue;
            }
            return Err(error.into());
        }
        interrupted = 0;
        reads += 1;
        if reads > MAX_ARTIFACTS + 4 {
            return Err(SealError::Changed);
        }
        if count == 0 {
            break;
        }
        let length = usize::try_from(count).map_err(|_| SealError::Changed)?;
        if length > buffer.len() {
            return Err(SealError::Changed);
        }
        let mut offset = 0_usize;
        while offset < length {
            // linux_dirent64: ino u64, off i64, reclen u16, type u8, name.
            if length - offset < 20 {
                return Err(SealError::Changed);
            }
            let inode = u64::from_ne_bytes(buffer[offset..offset + 8].try_into().unwrap());
            let reclen = usize::from(u16::from_ne_bytes(
                buffer[offset + 16..offset + 18].try_into().unwrap(),
            ));
            let end = offset
                .checked_add(reclen)
                .filter(|end| *end <= length)
                .ok_or(SealError::Changed)?;
            if inode == 0 || reclen < 20 || reclen % 8 != 0 {
                return Err(SealError::Changed);
            }
            let raw_name = &buffer[offset + 19..end];
            let nul = raw_name
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(SealError::Changed)?;
            let name = &raw_name[..nul];
            if name.is_empty() || name.len() > 255 || name.contains(&b'/') {
                return Err(SealError::Changed);
            }
            if name != b"." && name != b".." {
                if names.len() == MAX_ARTIFACTS {
                    return Err(SealError::Changed);
                }
                names.push(OsString::from_vec(name.to_vec()));
            }
            offset = end;
        }
    }
    names.sort();
    Ok(names)
}

// JournalDir's inotify registration uses /proc/self/fd. Check that lookup is
// actually procfs and resolves our pinned directories before using it. A
// privileged actor changing mount namespaces remains outside the trust model.
pub(crate) fn require_procfs(targets: &[&File]) -> Result<(), SealError> {
    let proc_fd = File::open("/proc/self/fd")?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(proc_fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
    if stat.f_type as libc::c_long != PROC_SUPER_MAGIC {
        return Err(SealError::InvalidEvidence);
    }
    for target in targets {
        let name =
            CString::new(target.as_raw_fd().to_string()).map_err(|_| SealError::InvalidEvidence)?;
        let raw = unsafe {
            libc::openat(
                proc_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let reopened = unsafe { File::from_raw_fd(raw) };
        if !same_inode(&target.metadata()?, &reopened.metadata()?) {
            return Err(SealError::Changed);
        }
    }
    Ok(())
}

pub(crate) fn live_metadata(directory: &JournalDir, name: &OsStr) -> Result<Metadata, SealError> {
    let name = CString::new(name.as_bytes()).map_err(|_| SealError::InvalidEvidence)?;
    let raw = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(raw) }.metadata()?)
}

fn check_file(
    file: &File,
    directory: &JournalDir,
    name: &OsStr,
    expected_size: u64,
    expected_hash: &str,
) -> Result<Metadata, SealError> {
    let before = file.metadata()?;
    if !crate::journal_store::trusted_journal_file(&before)
        || expected_size == 0
        || expected_size > MAX_ARTIFACT_BYTES
        || before.len() != expected_size
    {
        return Err(SealError::InvalidEvidence);
    }
    let live = live_metadata(directory, name)?;
    if !same_file_version(&before, &live) {
        return Err(SealError::Changed);
    }
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 32 * 1024];
    while offset < expected_size {
        let limit = usize::try_from((expected_size - offset).min(buffer.len() as u64))
            .map_err(|_| SealError::InvalidEvidence)?;
        let count = file.read_at(&mut buffer[..limit], offset)?;
        if count == 0 {
            return Err(SealError::Changed);
        }
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    if format!("{:x}", hash.finalize()) != expected_hash {
        return Err(SealError::InvalidEvidence);
    }
    let held = file.metadata()?;
    let live = live_metadata(directory, name)?;
    if !same_file_version(&before, &held) || !same_file_version(&held, &live) {
        return Err(SealError::Changed);
    }
    Ok(held)
}

impl SealedRecovery {
    pub(crate) fn seal(
        session: &LockedExecutionSession<'_>,
        manifest: &MetadataBackupManifest,
        receipt: &MetadataBackupReceipt,
        copies: PinnedCopies,
    ) -> Result<Self, SealError> {
        Self::seal_inner(session, manifest, receipt, copies, || {})
    }

    fn seal_inner(
        session: &LockedExecutionSession<'_>,
        manifest: &MetadataBackupManifest,
        receipt: &MetadataBackupReceipt,
        copies: PinnedCopies,
        after_watch: impl FnOnce(),
    ) -> Result<Self, SealError> {
        if unsafe { libc::geteuid() } != 0
            || session.journal().schema_version != 2
            || session.journal().phase != lsm_planner::JournalPhase::IdentityRevalidated
        {
            return Err(SealError::InvalidEvidence);
        }
        session.require_current_durable_journal()?;
        let binding = RecoveryBinding {
            journal_id: session.journal().journal_id.clone(),
            session_id: session.session_id().to_owned(),
            handoff_id: session.handoff().handoff_id().to_owned(),
            plan_id: session.journal().plan_id.clone(),
            target_manifest_digest: session.journal().baseline_manifest_digest.clone(),
            manifest_id: manifest.manifest_id().to_owned(),
            receipt_id: receipt.receipt_id().to_owned(),
        };
        if binding.plan_id != session.handoff().plan().plan_id()
            || binding.target_manifest_digest != session.handoff().target_identity().manifest_digest
        {
            return Err(SealError::InvalidEvidence);
        }
        validate_capture_binding(manifest, receipt, &binding)
            .map_err(|_| SealError::InvalidEvidence)?;
        let primary_path = Path::new(crate::BACKUP_DIRECTORY)
            .join(&binding.handoff_id)
            .join(&binding.journal_id);
        if primary_path != Path::new(manifest.artifact_directory())
            || copies.pairs.len() != receipt.artifacts().len()
            || copies.pairs.is_empty()
        {
            return Err(SealError::InvalidEvidence);
        }
        let mut recovery_name = primary_path
            .file_name()
            .ok_or(SealError::InvalidEvidence)?
            .to_os_string();
        recovery_name.push(".recovery");
        let recovery_path = primary_path.with_file_name(recovery_name);
        let primary_dir = JournalDir::open(&primary_path)?;
        let recovery_dir = JournalDir::open(&recovery_path)?;
        require_procfs(&[primary_dir.file(), recovery_dir.file()])?;
        let mut primary_watch = primary_dir.watch_namespace()?;
        let mut recovery_watch = recovery_dir.watch_namespace()?;
        primary_dir.verify_namespace()?;
        recovery_dir.verify_namespace()?;
        require_directory(&copies.primary_dir, &primary_dir)?;
        require_directory(&copies.recovery_dir, &recovery_dir)?;
        if same_inode(
            &primary_dir.file().metadata()?,
            &recovery_dir.file().metadata()?,
        ) {
            return Err(SealError::InvalidEvidence);
        }
        let mut primary_names = Vec::<OsString>::new();
        let mut recovery_names = Vec::<OsString>::new();
        let mut inode_set = BTreeSet::new();
        for ((primary, recovery), artifact) in copies.pairs.iter().zip(receipt.artifacts()) {
            let name = Path::new(&artifact.artifact_path)
                .file_name()
                .ok_or(SealError::InvalidEvidence)?
                .to_os_string();
            let mut recovery_name = name.clone();
            recovery_name.push(".recovery");
            let pm = primary.metadata()?;
            let rm = recovery.metadata()?;
            if (pm.dev(), pm.ino()) != (artifact.device_id, artifact.inode)
                || !inode_set.insert((pm.dev(), pm.ino()))
                || !inode_set.insert((rm.dev(), rm.ino()))
            {
                return Err(SealError::InvalidEvidence);
            }
            check_file(
                primary,
                &primary_dir,
                &name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            check_file(
                recovery,
                &recovery_dir,
                &recovery_name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            primary_names.push(name);
            recovery_names.push(recovery_name);
        }
        let mut sorted_primary = primary_names.clone();
        let mut sorted_recovery = recovery_names.clone();
        sorted_primary.sort();
        sorted_recovery.sort();
        if bounded_names(&primary_dir)? != sorted_primary
            || bounded_names(&recovery_dir)? != sorted_recovery
        {
            return Err(SealError::Changed);
        }
        primary_watch.require_unchanged()?;
        recovery_watch.require_unchanged()?;
        after_watch();
        primary_dir.verify_namespace()?;
        recovery_dir.verify_namespace()?;
        primary_watch.require_unchanged()?;
        recovery_watch.require_unchanged()?;

        // A later error can leave an earlier inode sealed. Preserve all files;
        // never issue a recovery record for a partially completed operation.
        for (primary, recovery) in &copies.pairs {
            crate::backup_verity::enable(primary)?;
            crate::backup_verity::enable(recovery)?;
        }
        for (primary, recovery) in &copies.pairs {
            primary.sync_all()?;
            recovery.sync_all()?;
        }
        primary_dir.sync()?;
        recovery_dir.sync()?;
        let mut views = Vec::with_capacity(copies.pairs.len());
        let mut measurements = Vec::with_capacity(copies.pairs.len());
        for (((primary, recovery), artifact), (primary_name, recovery_name)) in copies
            .pairs
            .iter()
            .zip(receipt.artifacts())
            .zip(primary_names.iter().zip(&recovery_names))
        {
            // Match names by artifact, not lexicographic order.
            let expected_name = Path::new(&artifact.artifact_path)
                .file_name()
                .ok_or(SealError::InvalidEvidence)?;
            let mut expected_recovery = expected_name.to_os_string();
            expected_recovery.push(".recovery");
            if primary_name != expected_name || recovery_name != &expected_recovery {
                return Err(SealError::InvalidEvidence);
            }
            let pm = check_file(
                primary,
                &primary_dir,
                primary_name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            let rm = check_file(
                recovery,
                &recovery_dir,
                recovery_name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            if (pm.dev(), pm.ino()) != (artifact.device_id, artifact.inode) || same_inode(&pm, &rm)
            {
                return Err(SealError::Changed);
            }
            let path = recovery_path.join(recovery_name);
            let recovery_path = path.to_str().ok_or(SealError::InvalidEvidence)?.to_owned();
            views.push(ExperimentalCopyPair {
                ordinal: artifact.ordinal,
                primary: ExperimentalCopyView {
                    path: artifact.artifact_path.clone(),
                    size_bytes: artifact.size_bytes,
                    sha256: artifact.sha256.clone(),
                    device_id: pm.dev(),
                    inode: pm.ino(),
                },
                recovery: ExperimentalCopyView {
                    path: recovery_path,
                    size_bytes: artifact.size_bytes,
                    sha256: artifact.sha256.clone(),
                    device_id: rm.dev(),
                    inode: rm.ino(),
                },
            });
            measurements.push((
                crate::backup_verity::measure(primary)?,
                crate::backup_verity::measure(recovery)?,
            ));
        }
        primary_dir.verify_namespace()?;
        recovery_dir.verify_namespace()?;
        primary_watch.require_unchanged()?;
        recovery_watch.require_unchanged()?;
        let v2 = from_experimental_verified_metadata(manifest, receipt, &binding, &views)
            .map_err(|_| SealError::InvalidEvidence)?;
        let record =
            experimental_bind_verity(&v2, &measurements).map_err(|_| SealError::InvalidEvidence)?;
        session.require_current_durable_journal()?;
        primary_dir.verify_namespace()?;
        recovery_dir.verify_namespace()?;
        require_procfs(&[primary_dir.file(), recovery_dir.file()])?;
        if bounded_names(&primary_dir)? != sorted_primary
            || bounded_names(&recovery_dir)? != sorted_recovery
        {
            return Err(SealError::Changed);
        }
        primary_watch.require_unchanged()?;
        recovery_watch.require_unchanged()?;
        Ok(Self {
            record,
            _copies: copies,
            _primary_dir: primary_dir,
            _recovery_dir: recovery_dir,
            _primary_watch: primary_watch,
            _recovery_watch: recovery_watch,
        })
    }

    pub(crate) fn record(&self) -> &BackupRecoveryRecord {
        &self.record
    }

    /// Revalidates the live pins and all bytes. This is a point-in-time
    /// observation, not an atomic guarantee against privileged namespace edits.
    pub(crate) fn revalidate(
        &mut self,
        session: &LockedExecutionSession<'_>,
    ) -> Result<(), SealError> {
        session.require_current_durable_journal()?;
        let binding = self.record.binding();
        if self.record.schema_version() != 3
            || session.journal().schema_version != 2
            || session.journal().phase != lsm_planner::JournalPhase::IdentityRevalidated
            || binding.journal_id != session.journal().journal_id
            || binding.session_id != session.session_id()
            || binding.handoff_id != session.handoff().handoff_id()
            || binding.plan_id != session.journal().plan_id
            || binding.target_manifest_digest != session.journal().baseline_manifest_digest
            || self.record.artifacts().len() != self._copies.pairs.len()
        {
            return Err(SealError::InvalidEvidence);
        }
        self._primary_dir.verify_namespace()?;
        self._recovery_dir.verify_namespace()?;
        require_procfs(&[self._primary_dir.file(), self._recovery_dir.file()])?;
        self._primary_watch.require_unchanged()?;
        self._recovery_watch.require_unchanged()?;
        let primary_path = Path::new(crate::BACKUP_DIRECTORY)
            .join(&binding.handoff_id)
            .join(&binding.journal_id);
        let mut recovery_name = primary_path
            .file_name()
            .ok_or(SealError::InvalidEvidence)?
            .to_os_string();
        recovery_name.push(".recovery");
        let recovery_path = primary_path.with_file_name(recovery_name);
        let mut primary_names = Vec::with_capacity(self.record.artifacts().len());
        let mut recovery_names = Vec::with_capacity(self.record.artifacts().len());
        for ((primary, recovery), artifact) in
            self._copies.pairs.iter().zip(self.record.artifacts())
        {
            let primary_artifact = Path::new(&artifact.primary_path);
            let recovery_artifact = Path::new(&artifact.recovery_path);
            if primary_artifact.parent() != Some(primary_path.as_path())
                || recovery_artifact.parent() != Some(recovery_path.as_path())
            {
                return Err(SealError::InvalidEvidence);
            }
            let primary_name = primary_artifact
                .file_name()
                .ok_or(SealError::InvalidEvidence)?;
            let recovery_name = recovery_artifact
                .file_name()
                .ok_or(SealError::InvalidEvidence)?;
            let pm = check_file(
                primary,
                &self._primary_dir,
                primary_name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            let rm = check_file(
                recovery,
                &self._recovery_dir,
                recovery_name,
                artifact.size_bytes,
                &artifact.sha256,
            )?;
            if Some(pm.dev()) != artifact.capture_device_id
                || Some(pm.ino()) != artifact.capture_inode
                || same_inode(&pm, &rm)
            {
                return Err(SealError::Changed);
            }
            let expected = artifact.verity.as_ref().ok_or(SealError::InvalidEvidence)?;
            let format_digest = |digest: [u8; 32]| {
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            };
            if format_digest(crate::backup_verity::measure(primary)?) != expected.primary_sha256
                || format_digest(crate::backup_verity::measure(recovery)?)
                    != expected.recovery_sha256
            {
                return Err(SealError::Changed);
            }
            primary_names.push(primary_name.to_os_string());
            recovery_names.push(recovery_name.to_os_string());
        }
        primary_names.sort();
        recovery_names.sort();
        if bounded_names(&self._primary_dir)? != primary_names
            || bounded_names(&self._recovery_dir)? != recovery_names
        {
            return Err(SealError::Changed);
        }
        self._primary_dir.verify_namespace()?;
        self._recovery_dir.verify_namespace()?;
        self._primary_watch.require_unchanged()?;
        self._recovery_watch.require_unchanged()?;
        Ok(())
    }

    pub(crate) fn contains_directory(&self, metadata: &Metadata) -> Result<bool, SealError> {
        Ok(same_inode(metadata, &self._primary_dir.file().metadata()?)
            || same_inode(metadata, &self._recovery_dir.file().metadata()?))
    }
}

#[cfg(test)]
#[path = "sealed_recovery_tests.rs"]
pub(crate) mod tests;
