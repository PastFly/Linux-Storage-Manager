//! Experimental record publication; this does not authorize approval or mutation.
//!
//! The record digest identifies bytes but does not authenticate them against
//! arbitrary root. Namespace checks are point-in-time; no claim is made about
//! transient privileged mount/rename changes or disk failure independence.
#![allow(dead_code)]

use crate::backup_recovery_record::{decode_v3_with_trusted_context, BackupRecoveryRecord};
use crate::journal_fd::JournalDir;
use crate::sealed_recovery::{
    bounded_names, live_metadata, require_directory, require_procfs, same_file_version, same_inode,
    SealError, SealedRecovery,
};
use crate::LockedExecutionSession;
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicationError {
    #[error("sealed recovery validation failed: {0}")]
    Seal(#[from] SealError),
    #[error("recovery record I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("recovery record directory failed: {0}")]
    Directory(#[from] crate::JournalStoreError),
    #[error("recovery record or its directory changed")]
    Changed,
}

struct SelfWatch {
    file: File,
}
impl SelfWatch {
    fn new(directory: &JournalDir) -> Result<Self, PublicationError> {
        require_procfs(&[directory.file()])?;
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let path = CString::new(format!("/proc/self/fd/{}", directory.file().as_raw_fd()))
            .map_err(|_| PublicationError::Changed)?;
        let mask = libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_UNMOUNT;
        if unsafe { libc::inotify_add_watch(file.as_raw_fd(), path.as_ptr(), mask) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { file })
    }
    fn require_unchanged(&mut self) -> Result<(), PublicationError> {
        let mut buffer = [0_u8; 4096];
        for _ in 0..64 {
            match self.file.read(&mut buffer) {
                Ok(_) => return Err(PublicationError::Changed),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        Err(PublicationError::Changed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicationStage {
    Created,
    WrittenAndSynced,
    SealedAndSynced,
    Renamed,
    DirectorySynced,
}

/// The value holds the sealed copies, published directory and record FD; it is
/// not a journal binding or a guarantee of continuous namespace protection.
pub(crate) struct PublishedRecovery {
    _sealed: SealedRecovery,
    _directory: JournalDir,
    _directory_input: File,
    _record: File,
    _watch: SelfWatch,
    record_path: PathBuf,
    measurement: [u8; 32],
}

fn open_file(
    directory: &JournalDir,
    name: &OsStr,
    flags: libc::c_int,
) -> Result<File, PublicationError> {
    let name = CString::new(name.as_bytes()).map_err(|_| PublicationError::Changed)?;
    let fd = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn sync_directory_chain(path: &Path) -> Result<(), PublicationError> {
    // Sync the leaf before each parent. Missing/untrusted/unsyncable ancestors
    // fail closed; this is not a power-loss simulation.
    for ancestor in path.ancestors() {
        let directory = JournalDir::open(ancestor)?;
        directory.verify_namespace()?;
        directory.sync()?;
    }
    Ok(())
}

fn validate_record(
    file: &File,
    directory: &JournalDir,
    name: &OsStr,
    record: &BackupRecoveryRecord,
    bytes: &[u8],
    measurement: [u8; 32],
) -> Result<(), PublicationError> {
    let initial = file.metadata()?;
    if !crate::journal_store::trusted_journal_file(&initial)
        || initial.len() as usize != bytes.len()
        || bytes.len() > MAX_RECORD_BYTES
    {
        return Err(PublicationError::Changed);
    }
    let current = live_metadata(directory, name)?;
    if !same_file_version(&initial, &current) {
        return Err(PublicationError::Changed);
    }
    use std::os::unix::fs::FileExt;
    let mut contents = vec![0_u8; bytes.len()];
    let mut offset = 0;
    while offset < contents.len() {
        let read = file.read_at(&mut contents[offset..], offset as u64)?;
        if read == 0 {
            return Err(PublicationError::Changed);
        }
        offset += read;
    }
    if contents != bytes
        || decode_v3_with_trusted_context(&contents, record.record_id(), record.binding())
            .map_err(|_| PublicationError::Changed)?
            != *record
        || crate::backup_verity::measure(file)? != measurement
        || !same_file_version(&initial, &file.metadata()?)
        || !same_file_version(&initial, &live_metadata(directory, name)?)
    {
        return Err(PublicationError::Changed);
    }
    Ok(())
}

impl PublishedRecovery {
    pub(crate) fn publish(
        session: &LockedExecutionSession<'_>,
        sealed: SealedRecovery,
        record_directory: File,
    ) -> Result<Self, PublicationError> {
        Self::publish_inner(session, sealed, record_directory, |_| Ok(()))
    }

    fn publish_inner(
        session: &LockedExecutionSession<'_>,
        mut sealed: SealedRecovery,
        record_directory: File,
        mut hook: impl FnMut(PublicationStage) -> io::Result<()>,
    ) -> Result<Self, PublicationError> {
        sealed.revalidate(session)?;
        let record = sealed.record().clone();
        let binding = record.binding();
        let primary_root = Path::new(crate::BACKUP_DIRECTORY)
            .join(&binding.handoff_id)
            .join(&binding.journal_id);
        let mut name = primary_root
            .file_name()
            .ok_or(PublicationError::Changed)?
            .to_os_string();
        name.push(".record");
        let root = primary_root.with_file_name(name);
        let directory = JournalDir::open(&root)?;
        directory.verify_namespace()?;
        require_directory(&record_directory, &directory)?;
        let metadata = directory.file().metadata()?;
        if sealed.contains_directory(&metadata)? || !bounded_names(&directory)?.is_empty() {
            return Err(PublicationError::Changed);
        }
        let mut watch = SelfWatch::new(&directory)?;
        directory.verify_namespace()?;
        watch.require_unchanged()?;
        sync_directory_chain(&root)?;
        let bytes = record.encode().map_err(|_| PublicationError::Changed)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(PublicationError::Changed);
        }
        let staging = format!(".{}.pending", record.record_id());
        let final_name = format!("{}.json", record.record_id());
        let mut writer = open_file(
            &directory,
            OsStr::new(&staging),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        hook(PublicationStage::Created)?;
        writer.write_all(&bytes)?;
        writer.sync_all()?;
        hook(PublicationStage::WrittenAndSynced)?;
        let staged = open_file(
            &directory,
            OsStr::new(&staging),
            libc::O_RDONLY | libc::O_NONBLOCK,
        )?;
        if !crate::journal_store::trusted_journal_file(&writer.metadata()?)
            || !same_inode(&writer.metadata()?, &staged.metadata()?)
        {
            return Err(PublicationError::Changed);
        }
        // Observe close errors; never retry close after EINTR because the fd may
        // already have been closed and reused by another thread.
        let raw = writer.into_raw_fd();
        if unsafe { libc::close(raw) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        crate::backup_verity::enable(&staged)?;
        staged.sync_all()?;
        let measurement = crate::backup_verity::measure(&staged)?;
        validate_record(
            &staged,
            &directory,
            OsStr::new(&staging),
            &record,
            &bytes,
            measurement,
        )?;
        directory.sync()?;
        hook(PublicationStage::SealedAndSynced)?;
        sealed.revalidate(session)?;
        directory.verify_namespace()?;
        watch.require_unchanged()?;
        if bounded_names(&directory)? != [OsStr::new(&staging)] {
            return Err(PublicationError::Changed);
        }
        directory.publish_new(OsStr::new(&staging), OsStr::new(&final_name))?;
        hook(PublicationStage::Renamed)?;
        directory.sync()?;
        sync_directory_chain(&root)?;
        hook(PublicationStage::DirectorySynced)?;
        validate_record(
            &staged,
            &directory,
            OsStr::new(&final_name),
            &record,
            &bytes,
            measurement,
        )?;
        if bounded_names(&directory)? != [OsStr::new(&final_name)] {
            return Err(PublicationError::Changed);
        }
        sealed.revalidate(session)?;
        directory.verify_namespace()?;
        require_procfs(&[directory.file()])?;
        watch.require_unchanged()?;
        Ok(Self {
            _sealed: sealed,
            _directory: directory,
            _directory_input: record_directory,
            _record: staged,
            _watch: watch,
            record_path: root.join(final_name),
            measurement,
        })
    }
}

#[cfg(test)]
#[path = "sealed_recovery_store_tests.rs"]
mod tests;
