mod approval;
mod backup_capture;
mod backup_manifest;
mod execution_intent;
mod journal_store;
mod locked_session;
mod native_operation;
mod precondition_evidence;
mod preconditions;

pub use approval::{approve_exact_plan, ExactPlanApproval, ExactPlanApprovalError};
pub use backup_capture::{
    capture_metadata_backups, revalidate_metadata_backup_receipt, BackupArtifactReceipt,
    BackupCaptureError, BackupReceiptRevalidation, MetadataBackupReceipt,
};
pub use backup_manifest::{
    build_metadata_backup_manifest, BackupCommandSpec, BackupExpectedIdentity, BackupManifestError,
    MetadataBackupKind, MetadataBackupManifest, MetadataBackupRequirement, BACKUP_DIRECTORY,
};
pub use execution_intent::{
    freeze_execution_intent, ExecutionIntentError, ExecutionIntentManifestStatus,
    FrozenExecutionIntentManifest, FrozenIntentAction, FrozenIntentRole, FrozenIntentStep,
    VerificationBarrierSpec,
};
pub use journal_store::{DurableJournalStore, JournalStoreError};
pub use locked_session::{
    LockedExecutionSession, LockedRevalidation, LockedRevalidationStatus, LockedSessionError,
};
pub use native_operation::{
    build_native_operation_spec, classify_frozen_intent_action, compile_native_step,
    NativeCompiledStep, NativeOperationKind, NativeOperationSpec, NATIVE_OPERATION_ALLOWLIST,
};
pub use precondition_evidence::{
    build_pre_mutation_evidence, PreMutationEvidenceBundle, PreMutationEvidenceError,
    PreMutationEvidenceStatus,
};
pub use preconditions::{
    verify_preconditions, PreconditionsVerification, PreconditionsVerificationError,
};

use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use lsm_planner::HOST_STORAGE_LOCK_PATH;
use thiserror::Error;

/// M1B1 deliberately exposes no storage mutation API.
pub const MUTATION_ENABLED: bool = false;

#[derive(Debug)]
pub struct HostStorageLock {
    file: File,
    path: PathBuf,
}

#[derive(Debug, Error)]
pub enum HostLockError {
    #[error("host storage lock is already held")]
    Busy,
    #[error("lock parent path is unsafe: {0}")]
    UnsafeParent(PathBuf),
    #[error("lock path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("could not prepare host storage lock at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

impl HostStorageLock {
    pub fn try_acquire_default() -> Result<Self, HostLockError> {
        Self::try_acquire_path(Path::new(HOST_STORAGE_LOCK_PATH))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn try_acquire_path(path: &Path) -> Result<Self, HostLockError> {
        prepare_parent(path)?;

        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);

        let file = options.open(path).map_err(|source| HostLockError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let metadata = file.metadata().map_err(|source| HostLockError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.file_type().is_file() {
            return Err(HostLockError::NotRegularFile(path.to_path_buf()));
        }

        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = io::Error::last_os_error();
            if matches!(
                source.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            ) {
                return Err(HostLockError::Busy);
            }
            return Err(HostLockError::Io {
                path: path.to_path_buf(),
                source,
            });
        }

        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }
}

impl Drop for HostStorageLock {
    fn drop(&mut self) {
        // Closing the file descriptor also releases flock. Explicit unlock makes the
        // lifetime boundary obvious and is best-effort during Drop.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn prepare_parent(path: &Path) -> Result<(), HostLockError> {
    let parent = path
        .parent()
        .ok_or_else(|| HostLockError::UnsafeParent(path.to_path_buf()))?;

    if parent.exists() {
        let metadata = fs::symlink_metadata(parent).map_err(|source| HostLockError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HostLockError::UnsafeParent(parent.to_path_buf()));
        }
        return Ok(());
    }

    fs::create_dir_all(parent).map_err(|source| HostLockError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let metadata = fs::symlink_metadata(parent).map_err(|source| HostLockError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HostLockError::UnsafeParent(parent.to_path_buf()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_path(name: &str) -> PathBuf {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "linux-storage-manager-lock-test-{}-{unique}",
                std::process::id()
            ))
            .join(name)
    }

    #[test]
    fn second_lock_on_same_path_fails_busy() {
        let path = test_path("storage.lock");
        let first = HostStorageLock::try_acquire_path(&path).unwrap();

        let second = HostStorageLock::try_acquire_path(&path);

        assert!(matches!(second, Err(HostLockError::Busy)));
        assert_eq!(first.path(), path);
        drop(first);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn dropping_lock_allows_reacquisition() {
        let path = test_path("storage.lock");
        {
            let lock = HostStorageLock::try_acquire_path(&path).unwrap();
            assert_eq!(lock.path(), path);
        }

        let lock = HostStorageLock::try_acquire_path(&path).unwrap();
        assert_eq!(lock.path(), path);
        drop(lock);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn final_symlink_is_rejected() {
        let path = test_path("storage.lock");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let target = parent.join("real.lock");
        File::create(&target).unwrap();
        symlink(&target, &path).unwrap();

        let result = HostStorageLock::try_acquire_path(&path);

        assert!(matches!(
            result,
            Err(HostLockError::Io {
                source,
                ..
            }) if matches!(source.raw_os_error(), Some(code) if code == libc::ELOOP)
        ));
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn symlink_parent_is_rejected() {
        let root = test_path("root");
        let real_parent = root.join("real");
        let symlink_parent = root.join("link");
        fs::create_dir_all(&real_parent).unwrap();
        symlink(&real_parent, &symlink_parent).unwrap();
        let path = symlink_parent.join("storage.lock");

        let result = HostStorageLock::try_acquire_path(&path);

        assert!(matches!(result, Err(HostLockError::UnsafeParent(p)) if p == symlink_parent));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_api_remains_disabled() {
        assert!(!std::hint::black_box(MUTATION_ENABLED));
        assert_eq!(
            HOST_STORAGE_LOCK_PATH,
            "/run/lock/linux-storage-manager/storage.lock"
        );
    }
}
