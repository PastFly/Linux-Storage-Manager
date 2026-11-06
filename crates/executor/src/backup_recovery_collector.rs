//! Experimental recovery-copy preparation. This is not a recovery authorization.
use crate::backup_recovery_record::{BackupRecoveryRecord, RecoveryBinding};
use crate::{MetadataBackupManifest, MetadataBackupReceipt};
use std::path::Path;

#[derive(Debug)]
pub(crate) enum CollectorError {
    ObserverProofUnavailable,
    InvalidEvidence,
}

pub(crate) struct PendingCopies;

impl PendingCopies {
    pub(crate) fn seal(self) -> Result<BackupRecoveryRecord, CollectorError> {
        Err(CollectorError::ObserverProofUnavailable)
    }
}

// Red-phase stub. The completed component must preserve pending evidence on error.
pub(crate) fn prepare_at(
    _manifest: &MetadataBackupManifest,
    _receipt: &MetadataBackupReceipt,
    _trusted: &RecoveryBinding,
    _primary_root: &Path,
    _recovery_root: &Path,
) -> Result<PendingCopies, CollectorError> {
    Err(CollectorError::InvalidEvidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

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
}
