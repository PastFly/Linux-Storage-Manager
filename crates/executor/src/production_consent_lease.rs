use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    verify_default_production_mutation_consent, ProductionMutationActivationIntent,
    ProductionMutationConsentError, ProductionMutationConsentFileIdentity,
    ProductionMutationConsentReceipt, PRODUCTION_MUTATION_CONSENT_PATH,
};

const CONSENT_READ_CHUNK: usize = 4096;

#[derive(Debug)]
pub struct PinnedProductionMutationConsent {
    receipt: ProductionMutationConsentReceipt,
    file: File,
}

impl PinnedProductionMutationConsent {
    pub fn receipt(&self) -> &ProductionMutationConsentReceipt {
        &self.receipt
    }
}

#[derive(Debug, Error)]
pub enum ProductionMutationConsentLeaseError {
    #[error("production runtime consent verification failed: {0}")]
    Consent(#[from] ProductionMutationConsentError),
    #[error("pinned consent file no longer matches the verified file identity")]
    PinnedFileMismatch,
    #[error("current consent path no longer resolves to the pinned verified consent")]
    CurrentPathMismatch,
    #[error("pinned consent I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

fn sha256_file(file: &File, expected_size: u64) -> Result<String, std::io::Error> {
    let mut hasher = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; CONSENT_READ_CHUNK];

    while offset < expected_size {
        let remaining = (expected_size - offset) as usize;
        let want = remaining.min(buffer.len());
        let read = file.read_at(&mut buffer[..want], offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("consent file offset overflow"))?;
    }

    if offset != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "consent file size changed while hashing",
        ));
    }

    let mut probe = [0_u8; 1];
    if file.read_at(&mut probe, expected_size)? != 0 {
        return Err(std::io::Error::other(
            "consent file grew while hashing",
        ));
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn open_file_matches_identity(
    file: &File,
    expected: &ProductionMutationConsentFileIdentity,
) -> Result<bool, std::io::Error> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.dev() != expected.device_id
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.uid
        || metadata.mode() != expected.mode
        || metadata.nlink() != expected.link_count
        || metadata.len() != expected.size_bytes
    {
        return Ok(false);
    }

    Ok(sha256_file(file, expected.size_bytes)? == expected.sha256)
}

fn open_pinned_default_consent(
    receipt: ProductionMutationConsentReceipt,
) -> Result<PinnedProductionMutationConsent, ProductionMutationConsentLeaseError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(PRODUCTION_MUTATION_CONSENT_PATH))?;

    if !open_file_matches_identity(&file, &receipt.consent_file)? {
        return Err(ProductionMutationConsentLeaseError::PinnedFileMismatch);
    }

    Ok(PinnedProductionMutationConsent { receipt, file })
}

/// Verify the fixed root-owned production consent and retain the exact opened
/// file object across the final production authorization path.
///
/// The initial receipt is still produced by M1B36. M1B39 then reopens the
/// fixed path with O_NOFOLLOW, proves that the opened object is exactly the
/// receipt's device/inode/metadata/content identity, and keeps that descriptor
/// alive until the production execution attempt finishes.
pub fn pin_default_production_mutation_consent(
    intent: &ProductionMutationActivationIntent,
) -> Result<PinnedProductionMutationConsent, ProductionMutationConsentLeaseError> {
    let receipt = verify_default_production_mutation_consent(intent)?;
    open_pinned_default_consent(receipt)
}

/// Revalidate both the current consent pathname and the still-open pinned file.
///
/// This catches pathname replacement/removal as well as in-place metadata or
/// content changes after the lease was created. The caller should invoke this
/// as the final consent check immediately before descriptor execution.
pub fn revalidate_pinned_production_mutation_consent(
    intent: &ProductionMutationActivationIntent,
    lease: &PinnedProductionMutationConsent,
) -> Result<ProductionMutationConsentReceipt, ProductionMutationConsentLeaseError> {
    let current = verify_default_production_mutation_consent(intent)?;
    if current.receipt_id != lease.receipt.receipt_id
        || current.consent_file != lease.receipt.consent_file
    {
        return Err(ProductionMutationConsentLeaseError::CurrentPathMismatch);
    }
    if !open_file_matches_identity(&lease.file, &lease.receipt.consent_file)? {
        return Err(ProductionMutationConsentLeaseError::PinnedFileMismatch);
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, File) {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "lsm-consent-lease-{}-{stamp}-{name}",
            std::process::id()
        ));
        fs::write(&path, bytes).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions).unwrap();
        let file = File::open(&path).unwrap();
        (path, file)
    }

    fn identity(file: &File, bytes: &[u8]) -> ProductionMutationConsentFileIdentity {
        let metadata = file.metadata().unwrap();
        ProductionMutationConsentFileIdentity {
            device_id: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            link_count: metadata.nlink(),
            size_bytes: metadata.len(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    #[test]
    fn opened_file_identity_and_content_must_match_exactly() {
        let bytes = b"exact-consent";
        let (path, file) = temp_file("exact", bytes);
        let expected = identity(&file, bytes);

        assert!(open_file_matches_identity(&file, &expected).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn in_place_content_change_invalidates_pinned_file() {
        let bytes = b"exact-consent";
        let (path, file) = temp_file("changed", bytes);
        let expected = identity(&file, bytes);
        fs::write(&path, b"other-consent").unwrap();

        assert!(!open_file_matches_identity(&file, &expected).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pathname_replacement_does_not_change_pinned_inode() {
        let bytes = b"exact-consent";
        let (path, file) = temp_file("replace", bytes);
        let expected = identity(&file, bytes);
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, bytes).unwrap();
        let mut permissions = fs::metadata(&replacement).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&replacement, permissions).unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert!(open_file_matches_identity(&file, &expected).unwrap());
        assert_ne!(fs::metadata(&path).unwrap().ino(), expected.inode);
        fs::remove_file(path).unwrap();
    }
}
