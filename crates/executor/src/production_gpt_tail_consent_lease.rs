use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    verify_default_production_gpt_tail_create_consent, ProductionGptTailCreateActivationIntent,
    ProductionGptTailCreateConsentError, ProductionGptTailCreateConsentFileIdentity,
    ProductionGptTailCreateConsentReceipt, PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
};

const CONSENT_READ_CHUNK: usize = 4096;

#[derive(Debug)]
pub struct PinnedProductionGptTailCreateConsent {
    receipt: ProductionGptTailCreateConsentReceipt,
    file: File,
}

impl PinnedProductionGptTailCreateConsent {
    pub fn receipt(&self) -> &ProductionGptTailCreateConsentReceipt {
        &self.receipt
    }
}

#[derive(Debug, Error)]
pub enum ProductionGptTailCreateConsentLeaseError {
    #[error("production GPT-tail create consent verification failed: {0}")]
    Consent(#[from] ProductionGptTailCreateConsentError),
    #[error("pinned GPT-tail consent file no longer matches the verified identity")]
    PinnedFileMismatch,
    #[error("current GPT-tail consent path no longer resolves to the pinned verified consent")]
    CurrentPathMismatch,
    #[error("pinned GPT-tail consent I/O failed: {0}")]
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
            .ok_or_else(|| std::io::Error::other("GPT-tail consent file offset overflow"))?;
    }

    if offset != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "GPT-tail consent file size changed while hashing",
        ));
    }

    let mut probe = [0_u8; 1];
    if file.read_at(&mut probe, expected_size)? != 0 {
        return Err(std::io::Error::other(
            "GPT-tail consent file grew while hashing",
        ));
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn open_file_matches_identity(
    file: &File,
    expected: &ProductionGptTailCreateConsentFileIdentity,
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
    receipt: ProductionGptTailCreateConsentReceipt,
) -> Result<PinnedProductionGptTailCreateConsent, ProductionGptTailCreateConsentLeaseError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH))?;

    if !open_file_matches_identity(&file, &receipt.consent_file)? {
        return Err(ProductionGptTailCreateConsentLeaseError::PinnedFileMismatch);
    }

    Ok(PinnedProductionGptTailCreateConsent { receipt, file })
}

pub fn pin_default_production_gpt_tail_create_consent(
    activation: &ProductionGptTailCreateActivationIntent,
) -> Result<PinnedProductionGptTailCreateConsent, ProductionGptTailCreateConsentLeaseError> {
    let receipt = verify_default_production_gpt_tail_create_consent(activation)?;
    open_pinned_default_consent(receipt)
}

fn validate_current_receipt_against_lease(
    current: ProductionGptTailCreateConsentReceipt,
    lease: &PinnedProductionGptTailCreateConsent,
) -> Result<ProductionGptTailCreateConsentReceipt, ProductionGptTailCreateConsentLeaseError> {
    if current.receipt_id != lease.receipt.receipt_id
        || current.consent_file != lease.receipt.consent_file
    {
        return Err(ProductionGptTailCreateConsentLeaseError::CurrentPathMismatch);
    }
    if !open_file_matches_identity(&lease.file, &lease.receipt.consent_file)? {
        return Err(ProductionGptTailCreateConsentLeaseError::PinnedFileMismatch);
    }
    Ok(current)
}

pub fn revalidate_pinned_production_gpt_tail_create_consent(
    activation: &ProductionGptTailCreateActivationIntent,
    lease: &PinnedProductionGptTailCreateConsent,
) -> Result<ProductionGptTailCreateConsentReceipt, ProductionGptTailCreateConsentLeaseError> {
    let current = verify_default_production_gpt_tail_create_consent(activation)?;
    validate_current_receipt_against_lease(current, lease)
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
            "lsm-gpt-tail-consent-lease-{}-{stamp}-{name}",
            std::process::id()
        ));
        fs::write(&path, bytes).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&path, permissions).unwrap();
        let file = File::open(&path).unwrap();
        (path, file)
    }

    fn identity(file: &File, bytes: &[u8]) -> ProductionGptTailCreateConsentFileIdentity {
        let metadata = file.metadata().unwrap();
        ProductionGptTailCreateConsentFileIdentity {
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
    fn opened_gpt_tail_consent_identity_and_content_must_match() {
        let bytes = b"exact-gpt-tail-consent";
        let (path, file) = temp_file("exact", bytes);
        let expected = identity(&file, bytes);

        assert!(open_file_matches_identity(&file, &expected).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn in_place_gpt_tail_consent_change_invalidates_pinned_file() {
        let bytes = b"exact-gpt-tail-consent";
        let (path, file) = temp_file("changed", bytes);
        let expected = identity(&file, bytes);
        fs::write(&path, b"other-gpt-tail-consent").unwrap();

        assert!(!open_file_matches_identity(&file, &expected).unwrap());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn pathname_replacement_invalidates_pinned_gpt_tail_consent() {
        let bytes = b"exact-gpt-tail-consent";
        let (path, file) = temp_file("replace", bytes);
        let expected = identity(&file, bytes);
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, bytes).unwrap();
        let mut permissions = fs::metadata(&replacement).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&replacement, permissions).unwrap();
        fs::rename(&replacement, &path).unwrap();

        assert!(!open_file_matches_identity(&file, &expected).unwrap());
        assert_ne!(fs::metadata(&path).unwrap().ino(), expected.inode);
        fs::remove_file(path).unwrap();
    }
}
