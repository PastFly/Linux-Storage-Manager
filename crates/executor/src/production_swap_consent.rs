use std::fs::{self, OpenOptions};
use std::io::{Read, Take};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProductionSwapReplacementActivationIntent;

pub const PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH: &str =
    "/etc/linux-storage-manager/production-swap-replacement-consent.json";
pub const PRODUCTION_SWAP_REPLACEMENT_CONSENT_PHRASE: &str =
    "I UNDERSTAND THIS WILL REPLACE ACTIVE SWAP";
pub const PRODUCTION_SWAP_REPLACEMENT_CONSENT_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-consent");
const MAX_CONSENT_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionSwapReplacementConsentDocument {
    pub schema_version: u32,
    pub activation_id: String,
    pub swap_replacement_intent_id: String,
    pub target: String,
    pub retiring_swap_device: String,
    pub swapfile_path: String,
    pub consent_phrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapReplacementConsentFileIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapReplacementConsentReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub swap_replacement_intent_id: String,
    pub target: String,
    pub retiring_swap_device: String,
    pub swapfile_path: String,
    pub consent_path: String,
    pub consent_file: ProductionSwapReplacementConsentFileIdentity,
    pub consent_verified: bool,
    pub execution_enabled: bool,
}

#[derive(Serialize)]
struct ConsentReceiptDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    swap_replacement_intent_id: &'a str,
    target: &'a str,
    retiring_swap_device: &'a str,
    swapfile_path: &'a str,
    consent_path: &'a str,
    consent_file: &'a ProductionSwapReplacementConsentFileIdentity,
    consent_verified: bool,
    execution_enabled: bool,
}

impl ProductionSwapReplacementConsentReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ConsentReceiptDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            target: &self.target,
            retiring_swap_device: &self.retiring_swap_device,
            swapfile_path: &self.swapfile_path,
            consent_path: &self.consent_path,
            consent_file: &self.consent_file,
            consent_verified: self.consent_verified,
            execution_enabled: self.execution_enabled,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapReplacementConsentError {
    #[error("production swap replacement consent feature is not compiled")]
    FeatureDisabled,
    #[error("swap replacement production activation integrity check failed")]
    ActivationInvalid,
    #[error("swap replacement activation is already execution-enabled")]
    ActivationAlreadyEnabled,
    #[error("consent parent directory is unsafe: {0}")]
    UnsafeParent(PathBuf),
    #[error("consent file is not a secure root-owned 0600 regular file")]
    UnsafeFile,
    #[error("consent file size is invalid")]
    InvalidFileSize,
    #[error("consent document is invalid JSON: {0}")]
    Decode(String),
    #[error("consent document contains a non-canonical or unknown shape")]
    NonCanonicalDocument,
    #[error("consent document does not match the exact activation")]
    BindingMismatch,
    #[error("consent phrase is not exact")]
    ConsentPhraseMismatch,
    #[error("consent I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("consent receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn io_error(path: &Path, source: std::io::Error) -> ProductionSwapReplacementConsentError {
    ProductionSwapReplacementConsentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_activation(
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<(), ProductionSwapReplacementConsentError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
    {
        return Err(ProductionSwapReplacementConsentError::ActivationInvalid);
    }
    if activation.execution_enabled {
        return Err(ProductionSwapReplacementConsentError::ActivationAlreadyEnabled);
    }
    Ok(())
}

fn validate_document(
    activation: &ProductionSwapReplacementActivationIntent,
    bytes: &[u8],
) -> Result<ProductionSwapReplacementConsentDocument, ProductionSwapReplacementConsentError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionSwapReplacementConsentError::InvalidFileSize);
    }

    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ProductionSwapReplacementConsentError::Decode(error.to_string()))?;
    let document: ProductionSwapReplacementConsentDocument = serde_json::from_value(raw.clone())
        .map_err(|error| ProductionSwapReplacementConsentError::Decode(error.to_string()))?;
    if serde_json::to_value(&document)? != raw {
        return Err(ProductionSwapReplacementConsentError::NonCanonicalDocument);
    }

    if document.schema_version != 1
        || document.activation_id != activation.activation_id
        || document.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || document.target != activation.target
        || document.retiring_swap_device != activation.retiring_swap_device
        || document.swapfile_path != activation.swapfile_path
    {
        return Err(ProductionSwapReplacementConsentError::BindingMismatch);
    }
    if document.consent_phrase != PRODUCTION_SWAP_REPLACEMENT_CONSENT_PHRASE {
        return Err(ProductionSwapReplacementConsentError::ConsentPhraseMismatch);
    }
    Ok(document)
}

fn validate_file_identity(
    identity: &ProductionSwapReplacementConsentFileIdentity,
) -> Result<(), ProductionSwapReplacementConsentError> {
    if identity.uid != 0
        || identity.mode & 0o777 != 0o600
        || identity.link_count != 1
        || identity.size_bytes == 0
        || identity.size_bytes > MAX_CONSENT_BYTES
        || identity.sha256.len() != 64
        || !identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProductionSwapReplacementConsentError::UnsafeFile);
    }
    Ok(())
}

fn bind_consent_receipt(
    activation: &ProductionSwapReplacementActivationIntent,
    consent_path: &str,
    bytes: &[u8],
    file_identity: ProductionSwapReplacementConsentFileIdentity,
) -> Result<ProductionSwapReplacementConsentReceipt, ProductionSwapReplacementConsentError> {
    validate_activation(activation)?;
    validate_file_identity(&file_identity)?;
    validate_document(activation, bytes)?;

    let mut receipt = ProductionSwapReplacementConsentReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: activation.activation_id.clone(),
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        target: activation.target.clone(),
        retiring_swap_device: activation.retiring_swap_device.clone(),
        swapfile_path: activation.swapfile_path.clone(),
        consent_path: consent_path.to_owned(),
        consent_file: file_identity,
        consent_verified: true,
        execution_enabled: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

fn validate_secure_parent(path: &Path) -> Result<(), ProductionSwapReplacementConsentError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProductionSwapReplacementConsentError::UnsafeParent(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| io_error(parent, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionSwapReplacementConsentError::UnsafeParent(
            parent.to_path_buf(),
        ));
    }
    Ok(())
}

fn read_default_consent_file() -> Result<
    (Vec<u8>, ProductionSwapReplacementConsentFileIdentity),
    ProductionSwapReplacementConsentError,
> {
    let path = Path::new(PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH);
    validate_secure_parent(path)?;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_CONSENT_BYTES
    {
        return Err(ProductionSwapReplacementConsentError::UnsafeFile);
    }

    let mut bytes = Vec::new();
    let mut limited: Take<&mut std::fs::File> = (&mut file).take(MAX_CONSENT_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionSwapReplacementConsentError::InvalidFileSize);
    }

    let identity = ProductionSwapReplacementConsentFileIdentity {
        device_id: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        link_count: metadata.nlink(),
        size_bytes: metadata.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    Ok((bytes, identity))
}

/// Verify explicit root-owned runtime consent for exactly one M1B56 swap
/// replacement activation. This remains non-executing and produces a receipt
/// with execution_enabled=false.
pub fn verify_default_production_swap_replacement_consent(
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<ProductionSwapReplacementConsentReceipt, ProductionSwapReplacementConsentError> {
    if !PRODUCTION_SWAP_REPLACEMENT_CONSENT_COMPILED {
        return Err(ProductionSwapReplacementConsentError::FeatureDisabled);
    }
    validate_activation(activation)?;
    let (bytes, identity) = read_default_consent_file()?;
    bind_consent_receipt(
        activation,
        PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
        &bytes,
        identity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProductionSwapReplacementProfile;

    fn activation() -> ProductionSwapReplacementActivationIntent {
        let mut activation = ProductionSwapReplacementActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionSwapReplacementProfile::TailSwapPartitionToExt4Swapfile,
            swap_replacement_intent_id: "a".repeat(64),
            target: "/data".into(),
            disk: "/dev/loop7".into(),
            retiring_swap_device: "/dev/loop7p5".into(),
            retiring_swap_bytes: 64 * 1024 * 1024,
            retiring_swap_priority: 7,
            persistent_swap_source: "UUID=swap-uuid".into(),
            persistent_swap_target: "none".into(),
            persistent_swap_options: vec!["sw".into()],
            persistent_swap_dump: 0,
            persistent_swap_pass: 0,
            destination_mount: "/data".into(),
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            destination_filesystem: "ext4".into(),
            destination_available_bytes: 128 * 1024 * 1024,
            swapfile_mode: 0o600,
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        activation.activation_id = activation.expected_activation_id().unwrap();
        activation
    }

    fn document(
        activation: &ProductionSwapReplacementActivationIntent,
    ) -> ProductionSwapReplacementConsentDocument {
        ProductionSwapReplacementConsentDocument {
            schema_version: 1,
            activation_id: activation.activation_id.clone(),
            swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
            target: activation.target.clone(),
            retiring_swap_device: activation.retiring_swap_device.clone(),
            swapfile_path: activation.swapfile_path.clone(),
            consent_phrase: PRODUCTION_SWAP_REPLACEMENT_CONSENT_PHRASE.into(),
        }
    }

    fn file_identity(bytes: &[u8]) -> ProductionSwapReplacementConsentFileIdentity {
        ProductionSwapReplacementConsentFileIdentity {
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o600,
            link_count: 1,
            size_bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    #[test]
    fn exact_root_consent_binds_to_one_swap_activation() {
        let activation = activation();
        let bytes = serde_json::to_vec(&document(&activation)).unwrap();
        let receipt = bind_consent_receipt(
            &activation,
            PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
            &bytes,
            file_identity(&bytes),
        )
        .unwrap();

        assert!(receipt.integrity_matches().unwrap());
        assert!(receipt.consent_verified);
        assert!(!receipt.execution_enabled);
    }

    #[test]
    fn stale_activation_binding_is_rejected() {
        let activation = activation();
        let mut document = document(&activation);
        document.activation_id = "f".repeat(64);
        let bytes = serde_json::to_vec(&document).unwrap();

        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionSwapReplacementConsentError::BindingMismatch)
        ));
    }

    #[test]
    fn phrase_must_be_exact() {
        let activation = activation();
        let mut document = document(&activation);
        document.consent_phrase = "yes".into();
        let bytes = serde_json::to_vec(&document).unwrap();

        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionSwapReplacementConsentError::ConsentPhraseMismatch)
        ));
    }

    #[test]
    fn loose_or_nonroot_file_identity_is_rejected() {
        let activation = activation();
        let bytes = serde_json::to_vec(&document(&activation)).unwrap();

        let mut nonroot = file_identity(&bytes);
        nonroot.uid = 1000;
        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
                &bytes,
                nonroot,
            ),
            Err(ProductionSwapReplacementConsentError::UnsafeFile)
        ));

        let mut loose = file_identity(&bytes);
        loose.mode = libc::S_IFREG | 0o640;
        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
                &bytes,
                loose,
            ),
            Err(ProductionSwapReplacementConsentError::UnsafeFile)
        ));
    }
}
