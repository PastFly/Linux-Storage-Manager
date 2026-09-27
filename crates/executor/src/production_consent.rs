use std::fs::{self, OpenOptions};
use std::io::{Read, Take};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProductionMutationActivationIntent;

pub const PRODUCTION_MUTATION_CONSENT_PATH: &str =
    "/etc/linux-storage-manager/production-mutation-consent.json";
pub const PRODUCTION_MUTATION_CONSENT_PHRASE: &str =
    "I UNDERSTAND THIS WILL MODIFY STORAGE";
pub const PRODUCTION_MUTATION_CONSENT_COMPILED: bool =
    cfg!(feature = "production-mutation-consent");
const MAX_CONSENT_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionMutationConsentDocument {
    pub schema_version: u32,
    pub activation_id: String,
    pub execution_id: String,
    pub target: String,
    pub resolved_device: String,
    pub consent_phrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationConsentFileIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationConsentReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub execution_id: String,
    pub target: String,
    pub resolved_device: String,
    pub consent_path: String,
    pub consent_file: ProductionMutationConsentFileIdentity,
    pub consent_verified: bool,
    pub execution_enabled: bool,
}

impl ProductionMutationConsentReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.activation_id,
            &self.execution_id,
            &self.target,
            &self.resolved_device,
            &self.consent_path,
            &self.consent_file,
            self.consent_verified,
            self.execution_enabled,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum ProductionMutationConsentError {
    #[error("production mutation consent feature is not compiled")]
    FeatureDisabled,
    #[error("production activation intent integrity check failed")]
    ActivationIntentInvalid,
    #[error("production activation intent is already execution-enabled")]
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
    #[error("consent document does not match the exact activation intent")]
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

fn io_error(path: &Path, source: std::io::Error) -> ProductionMutationConsentError {
    ProductionMutationConsentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_activation_intent(
    intent: &ProductionMutationActivationIntent,
) -> Result<(), ProductionMutationConsentError> {
    if !intent.integrity_matches()? || !intent.compile_feature_enabled {
        return Err(ProductionMutationConsentError::ActivationIntentInvalid);
    }
    if intent.execution_enabled {
        return Err(ProductionMutationConsentError::ActivationAlreadyEnabled);
    }
    Ok(())
}

fn validate_document(
    intent: &ProductionMutationActivationIntent,
    bytes: &[u8],
) -> Result<ProductionMutationConsentDocument, ProductionMutationConsentError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionMutationConsentError::InvalidFileSize);
    }

    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ProductionMutationConsentError::Decode(error.to_string()))?;
    let document: ProductionMutationConsentDocument = serde_json::from_value(raw.clone())
        .map_err(|error| ProductionMutationConsentError::Decode(error.to_string()))?;
    let canonical = serde_json::to_value(&document)?;
    if raw != canonical {
        return Err(ProductionMutationConsentError::NonCanonicalDocument);
    }

    if document.schema_version != 1
        || document.activation_id != intent.activation_id
        || document.execution_id != intent.execution_id
        || document.target != intent.target
        || document.resolved_device != intent.resolved_device
    {
        return Err(ProductionMutationConsentError::BindingMismatch);
    }
    if document.consent_phrase != PRODUCTION_MUTATION_CONSENT_PHRASE {
        return Err(ProductionMutationConsentError::ConsentPhraseMismatch);
    }

    Ok(document)
}

fn validate_file_identity(
    identity: &ProductionMutationConsentFileIdentity,
) -> Result<(), ProductionMutationConsentError> {
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
        return Err(ProductionMutationConsentError::UnsafeFile);
    }
    Ok(())
}

fn bind_consent_receipt(
    intent: &ProductionMutationActivationIntent,
    consent_path: &str,
    bytes: &[u8],
    file_identity: ProductionMutationConsentFileIdentity,
) -> Result<ProductionMutationConsentReceipt, ProductionMutationConsentError> {
    validate_activation_intent(intent)?;
    validate_file_identity(&file_identity)?;
    validate_document(intent, bytes)?;

    let mut receipt = ProductionMutationConsentReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: intent.activation_id.clone(),
        execution_id: intent.execution_id.clone(),
        target: intent.target.clone(),
        resolved_device: intent.resolved_device.clone(),
        consent_path: consent_path.to_owned(),
        consent_file: file_identity,
        consent_verified: true,
        execution_enabled: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

fn validate_secure_parent(path: &Path) -> Result<(), ProductionMutationConsentError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProductionMutationConsentError::UnsafeParent(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| io_error(parent, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionMutationConsentError::UnsafeParent(
            parent.to_path_buf(),
        ));
    }
    Ok(())
}

/// Verify the explicit root-owned runtime consent for the exact activation.
///
/// This function is read-only. The consent file must live at the fixed path,
/// its parent must be root-owned and not group/world writable, and the file
/// itself must be one-link root-owned mode 0600. The document is bound to one
/// exact activation/execution/target and cannot authorize another plan.
///
/// Even after success, the receipt records execution_enabled=false. The next
/// reviewed gate must consume both M1B35 activation and this consent receipt.
pub fn verify_default_production_mutation_consent(
    intent: &ProductionMutationActivationIntent,
) -> Result<ProductionMutationConsentReceipt, ProductionMutationConsentError> {
    if !PRODUCTION_MUTATION_CONSENT_COMPILED {
        return Err(ProductionMutationConsentError::FeatureDisabled);
    }
    validate_activation_intent(intent)?;

    let path = Path::new(PRODUCTION_MUTATION_CONSENT_PATH);
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
        return Err(ProductionMutationConsentError::UnsafeFile);
    }

    let mut bytes = Vec::new();
    let mut limited: Take<&mut std::fs::File> = (&mut file).take(MAX_CONSENT_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionMutationConsentError::InvalidFileSize);
    }

    let identity = ProductionMutationConsentFileIdentity {
        device_id: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        link_count: metadata.nlink(),
        size_bytes: metadata.len(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    bind_consent_receipt(intent, PRODUCTION_MUTATION_CONSENT_PATH, &bytes, identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProductionMutationProfile, PRODUCTION_MUTATION_ACTIVATION_COMPILED};

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn intent() -> ProductionMutationActivationIntent {
        let mut intent = ProductionMutationActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionMutationProfile::ExistingSinglePvLvmFilesystem,
            execution_id: digest('a'),
            source_manifest_id: digest('b'),
            native_manifest_digest: digest('c'),
            fresh_identity_digest: digest('d'),
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            lv_step_id: 3,
            filesystem_step_id: 4,
            filesystem_type: "ext4".into(),
            filesystem_mountpoint: Some("/mnt/data".into()),
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        let bytes = serde_json::to_vec(&(
            intent.schema_version,
            intent.profile,
            &intent.execution_id,
            &intent.source_manifest_id,
            &intent.native_manifest_digest,
            &intent.fresh_identity_digest,
            &intent.target,
            &intent.resolved_device,
            intent.lv_step_id,
            intent.filesystem_step_id,
            &intent.filesystem_type,
            &intent.filesystem_mountpoint,
            intent.compile_feature_enabled,
            intent.execution_enabled,
        ))
        .unwrap();
        intent.activation_id = format!("{:x}", Sha256::digest(bytes));
        intent
    }

    fn document(intent: &ProductionMutationActivationIntent) -> Vec<u8> {
        serde_json::to_vec(&ProductionMutationConsentDocument {
            schema_version: 1,
            activation_id: intent.activation_id.clone(),
            execution_id: intent.execution_id.clone(),
            target: intent.target.clone(),
            resolved_device: intent.resolved_device.clone(),
            consent_phrase: PRODUCTION_MUTATION_CONSENT_PHRASE.into(),
        })
        .unwrap()
    }

    fn file_identity(bytes: &[u8]) -> ProductionMutationConsentFileIdentity {
        ProductionMutationConsentFileIdentity {
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
    fn exact_consent_document_binds_to_one_activation() {
        let intent = intent();
        let bytes = document(&intent);
        let receipt = bind_consent_receipt(
            &intent,
            PRODUCTION_MUTATION_CONSENT_PATH,
            &bytes,
            file_identity(&bytes),
        )
        .unwrap();

        assert!(receipt.integrity_matches().unwrap());
        assert!(receipt.consent_verified);
        assert!(!receipt.execution_enabled);
    }

    #[test]
    fn stale_activation_id_is_rejected() {
        let intent = intent();
        let mut raw: ProductionMutationConsentDocument =
            serde_json::from_slice(&document(&intent)).unwrap();
        raw.activation_id = digest('f');
        let bytes = serde_json::to_vec(&raw).unwrap();

        assert!(matches!(
            bind_consent_receipt(
                &intent,
                PRODUCTION_MUTATION_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionMutationConsentError::BindingMismatch)
        ));
    }

    #[test]
    fn consent_phrase_must_be_exact() {
        let intent = intent();
        let mut raw: ProductionMutationConsentDocument =
            serde_json::from_slice(&document(&intent)).unwrap();
        raw.consent_phrase = "yes".into();
        let bytes = serde_json::to_vec(&raw).unwrap();

        assert!(matches!(
            bind_consent_receipt(
                &intent,
                PRODUCTION_MUTATION_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionMutationConsentError::ConsentPhraseMismatch)
        ));
    }

    #[test]
    fn non_root_or_loose_mode_consent_file_is_rejected() {
        let intent = intent();
        let bytes = document(&intent);
        let mut identity = file_identity(&bytes);
        identity.uid = 1000;
        assert!(matches!(
            bind_consent_receipt(
                &intent,
                PRODUCTION_MUTATION_CONSENT_PATH,
                &bytes,
                identity,
            ),
            Err(ProductionMutationConsentError::UnsafeFile)
        ));

        let mut identity = file_identity(&bytes);
        identity.mode = libc::S_IFREG | 0o640;
        assert!(matches!(
            bind_consent_receipt(
                &intent,
                PRODUCTION_MUTATION_CONSENT_PATH,
                &bytes,
                identity,
            ),
            Err(ProductionMutationConsentError::UnsafeFile)
        ));
    }

    #[test]
    fn compile_features_remain_separate_gates() {
        if PRODUCTION_MUTATION_CONSENT_COMPILED {
            assert!(PRODUCTION_MUTATION_ACTIVATION_COMPILED);
        }
    }
}
