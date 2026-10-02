use std::fs::{self, OpenOptions};
use std::io::{Read, Take};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProductionGptTailCreateActivationIntent;

pub const PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH: &str =
    "/etc/linux-storage-manager/production-gpt-tail-create-consent.json";
pub const PRODUCTION_GPT_TAIL_CREATE_CONSENT_PHRASE: &str =
    "I UNDERSTAND THIS WILL MODIFY AN EXISTING GPT DISK AND FORMAT A NEW PARTITION";
pub const PRODUCTION_GPT_TAIL_CREATE_CONSENT_COMPILED: bool =
    cfg!(feature = "production-gpt-tail-consent");
const MAX_CONSENT_BYTES: u64 = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionGptTailCreateConsentDocument {
    pub schema_version: u32,
    pub activation_id: String,
    pub create_intent_id: String,
    pub disk: String,
    pub gpt_disk_id: String,
    pub gpt_table_sha256: String,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub filesystem: String,
    pub consent_phrase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateConsentFileIdentity {
    pub device_id: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateConsentReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub create_intent_id: String,
    pub disk: String,
    pub gpt_disk_id: String,
    pub gpt_table_sha256: String,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub filesystem: String,
    pub consent_path: String,
    pub consent_file: ProductionGptTailCreateConsentFileIdentity,
    pub consent_verified: bool,
    pub execution_enabled: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    create_intent_id: &'a str,
    disk: &'a str,
    gpt_disk_id: &'a str,
    gpt_table_sha256: &'a str,
    partition_start_sector: u64,
    partition_sector_count: u64,
    filesystem: &'a str,
    consent_path: &'a str,
    consent_file: &'a ProductionGptTailCreateConsentFileIdentity,
    consent_verified: bool,
    execution_enabled: bool,
}

impl ProductionGptTailCreateConsentReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    pub(crate) fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            create_intent_id: &self.create_intent_id,
            disk: &self.disk,
            gpt_disk_id: &self.gpt_disk_id,
            gpt_table_sha256: &self.gpt_table_sha256,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            filesystem: &self.filesystem,
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
pub enum ProductionGptTailCreateConsentError {
    #[error("production GPT-tail create consent feature is not compiled")]
    FeatureDisabled,
    #[error("GPT-tail create activation integrity check failed")]
    ActivationInvalid,
    #[error("GPT-tail create activation already crossed an execution/mutation boundary")]
    ActivationAlreadyEnabled,
    #[error("GPT-tail consent parent directory is unsafe: {0}")]
    UnsafeParent(PathBuf),
    #[error("GPT-tail consent file is not a secure root-owned 0600 regular file")]
    UnsafeFile,
    #[error("GPT-tail consent file size is invalid")]
    InvalidFileSize,
    #[error("GPT-tail consent document is invalid JSON: {0}")]
    Decode(String),
    #[error("GPT-tail consent document contains a non-canonical or unknown shape")]
    NonCanonicalDocument,
    #[error("GPT-tail consent document does not match the exact activation")]
    BindingMismatch,
    #[error("GPT-tail consent phrase is not exact")]
    ConsentPhraseMismatch,
    #[error("GPT-tail consent I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("GPT-tail consent receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn io_error(path: &Path, source: std::io::Error) -> ProductionGptTailCreateConsentError {
    ProductionGptTailCreateConsentError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_activation(
    activation: &ProductionGptTailCreateActivationIntent,
) -> Result<(), ProductionGptTailCreateConsentError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !activation.partition_slot_deferred
    {
        return Err(ProductionGptTailCreateConsentError::ActivationInvalid);
    }
    if activation.execution_enabled
        || activation.partition_table_changed
        || activation.filesystem_formatted
    {
        return Err(ProductionGptTailCreateConsentError::ActivationAlreadyEnabled);
    }
    Ok(())
}

fn validate_document(
    activation: &ProductionGptTailCreateActivationIntent,
    bytes: &[u8],
) -> Result<ProductionGptTailCreateConsentDocument, ProductionGptTailCreateConsentError> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionGptTailCreateConsentError::InvalidFileSize);
    }

    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ProductionGptTailCreateConsentError::Decode(error.to_string()))?;
    let document: ProductionGptTailCreateConsentDocument = serde_json::from_value(raw.clone())
        .map_err(|error| ProductionGptTailCreateConsentError::Decode(error.to_string()))?;
    if serde_json::to_value(&document)? != raw {
        return Err(ProductionGptTailCreateConsentError::NonCanonicalDocument);
    }

    if document.schema_version != 1
        || document.activation_id != activation.activation_id
        || document.create_intent_id != activation.create_intent_id
        || document.disk != activation.disk
        || document.gpt_disk_id != activation.gpt_disk_id
        || document.gpt_table_sha256 != activation.gpt_table_sha256
        || document.partition_start_sector != activation.partition_start_sector
        || document.partition_sector_count != activation.partition_sector_count
        || document.filesystem != activation.filesystem
    {
        return Err(ProductionGptTailCreateConsentError::BindingMismatch);
    }
    if document.consent_phrase != PRODUCTION_GPT_TAIL_CREATE_CONSENT_PHRASE {
        return Err(ProductionGptTailCreateConsentError::ConsentPhraseMismatch);
    }
    Ok(document)
}

fn validate_file_identity(
    identity: &ProductionGptTailCreateConsentFileIdentity,
) -> Result<(), ProductionGptTailCreateConsentError> {
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
        return Err(ProductionGptTailCreateConsentError::UnsafeFile);
    }
    Ok(())
}

fn bind_consent_receipt(
    activation: &ProductionGptTailCreateActivationIntent,
    consent_path: &str,
    bytes: &[u8],
    file_identity: ProductionGptTailCreateConsentFileIdentity,
) -> Result<ProductionGptTailCreateConsentReceipt, ProductionGptTailCreateConsentError> {
    validate_activation(activation)?;
    validate_file_identity(&file_identity)?;
    validate_document(activation, bytes)?;

    let mut receipt = ProductionGptTailCreateConsentReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: activation.activation_id.clone(),
        create_intent_id: activation.create_intent_id.clone(),
        disk: activation.disk.clone(),
        gpt_disk_id: activation.gpt_disk_id.clone(),
        gpt_table_sha256: activation.gpt_table_sha256.clone(),
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        filesystem: activation.filesystem.clone(),
        consent_path: consent_path.to_owned(),
        consent_file: file_identity,
        consent_verified: true,
        execution_enabled: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

fn validate_secure_parent(path: &Path) -> Result<(), ProductionGptTailCreateConsentError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProductionGptTailCreateConsentError::UnsafeParent(path.to_path_buf()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| io_error(parent, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionGptTailCreateConsentError::UnsafeParent(
            parent.to_path_buf(),
        ));
    }
    Ok(())
}

fn read_default_consent_file() -> Result<
    (Vec<u8>, ProductionGptTailCreateConsentFileIdentity),
    ProductionGptTailCreateConsentError,
> {
    let path = Path::new(PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH);
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
        return Err(ProductionGptTailCreateConsentError::UnsafeFile);
    }

    let mut bytes = Vec::new();
    let mut limited: Take<&mut std::fs::File> = (&mut file).take(MAX_CONSENT_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_CONSENT_BYTES {
        return Err(ProductionGptTailCreateConsentError::InvalidFileSize);
    }

    let identity = ProductionGptTailCreateConsentFileIdentity {
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

pub fn verify_default_production_gpt_tail_create_consent(
    activation: &ProductionGptTailCreateActivationIntent,
) -> Result<ProductionGptTailCreateConsentReceipt, ProductionGptTailCreateConsentError> {
    if !PRODUCTION_GPT_TAIL_CREATE_CONSENT_COMPILED {
        return Err(ProductionGptTailCreateConsentError::FeatureDisabled);
    }
    validate_activation(activation)?;
    let (bytes, identity) = read_default_consent_file()?;
    bind_consent_receipt(
        activation,
        PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
        &bytes,
        identity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProductionGptTailCreateProfile;

    fn activation() -> ProductionGptTailCreateActivationIntent {
        let mut activation = ProductionGptTailCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionGptTailCreateProfile::ExistingGptTailFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: format!("space-{}", "c".repeat(58)),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            gpt_disk_id: "12345678-1234-1234-1234-123456789abc".into(),
            gpt_first_lba: 34,
            gpt_last_lba: 1_048_542,
            gpt_sector_size_bytes: 512,
            gpt_table_sha256: "d".repeat(64),
            existing_partition_count: 1,
            source_start_sector: 133_120,
            source_sector_count: 915_423,
            source_size_bytes: 468_696_576,
            partition_start_sector: 133_120,
            partition_sector_count: 131_072,
            partition_size_bytes: 64 * 1024 * 1024,
            filesystem: "ext4".into(),
            partition_slot_deferred: true,
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        activation.activation_id = activation.expected_activation_id().unwrap();
        activation
    }

    fn document(
        activation: &ProductionGptTailCreateActivationIntent,
    ) -> ProductionGptTailCreateConsentDocument {
        ProductionGptTailCreateConsentDocument {
            schema_version: 1,
            activation_id: activation.activation_id.clone(),
            create_intent_id: activation.create_intent_id.clone(),
            disk: activation.disk.clone(),
            gpt_disk_id: activation.gpt_disk_id.clone(),
            gpt_table_sha256: activation.gpt_table_sha256.clone(),
            partition_start_sector: activation.partition_start_sector,
            partition_sector_count: activation.partition_sector_count,
            filesystem: activation.filesystem.clone(),
            consent_phrase: PRODUCTION_GPT_TAIL_CREATE_CONSENT_PHRASE.into(),
        }
    }

    fn file_identity(bytes: &[u8]) -> ProductionGptTailCreateConsentFileIdentity {
        ProductionGptTailCreateConsentFileIdentity {
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
    fn exact_root_consent_binds_to_one_gpt_tail_activation() {
        let activation = activation();
        let bytes = serde_json::to_vec(&document(&activation)).unwrap();
        let receipt = bind_consent_receipt(
            &activation,
            PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
            &bytes,
            file_identity(&bytes),
        )
        .unwrap();

        assert!(receipt.integrity_matches().unwrap());
        assert!(receipt.consent_verified);
        assert!(!receipt.execution_enabled);
        assert_eq!(receipt.disk, "/dev/loop7");
        assert_eq!(receipt.gpt_table_sha256, activation.gpt_table_sha256);
    }

    #[test]
    fn stale_table_digest_binding_is_rejected() {
        let activation = activation();
        let mut document = document(&activation);
        document.gpt_table_sha256 = "e".repeat(64);
        let bytes = serde_json::to_vec(&document).unwrap();

        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionGptTailCreateConsentError::BindingMismatch)
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
                PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
                &bytes,
                file_identity(&bytes),
            ),
            Err(ProductionGptTailCreateConsentError::ConsentPhraseMismatch)
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
                PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
                &bytes,
                nonroot,
            ),
            Err(ProductionGptTailCreateConsentError::UnsafeFile)
        ));

        let mut loose = file_identity(&bytes);
        loose.mode = libc::S_IFREG | 0o640;
        assert!(matches!(
            bind_consent_receipt(
                &activation,
                PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
                &bytes,
                loose,
            ),
            Err(ProductionGptTailCreateConsentError::UnsafeFile)
        ));
    }
}
