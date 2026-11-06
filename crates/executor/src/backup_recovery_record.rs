//! Inert experimental recovery evidence format. Not connected to production.
//!
//! A digest is an integrity binding, not authentication. The expected digest
//! must come from independently trusted, durable journal evidence. Paths and
//! contents require safe filesystem revalidation before any recovery action.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Component, Path};

const DOMAIN_V1: &[u8] = b"linux-storage-manager:backup-recovery-record:v1\0";
const DOMAIN_V2: &[u8] = b"linux-storage-manager:backup-recovery-record:v2\0";
const DOMAIN_V3: &[u8] = b"linux-storage-manager:backup-recovery-record:v3\0";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_ARTIFACTS: usize = 16;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_IDENTITY_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryBinding {
    pub journal_id: String,
    pub session_id: String,
    pub handoff_id: String,
    pub plan_id: String,
    pub target_manifest_digest: String,
    pub manifest_id: String,
    pub receipt_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RecoveryIdentity {
    PartitionTable {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    LvmVolumeGroup {
        vg_name: String,
        vg_uuid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryArtifact {
    pub ordinal: u32,
    pub identity: RecoveryIdentity,
    pub primary_path: String,
    pub recovery_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    /// Historical receipt fingerprint inputs, not identities across reboot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_device_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verity: Option<VerityPair>,
}

/// SHA-256 fs-verity measurements, distinct from the ordinary content hash.
/// Presence alone does not prove that the files were sealed or remain present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerityPair {
    pub primary_sha256: String,
    pub recovery_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryPayload {
    pub schema_version: u32,
    #[serde(flatten)]
    pub binding: RecoveryBinding,
    pub artifacts: Vec<RecoveryArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupRecoveryRecord {
    record_id: String,
    payload: RecoveryPayload,
}

#[derive(Debug)]
pub(crate) enum RecordError {
    TooLarge,
    Malformed,
    Invalid,
    BindingMismatch,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_atom(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES && !value.chars().any(char::is_control)
}

fn valid_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !value.chars().any(char::is_control)
        && path.is_absolute()
        && value != "/"
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.split('/').any(|part| part == "." || part == "..")
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn validate_payload(payload: &RecoveryPayload) -> Result<(), RecordError> {
    let binding = &payload.binding;
    if !matches!(payload.schema_version, 1..=3)
        || ![
            &binding.journal_id,
            &binding.session_id,
            &binding.handoff_id,
            &binding.plan_id,
            &binding.target_manifest_digest,
            &binding.manifest_id,
            &binding.receipt_id,
        ]
        .iter()
        .all(|value| valid_digest(value))
        || payload.artifacts.is_empty()
        || payload.artifacts.len() > MAX_ARTIFACTS
    {
        return Err(RecordError::Invalid);
    }
    let mut paths = BTreeSet::new();
    for (index, artifact) in payload.artifacts.iter().enumerate() {
        let identity_ok = match &artifact.identity {
            RecoveryIdentity::PartitionTable {
                disk,
                table_label,
                table_id,
            } => {
                valid_path(disk)
                    && valid_atom(table_label)
                    && table_id.as_deref().is_none_or(valid_atom)
            }
            RecoveryIdentity::LvmVolumeGroup { vg_name, vg_uuid } => {
                valid_atom(vg_name) && valid_atom(vg_uuid)
            }
        };
        if artifact.ordinal as usize != index + 1
            || !identity_ok
            || !valid_path(&artifact.primary_path)
            || !valid_path(&artifact.recovery_path)
            || !paths.insert(&artifact.primary_path)
            || !paths.insert(&artifact.recovery_path)
            || artifact.size_bytes == 0
            || artifact.size_bytes > MAX_ARTIFACT_BYTES
            || !valid_digest(&artifact.sha256)
            || match payload.schema_version {
                1 => {
                    artifact.capture_device_id.is_some()
                        || artifact.capture_inode.is_some()
                        || artifact.verity.is_some()
                }
                2 => {
                    artifact.capture_device_id.is_none()
                        || artifact.capture_inode.is_none()
                        || artifact.verity.is_some()
                }
                3 => {
                    artifact.capture_device_id.is_none()
                        || artifact.capture_inode.is_none()
                        || !artifact.verity.as_ref().is_some_and(|pair| {
                            valid_digest(&pair.primary_sha256)
                                && valid_digest(&pair.recovery_sha256)
                        })
                }
                _ => true,
            }
        {
            return Err(RecordError::Invalid);
        }
    }
    if matches!(payload.schema_version, 2 | 3) {
        let mut artifacts = Vec::with_capacity(payload.artifacts.len());
        for artifact in &payload.artifacts {
            let (kind, expected_identity) = match &artifact.identity {
                RecoveryIdentity::PartitionTable {
                    disk,
                    table_label,
                    table_id,
                } => (
                    crate::MetadataBackupKind::PartitionTable,
                    crate::BackupExpectedIdentity::PartitionTable {
                        disk: disk.clone(),
                        table_label: table_label.clone(),
                        table_id: table_id.clone(),
                    },
                ),
                RecoveryIdentity::LvmVolumeGroup { vg_name, vg_uuid } => (
                    crate::MetadataBackupKind::LvmVolumeGroup,
                    crate::BackupExpectedIdentity::LvmVolumeGroup {
                        vg_name: vg_name.clone(),
                        vg_uuid: vg_uuid.clone(),
                    },
                ),
            };
            artifacts.push(crate::BackupArtifactReceipt {
                ordinal: artifact.ordinal,
                kind,
                artifact_path: artifact.primary_path.clone(),
                expected_identity,
                device_id: artifact.capture_device_id.ok_or(RecordError::Invalid)?,
                inode: artifact.capture_inode.ok_or(RecordError::Invalid)?,
                size_bytes: artifact.size_bytes,
                sha256: artifact.sha256.clone(),
            });
        }
        if !verify_receipt_artifacts(&payload.binding, &artifacts, &payload.binding.receipt_id) {
            return Err(RecordError::BindingMismatch);
        }
    }
    Ok(())
}

fn verify_receipt_artifacts(
    binding: &RecoveryBinding,
    artifacts: &[crate::BackupArtifactReceipt],
    expected_receipt_id: &str,
) -> bool {
    let bytes = serde_json::to_vec(&(
        2_u32,
        &binding.manifest_id,
        &binding.handoff_id,
        &binding.plan_id,
        &binding.target_manifest_digest,
        &binding.session_id,
        &binding.journal_id,
        false,
        artifacts,
    ));
    bytes.is_ok_and(|bytes| format!("{:x}", Sha256::digest(bytes)) == expected_receipt_id)
}

fn check_trusted_context(record: &BackupRecoveryRecord, trusted: &RecoveryBinding) -> bool {
    &record.payload.binding == trusted
}

fn record_id(payload: &RecoveryPayload) -> Result<String, RecordError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| RecordError::Malformed)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let mut hash = Sha256::new();
    hash.update(match payload.schema_version {
        1 => DOMAIN_V1,
        2 => DOMAIN_V2,
        3 => DOMAIN_V3,
        _ => return Err(RecordError::Invalid),
    });
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
}

/// Test-only stand-in for evidence collected from an already verified copy.
/// This is metadata supplied by the caller, not proof of an actual file,
/// protected namespace, current lease, or durable storage.
pub(crate) struct ExperimentalCopyView {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub device_id: u64,
    pub inode: u64,
}

pub(crate) struct ExperimentalCopyPair {
    pub ordinal: u32,
    pub primary: ExperimentalCopyView,
    pub recovery: ExperimentalCopyView,
}

fn copy_pair_matches(
    requirement: &crate::MetadataBackupRequirement,
    receipt_artifact: &crate::BackupArtifactReceipt,
    pair: &ExperimentalCopyPair,
    root: &Path,
    recovery_root: &Path,
) -> bool {
    let primary = Path::new(&requirement.artifact_path);
    let Some(name) = primary.file_name() else {
        return false;
    };
    let mut recovery_name = name.to_os_string();
    recovery_name.push(".recovery");
    primary.parent() == Some(root)
        && requirement.ordinal == receipt_artifact.ordinal
        && pair.ordinal == receipt_artifact.ordinal
        && requirement.kind == receipt_artifact.kind
        && requirement.artifact_path == receipt_artifact.artifact_path
        && requirement.expected_identity == receipt_artifact.expected_identity
        && pair.primary.path == receipt_artifact.artifact_path
        && Path::new(&pair.recovery.path) == recovery_root.join(recovery_name)
        && pair.primary.size_bytes == receipt_artifact.size_bytes
        && pair.recovery.size_bytes == receipt_artifact.size_bytes
        && pair.primary.sha256 == receipt_artifact.sha256
        && pair.recovery.sha256 == receipt_artifact.sha256
        && pair.primary.device_id == receipt_artifact.device_id
        && pair.primary.inode == receipt_artifact.inode
        && (pair.primary.device_id, pair.primary.inode)
            != (pair.recovery.device_id, pair.recovery.inode)
}

fn manifest_fingerprint(manifest: &crate::MetadataBackupManifest) -> Result<String, RecordError> {
    let bytes = serde_json::to_vec(&(
        manifest.schema_version(),
        manifest.handoff_id(),
        manifest.plan_id(),
        manifest.target_manifest_digest(),
        manifest.artifact_directory(),
        manifest.mutation_enabled(),
        manifest.owner_acceptance_required(),
        manifest.requirements(),
    ))
    .map_err(|_| RecordError::Malformed)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Experimental adapter. A future verified filesystem collector must replace
/// `copies` and bind it durably before this format can authorize anything.
pub(crate) fn validate_capture_binding(
    manifest: &crate::MetadataBackupManifest,
    receipt: &crate::MetadataBackupReceipt,
    trusted: &RecoveryBinding,
) -> Result<(), RecordError> {
    if manifest.schema_version() != 1
        || manifest.mutation_enabled()
        || !manifest.owner_acceptance_required()
        || receipt.recovery_schema_version() != 2
        || receipt.mutation_enabled()
        || manifest_fingerprint(manifest)? != manifest.manifest_id()
        || manifest.manifest_id() != trusted.manifest_id
        || manifest.handoff_id() != trusted.handoff_id
        || manifest.plan_id() != trusted.plan_id
        || manifest.target_manifest_digest() != trusted.target_manifest_digest
        || receipt.receipt_id() != trusted.receipt_id
        || receipt.manifest_id() != trusted.manifest_id
        || receipt.handoff_id() != trusted.handoff_id
        || receipt.plan_id() != trusted.plan_id
        || receipt.target_manifest_digest() != trusted.target_manifest_digest
        || receipt.recovery_session_id() != trusted.session_id
        || receipt.recovery_journal_id() != trusted.journal_id
        || manifest.requirements().len() != receipt.artifacts().len()
        || receipt.artifacts().is_empty()
        || receipt.artifacts().len() > MAX_ARTIFACTS
        || !verify_receipt_artifacts(trusted, receipt.artifacts(), receipt.receipt_id())
    {
        return Err(RecordError::BindingMismatch);
    }

    let root = Path::new(manifest.artifact_directory());
    let legacy_root = Path::new(crate::BACKUP_DIRECTORY).join(&trusted.handoff_id);
    let attempt_root = legacy_root.join(&trusted.journal_id);
    if root != legacy_root && root != attempt_root {
        return Err(RecordError::BindingMismatch);
    }
    if !valid_path(manifest.artifact_directory()) {
        return Err(RecordError::Invalid);
    }
    let mut paths = BTreeSet::new();
    for (index, (requirement, artifact)) in manifest
        .requirements()
        .iter()
        .zip(receipt.artifacts())
        .enumerate()
    {
        let identity_valid = match (&artifact.kind, &artifact.expected_identity) {
            (
                crate::MetadataBackupKind::PartitionTable,
                crate::BackupExpectedIdentity::PartitionTable {
                    disk,
                    table_label,
                    table_id,
                },
            ) => {
                valid_path(disk)
                    && valid_atom(table_label)
                    && table_id.as_deref().is_none_or(valid_atom)
            }
            (
                crate::MetadataBackupKind::LvmVolumeGroup,
                crate::BackupExpectedIdentity::LvmVolumeGroup { vg_name, vg_uuid },
            ) => valid_atom(vg_name) && valid_atom(vg_uuid),
            _ => false,
        };
        if requirement.ordinal as usize != index + 1
            || requirement.ordinal != artifact.ordinal
            || requirement.kind != artifact.kind
            || requirement.artifact_path != artifact.artifact_path
            || requirement.expected_identity != artifact.expected_identity
            || !identity_valid
            || !valid_path(&artifact.artifact_path)
            || Path::new(&artifact.artifact_path).parent() != Some(root)
            || !paths.insert(&artifact.artifact_path)
            || artifact.size_bytes == 0
            || artifact.size_bytes > MAX_ARTIFACT_BYTES
            || !valid_digest(&artifact.sha256)
        {
            return Err(RecordError::BindingMismatch);
        }
    }
    Ok(())
}

pub(crate) fn from_experimental_verified_metadata(
    manifest: &crate::MetadataBackupManifest,
    receipt: &crate::MetadataBackupReceipt,
    trusted: &RecoveryBinding,
    copies: &[ExperimentalCopyPair],
) -> Result<BackupRecoveryRecord, RecordError> {
    validate_capture_binding(manifest, receipt, trusted)?;
    if receipt.artifacts().len() != copies.len() {
        return Err(RecordError::BindingMismatch);
    }
    let root = Path::new(manifest.artifact_directory());
    let mut recovery_dir_name = root.file_name().ok_or(RecordError::Invalid)?.to_os_string();
    recovery_dir_name.push(".recovery");
    let recovery_root = root.with_file_name(recovery_dir_name);
    let mut artifacts = Vec::with_capacity(copies.len());
    for ((requirement, receipt_artifact), pair) in manifest
        .requirements()
        .iter()
        .zip(receipt.artifacts())
        .zip(copies)
    {
        if !copy_pair_matches(requirement, receipt_artifact, pair, root, &recovery_root) {
            return Err(RecordError::BindingMismatch);
        }
        let identity = match (&receipt_artifact.kind, &receipt_artifact.expected_identity) {
            (
                crate::MetadataBackupKind::PartitionTable,
                crate::BackupExpectedIdentity::PartitionTable {
                    disk,
                    table_label,
                    table_id,
                },
            ) => RecoveryIdentity::PartitionTable {
                disk: disk.clone(),
                table_label: table_label.clone(),
                table_id: table_id.clone(),
            },
            (
                crate::MetadataBackupKind::LvmVolumeGroup,
                crate::BackupExpectedIdentity::LvmVolumeGroup { vg_name, vg_uuid },
            ) => RecoveryIdentity::LvmVolumeGroup {
                vg_name: vg_name.clone(),
                vg_uuid: vg_uuid.clone(),
            },
            _ => return Err(RecordError::Invalid),
        };
        artifacts.push(RecoveryArtifact {
            ordinal: receipt_artifact.ordinal,
            identity,
            primary_path: pair.primary.path.clone(),
            recovery_path: pair.recovery.path.clone(),
            size_bytes: receipt_artifact.size_bytes,
            sha256: receipt_artifact.sha256.clone(),
            capture_device_id: Some(receipt_artifact.device_id),
            capture_inode: Some(receipt_artifact.inode),
            verity: None,
        });
    }
    BackupRecoveryRecord::new(RecoveryPayload {
        schema_version: 2,
        binding: trusted.clone(),
        artifacts,
    })
}

impl BackupRecoveryRecord {
    pub(crate) fn new(payload: RecoveryPayload) -> Result<Self, RecordError> {
        validate_payload(&payload)?;
        let record = Self {
            record_id: record_id(&payload)?,
            payload,
        };
        // Validate the complete envelope, not just the hashed payload, before
        // exposing an ID that could be bound to durable state.
        record.encode()?;
        Ok(record)
    }

    pub(crate) fn record_id(&self) -> &str {
        &self.record_id
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, RecordError> {
        validate_payload(&self.payload)?;
        if record_id(&self.payload)? != self.record_id {
            return Err(RecordError::Invalid);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| RecordError::Malformed)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge);
        }
        Ok(bytes)
    }
}

/// Metadata conversion only: callers must independently establish that each
/// measurement came from the corresponding durable, protected file. This
/// deliberately cannot by itself authorize production mutation or recovery.
pub(crate) fn experimental_bind_verity(
    record: &BackupRecoveryRecord,
    measurements: &[([u8; 32], [u8; 32])],
) -> Result<BackupRecoveryRecord, RecordError> {
    if record.payload.schema_version != 2
        || record.payload.artifacts.len() != measurements.len()
        || record_id(&record.payload)? != record.record_id
    {
        return Err(RecordError::BindingMismatch);
    }
    let mut payload = record.payload.clone();
    payload.schema_version = 3;
    for (artifact, (primary, recovery)) in payload.artifacts.iter_mut().zip(measurements) {
        let hex = |bytes: &[u8; 32]| bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        artifact.verity = Some(VerityPair {
            primary_sha256: hex(primary),
            recovery_sha256: hex(recovery),
        });
    }
    BackupRecoveryRecord::new(payload)
}

pub(crate) fn decode(bytes: &[u8], expected_id: &str) -> Result<BackupRecoveryRecord, RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    if !valid_digest(expected_id) {
        return Err(RecordError::Invalid);
    }
    let record: BackupRecoveryRecord =
        serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed)?;
    validate_payload(&record.payload)?;
    if record.record_id != expected_id || record_id(&record.payload)? != expected_id {
        return Err(RecordError::BindingMismatch);
    }
    Ok(record)
}

pub(crate) fn decode_with_trusted_context(
    bytes: &[u8],
    expected_id: &str,
    trusted: &RecoveryBinding,
) -> Result<BackupRecoveryRecord, RecordError> {
    let record = decode(bytes, expected_id)?;
    if !matches!(record.payload.schema_version, 2 | 3) || !check_trusted_context(&record, trusted) {
        return Err(RecordError::BindingMismatch);
    }
    Ok(record)
}

/// Decode only a v3 record under an independently supplied trusted anchor.
/// This checks metadata; callers must still verify the actual files.
pub(crate) fn decode_v3_with_trusted_context(
    bytes: &[u8],
    expected_id: &str,
    trusted: &RecoveryBinding,
) -> Result<BackupRecoveryRecord, RecordError> {
    let record = decode_with_trusted_context(bytes, expected_id, trusted)?;
    if record.payload.schema_version != 3 {
        return Err(RecordError::BindingMismatch);
    }
    Ok(record)
}

impl BackupRecoveryRecord {
    pub(crate) fn artifacts(&self) -> &[RecoveryArtifact] {
        &self.payload.artifacts
    }

    pub(crate) fn binding(&self) -> &RecoveryBinding {
        &self.payload.binding
    }

    pub(crate) fn schema_version(&self) -> u32 {
        self.payload.schema_version
    }
}

#[cfg(test)]
mod tests {
    const RECORD_ID: &str = "54a186958ab3c29898a9213a1b8d2a6d374a817e29079649efa304842a204d5c";
    const FIXTURE: &str = r#"{"record_id":"54a186958ab3c29898a9213a1b8d2a6d374a817e29079649efa304842a204d5c","payload":{"schema_version":1,"journal_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","handoff_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","plan_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","target_manifest_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","manifest_id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","receipt_id":"1111111111111111111111111111111111111111111111111111111111111111","artifacts":[{"ordinal":1,"identity":{"kind":"partition_table","disk":"/dev/vda","table_label":"gpt","table_id":"123"},"primary_path":"/var/lib/lsm/backups/primary","recovery_path":"/var/lib/lsm/backups/recovery","size_bytes":42,"sha256":"2222222222222222222222222222222222222222222222222222222222222222"}]}}"#;

    use super::*;

    fn v2_fixture() -> BackupRecoveryRecord {
        let mut payload = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap().payload;
        payload.schema_version = 2;
        payload.binding.receipt_id =
            "573c963f221eeb5287715a6dd620a3f7b3f84f31facbccdb4de567f8c32001fe".into();
        payload.artifacts[0].capture_device_id = Some(123);
        payload.artifacts[0].capture_inode = Some(456);
        BackupRecoveryRecord::new(payload).unwrap()
    }

    #[test]
    fn strict_decoder_rejects_v1_even_with_matching_anchor_and_context() {
        let legacy = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        assert!(matches!(
            decode_with_trusted_context(FIXTURE.as_bytes(), RECORD_ID, &legacy.payload.binding),
            Err(RecordError::BindingMismatch)
        ));
    }

    #[test]
    fn strict_decoder_rejects_each_changed_trusted_context_field() {
        let record = v2_fixture();
        let bytes = record.encode().unwrap();
        let trusted = record.payload.binding.clone();
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &trusted).is_ok());

        for field in 0..7 {
            let mut changed = trusted.clone();
            let value = match field {
                0 => &mut changed.journal_id,
                1 => &mut changed.session_id,
                2 => &mut changed.handoff_id,
                3 => &mut changed.plan_id,
                4 => &mut changed.target_manifest_digest,
                5 => &mut changed.manifest_id,
                6 => &mut changed.receipt_id,
                _ => unreachable!(),
            };
            *value = "9".repeat(64);
            assert!(
                matches!(
                    decode_with_trusted_context(&bytes, record.record_id(), &changed),
                    Err(RecordError::BindingMismatch)
                ),
                "trusted context field {field} was not checked"
            );
        }
    }

    #[test]
    fn v2_receipt_rejects_reordered_and_removed_artifacts() {
        let mut payload = v2_fixture().payload;
        payload.binding.receipt_id =
            "fe55941e493b7852597b24dba88d34467bbd94531c786a1b0c24d17894a762e3".into();
        payload.artifacts.push(RecoveryArtifact {
            ordinal: 2,
            identity: RecoveryIdentity::LvmVolumeGroup {
                vg_name: "vgdata".into(),
                vg_uuid: "vg-uuid".into(),
            },
            primary_path: "/var/lib/lsm/backups/vg".into(),
            recovery_path: "/var/lib/lsm/backups/vg.recovery".into(),
            size_bytes: 64,
            sha256: "3".repeat(64),
            capture_device_id: Some(123),
            capture_inode: Some(789),
            verity: None,
        });
        let original = BackupRecoveryRecord::new(payload.clone()).unwrap();
        let bytes = original.encode().unwrap();
        assert!(
            decode_with_trusted_context(&bytes, original.record_id(), &payload.binding).is_ok()
        );

        let mut reordered = payload.clone();
        reordered.artifacts.swap(0, 1);
        reordered.artifacts[0].ordinal = 1;
        reordered.artifacts[1].ordinal = 2;
        let mut removed = payload.clone();
        removed.artifacts.pop();
        let mut added = payload.clone();
        let mut third = added.artifacts[1].clone();
        third.ordinal = 3;
        third.primary_path = "/var/lib/lsm/backups/another-vg".into();
        third.recovery_path = "/var/lib/lsm/backups/another-vg.recovery".into();
        added.artifacts.push(third);
        for changed in [reordered, removed, added] {
            let changed_id = record_id(&changed).unwrap();
            let bytes = serde_json::to_vec(&BackupRecoveryRecord {
                record_id: changed_id.clone(),
                payload: changed,
            })
            .unwrap();
            assert!(matches!(
                decode_with_trusted_context(&bytes, &changed_id, &payload.binding),
                Err(RecordError::BindingMismatch)
            ));
        }
    }

    #[test]
    fn changed_recovery_path_cannot_override_original_trusted_anchor() {
        let original = v2_fixture();
        let trusted = original.payload.binding.clone();
        let mut changed = original.payload.clone();
        changed.artifacts[0].recovery_path = "/elsewhere/recovery".into();
        let changed_id = record_id(&changed).unwrap();
        let bytes = serde_json::to_vec(&BackupRecoveryRecord {
            record_id: changed_id.clone(),
            payload: changed,
        })
        .unwrap();
        assert!(matches!(
            decode_with_trusted_context(&bytes, original.record_id(), &trusted),
            Err(RecordError::BindingMismatch)
        ));
        // A digest supplied by the modified record is not a trusted anchor.
        assert!(decode_with_trusted_context(&bytes, &changed_id, &trusted).is_ok());
    }

    #[test]
    fn receipt_v2_rejects_artifact_substitution_with_original_receipt_id() {
        let binding = decode(FIXTURE.as_bytes(), RECORD_ID)
            .unwrap()
            .payload
            .binding;
        let mut artifact = crate::BackupArtifactReceipt {
            ordinal: 1,
            kind: crate::MetadataBackupKind::PartitionTable,
            artifact_path: "/var/lib/lsm/backups/primary".into(),
            expected_identity: crate::BackupExpectedIdentity::PartitionTable {
                disk: "/dev/vda".into(),
                table_label: "gpt".into(),
                table_id: Some("123".into()),
            },
            device_id: 123,
            inode: 456,
            size_bytes: 42,
            sha256: "2".repeat(64),
        };
        let original_id = "573c963f221eeb5287715a6dd620a3f7b3f84f31facbccdb4de567f8c32001fe";
        assert!(verify_receipt_artifacts(
            &binding,
            &[artifact.clone()],
            original_id
        ));
        artifact.sha256 = "3".repeat(64);
        assert!(!verify_receipt_artifacts(
            &binding,
            &[artifact],
            original_id
        ));
    }

    #[test]
    fn valid_record_id_cannot_override_trusted_session_context() {
        let record = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        let mut trusted = record.payload.binding.clone();
        assert!(check_trusted_context(&record, &trusted));
        trusted.session_id = "9".repeat(64);
        assert!(!check_trusted_context(&record, &trusted));
    }

    #[test]
    fn v2_reproduces_capture_receipt_and_rejects_rebound_tampering() {
        let old = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        let mut payload = old.payload;
        payload.schema_version = 2;
        payload.binding.receipt_id =
            "573c963f221eeb5287715a6dd620a3f7b3f84f31facbccdb4de567f8c32001fe".into();
        payload.artifacts[0].capture_device_id = Some(123);
        payload.artifacts[0].capture_inode = Some(456);
        let record = BackupRecoveryRecord::new(payload.clone()).unwrap();
        let bytes = record.encode().unwrap();
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &payload.binding).is_ok());
        let mut unrelated = payload.binding.clone();
        unrelated.session_id = "9".repeat(64);
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &unrelated).is_err());

        let mut changed_inode = payload.clone();
        changed_inode.artifacts[0].capture_inode = Some(457);
        let mut changed_hash = payload.clone();
        changed_hash.artifacts[0].sha256 = "3".repeat(64);
        let mut changed_path = payload;
        changed_path.artifacts[0].primary_path = "/var/lib/lsm/backups/changed".into();
        for tampered in [changed_inode, changed_hash, changed_path] {
            let changed_id = record_id(&tampered).unwrap();
            let bytes = serde_json::to_vec(&BackupRecoveryRecord {
                record_id: changed_id.clone(),
                payload: tampered,
            })
            .unwrap();
            assert!(decode(&bytes, &changed_id).is_err());
        }
    }

    #[test]
    fn copy_metadata_must_match_both_copies_and_capture_receipt() {
        let identity = crate::BackupExpectedIdentity::PartitionTable {
            disk: "/dev/vda".into(),
            table_label: "gpt".into(),
            table_id: Some("123".into()),
        };
        let command = crate::BackupCommandSpec {
            program: "sfdisk".into(),
            args: Vec::new(),
            stdin_path: None,
            stdout_path: None,
            mutates_storage_metadata: false,
        };
        let requirement = crate::MetadataBackupRequirement {
            ordinal: 1,
            kind: crate::MetadataBackupKind::PartitionTable,
            artifact_path: "/backups/primary".into(),
            expected_identity: identity.clone(),
            capture: command.clone(),
            recovery: command,
            verification_notes: Vec::new(),
        };
        let artifact = crate::BackupArtifactReceipt {
            ordinal: 1,
            kind: crate::MetadataBackupKind::PartitionTable,
            artifact_path: "/backups/primary".into(),
            expected_identity: identity,
            device_id: 123,
            inode: 456,
            size_bytes: 42,
            sha256: "2".repeat(64),
        };
        let mut pair = ExperimentalCopyPair {
            ordinal: 1,
            primary: ExperimentalCopyView {
                path: "/backups/primary".into(),
                size_bytes: 42,
                sha256: "2".repeat(64),
                device_id: 123,
                inode: 456,
            },
            recovery: ExperimentalCopyView {
                path: "/backups.recovery/primary.recovery".into(),
                size_bytes: 42,
                sha256: "2".repeat(64),
                device_id: 123,
                inode: 457,
            },
        };
        let root = Path::new("/backups");
        let recovery_root = Path::new("/backups.recovery");
        assert!(copy_pair_matches(
            &requirement,
            &artifact,
            &pair,
            root,
            recovery_root
        ));
        pair.recovery.sha256 = "3".repeat(64);
        assert!(!copy_pair_matches(
            &requirement,
            &artifact,
            &pair,
            root,
            recovery_root
        ));
        pair.recovery.sha256 = "2".repeat(64);
        pair.recovery.inode = 456;
        assert!(!copy_pair_matches(
            &requirement,
            &artifact,
            &pair,
            root,
            recovery_root
        ));
        pair.recovery.inode = 457;
        pair.primary.device_id = 124;
        assert!(!copy_pair_matches(
            &requirement,
            &artifact,
            &pair,
            root,
            recovery_root
        ));
        pair.primary.device_id = 123;
        pair.recovery.path = "/elsewhere/primary.recovery".into();
        assert!(!copy_pair_matches(
            &requirement,
            &artifact,
            &pair,
            root,
            recovery_root
        ));
    }

    #[test]
    fn adapter_binds_real_manifest_and_receipt_to_trusted_context() {
        let (_handoff, manifest, receipt, lock_path, temporary_root) =
            crate::backup_capture::tests::captured_direct_fixture("recovery-adapter");
        let trusted = RecoveryBinding {
            journal_id: receipt.recovery_journal_id().into(),
            session_id: receipt.recovery_session_id().into(),
            handoff_id: manifest.handoff_id().into(),
            plan_id: manifest.plan_id().into(),
            target_manifest_digest: manifest.target_manifest_digest().into(),
            manifest_id: manifest.manifest_id().into(),
            receipt_id: receipt.receipt_id().into(),
        };
        let root = Path::new(manifest.artifact_directory());
        let mut recovery_directory = root.file_name().unwrap().to_os_string();
        recovery_directory.push(".recovery");
        let recovery_root = root.with_file_name(recovery_directory);
        // Synthetic view by design: no claim is made that recovery files exist.
        let mut pairs = receipt
            .artifacts()
            .iter()
            .map(|artifact| {
                let mut recovery_name = Path::new(&artifact.artifact_path)
                    .file_name()
                    .unwrap()
                    .to_os_string();
                recovery_name.push(".recovery");
                ExperimentalCopyPair {
                    ordinal: artifact.ordinal,
                    primary: ExperimentalCopyView {
                        path: artifact.artifact_path.clone(),
                        size_bytes: artifact.size_bytes,
                        sha256: artifact.sha256.clone(),
                        device_id: artifact.device_id,
                        inode: artifact.inode,
                    },
                    recovery: ExperimentalCopyView {
                        path: recovery_root.join(recovery_name).to_str().unwrap().into(),
                        size_bytes: artifact.size_bytes,
                        sha256: artifact.sha256.clone(),
                        device_id: artifact.device_id,
                        inode: artifact.inode ^ 1,
                    },
                }
            })
            .collect::<Vec<_>>();
        let record =
            from_experimental_verified_metadata(&manifest, &receipt, &trusted, &pairs).unwrap();
        assert_eq!(record.payload.schema_version, 2);
        let bytes = record.encode().unwrap();
        assert_eq!(
            decode_with_trusted_context(&bytes, record.record_id(), &trusted).unwrap(),
            record
        );
        let mut other_context = trusted.clone();
        other_context.session_id = "9".repeat(64);
        assert!(
            from_experimental_verified_metadata(&manifest, &receipt, &other_context, &pairs)
                .is_err()
        );
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &other_context).is_err());
        pairs[0].recovery.sha256 = "0".repeat(64);
        assert!(
            from_experimental_verified_metadata(&manifest, &receipt, &trusted, &pairs).is_err()
        );

        drop(receipt);
        let _ = std::fs::remove_dir_all(lock_path.parent().unwrap());
        let _ = std::fs::remove_dir_all(temporary_root);
    }

    #[test]
    fn independently_computed_valid_record_is_accepted() {
        let result = decode(FIXTURE.as_bytes(), RECORD_ID);
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn v3_requires_and_binds_both_verity_measurements() {
        let mut payload = v2_fixture().payload;
        payload.schema_version = 3;
        assert!(BackupRecoveryRecord::new(payload.clone()).is_err());
        payload.artifacts[0].verity = Some(VerityPair {
            primary_sha256: "4".repeat(64),
            recovery_sha256: "5".repeat(64),
        });
        let record = BackupRecoveryRecord::new(payload.clone()).unwrap();
        let trusted = payload.binding.clone();
        let bytes = record.encode().unwrap();
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &trusted).is_ok());
        let mut downgraded = payload.clone();
        downgraded.schema_version = 2;
        assert!(BackupRecoveryRecord::new(downgraded).is_err());
        let mut another_session = trusted.clone();
        another_session.session_id = "7".repeat(64);
        assert!(decode_with_trusted_context(&bytes, record.record_id(), &another_session).is_err());
        for primary in [true, false] {
            let mut changed = payload.clone();
            let verity = changed.artifacts[0].verity.as_mut().unwrap();
            if primary {
                verity.primary_sha256 = "6".repeat(64);
            } else {
                verity.recovery_sha256 = "6".repeat(64);
            }
            let changed = BackupRecoveryRecord::new(changed).unwrap();
            assert!(decode_with_trusted_context(
                &changed.encode().unwrap(),
                record.record_id(),
                &trusted
            )
            .is_err());
        }
        payload.artifacts[0].verity.as_mut().unwrap().primary_sha256 = "A".repeat(64);
        assert!(BackupRecoveryRecord::new(payload).is_err());
    }

    #[test]
    fn v3_experimental_adapter_requires_one_pair_per_artifact() {
        let v2 = v2_fixture();
        assert!(experimental_bind_verity(&v2, &[]).is_err());
        let pairs = vec![([0x11; 32], [0x22; 32])];
        let v3 = experimental_bind_verity(&v2, &pairs).unwrap();
        assert_eq!(v3.payload.schema_version, 3);
        let measurements = v3.payload.artifacts[0].verity.as_ref().unwrap();
        assert_eq!(measurements.primary_sha256, "11".repeat(32));
        assert_eq!(measurements.recovery_sha256, "22".repeat(32));
        assert_ne!(v2.record_id(), v3.record_id());
        assert!(experimental_bind_verity(&v3, &pairs).is_err());
    }

    #[test]
    fn round_trip_preserves_record_and_external_anchor() {
        let original = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        let created = BackupRecoveryRecord::new(original.payload.clone()).unwrap();
        assert_eq!(created.record_id(), RECORD_ID);
        let bytes = created.encode().unwrap();
        assert_eq!(decode(&bytes, RECORD_ID).unwrap(), original);
    }

    #[test]
    fn constructor_never_returns_an_unencodable_record_at_size_limit() {
        let original = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        let mut payload = original.payload;
        payload.artifacts.clear();
        for index in 0..MAX_ARTIFACTS {
            let mut artifact = decode(FIXTURE.as_bytes(), RECORD_ID)
                .unwrap()
                .payload
                .artifacts
                .remove(0);
            artifact.ordinal = index as u32 + 1;
            artifact.primary_path = format!("/primary/{index}/{}", "a".repeat(1800));
            artifact.recovery_path = format!("/recovery/{index}/{}", "b".repeat(1800));
            payload.artifacts.push(artifact);
        }
        // Locate a record whose payload fits but whose envelope crosses the limit.
        let current = serde_json::to_vec(&payload).unwrap().len();
        assert!(current < MAX_RECORD_BYTES - 50);
        for index in 0..MAX_RECORD_BYTES - 50 - current {
            payload.artifacts[index % MAX_ARTIFACTS]
                .primary_path
                .push('a');
        }
        assert!(serde_json::to_vec(&payload).unwrap().len() <= MAX_RECORD_BYTES);
        assert!(validate_payload(&payload).is_ok());
        if let Ok(record) = BackupRecoveryRecord::new(payload) {
            assert!(
                record.encode().is_ok(),
                "constructor accepted an oversized envelope"
            );
        }
    }

    #[test]
    fn changed_artifact_or_binding_and_wrong_external_anchor_are_rejected() {
        for modified in [
            FIXTURE.replace("/backups/primary", "/backups/changed"),
            FIXTURE.replace("\"size_bytes\":42", "\"size_bytes\":43"),
            FIXTURE.replace(&"a".repeat(64), &"3".repeat(64)),
            FIXTURE.replace(&"2".repeat(64), &"4".repeat(64)),
        ] {
            assert!(decode(modified.as_bytes(), RECORD_ID).is_err());
        }
        assert!(decode(FIXTURE.as_bytes(), &"0".repeat(64)).is_err());
        assert!(decode(FIXTURE.as_bytes(), "bad-anchor").is_err());
    }

    #[test]
    fn changed_record_and_recomputed_digest_still_reject_original_anchor() {
        let mut record = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        record.payload.binding.journal_id = "3".repeat(64);
        record.record_id = record_id(&record.payload).unwrap();
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(decode(&bytes, RECORD_ID).is_err());
        // A digest supplied by the same untrusted record is not authentication.
        assert!(decode(&bytes, &record.record_id).is_ok());
    }

    #[test]
    fn malformed_oversized_unknown_and_duplicate_fields_are_rejected() {
        let oversized = vec![b' '; MAX_RECORD_BYTES + 1];
        assert!(matches!(
            decode(&oversized, RECORD_ID),
            Err(RecordError::TooLarge)
        ));
        for modified in [
            "{".to_owned(),
            FIXTURE.replace("\"size_bytes\":42", "\"size_bytes\":42,\"extra\":1"),
            FIXTURE.replace(
                "\"schema_version\":1",
                "\"schema_version\":1,\"schema_version\":1",
            ),
            FIXTURE.replace("\"schema_version\":1", "\"schema_version\":2"),
        ] {
            assert!(decode(modified.as_bytes(), RECORD_ID).is_err());
        }
    }

    #[test]
    fn structural_checks_reject_recomputed_invalid_records() {
        let original = decode(FIXTURE.as_bytes(), RECORD_ID).unwrap();
        let mut invalid_payloads = Vec::new();
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].recovery_path = invalid.artifacts[0].primary_path.clone();
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].recovery_path = "/var/lib/lsm/../outside".into();
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].size_bytes = 0;
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].size_bytes = MAX_ARTIFACT_BYTES + 1;
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].ordinal = 2;
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts[0].sha256 = "A".repeat(64);
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        invalid.artifacts.clear();
        invalid_payloads.push(invalid);
        let mut invalid = original.payload.clone();
        for index in 1..=MAX_ARTIFACTS {
            let mut extra = original.payload.artifacts[0].clone();
            extra.ordinal = index as u32 + 1;
            extra.primary_path = format!("/backups/{index}");
            extra.recovery_path = format!("/recovery/{index}");
            invalid.artifacts.push(extra);
        }
        invalid_payloads.push(invalid);
        for payload in invalid_payloads {
            let id = record_id(&payload).unwrap();
            let bytes = serde_json::to_vec(&BackupRecoveryRecord {
                record_id: id.clone(),
                payload,
            })
            .unwrap();
            assert!(decode(&bytes, &id).is_err());
        }
    }
}
