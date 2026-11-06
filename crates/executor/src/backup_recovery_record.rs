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

const DOMAIN: &[u8] = b"linux-storage-manager:backup-recovery-record:v1\0";
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
    if payload.schema_version != 1
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
        {
            return Err(RecordError::Invalid);
        }
    }
    Ok(())
}

fn record_id(payload: &RecoveryPayload) -> Result<String, RecordError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| RecordError::Malformed)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
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

#[cfg(test)]
mod tests {
    const RECORD_ID: &str = "54a186958ab3c29898a9213a1b8d2a6d374a817e29079649efa304842a204d5c";
    const FIXTURE: &str = r#"{"record_id":"54a186958ab3c29898a9213a1b8d2a6d374a817e29079649efa304842a204d5c","payload":{"schema_version":1,"journal_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","session_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","handoff_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","plan_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","target_manifest_digest":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","manifest_id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","receipt_id":"1111111111111111111111111111111111111111111111111111111111111111","artifacts":[{"ordinal":1,"identity":{"kind":"partition_table","disk":"/dev/vda","table_label":"gpt","table_id":"123"},"primary_path":"/var/lib/lsm/backups/primary","recovery_path":"/var/lib/lsm/backups/recovery","size_bytes":42,"sha256":"2222222222222222222222222222222222222222222222222222222222222222"}]}}"#;

    use super::*;

    // Red-phase stubs. Production adapter checks replace these before use.
    fn verify_receipt_artifacts(
        _binding: &RecoveryBinding,
        _artifacts: &[crate::BackupArtifactReceipt],
        _expected_receipt_id: &str,
    ) -> bool {
        true
    }

    fn check_trusted_context(_record: &BackupRecoveryRecord, _trusted: &RecoveryBinding) -> bool {
        true
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
    fn independently_computed_valid_record_is_accepted() {
        let result = decode(FIXTURE.as_bytes(), RECORD_ID);
        assert!(result.is_ok(), "{result:?}");
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
