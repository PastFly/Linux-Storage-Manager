use std::path::{Component, Path};

use lsm_planner::ExecutionStartBinding;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{FrozenIntentRole, NativeOperationSpec, ValidatedNativeManifest};

pub const PRIVILEGED_HELPER_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedHelperRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub execution_id: String,
    pub source_manifest_id: String,
    pub native_manifest_digest: String,
    pub fresh_identity_digest: String,
    pub plan_step_id: u32,
    pub operation: NativeOperationSpec,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivilegedHelperProtocolError {
    #[error("unsupported privileged-helper protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("execution binding integrity check failed")]
    ExecutionBindingIntegrityMismatch,
    #[error("execution binding does not match the validated native manifest")]
    ExecutionBindingMismatch,
    #[error("plan step {0} is not an authorized mutation step")]
    UnauthorizedStep(u32),
    #[error("plan step {0} does not resolve to exactly one native step")]
    StepNotUnique(u32),
    #[error("plan step {0} is not a mutation candidate")]
    StepNotMutation(u32),
    #[error("privileged-helper request contains an unsafe operation payload")]
    UnsafeOperationPayload,
    #[error("privileged-helper request digest is invalid")]
    RequestDigestMismatch,
    #[error("privileged-helper request serialization failed: {0}")]
    Serialization(String),
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_absolute_path(value: &str) -> bool {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return false;
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn safe_device_path(value: &str) -> bool {
    safe_absolute_path(value) && value.starts_with("/dev/")
}

fn operation_is_safe(operation: &NativeOperationSpec) -> bool {
    match operation {
        NativeOperationSpec::ExtendPartition {
            partition,
            start_sector,
            old_size_sectors,
            new_size_sectors,
            sector_size_bytes,
        } => {
            safe_device_path(partition)
                && *start_sector > 0
                && *old_size_sectors > 0
                && *new_size_sectors > *old_size_sectors
                && matches!(*sector_size_bytes, 512 | 4096)
        }
        NativeOperationSpec::ResizePhysicalVolume {
            pv_uuid,
            expected_pv_size_bytes,
        } => !pv_uuid.is_empty() && *expected_pv_size_bytes > 0,
        NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid,
            additional_extents,
            expected_lv_size_bytes,
        } => !lv_uuid.is_empty() && *additional_extents > 0 && *expected_lv_size_bytes > 0,
        NativeOperationSpec::GrowFilesystem {
            fs_type,
            mountpoint,
        } => match fs_type.as_str() {
            "ext4" => mountpoint.as_deref().is_none_or(safe_absolute_path),
            "xfs" => mountpoint.as_deref().is_some_and(safe_absolute_path),
            _ => false,
        },
        _ => false,
    }
}

fn expected_request_id(
    schema_version: u32,
    execution_id: &str,
    source_manifest_id: &str,
    native_manifest_digest: &str,
    fresh_identity_digest: &str,
    plan_step_id: u32,
    operation: &NativeOperationSpec,
) -> Result<String, PrivilegedHelperProtocolError> {
    let bytes = serde_json::to_vec(&(
        schema_version,
        execution_id,
        source_manifest_id,
        native_manifest_digest,
        fresh_identity_digest,
        plan_step_id,
        operation,
    ))
    .map_err(|error| PrivilegedHelperProtocolError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

pub fn build_privileged_helper_request(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    plan_step_id: u32,
) -> Result<PrivilegedHelperRequest, PrivilegedHelperProtocolError> {
    if execution.schema_version != 1
        || !execution
            .integrity_matches()
            .map_err(|error| PrivilegedHelperProtocolError::Serialization(error.to_string()))?
    {
        return Err(PrivilegedHelperProtocolError::ExecutionBindingIntegrityMismatch);
    }
    if execution.source_manifest_id != validated.manifest().source_manifest_id
        || execution.native_manifest_digest != validated.digest()
        || !is_sha256_hex(&execution.source_manifest_id)
        || !is_sha256_hex(&execution.native_manifest_digest)
        || !is_sha256_hex(&execution.fresh_identity_digest)
    {
        return Err(PrivilegedHelperProtocolError::ExecutionBindingMismatch);
    }
    if !execution.mutation_step_ids.contains(&plan_step_id) {
        return Err(PrivilegedHelperProtocolError::UnauthorizedStep(
            plan_step_id,
        ));
    }

    let mut matches = validated
        .manifest()
        .steps
        .iter()
        .filter(|step| step.plan_step_id == plan_step_id);
    let step = matches
        .next()
        .ok_or(PrivilegedHelperProtocolError::StepNotUnique(plan_step_id))?;
    if matches.next().is_some() {
        return Err(PrivilegedHelperProtocolError::StepNotUnique(plan_step_id));
    }
    if step.role != FrozenIntentRole::MutationCandidate {
        return Err(PrivilegedHelperProtocolError::StepNotMutation(plan_step_id));
    }
    if !operation_is_safe(&step.operation) {
        return Err(PrivilegedHelperProtocolError::UnsafeOperationPayload);
    }

    let request_id = expected_request_id(
        PRIVILEGED_HELPER_PROTOCOL_VERSION,
        &execution.execution_id,
        &execution.source_manifest_id,
        &execution.native_manifest_digest,
        &execution.fresh_identity_digest,
        plan_step_id,
        &step.operation,
    )?;

    Ok(PrivilegedHelperRequest {
        schema_version: PRIVILEGED_HELPER_PROTOCOL_VERSION,
        request_id,
        execution_id: execution.execution_id.clone(),
        source_manifest_id: execution.source_manifest_id.clone(),
        native_manifest_digest: execution.native_manifest_digest.clone(),
        fresh_identity_digest: execution.fresh_identity_digest.clone(),
        plan_step_id,
        operation: step.operation.clone(),
    })
}

pub fn validate_privileged_helper_request(
    request: &PrivilegedHelperRequest,
) -> Result<(), PrivilegedHelperProtocolError> {
    if request.schema_version != PRIVILEGED_HELPER_PROTOCOL_VERSION {
        return Err(PrivilegedHelperProtocolError::UnsupportedVersion(
            request.schema_version,
        ));
    }
    if !is_sha256_hex(&request.execution_id)
        || !is_sha256_hex(&request.source_manifest_id)
        || !is_sha256_hex(&request.native_manifest_digest)
        || !is_sha256_hex(&request.fresh_identity_digest)
        || request.plan_step_id == 0
        || !operation_is_safe(&request.operation)
    {
        return Err(PrivilegedHelperProtocolError::UnsafeOperationPayload);
    }

    let expected = expected_request_id(
        request.schema_version,
        &request.execution_id,
        &request.source_manifest_id,
        &request.native_manifest_digest,
        &request.fresh_identity_digest,
        request.plan_step_id,
        &request.operation,
    )?;
    if request.request_id != expected {
        return Err(PrivilegedHelperProtocolError::RequestDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        validate_and_bind_native_manifest, FrozenIntentRole, NativeCompiledManifest,
        NativeCompiledStep, NativeVerificationBarrier,
    };
    use lsm_planner::{ExecutionStartBinding, Reversibility};

    fn validated(operation: NativeOperationSpec) -> ValidatedNativeManifest {
        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: "a".repeat(64),
            steps: vec![NativeCompiledStep {
                plan_step_id: 3,
                depends_on: vec![],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation,
            }],
            verification_barriers: vec![NativeVerificationBarrier {
                after_plan_step_id: 3,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            }],
        })
        .unwrap()
    }

    fn execution(validated: &ValidatedNativeManifest) -> ExecutionStartBinding {
        let mut binding = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: "journal".into(),
            plan_id: "plan".into(),
            approval_id: "approval".into(),
            source_manifest_id: validated.manifest().source_manifest_id.clone(),
            native_manifest_digest: validated.digest().to_owned(),
            fresh_identity_digest: "b".repeat(64),
            mutation_step_ids: vec![3],
            approved_journal_digest: "c".repeat(64),
        };
        binding.execution_id = binding.expected_execution_id().unwrap();
        binding
    }

    #[test]
    fn exact_native_mutation_builds_deterministic_protocol_request() {
        let validated = validated(NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid: "lv-uuid".into(),
            additional_extents: 8,
            expected_lv_size_bytes: 1024 * 1024 * 1024,
        });
        let execution = execution(&validated);

        let first = build_privileged_helper_request(&validated, &execution, 3).unwrap();
        let second = build_privileged_helper_request(&validated, &execution, 3).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.schema_version, PRIVILEGED_HELPER_PROTOCOL_VERSION);
        assert_eq!(first.plan_step_id, 3);
        assert_eq!(first.native_manifest_digest, validated.digest());
        validate_privileged_helper_request(&first).unwrap();
    }

    #[test]
    fn protocol_rejects_unlisted_or_unsafe_filesystem_payloads() {
        let validated = validated(NativeOperationSpec::GrowFilesystem {
            fs_type: "xfs".into(),
            mountpoint: None,
        });
        let execution = execution(&validated);
        assert_eq!(
            build_privileged_helper_request(&validated, &execution, 3),
            Err(PrivilegedHelperProtocolError::UnsafeOperationPayload)
        );
    }

    #[test]
    fn request_digest_detects_operation_tampering() {
        let validated = validated(NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid: "lv-uuid".into(),
            additional_extents: 4,
            expected_lv_size_bytes: 512 * 1024 * 1024,
        });
        let execution = execution(&validated);
        let mut request = build_privileged_helper_request(&validated, &execution, 3).unwrap();

        request.operation = NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid: "lv-uuid".into(),
            additional_extents: 5,
            expected_lv_size_bytes: 512 * 1024 * 1024,
        };

        assert_eq!(
            validate_privileged_helper_request(&request),
            Err(PrivilegedHelperProtocolError::RequestDigestMismatch)
        );
    }

    #[test]
    fn request_builder_rejects_foreign_execution_binding() {
        let validated = validated(NativeOperationSpec::ResizePhysicalVolume {
            pv_uuid: "pv-uuid".into(),
            expected_pv_size_bytes: 1024,
        });
        let mut execution = execution(&validated);
        execution.native_manifest_digest = "d".repeat(64);
        execution.execution_id = execution.expected_execution_id().unwrap();

        assert_eq!(
            build_privileged_helper_request(&validated, &execution, 3),
            Err(PrivilegedHelperProtocolError::ExecutionBindingMismatch)
        );
    }
}
