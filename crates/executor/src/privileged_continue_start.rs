use lsm_planner::{JournalPhase, OperationJournal};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    validate_privileged_helper_request, LockedExecutionSession, LockedSessionError,
    PreparedPrivilegedInvocation, PrivilegedHelperProtocolError, PrivilegedHelperRequest,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedContinuationStartReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub execution_id: String,
    pub verified_boundary_id: String,
    pub prepared_id: String,
    pub journal_id: String,
    pub plan_step_id: u32,
    pub live_identity_digest: String,
    pub executing_journal_digest: String,
}

impl PrivilegedContinuationStartReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    pub(crate) fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.verified_boundary_id,
            &self.prepared_id,
            &self.journal_id,
            self.plan_step_id,
            &self.live_identity_digest,
            &self.executing_journal_digest,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedContinuationStartError {
    #[error("privileged-helper request validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("durable journal is not at a verified executing continuation boundary")]
    JournalNotExecuting,
    #[error("durable execution binding is missing or invalid")]
    ExecutionBindingInvalid,
    #[error("durable verified boundary is missing or invalid")]
    VerifiedBoundaryInvalid,
    #[error("request is not the exact next authorized mutation step")]
    StepSequenceMismatch,
    #[error("prepared continuation invocation integrity check failed")]
    PreparedIntegrityMismatch,
    #[error("prepared invocation does not match the continuation request")]
    PreparedRequestMismatch,
    #[error("continuation request does not match the durable execution binding")]
    RequestExecutionMismatch,
    #[error("continuation request does not consume the latest verified identity")]
    IdentityBoundaryMismatch,
    #[error("durable journal access failed: {0}")]
    Session(#[from] LockedSessionError),
    #[error("continuation-start receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn journal_digest(journal: &OperationJournal) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(journal)?)
    ))
}

fn build_continuation_start_receipt(
    journal: &OperationJournal,
    request: &PrivilegedHelperRequest,
    prepared: &PreparedPrivilegedInvocation,
) -> Result<PrivilegedContinuationStartReceipt, PrivilegedContinuationStartError> {
    validate_privileged_helper_request(request)?;
    if journal.phase != JournalPhase::Executing || !journal.mutation_may_have_started {
        return Err(PrivilegedContinuationStartError::JournalNotExecuting);
    }

    let execution = journal
        .execution
        .as_ref()
        .ok_or(PrivilegedContinuationStartError::ExecutionBindingInvalid)?;
    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(PrivilegedContinuationStartError::ExecutionBindingInvalid);
    }
    if execution.journal_id != journal.journal_id
        || execution.plan_id != journal.plan_id
        || request.execution_id != execution.execution_id
        || request.source_manifest_id != execution.source_manifest_id
        || request.native_manifest_digest != execution.native_manifest_digest
    {
        return Err(PrivilegedContinuationStartError::RequestExecutionMismatch);
    }

    let boundary = journal
        .verified_boundary
        .as_ref()
        .ok_or(PrivilegedContinuationStartError::VerifiedBoundaryInvalid)?;
    if boundary.schema_version != 1
        || !boundary.integrity_matches().unwrap_or(false)
        || boundary.execution_id != execution.execution_id
        || boundary.final_step_id.is_some()
        || boundary.final_identity_digest.is_some()
    {
        return Err(PrivilegedContinuationStartError::VerifiedBoundaryInvalid);
    }

    let position = execution
        .mutation_step_ids
        .iter()
        .position(|step_id| *step_id == request.plan_step_id)
        .ok_or(PrivilegedContinuationStartError::StepSequenceMismatch)?;
    if position == 0
        || boundary.completed_step_id != execution.mutation_step_ids[position - 1]
        || boundary.next_step_id != request.plan_step_id
    {
        return Err(PrivilegedContinuationStartError::StepSequenceMismatch);
    }
    if request.fresh_identity_digest != boundary.fresh_identity_digest {
        return Err(PrivilegedContinuationStartError::IdentityBoundaryMismatch);
    }

    if !prepared.integrity_matches()? {
        return Err(PrivilegedContinuationStartError::PreparedIntegrityMismatch);
    }
    if prepared.request_id != request.request_id
        || prepared.execution_id != request.execution_id
        || prepared.plan_step_id != request.plan_step_id
        || prepared.live_identity_digest != request.fresh_identity_digest
    {
        return Err(PrivilegedContinuationStartError::PreparedRequestMismatch);
    }

    let mut receipt = PrivilegedContinuationStartReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        execution_id: execution.execution_id.clone(),
        verified_boundary_id: boundary.boundary_id.clone(),
        prepared_id: prepared.prepared_id.clone(),
        journal_id: journal.journal_id.clone(),
        plan_step_id: request.plan_step_id,
        live_identity_digest: request.fresh_identity_digest.clone(),
        executing_journal_digest: journal_digest(journal)?,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Bind a prepared later mutation step to the exact durable verified boundary.
///
/// Unlike the first mutation step, this does not create a new execution
/// journal transition. The current Executing record already contains the
/// verified boundary that authorizes exactly one adjacent next step.
pub fn bind_prepared_privileged_continuation(
    session: &LockedExecutionSession<'_>,
    request: &PrivilegedHelperRequest,
    prepared: &PreparedPrivilegedInvocation,
) -> Result<PrivilegedContinuationStartReceipt, PrivilegedContinuationStartError> {
    session.require_current_durable_journal()?;
    build_continuation_start_receipt(session.journal(), request, prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_privileged_helper_request_for_durable_step, validate_and_bind_native_manifest,
        FrozenIntentRole, NativeCompiledManifest, NativeCompiledStep, NativeOperationSpec,
        NativeVerificationBarrier, PrivilegedToolResolution, TrustedToolIdentity,
    };
    use lsm_planner::{
        ExecutionStartBinding, LayerRouteStatus, Reversibility, TargetIdentityManifest,
        VerifiedMutationBoundaryBinding,
    };

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn validated() -> crate::ValidatedNativeManifest {
        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: digest('a'),
            steps: vec![
                NativeCompiledStep {
                    plan_step_id: 3,
                    depends_on: vec![],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::ExtendLogicalVolume {
                        lv_uuid: "lv-uuid".into(),
                        additional_extents: 1,
                        expected_lv_size_bytes: 512,
                    },
                },
                NativeCompiledStep {
                    plan_step_id: 4,
                    depends_on: vec![3],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::GrowFilesystem {
                        fs_type: "ext4".into(),
                        mountpoint: Some("/mnt/data".into()),
                    },
                },
            ],
            verification_barriers: vec![
                NativeVerificationBarrier {
                    after_plan_step_id: 3,
                    before_next_mutation: true,
                    require_fresh_target_identity: true,
                    require_fresh_capabilities: true,
                    require_expected_state_check: true,
                    stop_on_mismatch: true,
                },
                NativeVerificationBarrier {
                    after_plan_step_id: 4,
                    before_next_mutation: true,
                    require_fresh_target_identity: true,
                    require_fresh_capabilities: true,
                    require_expected_state_check: true,
                    stop_on_mismatch: true,
                },
            ],
        })
        .unwrap()
    }

    fn execution(validated: &crate::ValidatedNativeManifest) -> ExecutionStartBinding {
        let mut value = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: digest('1'),
            plan_id: digest('2'),
            approval_id: digest('3'),
            source_manifest_id: validated.manifest().source_manifest_id.clone(),
            native_manifest_digest: validated.digest().to_owned(),
            fresh_identity_digest: digest('b'),
            mutation_step_ids: vec![3, 4],
            approved_journal_digest: digest('4'),
        };
        value.execution_id = value.expected_execution_id().unwrap();
        value
    }

    fn identity(manifest_digest: String) -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/data".into(),
            manifest_digest,
            resolved_device: "/dev/mapper/vg-data".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![],
            partitions: vec![],
            lvm: vec![],
            filesystem: None,
            mounts: vec![],
        }
    }

    fn journal(execution: &ExecutionStartBinding) -> OperationJournal {
        let mut boundary = VerifiedMutationBoundaryBinding {
            schema_version: 1,
            boundary_id: String::new(),
            execution_id: execution.execution_id.clone(),
            completed_step_id: 3,
            next_step_id: 4,
            fresh_identity_digest: digest('f'),
            final_step_id: None,
            final_identity_digest: None,
        };
        boundary.boundary_id = boundary.expected_boundary_id().unwrap();

        OperationJournal {
            schema_version: 1,
            journal_id: execution.journal_id.clone(),
            plan_id: execution.plan_id.clone(),
            target: "/mnt/data".into(),
            baseline_manifest_digest: execution.fresh_identity_digest.clone(),
            phase: JournalPhase::Executing,
            mutation_may_have_started: true,
            approval: None,
            execution: Some(execution.clone()),
            verified_boundary: Some(boundary),
            events: vec![],
        }
    }

    fn prepared(request: &PrivilegedHelperRequest) -> PreparedPrivilegedInvocation {
        let tools = PrivilegedToolResolution {
            command_digest: digest('8'),
            primary: TrustedToolIdentity {
                program: crate::PrivilegedProgram::Resize2fs,
                requested_path: "/usr/sbin/resize2fs".into(),
                canonical_path: "/usr/sbin/resize2fs".into(),
                device_id: 1,
                inode: 2,
                uid: 0,
                mode: 0o100755,
                size_bytes: 4096,
                sha256: digest('9'),
            },
            kernel_refresh: None,
        };
        let mut value = PreparedPrivilegedInvocation {
            schema_version: 1,
            prepared_id: String::new(),
            request_id: request.request_id.clone(),
            execution_id: request.execution_id.clone(),
            plan_step_id: request.plan_step_id,
            live_identity_digest: request.fresh_identity_digest.clone(),
            command_digest: tools.command_digest.clone(),
            tool_resolution_digest: tools.digest().unwrap(),
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.request_id,
            &value.execution_id,
            value.plan_step_id,
            &value.live_identity_digest,
            &value.command_digest,
            &value.tool_resolution_digest,
        ))
        .unwrap();
        value.prepared_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    #[test]
    fn exact_verified_boundary_binds_the_next_prepared_step() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('f')),
            4,
        )
        .unwrap();
        let prepared = prepared(&request);

        let receipt = build_continuation_start_receipt(&journal, &request, &prepared).unwrap();
        assert!(receipt.integrity_matches().unwrap());
        assert_eq!(receipt.plan_step_id, 4);
        assert_eq!(receipt.live_identity_digest, digest('f'));
        assert_eq!(
            receipt.verified_boundary_id,
            journal.verified_boundary.as_ref().unwrap().boundary_id
        );
    }

    #[test]
    fn stale_pre_mutation_identity_is_rejected_for_continuation() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution);
        assert!(build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b')),
            4,
        )
        .is_err());
    }

    #[test]
    fn tampered_continuation_receipt_is_detected() {
        let mut receipt = PrivilegedContinuationStartReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: digest('a'),
            verified_boundary_id: digest('b'),
            prepared_id: digest('c'),
            journal_id: digest('d'),
            plan_step_id: 4,
            live_identity_digest: digest('e'),
            executing_journal_digest: digest('f'),
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        assert!(receipt.integrity_matches().unwrap());
        receipt.plan_step_id = 5;
        assert!(!receipt.integrity_matches().unwrap());
    }
}
