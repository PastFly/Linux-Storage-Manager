use lsm_planner::{ExecutionStartBinding, JournalPhase};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    LockedExecutionSession, LockedSessionError, PreparedPrivilegedInvocation,
    PrivilegedHelperRequest,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedExecutionStartReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub execution_id: String,
    pub prepared_id: String,
    pub journal_id: String,
    pub first_plan_step_id: u32,
    pub executing_journal_digest: String,
}

impl PrivilegedExecutionStartReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.prepared_id,
            &self.journal_id,
            self.first_plan_step_id,
            &self.executing_journal_digest,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedExecutionStartError {
    #[error("prepared invocation integrity check failed")]
    PreparedIntegrityMismatch,
    #[error("execution binding integrity check failed")]
    ExecutionIntegrityMismatch,
    #[error("prepared invocation does not match the helper request")]
    PreparedRequestMismatch,
    #[error("helper request does not match the exact execution binding")]
    RequestExecutionMismatch,
    #[error("only the first authorized mutation step may start execution")]
    FirstStepMismatch,
    #[error("execution start requires an approved durable journal")]
    JournalNotApproved,
    #[error("locked execution session does not match the execution binding")]
    SessionExecutionMismatch,
    #[error("could not persist the exact execution start: {0}")]
    Session(#[from] LockedSessionError),
    #[error("execution-start receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn journal_digest<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value)?)
    ))
}

fn validate_start_binding(
    session: &LockedExecutionSession<'_>,
    execution: &ExecutionStartBinding,
    request: &PrivilegedHelperRequest,
    prepared: &PreparedPrivilegedInvocation,
) -> Result<u32, PrivilegedExecutionStartError> {
    if !prepared.integrity_matches()? {
        return Err(PrivilegedExecutionStartError::PreparedIntegrityMismatch);
    }
    if !execution.integrity_matches()? {
        return Err(PrivilegedExecutionStartError::ExecutionIntegrityMismatch);
    }
    if session.journal().phase != JournalPhase::Approved
        || session.journal().mutation_may_have_started
        || session.journal().execution.is_some()
    {
        return Err(PrivilegedExecutionStartError::JournalNotApproved);
    }

    if prepared.request_id != request.request_id
        || prepared.execution_id != request.execution_id
        || prepared.plan_step_id != request.plan_step_id
        || prepared.live_identity_digest != request.fresh_identity_digest
    {
        return Err(PrivilegedExecutionStartError::PreparedRequestMismatch);
    }

    if request.execution_id != execution.execution_id
        || request.source_manifest_id != execution.source_manifest_id
        || request.native_manifest_digest != execution.native_manifest_digest
        || request.fresh_identity_digest != execution.fresh_identity_digest
    {
        return Err(PrivilegedExecutionStartError::RequestExecutionMismatch);
    }

    let first_step = execution
        .mutation_step_ids
        .first()
        .copied()
        .ok_or(PrivilegedExecutionStartError::FirstStepMismatch)?;
    if request.plan_step_id != first_step {
        return Err(PrivilegedExecutionStartError::FirstStepMismatch);
    }

    if session.journal().journal_id != execution.journal_id
        || session.journal().plan_id != execution.plan_id
        || session.journal().baseline_manifest_digest != execution.fresh_identity_digest
        || session
            .journal()
            .approval
            .as_ref()
            .map(|approval| approval.approval_id.as_str())
            != Some(execution.approval_id.as_str())
    {
        return Err(PrivilegedExecutionStartError::SessionExecutionMismatch);
    }

    Ok(first_step)
}

/// Persist the conservative pre-spawn mutation boundary only after the exact
/// helper-side prepared invocation has been verified against the locked,
/// approved execution binding.
///
/// This function does not spawn a storage command. On success the durable
/// journal enters Executing with mutation_may_have_started=true before a
/// future privileged spawn is permitted, eliminating a crash window between
/// process start and durable execution-state persistence.
pub fn persist_prepared_privileged_execution_start(
    session: &mut LockedExecutionSession<'_>,
    execution: &ExecutionStartBinding,
    request: &PrivilegedHelperRequest,
    prepared: &PreparedPrivilegedInvocation,
) -> Result<PrivilegedExecutionStartReceipt, PrivilegedExecutionStartError> {
    let first_step = validate_start_binding(session, execution, request, prepared)?;
    session.persist_execution_started(execution)?;

    let executing_journal_digest = journal_digest(session.journal())?;
    let mut receipt = PrivilegedExecutionStartReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        execution_id: execution.execution_id.clone(),
        prepared_id: prepared.prepared_id.clone(),
        journal_id: execution.journal_id.clone(),
        first_plan_step_id: first_step,
        executing_journal_digest,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn execution() -> ExecutionStartBinding {
        let mut binding = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: digest('1'),
            plan_id: digest('2'),
            approval_id: digest('3'),
            source_manifest_id: digest('4'),
            native_manifest_digest: digest('5'),
            fresh_identity_digest: digest('6'),
            mutation_step_ids: vec![7, 8],
            approved_journal_digest: digest('9'),
        };
        binding.execution_id = binding.expected_execution_id().unwrap();
        binding
    }

    fn request(execution: &ExecutionStartBinding) -> PrivilegedHelperRequest {
        PrivilegedHelperRequest {
            schema_version: crate::PRIVILEGED_HELPER_PROTOCOL_VERSION,
            request_id: digest('a'),
            execution_id: execution.execution_id.clone(),
            source_manifest_id: execution.source_manifest_id.clone(),
            native_manifest_digest: execution.native_manifest_digest.clone(),
            fresh_identity_digest: execution.fresh_identity_digest.clone(),
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            plan_step_id: 7,
            operation: crate::NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid: "lv-uuid".into(),
                additional_extents: 1,
                expected_lv_size_bytes: 1024,
            },
        }
    }

    #[test]
    fn execution_start_receipt_is_tamper_evident() {
        let mut receipt = PrivilegedExecutionStartReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: digest('a'),
            prepared_id: digest('b'),
            journal_id: digest('c'),
            first_plan_step_id: 7,
            executing_journal_digest: digest('d'),
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        assert!(receipt.integrity_matches().unwrap());

        receipt.first_plan_step_id = 8;
        assert!(!receipt.integrity_matches().unwrap());
    }

    #[test]
    fn request_must_start_with_first_execution_step() {
        let execution = execution();
        let mut request = request(&execution);
        request.plan_step_id = 8;
        assert_ne!(
            request.plan_step_id,
            execution.mutation_step_ids.first().copied().unwrap()
        );
    }
}
