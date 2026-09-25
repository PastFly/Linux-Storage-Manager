use lsm_planner::{JournalPhase, OperationJournal};
use thiserror::Error;

use crate::{
    validate_privileged_helper_request, LockedExecutionSession, LockedSessionError,
    PrivilegedHelperProtocolError, PrivilegedHelperRequest, PrivilegedLayerVerificationReceipt,
    PrivilegedProcessReceipt, PrivilegedRuntimeDisposition,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedDurableDisposition {
    Continue { next_step_id: u32 },
    Complete,
    RecoveryRequired,
}

#[derive(Debug, Error)]
pub enum PrivilegedDurableTransitionError {
    #[error("durable privileged continuation requires an executing mutation journal")]
    JournalNotExecuting,
    #[error("durable execution binding is missing or invalid")]
    ExecutionBindingInvalid,
    #[error("privileged-helper request validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("privileged process receipt integrity check failed")]
    ProcessReceiptIntegrityMismatch,
    #[error("privileged request/process/execution binding mismatch")]
    RuntimeBindingMismatch,
    #[error("completed mutation step is not in the exact durable execution order")]
    StepSequenceMismatch,
    #[error("durable verified identity chain does not authorize this mutation step")]
    IdentityChainMismatch,
    #[error("successful process outcome requires an exact layer verification receipt")]
    VerificationReceiptMissing,
    #[error("layer verification receipt integrity check failed")]
    VerificationReceiptIntegrityMismatch,
    #[error("layer verification receipt does not match the request/process/execution")]
    VerificationBindingMismatch,
    #[error("durable journal update failed: {0}")]
    Durable(#[from] LockedSessionError),
}

fn execution_for_journal(
    journal: &OperationJournal,
) -> Result<&lsm_planner::ExecutionStartBinding, PrivilegedDurableTransitionError> {
    if journal.phase != JournalPhase::Executing || !journal.mutation_may_have_started {
        return Err(PrivilegedDurableTransitionError::JournalNotExecuting);
    }
    let execution = journal
        .execution
        .as_ref()
        .ok_or(PrivilegedDurableTransitionError::ExecutionBindingInvalid)?;
    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(PrivilegedDurableTransitionError::ExecutionBindingInvalid);
    }
    Ok(execution)
}

fn validate_identity_chain(
    journal: &OperationJournal,
    plan_step_id: u32,
    request_identity_digest: &str,
) -> Result<usize, PrivilegedDurableTransitionError> {
    let execution = execution_for_journal(journal)?;
    let position = execution
        .mutation_step_ids
        .iter()
        .position(|step_id| *step_id == plan_step_id)
        .ok_or(PrivilegedDurableTransitionError::StepSequenceMismatch)?;

    if position == 0 {
        if journal.verified_boundary.is_some()
            || request_identity_digest != execution.fresh_identity_digest
        {
            return Err(PrivilegedDurableTransitionError::IdentityChainMismatch);
        }
        return Ok(position);
    }

    let boundary = journal
        .verified_boundary
        .as_ref()
        .ok_or(PrivilegedDurableTransitionError::IdentityChainMismatch)?;
    if boundary.schema_version != 1
        || !boundary.integrity_matches().unwrap_or(false)
        || boundary.execution_id != execution.execution_id
        || boundary.completed_step_id != execution.mutation_step_ids[position - 1]
        || boundary.next_step_id != plan_step_id
        || boundary.fresh_identity_digest != request_identity_digest
        || boundary.final_step_id.is_some()
        || boundary.final_identity_digest.is_some()
    {
        return Err(PrivilegedDurableTransitionError::IdentityChainMismatch);
    }

    Ok(position)
}

/// Convert the exact runtime and live-verification receipts into the only
/// durable action allowed for the current mutation step.
///
/// A process exit that requests recovery never authorizes continuation.
/// A successful process still requires the exact live M1B32 verification
/// receipt before another mutation or terminal completion is possible.
pub fn classify_privileged_durable_transition(
    journal: &OperationJournal,
    request: &PrivilegedHelperRequest,
    process: &PrivilegedProcessReceipt,
    verification: Option<&PrivilegedLayerVerificationReceipt>,
) -> Result<PrivilegedDurableDisposition, PrivilegedDurableTransitionError> {
    validate_privileged_helper_request(request)?;
    let execution = execution_for_journal(journal)?;

    if process.schema_version != 1 || !process.integrity_matches().unwrap_or(false) {
        return Err(PrivilegedDurableTransitionError::ProcessReceiptIntegrityMismatch);
    }
    if process.execution_id != execution.execution_id
        || request.execution_id != execution.execution_id
        || request.source_manifest_id != execution.source_manifest_id
        || request.native_manifest_digest != execution.native_manifest_digest
        || process.plan_step_id != request.plan_step_id
        || !process.mutation_may_have_started
    {
        return Err(PrivilegedDurableTransitionError::RuntimeBindingMismatch);
    }

    let position =
        validate_identity_chain(journal, request.plan_step_id, &request.fresh_identity_digest)?;

    if process.disposition == PrivilegedRuntimeDisposition::RecoveryRequired {
        return Ok(PrivilegedDurableDisposition::RecoveryRequired);
    }

    let verification =
        verification.ok_or(PrivilegedDurableTransitionError::VerificationReceiptMissing)?;
    if verification.schema_version != 1 || !verification.integrity_matches().unwrap_or(false) {
        return Err(PrivilegedDurableTransitionError::VerificationReceiptIntegrityMismatch);
    }
    if !verification.expected_state_verified
        || verification.execution_id != execution.execution_id
        || verification.process_receipt_id != process.receipt_id
        || verification.request_id != request.request_id
        || verification.plan_step_id != request.plan_step_id
        || verification.before_identity_digest != request.fresh_identity_digest
    {
        return Err(PrivilegedDurableTransitionError::VerificationBindingMismatch);
    }

    match execution.mutation_step_ids.get(position + 1).copied() {
        Some(next_step_id) => Ok(PrivilegedDurableDisposition::Continue { next_step_id }),
        None => Ok(PrivilegedDurableDisposition::Complete),
    }
}

/// Persist one privileged mutation boundary through the interruption-safe
/// journal. Successful verification uses two durable writes:
/// Executing -> Verifying, then verified continuation/completion. A crash
/// between them therefore cannot authorize blind replay.
pub fn persist_privileged_durable_transition(
    session: &mut LockedExecutionSession<'_>,
    request: &PrivilegedHelperRequest,
    process: &PrivilegedProcessReceipt,
    verification: Option<&PrivilegedLayerVerificationReceipt>,
) -> Result<PrivilegedDurableDisposition, PrivilegedDurableTransitionError> {
    session.require_current_durable_journal()?;

    let disposition = match classify_privileged_durable_transition(
        session.journal(),
        request,
        process,
        verification,
    ) {
        Ok(disposition) => disposition,
        Err(error) => {
            if session.journal().mutation_may_have_started
                && matches!(
                    session.journal().phase,
                    JournalPhase::Executing | JournalPhase::Verifying
                )
            {
                session.persist_interrupted(
                    "privileged runtime or verification binding was rejected; reconciliation required",
                )?;
            }
            return Err(error);
        }
    };

    match disposition {
        PrivilegedDurableDisposition::RecoveryRequired => {
            session.persist_interrupted(
                "privileged storage process reported a recovery-required outcome",
            )?;
        }
        PrivilegedDurableDisposition::Continue { next_step_id } => {
            let verification =
                verification.ok_or(PrivilegedDurableTransitionError::VerificationReceiptMissing)?;
            session.persist_verification_started()?;
            session.persist_verification_passed_continue(
                request.plan_step_id,
                next_step_id,
                &verification.fresh_identity_digest,
            )?;
        }
        PrivilegedDurableDisposition::Complete => {
            let verification =
                verification.ok_or(PrivilegedDurableTransitionError::VerificationReceiptMissing)?;
            let mutation_step_count = session
                .journal()
                .execution
                .as_ref()
                .ok_or(PrivilegedDurableTransitionError::ExecutionBindingInvalid)?
                .mutation_step_ids
                .len();

            session.persist_verification_started()?;
            if mutation_step_count == 1 {
                session.persist_completed()?;
            } else {
                session.persist_verified_completed(
                    request.plan_step_id,
                    &verification.fresh_identity_digest,
                )?;
            }
        }
    }

    Ok(disposition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        build_privileged_helper_request_for_durable_step, validate_and_bind_native_manifest,
        FrozenIntentRole, NativeCompiledManifest, NativeCompiledStep, NativeOperationSpec,
        NativeVerificationBarrier,
    };
    use lsm_planner::{
        ExecutionStartBinding, LayerRouteStatus, LvmIdentity, LvmIdentityKind, Reversibility,
        TargetIdentityManifest, VerifiedMutationBoundaryBinding,
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

    fn identity(manifest_digest: String, lv_size: u64) -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/data".into(),
            manifest_digest,
            resolved_device: "/dev/mapper/vg-data".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![],
            partitions: vec![],
            lvm: vec![LvmIdentity {
                kind: LvmIdentityKind::LogicalVolume,
                name: "/dev/mapper/vg-data".into(),
                uuid: Some("lv-uuid".into()),
                size_bytes: lv_size,
                free_bytes: None,
                pe_start_bytes: None,
                extent_size_bytes: None,
                free_extent_count: None,
                pv_count: None,
                lv_count: None,
                attributes: None,
                layout: None,
                role: None,
            }],
            filesystem: None,
            mounts: vec![],
        }
    }

    fn journal(execution: &ExecutionStartBinding) -> OperationJournal {
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
            verified_boundary: None,
            events: vec![],
        }
    }

    fn boundary(
        execution: &ExecutionStartBinding,
        completed: u32,
        next: u32,
        fresh_digest: String,
    ) -> VerifiedMutationBoundaryBinding {
        let mut value = VerifiedMutationBoundaryBinding {
            schema_version: 1,
            boundary_id: String::new(),
            execution_id: execution.execution_id.clone(),
            completed_step_id: completed,
            next_step_id: next,
            fresh_identity_digest: fresh_digest,
            final_step_id: None,
            final_identity_digest: None,
        };
        value.boundary_id = value.expected_boundary_id().unwrap();
        value
    }

    fn process(
        request: &PrivilegedHelperRequest,
        disposition: PrivilegedRuntimeDisposition,
    ) -> PrivilegedProcessReceipt {
        let mut value = PrivilegedProcessReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: request.execution_id.clone(),
            permit_id: digest('5'),
            launch_id: digest('6'),
            plan_step_id: request.plan_step_id,
            command_digest: digest('7'),
            primary_exit_code: if disposition == PrivilegedRuntimeDisposition::RecoveryRequired {
                1
            } else {
                0
            },
            primary_stdout_sha256: digest('8'),
            primary_stderr_sha256: digest('9'),
            primary_stdout_truncated: false,
            primary_stderr_truncated: false,
            kernel_refresh_exit_code: None,
            kernel_refresh_stdout_sha256: None,
            kernel_refresh_stderr_sha256: None,
            kernel_refresh_stdout_truncated: None,
            kernel_refresh_stderr_truncated: None,
            mutation_may_have_started: true,
            disposition,
        };
        value.receipt_id = value.expected_receipt_id().unwrap();
        value
    }

    fn verification(
        request: &PrivilegedHelperRequest,
        process: &PrivilegedProcessReceipt,
        fresh_digest: String,
    ) -> PrivilegedLayerVerificationReceipt {
        let operation = match request.operation {
            NativeOperationSpec::ExtendPartition { .. } => "extend_partition",
            NativeOperationSpec::ResizePhysicalVolume { .. } => "resize_physical_volume",
            NativeOperationSpec::ExtendLogicalVolume { .. } => "extend_logical_volume",
            NativeOperationSpec::GrowFilesystem { .. } => "grow_filesystem",
            _ => "unsupported",
        };
        let mut value = PrivilegedLayerVerificationReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: request.execution_id.clone(),
            process_receipt_id: process.receipt_id.clone(),
            request_id: request.request_id.clone(),
            plan_step_id: request.plan_step_id,
            before_identity_digest: request.fresh_identity_digest.clone(),
            fresh_identity_digest: fresh_digest,
            verified_operation: operation.into(),
            expected_state_verified: true,
        };
        value.receipt_id = value.expected_receipt_id().unwrap();
        value
    }

    #[test]
    fn first_verified_step_allows_only_the_next_exact_mutation() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b'), 256),
            3,
        )
        .unwrap();
        let process = process(&request, PrivilegedRuntimeDisposition::RediscoveryRequired);
        let verification = verification(&request, &process, digest('f'));

        assert_eq!(
            classify_privileged_durable_transition(
                &journal,
                &request,
                &process,
                Some(&verification)
            )
            .unwrap(),
            PrivilegedDurableDisposition::Continue { next_step_id: 4 }
        );
    }

    #[test]
    fn later_step_request_must_use_last_verified_identity() {
        let validated = validated();
        let execution = execution(&validated);
        let mut journal = journal(&execution);
        journal.verified_boundary = Some(boundary(&execution, 3, 4, digest('f')));

        assert!(build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('f'), 512),
            4,
        )
        .is_ok());
        assert!(matches!(
            build_privileged_helper_request_for_durable_step(
                &validated,
                &journal,
                &identity(digest('b'), 512),
                4,
            ),
            Err(PrivilegedHelperProtocolError::FreshIdentityBindingMismatch)
        ));
    }

    #[test]
    fn final_verified_step_requires_exact_previous_boundary() {
        let validated = validated();
        let execution = execution(&validated);
        let mut journal = journal(&execution);
        journal.verified_boundary = Some(boundary(&execution, 3, 4, digest('f')));
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('f'), 512),
            4,
        )
        .unwrap();
        let process = process(&request, PrivilegedRuntimeDisposition::RediscoveryRequired);
        let verification = verification(&request, &process, digest('e'));

        assert_eq!(
            classify_privileged_durable_transition(
                &journal,
                &request,
                &process,
                Some(&verification)
            )
            .unwrap(),
            PrivilegedDurableDisposition::Complete
        );
    }

    #[test]
    fn recovery_process_never_needs_a_completion_receipt() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b'), 256),
            3,
        )
        .unwrap();
        let process = process(&request, PrivilegedRuntimeDisposition::RecoveryRequired);

        assert_eq!(
            classify_privileged_durable_transition(&journal, &request, &process, None).unwrap(),
            PrivilegedDurableDisposition::RecoveryRequired
        );
    }

    #[test]
    fn tampered_verification_receipt_fails_closed() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b'), 256),
            3,
        )
        .unwrap();
        let process = process(&request, PrivilegedRuntimeDisposition::RediscoveryRequired);
        let mut verification = verification(&request, &process, digest('f'));
        verification.fresh_identity_digest = digest('e');

        assert!(matches!(
            classify_privileged_durable_transition(
                &journal,
                &request,
                &process,
                Some(&verification)
            ),
            Err(PrivilegedDurableTransitionError::VerificationReceiptIntegrityMismatch)
        ));
    }
}
