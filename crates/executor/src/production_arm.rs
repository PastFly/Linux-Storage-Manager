use lsm_planner::{JournalPhase, OperationJournal};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    validate_privileged_helper_request, LockedExecutionSession, LockedSessionError,
    PrivilegedHelperProtocolError, PrivilegedHelperRequest, PrivilegedLaunchPermit,
};

pub const PRODUCTION_MUTATION_ARM_CONFIRMATION: &str =
    "I_UNDERSTAND_THIS_WILL_MODIFY_STORAGE";
pub const PRODUCTION_MUTATION_COMPILED: bool = cfg!(feature = "production-mutation");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationArm {
    pub schema_version: u32,
    pub arm_id: String,
    pub execution_id: String,
    pub journal_id: String,
    pub journal_digest: String,
    pub request_id: String,
    pub permit_id: String,
    pub launch_id: String,
    pub plan_step_id: u32,
    pub target: String,
    pub resolved_device: String,
    pub target_identity_digest: String,
    pub scope: String,
}

impl ProductionMutationArm {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.arm_id == self.expected_arm_id()?)
    }

    fn expected_arm_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.journal_id,
            &self.journal_digest,
            &self.request_id,
            &self.permit_id,
            &self.launch_id,
            self.plan_step_id,
            &self.target,
            &self.resolved_device,
            &self.target_identity_digest,
            &self.scope,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum ProductionMutationArmError {
    #[error("production mutation support is not compiled into this binary")]
    FeatureDisabled,
    #[error("production mutation arming requires effective uid 0")]
    RootRequired,
    #[error("production mutation confirmation phrase does not match the exact required value")]
    ConfirmationMismatch,
    #[error("durable journal is not at an executing mutation boundary")]
    JournalNotExecuting,
    #[error("durable execution binding is missing or invalid")]
    ExecutionBindingInvalid,
    #[error("privileged-helper request validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("launch permit integrity check failed")]
    PermitIntegrityMismatch,
    #[error("request, permit and durable execution binding do not match")]
    BindingMismatch,
    #[error("requested step is not the exact durable mutation position")]
    StepSequenceMismatch,
    #[error("requested target identity does not consume the current durable boundary")]
    IdentityBoundaryMismatch,
    #[error("production mutation arm serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("durable journal access failed: {0}")]
    Session(#[from] LockedSessionError),
}

fn journal_digest(journal: &OperationJournal) -> Result<String, serde_json::Error> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(journal)?)
    ))
}

fn build_production_mutation_arm(
    journal: &OperationJournal,
    request: &PrivilegedHelperRequest,
    permit: &PrivilegedLaunchPermit,
    confirmation: &str,
    effective_uid: u32,
    feature_compiled: bool,
) -> Result<ProductionMutationArm, ProductionMutationArmError> {
    if !feature_compiled {
        return Err(ProductionMutationArmError::FeatureDisabled);
    }
    if effective_uid != 0 {
        return Err(ProductionMutationArmError::RootRequired);
    }
    if confirmation != PRODUCTION_MUTATION_ARM_CONFIRMATION {
        return Err(ProductionMutationArmError::ConfirmationMismatch);
    }
    validate_privileged_helper_request(request)?;

    if journal.phase != JournalPhase::Executing || !journal.mutation_may_have_started {
        return Err(ProductionMutationArmError::JournalNotExecuting);
    }
    let execution = journal
        .execution
        .as_ref()
        .ok_or(ProductionMutationArmError::ExecutionBindingInvalid)?;
    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(ProductionMutationArmError::ExecutionBindingInvalid);
    }
    if !permit.integrity_matches().unwrap_or(false) {
        return Err(ProductionMutationArmError::PermitIntegrityMismatch);
    }

    if journal.journal_id != execution.journal_id
        || journal.plan_id != execution.plan_id
        || request.execution_id != execution.execution_id
        || request.source_manifest_id != execution.source_manifest_id
        || request.native_manifest_digest != execution.native_manifest_digest
        || request.target != journal.target
        || permit.execution_id != execution.execution_id
        || permit.plan_step_id != request.plan_step_id
        || permit.mutation_enabled
        || permit.process_spawned
    {
        return Err(ProductionMutationArmError::BindingMismatch);
    }

    let position = execution
        .mutation_step_ids
        .iter()
        .position(|step_id| *step_id == request.plan_step_id)
        .ok_or(ProductionMutationArmError::StepSequenceMismatch)?;

    if position == 0 {
        if journal.verified_boundary.is_some() {
            return Err(ProductionMutationArmError::StepSequenceMismatch);
        }
        if request.fresh_identity_digest != execution.fresh_identity_digest {
            return Err(ProductionMutationArmError::IdentityBoundaryMismatch);
        }
    } else {
        let boundary = journal
            .verified_boundary
            .as_ref()
            .ok_or(ProductionMutationArmError::StepSequenceMismatch)?;
        if boundary.schema_version != 1
            || !boundary.integrity_matches().unwrap_or(false)
            || boundary.execution_id != execution.execution_id
            || boundary.completed_step_id != execution.mutation_step_ids[position - 1]
            || boundary.next_step_id != request.plan_step_id
            || boundary.final_step_id.is_some()
            || boundary.final_identity_digest.is_some()
        {
            return Err(ProductionMutationArmError::StepSequenceMismatch);
        }
        if request.fresh_identity_digest != boundary.fresh_identity_digest {
            return Err(ProductionMutationArmError::IdentityBoundaryMismatch);
        }
    }

    let mut arm = ProductionMutationArm {
        schema_version: 1,
        arm_id: String::new(),
        execution_id: execution.execution_id.clone(),
        journal_id: journal.journal_id.clone(),
        journal_digest: journal_digest(journal)?,
        request_id: request.request_id.clone(),
        permit_id: permit.permit_id.clone(),
        launch_id: permit.launch_id.clone(),
        plan_step_id: request.plan_step_id,
        target: request.target.clone(),
        resolved_device: request.resolved_device.clone(),
        target_identity_digest: request.fresh_identity_digest.clone(),
        scope: "single_privileged_descriptor_launch".into(),
    };
    arm.arm_id = arm.expected_arm_id()?;
    Ok(arm)
}

/// Arm exactly one already-authorized privileged mutation step.
///
/// This API is inert in normal builds. Even when the production-mutation
/// feature is compiled, the caller must hold a current durable locked session,
/// run as root and provide the exact destructive-action confirmation phrase.
pub fn arm_production_mutation(
    session: &LockedExecutionSession<'_>,
    request: &PrivilegedHelperRequest,
    permit: &PrivilegedLaunchPermit,
    confirmation: &str,
) -> Result<ProductionMutationArm, ProductionMutationArmError> {
    session.require_current_durable_journal()?;
    let effective_uid = unsafe { libc::geteuid() };
    build_production_mutation_arm(
        session.journal(),
        request,
        permit,
        confirmation,
        effective_uid,
        PRODUCTION_MUTATION_COMPILED,
    )
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

    fn journal(execution: &ExecutionStartBinding, continuation: bool) -> OperationJournal {
        let verified_boundary = if continuation {
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
            Some(boundary)
        } else {
            None
        };

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
            verified_boundary,
            events: vec![],
        }
    }

    fn permit(request: &PrivilegedHelperRequest) -> PrivilegedLaunchPermit {
        let mut permit = PrivilegedLaunchPermit {
            schema_version: 1,
            permit_id: String::new(),
            execution_id: request.execution_id.clone(),
            execution_start_receipt_id: digest('5'),
            authorization_id: digest('6'),
            launch_id: digest('7'),
            plan_step_id: request.plan_step_id,
            command_digest: digest('8'),
            mutation_enabled: false,
            process_spawned: false,
        };
        let bytes = serde_json::to_vec(&(
            permit.schema_version,
            &permit.execution_id,
            &permit.execution_start_receipt_id,
            &permit.authorization_id,
            &permit.launch_id,
            permit.plan_step_id,
            &permit.command_digest,
            permit.mutation_enabled,
            permit.process_spawned,
        ))
        .unwrap();
        permit.permit_id = format!("{:x}", Sha256::digest(bytes));
        permit
    }

    #[test]
    fn feature_gate_is_checked_before_any_destructive_arm() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution, false);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b')),
            3,
        )
        .unwrap();

        assert!(matches!(
            build_production_mutation_arm(
                &journal,
                &request,
                &permit(&request),
                PRODUCTION_MUTATION_ARM_CONFIRMATION,
                0,
                false,
            ),
            Err(ProductionMutationArmError::FeatureDisabled)
        ));
    }

    #[test]
    fn arm_requires_root_and_exact_confirmation() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution, false);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b')),
            3,
        )
        .unwrap();
        let permit = permit(&request);

        assert!(matches!(
            build_production_mutation_arm(
                &journal,
                &request,
                &permit,
                PRODUCTION_MUTATION_ARM_CONFIRMATION,
                1000,
                true,
            ),
            Err(ProductionMutationArmError::RootRequired)
        ));
        assert!(matches!(
            build_production_mutation_arm(&journal, &request, &permit, "yes", 0, true),
            Err(ProductionMutationArmError::ConfirmationMismatch)
        ));
    }

    #[test]
    fn exact_first_step_can_be_armed_once_all_gates_match() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution, false);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b')),
            3,
        )
        .unwrap();
        let permit = permit(&request);

        let arm = build_production_mutation_arm(
            &journal,
            &request,
            &permit,
            PRODUCTION_MUTATION_ARM_CONFIRMATION,
            0,
            true,
        )
        .unwrap();
        assert!(arm.integrity_matches().unwrap());
        assert_eq!(arm.request_id, request.request_id);
        assert_eq!(arm.permit_id, permit.permit_id);
        assert_eq!(arm.target_identity_digest, digest('b'));
    }

    #[test]
    fn continuation_arm_consumes_only_the_latest_verified_identity() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution, true);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('f')),
            4,
        )
        .unwrap();

        let arm = build_production_mutation_arm(
            &journal,
            &request,
            &permit(&request),
            PRODUCTION_MUTATION_ARM_CONFIRMATION,
            0,
            true,
        )
        .unwrap();
        assert_eq!(arm.plan_step_id, 4);
        assert_eq!(arm.target_identity_digest, digest('f'));
    }

    #[test]
    fn arm_is_tamper_evident() {
        let validated = validated();
        let execution = execution(&validated);
        let journal = journal(&execution, false);
        let request = build_privileged_helper_request_for_durable_step(
            &validated,
            &journal,
            &identity(digest('b')),
            3,
        )
        .unwrap();
        let permit = permit(&request);
        let mut arm = build_production_mutation_arm(
            &journal,
            &request,
            &permit,
            PRODUCTION_MUTATION_ARM_CONFIRMATION,
            0,
            true,
        )
        .unwrap();

        arm.plan_step_id = 4;
        assert!(!arm.integrity_matches().unwrap());
    }
}
