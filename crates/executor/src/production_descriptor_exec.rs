use lsm_planner::{JournalPhase, OperationJournal};
use thiserror::Error;

use crate::privileged_exec::execute_authorized_privileged_descriptor_launch;
use crate::{
    verify_default_production_mutation_consent, LockedExecutionSession, LockedSessionError,
    PinnedPrivilegedTools, PrivilegedCommandSpec, PrivilegedDescriptorExecError,
    PrivilegedDescriptorLaunchSpec, PrivilegedDescriptorSequenceOutcome, PrivilegedHelperRequest,
    PrivilegedLaunchPermit, ProductionMutationActivationIntent, ProductionMutationConsentError,
    ProductionMutationConsentReceipt, ProductionMutationExecutionPermit,
};

/// M1B38 is the first compile-time gate that can cross the descriptor-exec
/// boundary. It remains absent from default builds.
pub const PRODUCTION_MUTATION_DESCRIPTOR_EXEC_COMPILED: bool =
    cfg!(feature = "production-mutation-execution");

#[derive(Debug, Clone, Copy)]
pub struct ProductionDescriptorExecutionChain<'a> {
    pub activation: &'a ProductionMutationActivationIntent,
    pub production_permit: &'a ProductionMutationExecutionPermit,
    pub request: &'a PrivilegedHelperRequest,
    pub launch_permit: &'a PrivilegedLaunchPermit,
    pub launch: &'a PrivilegedDescriptorLaunchSpec,
    pub pinned: &'a PinnedPrivilegedTools,
    pub command: &'a PrivilegedCommandSpec,
}

#[derive(Debug, Error)]
pub enum ProductionDescriptorExecutionError {
    #[error("production mutation execution feature is not compiled")]
    FeatureDisabled,
    #[error("durable execution journal is not at an executing mutation boundary")]
    JournalNotExecuting,
    #[error("durable execution binding is missing or invalid")]
    ExecutionBindingInvalid,
    #[error("production activation intent integrity check failed")]
    ActivationIntentInvalid,
    #[error("production execution permit integrity check failed")]
    ProductionPermitInvalid,
    #[error("fresh root-owned runtime consent no longer matches the sealed permit")]
    RuntimeConsentMismatch,
    #[error("production execution scope does not match the activation/request/journal")]
    ScopeBindingMismatch,
    #[error("current durable verified boundary does not authorize this exact mutation step")]
    StepBoundaryMismatch,
    #[error("privileged launch chain does not match the production execution permit")]
    LaunchBindingMismatch,
    #[error("production runtime consent verification failed: {0}")]
    Consent(#[from] ProductionMutationConsentError),
    #[error("durable journal access failed: {0}")]
    Session(#[from] LockedSessionError),
    #[error("descriptor execution failed: {0}")]
    Descriptor(#[from] PrivilegedDescriptorExecError),
}

fn validate_current_step(
    journal: &OperationJournal,
    request: &PrivilegedHelperRequest,
) -> Result<(), ProductionDescriptorExecutionError> {
    if journal.phase != JournalPhase::Executing || !journal.mutation_may_have_started {
        return Err(ProductionDescriptorExecutionError::JournalNotExecuting);
    }
    let execution = journal
        .execution
        .as_ref()
        .ok_or(ProductionDescriptorExecutionError::ExecutionBindingInvalid)?;
    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(ProductionDescriptorExecutionError::ExecutionBindingInvalid);
    }
    if request.execution_id != execution.execution_id
        || request.source_manifest_id != execution.source_manifest_id
        || request.native_manifest_digest != execution.native_manifest_digest
    {
        return Err(ProductionDescriptorExecutionError::ScopeBindingMismatch);
    }

    let Some(position) = execution
        .mutation_step_ids
        .iter()
        .position(|step_id| *step_id == request.plan_step_id)
    else {
        return Err(ProductionDescriptorExecutionError::StepBoundaryMismatch);
    };

    if position == 0 {
        if journal.verified_boundary.is_some()
            || request.fresh_identity_digest != execution.fresh_identity_digest
        {
            return Err(ProductionDescriptorExecutionError::StepBoundaryMismatch);
        }
        return Ok(());
    }

    let boundary = journal
        .verified_boundary
        .as_ref()
        .ok_or(ProductionDescriptorExecutionError::StepBoundaryMismatch)?;
    if boundary.schema_version != 1
        || !boundary.integrity_matches().unwrap_or(false)
        || boundary.execution_id != execution.execution_id
        || boundary.completed_step_id != execution.mutation_step_ids[position - 1]
        || boundary.next_step_id != request.plan_step_id
        || boundary.fresh_identity_digest != request.fresh_identity_digest
        || boundary.final_step_id.is_some()
        || boundary.final_identity_digest.is_some()
    {
        return Err(ProductionDescriptorExecutionError::StepBoundaryMismatch);
    }

    Ok(())
}

fn validate_gate(
    journal: &OperationJournal,
    fresh_consent: &ProductionMutationConsentReceipt,
    chain: ProductionDescriptorExecutionChain<'_>,
) -> Result<(), ProductionDescriptorExecutionError> {
    let ProductionDescriptorExecutionChain {
        activation,
        production_permit,
        request,
        launch_permit,
        launch,
        pinned,
        command,
    } = chain;
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || activation.execution_enabled
    {
        return Err(ProductionDescriptorExecutionError::ActivationIntentInvalid);
    }
    if production_permit.schema_version != 1
        || !production_permit.integrity_matches().unwrap_or(false)
        || !production_permit.compile_feature_enabled
        || production_permit.mutation_enabled
        || production_permit.process_spawned
    {
        return Err(ProductionDescriptorExecutionError::ProductionPermitInvalid);
    }
    if fresh_consent.schema_version != 1
        || !fresh_consent.integrity_matches().unwrap_or(false)
        || !fresh_consent.consent_verified
        || fresh_consent.execution_enabled
        || fresh_consent.receipt_id != production_permit.consent_receipt_id
    {
        return Err(ProductionDescriptorExecutionError::RuntimeConsentMismatch);
    }

    validate_current_step(journal, request)?;

    let execution = journal
        .execution
        .as_ref()
        .ok_or(ProductionDescriptorExecutionError::ExecutionBindingInvalid)?;
    if activation.activation_id != production_permit.activation_id
        || activation.execution_id != execution.execution_id
        || activation.execution_id != production_permit.execution_id
        || activation.source_manifest_id != execution.source_manifest_id
        || activation.native_manifest_digest != execution.native_manifest_digest
        || activation.target != production_permit.target
        || activation.resolved_device != production_permit.resolved_device
        || request.execution_id != production_permit.execution_id
        || request.target != production_permit.target
        || request.resolved_device != production_permit.resolved_device
        || request.plan_step_id != production_permit.plan_step_id
        || fresh_consent.activation_id != activation.activation_id
        || fresh_consent.execution_id != activation.execution_id
        || fresh_consent.target != activation.target
        || fresh_consent.resolved_device != activation.resolved_device
    {
        return Err(ProductionDescriptorExecutionError::ScopeBindingMismatch);
    }

    if !launch_permit.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !pinned.integrity_matches().unwrap_or(false)
        || production_permit.launch_permit_id != launch_permit.permit_id
        || production_permit.launch_id != launch.launch_id
        || launch_permit.launch_id != launch.launch_id
        || production_permit.plan_step_id != launch_permit.plan_step_id
        || production_permit.plan_step_id != launch.plan_step_id
        || command.plan_step_id != production_permit.plan_step_id
        || production_permit.command_digest != launch_permit.command_digest
        || production_permit.command_digest != launch.command_digest
        || command.digest().ok().as_deref() != Some(production_permit.command_digest.as_str())
    {
        return Err(ProductionDescriptorExecutionError::LaunchBindingMismatch);
    }

    Ok(())
}

/// Cross the descriptor-exec boundary for the narrow M1B35 profile.
///
/// The gate re-reads root-owned runtime consent immediately before spawn and
/// requires the current durable journal to authorize this exact step. Default
/// builds cannot call through because the production-mutation-execution
/// feature is not compiled.
///
/// A successful return is still not completion: the caller must classify the
/// process receipt, rediscover live state, verify the exact layer, and persist
/// M1B33 continuation/completion before any later mutation.
pub fn execute_production_descriptor_launch(
    session: &mut LockedExecutionSession<'_>,
    chain: ProductionDescriptorExecutionChain<'_>,
) -> Result<PrivilegedDescriptorSequenceOutcome, ProductionDescriptorExecutionError> {
    let activation = chain.activation;
    if !PRODUCTION_MUTATION_DESCRIPTOR_EXEC_COMPILED {
        return Err(ProductionDescriptorExecutionError::FeatureDisabled);
    }

    session.require_current_durable_journal()?;
    let fresh_consent = match verify_default_production_mutation_consent(activation) {
        Ok(receipt) => receipt,
        Err(error) => {
            session.persist_interrupted(
                "production runtime consent could not be revalidated immediately before spawn",
            )?;
            return Err(error.into());
        }
    };

    if let Err(error) = validate_gate(session.journal(), &fresh_consent, chain) {
        session.persist_interrupted(
            "production descriptor execution authorization drifted before spawn",
        )?;
        return Err(error);
    }

    match execute_authorized_privileged_descriptor_launch(
        chain.launch_permit,
        chain.launch,
        chain.pinned,
        chain.command,
    ) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            session.persist_interrupted(
                "production descriptor execution failed after the durable mutation boundary",
            )?;
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_cannot_cross_production_descriptor_boundary() {
        if !PRODUCTION_MUTATION_DESCRIPTOR_EXEC_COMPILED {
            assert!(!PRODUCTION_MUTATION_DESCRIPTOR_EXEC_COMPILED);
        }
    }
}
