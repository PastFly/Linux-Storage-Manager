use lsm_planner::{ExecutionStartBinding, TargetIdentityManifest};
use thiserror::Error;

use crate::{
    authorize_privileged_continuation_spawn, authorize_privileged_spawn,
    bind_prepared_privileged_continuation, build_privileged_descriptor_launch_spec,
    build_privileged_helper_request, build_privileged_helper_request_for_durable_step,
    compile_privileged_helper_command, persist_prepared_privileged_execution_start,
    pin_privileged_tools_for_spawn, prepare_privileged_invocation,
    resolve_privileged_command_tools, seal_privileged_continuation_launch_permit,
    seal_privileged_launch_permit, seal_production_mutation_execution_permit,
    LockedExecutionSession, LockedSessionError, PinnedPrivilegedTools,
    PinnedProductionMutationConsent, PreparedInvocationError, PreparedPrivilegedInvocation,
    PrivilegedArgvError, PrivilegedCommandSpec, PrivilegedContinuationStartError,
    PrivilegedDescriptorLaunchSpec, PrivilegedExecutionStartError, PrivilegedHelperProtocolError,
    PrivilegedHelperRequest, PrivilegedLaunchPermit, PrivilegedLaunchPermitError,
    PrivilegedLaunchSpecError, PrivilegedSpawnAuthorizationError, PrivilegedToolPinError,
    ProductionDescriptorExecutionChain, ProductionMutationActivationIntent,
    ProductionMutationConsentReceipt, ProductionMutationExecutionPermit,
    ProductionMutationExecutionPermitError, TrustedToolError, ValidatedNativeManifest,
};

#[derive(Debug)]
pub struct PreparedProductionMutationStep {
    request: PrivilegedHelperRequest,
    command: PrivilegedCommandSpec,
    prepared: PreparedPrivilegedInvocation,
    pinned: PinnedPrivilegedTools,
    launch: PrivilegedDescriptorLaunchSpec,
    launch_permit: PrivilegedLaunchPermit,
    production_permit: ProductionMutationExecutionPermit,
}

impl PreparedProductionMutationStep {
    pub fn request(&self) -> &PrivilegedHelperRequest {
        &self.request
    }

    pub fn command(&self) -> &PrivilegedCommandSpec {
        &self.command
    }

    pub fn prepared_invocation(&self) -> &PreparedPrivilegedInvocation {
        &self.prepared
    }

    pub fn launch(&self) -> &PrivilegedDescriptorLaunchSpec {
        &self.launch
    }

    pub fn launch_permit(&self) -> &PrivilegedLaunchPermit {
        &self.launch_permit
    }

    pub fn production_permit(&self) -> &ProductionMutationExecutionPermit {
        &self.production_permit
    }

    pub fn descriptor_chain<'a>(
        &'a self,
        activation: &'a ProductionMutationActivationIntent,
        consent_lease: &'a PinnedProductionMutationConsent,
    ) -> ProductionDescriptorExecutionChain<'a> {
        ProductionDescriptorExecutionChain {
            activation,
            production_permit: &self.production_permit,
            request: &self.request,
            launch_permit: &self.launch_permit,
            launch: &self.launch,
            pinned: &self.pinned,
            command: &self.command,
            consent_lease,
        }
    }
}

#[derive(Debug, Error)]
pub enum ProductionMutationPreparationError {
    #[error("privileged-helper request construction failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("privileged command compilation failed: {0}")]
    Command(#[from] PrivilegedArgvError),
    #[error("trusted tool resolution failed: {0}")]
    Tools(#[from] TrustedToolError),
    #[error("privileged invocation preparation failed: {0}")]
    Prepared(#[from] PreparedInvocationError),
    #[error("first-step durable execution start failed: {0}")]
    FirstStart(#[from] PrivilegedExecutionStartError),
    #[error("continuation durable-boundary binding failed: {0}")]
    ContinuationStart(#[from] PrivilegedContinuationStartError),
    #[error("pre-spawn authorization failed: {0}")]
    Authorization(#[from] PrivilegedSpawnAuthorizationError),
    #[error("trusted executable pinning failed: {0}")]
    Pin(#[from] PrivilegedToolPinError),
    #[error("descriptor launch construction failed: {0}")]
    Launch(#[from] PrivilegedLaunchSpecError),
    #[error("descriptor launch permit failed: {0}")]
    LaunchPermit(#[from] PrivilegedLaunchPermitError),
    #[error("production execution permit failed: {0}")]
    ProductionPermit(#[from] ProductionMutationExecutionPermitError),
    #[error("durable recovery transition failed: {0}")]
    Session(#[from] LockedSessionError),
}

fn compile_prepared_invocation(
    request: PrivilegedHelperRequest,
    identity: &TargetIdentityManifest,
) -> Result<
    (
        PrivilegedHelperRequest,
        PrivilegedCommandSpec,
        PreparedPrivilegedInvocation,
    ),
    ProductionMutationPreparationError,
> {
    let command = compile_privileged_helper_command(&request, identity)?;
    let tools = resolve_privileged_command_tools(&command)?;
    let prepared = prepare_privileged_invocation(&request, identity, &command, &tools)?;
    Ok((request, command, prepared))
}

fn recover_after_started_preparation(
    session: &mut LockedExecutionSession<'_>,
    reason: &str,
) -> Result<(), ProductionMutationPreparationError> {
    session.persist_interrupted(reason)?;
    Ok(())
}

/// Prepare the exact first production mutation from an Approved durable
/// session. Everything that can be verified without crossing the mutation
/// boundary is resolved before the journal enters Executing. Once the
/// conservative execution-start transition is persisted, any later
/// preparation failure is converted into durable RecoveryRequired.
pub fn prepare_first_production_mutation_step(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
    activation: &ProductionMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<PreparedProductionMutationStep, ProductionMutationPreparationError> {
    let request =
        build_privileged_helper_request(validated, execution, identity, activation.lv_step_id)?;
    let (request, command, prepared) = compile_prepared_invocation(request, identity)?;

    let start =
        persist_prepared_privileged_execution_start(session, execution, &request, &prepared)?;

    let result: Result<PreparedProductionMutationStep, ProductionMutationPreparationError> =
        (|| {
            let authorization = authorize_privileged_spawn(&start, &prepared, &command)?;
            let pinned = pin_privileged_tools_for_spawn(&authorization, &command)?;
            let launch = build_privileged_descriptor_launch_spec(&pinned, &command)?;
            let launch_permit = seal_privileged_launch_permit(&start, &authorization, &launch)?;
            let production_permit =
                seal_production_mutation_execution_permit(activation, consent, &launch_permit)?;

            Ok(PreparedProductionMutationStep {
                request,
                command,
                prepared,
                pinned,
                launch,
                launch_permit,
                production_permit,
            })
        })();

    match result {
        Ok(step) => Ok(step),
        Err(error) => {
            recover_after_started_preparation(
                session,
                "first production mutation preparation failed after durable execution start",
            )?;
            Err(error)
        }
    }
}

/// Prepare the exact filesystem continuation after M1B33 has durably verified
/// the preceding LV mutation. The request must consume the latest verified
/// identity digest and the continuation-start receipt must bind the exact
/// adjacent step. Any failure is recovery-required because the execution has
/// already crossed a prior mutation boundary.
pub fn prepare_continuation_production_mutation_step(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    identity: &TargetIdentityManifest,
    activation: &ProductionMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<PreparedProductionMutationStep, ProductionMutationPreparationError> {
    let result: Result<PreparedProductionMutationStep, ProductionMutationPreparationError> =
        (|| {
            let request = build_privileged_helper_request_for_durable_step(
                validated,
                session.journal(),
                identity,
                activation.filesystem_step_id,
            )?;
            let (request, command, prepared) = compile_prepared_invocation(request, identity)?;
            let continuation_start =
                bind_prepared_privileged_continuation(session, &request, &prepared)?;
            let authorization =
                authorize_privileged_continuation_spawn(&continuation_start, &prepared, &command)?;
            let pinned = pin_privileged_tools_for_spawn(&authorization, &command)?;
            let launch = build_privileged_descriptor_launch_spec(&pinned, &command)?;
            let launch_permit = seal_privileged_continuation_launch_permit(
                &continuation_start,
                &authorization,
                &launch,
            )?;
            let production_permit =
                seal_production_mutation_execution_permit(activation, consent, &launch_permit)?;

            Ok(PreparedProductionMutationStep {
                request,
                command,
                prepared,
                pinned,
                launch,
                launch_permit,
                production_permit,
            })
        })();

    match result {
        Ok(step) => Ok(step),
        Err(error) => {
            recover_after_started_preparation(
                session,
                "production continuation preparation failed after a verified mutation boundary",
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_is_only_present_with_production_execution_feature() {
        assert!(cfg!(feature = "production-mutation-execution"));
    }
}
