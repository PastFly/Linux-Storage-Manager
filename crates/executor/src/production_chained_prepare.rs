use lsm_planner::{ExecutionStartBinding, TargetIdentityManifest};
use thiserror::Error;

use crate::{
    authorize_privileged_continuation_spawn, authorize_privileged_spawn,
    bind_prepared_privileged_continuation, build_privileged_descriptor_launch_spec,
    build_privileged_helper_request, build_privileged_helper_request_for_durable_step,
    compile_privileged_helper_command, persist_prepared_privileged_execution_start,
    pin_privileged_tools_for_spawn, prepare_privileged_invocation,
    resolve_privileged_command_tools, seal_privileged_continuation_launch_permit,
    seal_privileged_launch_permit, seal_production_chained_mutation_execution_permit,
    LockedExecutionSession, LockedSessionError, PinnedPrivilegedTools,
    PinnedProductionMutationConsent, PreparedInvocationError, PreparedPrivilegedInvocation,
    PrivilegedArgvError, PrivilegedCommandSpec, PrivilegedContinuationStartError,
    PrivilegedDescriptorLaunchSpec, PrivilegedExecutionStartError, PrivilegedHelperProtocolError,
    PrivilegedHelperRequest, PrivilegedLaunchPermit, PrivilegedLaunchPermitError,
    PrivilegedLaunchSpecError, PrivilegedSpawnAuthorizationError, PrivilegedToolPinError,
    ProductionChainedDescriptorExecutionChain, ProductionChainedMutationActivationIntent,
    ProductionChainedMutationExecutionPermit, ProductionChainedMutationExecutionPermitError,
    ProductionMutationConsentReceipt, TrustedToolError, ValidatedNativeManifest,
};

#[derive(Debug)]
pub struct PreparedProductionChainedMutationStep {
    request: PrivilegedHelperRequest,
    command: PrivilegedCommandSpec,
    prepared: PreparedPrivilegedInvocation,
    pinned: PinnedPrivilegedTools,
    launch: PrivilegedDescriptorLaunchSpec,
    launch_permit: PrivilegedLaunchPermit,
    production_permit: ProductionChainedMutationExecutionPermit,
}

impl PreparedProductionChainedMutationStep {
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

    pub fn production_permit(&self) -> &ProductionChainedMutationExecutionPermit {
        &self.production_permit
    }

    pub fn descriptor_chain<'a>(
        &'a self,
        activation: &'a ProductionChainedMutationActivationIntent,
        consent_lease: &'a PinnedProductionMutationConsent,
    ) -> ProductionChainedDescriptorExecutionChain<'a> {
        ProductionChainedDescriptorExecutionChain {
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
pub enum ProductionChainedMutationPreparationError {
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
    #[error("chained production execution permit failed: {0}")]
    ProductionPermit(#[from] ProductionChainedMutationExecutionPermitError),
    #[error("durable verified boundary is missing or does not identify the next chained step")]
    NextStepUnavailable,
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
    ProductionChainedMutationPreparationError,
> {
    let command = compile_privileged_helper_command(&request, identity)?;
    let tools = resolve_privileged_command_tools(&command)?;
    let prepared = prepare_privileged_invocation(&request, identity, &command, &tools)?;
    Ok((request, command, prepared))
}

fn recover_after_started_preparation(
    session: &mut LockedExecutionSession<'_>,
    reason: &str,
) -> Result<(), ProductionChainedMutationPreparationError> {
    session.persist_interrupted(reason)?;
    Ok(())
}

fn seal_first_step(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
    activation: &ProductionChainedMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<PreparedProductionChainedMutationStep, ProductionChainedMutationPreparationError> {
    let request = build_privileged_helper_request(
        validated,
        execution,
        identity,
        activation.partition_step_id,
    )?;
    let (request, command, prepared) = compile_prepared_invocation(request, identity)?;
    let start =
        persist_prepared_privileged_execution_start(session, execution, &request, &prepared)?;

    let result: Result<
        PreparedProductionChainedMutationStep,
        ProductionChainedMutationPreparationError,
    > = (|| {
        let authorization = authorize_privileged_spawn(&start, &prepared, &command)?;
        let pinned = pin_privileged_tools_for_spawn(&authorization, &command)?;
        let launch = build_privileged_descriptor_launch_spec(&pinned, &command)?;
        let launch_permit = seal_privileged_launch_permit(&start, &authorization, &launch)?;
        let production_permit =
            seal_production_chained_mutation_execution_permit(activation, consent, &launch_permit)?;

        Ok(PreparedProductionChainedMutationStep {
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
                "first chained production mutation preparation failed after durable execution start",
            )?;
            Err(error)
        }
    }
}

/// Prepare the exact partition mutation that starts the four-step chained
/// production execution. All non-mutating command/provenance work is resolved
/// before the journal enters Executing; any failure after that durable boundary
/// is converted into RecoveryRequired.
pub fn prepare_first_production_chained_mutation_step(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
    activation: &ProductionChainedMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<PreparedProductionChainedMutationStep, ProductionChainedMutationPreparationError> {
    seal_first_step(session, validated, execution, identity, activation, consent)
}

fn exact_next_step(
    session: &LockedExecutionSession<'_>,
    activation: &ProductionChainedMutationActivationIntent,
) -> Result<u32, ProductionChainedMutationPreparationError> {
    let boundary = session
        .journal()
        .verified_boundary
        .as_ref()
        .ok_or(ProductionChainedMutationPreparationError::NextStepUnavailable)?;
    let allowed = [
        activation.pv_step_id,
        activation.lv_step_id,
        activation.filesystem_step_id,
    ];
    if boundary.execution_id != activation.execution_id
        || !boundary.integrity_matches().unwrap_or(false)
        || !allowed.contains(&boundary.next_step_id)
        || boundary.final_step_id.is_some()
        || boundary.final_identity_digest.is_some()
    {
        return Err(ProductionChainedMutationPreparationError::NextStepUnavailable);
    }
    Ok(boundary.next_step_id)
}

/// Prepare exactly the next durable continuation in the chained production
/// route. The step ID is not supplied by the caller: it is read from the
/// latest verified journal boundary and must be one of PV -> LV -> filesystem.
pub fn prepare_continuation_production_chained_mutation_step(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    identity: &TargetIdentityManifest,
    activation: &ProductionChainedMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<PreparedProductionChainedMutationStep, ProductionChainedMutationPreparationError> {
    let result: Result<
        PreparedProductionChainedMutationStep,
        ProductionChainedMutationPreparationError,
    > = (|| {
        let next_step_id = exact_next_step(session, activation)?;
        let request = build_privileged_helper_request_for_durable_step(
            validated,
            session.journal(),
            identity,
            next_step_id,
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
            seal_production_chained_mutation_execution_permit(activation, consent, &launch_permit)?;

        Ok(PreparedProductionChainedMutationStep {
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
                "chained production continuation preparation failed after a verified mutation boundary",
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_is_only_present_with_chained_production_execution_feature() {
        assert!(cfg!(feature = "production-chained-mutation-execution"));
    }

    #[test]
    fn chained_continuation_scope_excludes_the_initial_partition_step() {
        let activation = ProductionChainedMutationActivationIntent {
            schema_version: 1,
            activation_id: "a".repeat(64),
            profile: crate::ProductionChainedMutationProfile::SinglePvPartitionTailLvmFilesystem,
            execution_id: "b".repeat(64),
            source_manifest_id: "c".repeat(64),
            native_manifest_digest: "d".repeat(64),
            fresh_identity_digest: "e".repeat(64),
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            partition_step_id: 3,
            pv_step_id: 4,
            lv_step_id: 5,
            filesystem_step_id: 6,
            partition: "/dev/sda1".into(),
            pv_uuid: "pv-uuid".into(),
            lv_uuid: "lv-uuid".into(),
            filesystem_type: "ext4".into(),
            filesystem_mountpoint: Some("/mnt/data".into()),
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        let continuation = [
            activation.pv_step_id,
            activation.lv_step_id,
            activation.filesystem_step_id,
        ];
        assert!(!continuation.contains(&activation.partition_step_id));
        assert_eq!(continuation, [4, 5, 6]);
    }
}
