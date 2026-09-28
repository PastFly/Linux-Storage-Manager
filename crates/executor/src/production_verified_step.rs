use lsm_discovery::{discover_capabilities, discover_snapshot, SnapshotDiscoveryError};
use lsm_planner::{
    capture_target_identity, IdentityGuardError, PlannerError, TargetIdentityManifest,
};
use thiserror::Error;

use crate::production_descriptor_exec::execute_and_classify_production_descriptor_launch;
use crate::{
    persist_privileged_durable_transition, verify_privileged_layer_post_state,
    LockedExecutionSession, LockedSessionError, PrivilegedDurableDisposition,
    PrivilegedDurableTransitionError, PrivilegedLayerVerificationError,
    PrivilegedLayerVerificationReceipt, PrivilegedProcessReceipt, PrivilegedRuntimeDisposition,
    ProductionDescriptorExecutionChain, ProductionDescriptorExecutionError,
};

#[derive(Debug, Clone)]
pub struct ProductionVerifiedMutationStep {
    pub process_receipt: PrivilegedProcessReceipt,
    pub verification_receipt: PrivilegedLayerVerificationReceipt,
    pub durable_disposition: PrivilegedDurableDisposition,
    pub fresh_identity_digest: String,
}

#[derive(Debug, Error)]
pub enum ProductionVerifiedMutationStepError {
    #[error("production descriptor execution failed: {0}")]
    Execution(#[from] ProductionDescriptorExecutionError),
    #[error("production process entered durable recovery-required state")]
    RecoveryRequired,
    #[error("post-mutation storage rediscovery failed: {0}")]
    Discovery(#[from] SnapshotDiscoveryError),
    #[error("post-mutation capability inventory no longer matches the frozen handoff")]
    CapabilityInventoryMismatch,
    #[error("post-mutation capability comparison failed: {0}")]
    Planner(#[from] PlannerError),
    #[error("post-mutation target identity capture failed: {0}")]
    Identity(#[from] IdentityGuardError),
    #[error("post-mutation layer verification failed: {0}")]
    Verification(#[from] PrivilegedLayerVerificationError),
    #[error("durable verified continuation failed: {0}")]
    DurableTransition(#[from] PrivilegedDurableTransitionError),
    #[error("durable recovery transition failed: {0}")]
    Session(#[from] LockedSessionError),
}

fn enter_recovery(
    session: &mut LockedExecutionSession<'_>,
    reason: &str,
) -> Result<(), ProductionVerifiedMutationStepError> {
    session.persist_interrupted(reason)?;
    Ok(())
}

fn verify_before_identity(
    chain: ProductionDescriptorExecutionChain<'_>,
    before_identity: &TargetIdentityManifest,
) -> Result<(), ProductionVerifiedMutationStepError> {
    if before_identity.manifest_digest != chain.request.fresh_identity_digest
        || before_identity.target != chain.request.target
        || before_identity.resolved_device != chain.request.resolved_device
    {
        return Err(PrivilegedLayerVerificationError::BeforeIdentityMismatch.into());
    }
    Ok(())
}

/// Execute one production mutation and synchronously close its verification
/// boundary before returning.
///
/// The caller must provide the exact pre-spawn live identity that was used to
/// build the current privileged request. After the descriptor process exits,
/// this gate performs a fresh full snapshot, verifies capability inventory,
/// captures the fresh target identity, proves the exact M1B32 layer transition,
/// and persists M1B33 continuation/completion. A successful return therefore
/// means the mutation boundary is already durably reconciled.
///
/// Any rediscovery, capability, identity, verification, or binding failure
/// forces the current durable session into RecoveryRequired.
pub fn execute_verify_and_persist_production_step(
    session: &mut LockedExecutionSession<'_>,
    chain: ProductionDescriptorExecutionChain<'_>,
    before_identity: &TargetIdentityManifest,
) -> Result<ProductionVerifiedMutationStep, ProductionVerifiedMutationStepError> {
    if let Err(error) = verify_before_identity(chain, before_identity) {
        enter_recovery(
            session,
            "production pre-spawn identity did not match the exact privileged request",
        )?;
        return Err(error);
    }

    let process_receipt = execute_and_classify_production_descriptor_launch(session, chain)?;
    if process_receipt.disposition == PrivilegedRuntimeDisposition::RecoveryRequired {
        return Err(ProductionVerifiedMutationStepError::RecoveryRequired);
    }

    let snapshot = match discover_snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            enter_recovery(
                session,
                "production post-mutation storage rediscovery failed; reconciliation required",
            )?;
            return Err(error.into());
        }
    };

    let capabilities = discover_capabilities();
    let capabilities_match = match session.handoff().matches_capabilities(&capabilities) {
        Ok(matches) => matches,
        Err(error) => {
            enter_recovery(
                session,
                "production post-mutation capability comparison failed; reconciliation required",
            )?;
            return Err(error.into());
        }
    };
    if !capabilities_match {
        enter_recovery(
            session,
            "production post-mutation capability inventory changed; reconciliation required",
        )?;
        return Err(ProductionVerifiedMutationStepError::CapabilityInventoryMismatch);
    }

    let fresh_identity = match capture_target_identity(&snapshot, &chain.request.target) {
        Ok(identity) => identity,
        Err(error) => {
            enter_recovery(
                session,
                "production post-mutation target identity could not be captured; reconciliation required",
            )?;
            return Err(error.into());
        }
    };

    let verification_receipt = match verify_privileged_layer_post_state(
        chain.request,
        &process_receipt,
        before_identity,
        &fresh_identity,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            enter_recovery(
                session,
                "production post-mutation layer verification failed; reconciliation required",
            )?;
            return Err(error.into());
        }
    };

    let durable_disposition = persist_privileged_durable_transition(
        session,
        chain.request,
        &process_receipt,
        Some(&verification_receipt),
    )?;

    Ok(ProductionVerifiedMutationStep {
        process_receipt,
        verification_receipt,
        durable_disposition,
        fresh_identity_digest: fresh_identity.manifest_digest,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn production_verified_step_feature_is_explicit() {
        assert!(cfg!(feature = "production-mutation-execution"));
    }
}
