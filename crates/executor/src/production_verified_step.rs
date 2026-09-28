use std::thread;
use std::time::Duration;

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
    pub fresh_identity: TargetIdentityManifest,
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

const POST_MUTATION_REDISCOVERY_ATTEMPTS: usize = 20;
const POST_MUTATION_REDISCOVERY_DELAY: Duration = Duration::from_millis(50);

fn retryable_post_state_error(error: &PrivilegedLayerVerificationError) -> bool {
    matches!(
        error,
        PrivilegedLayerVerificationError::PartitionStateMismatch
            | PrivilegedLayerVerificationError::PhysicalVolumeStateMismatch
            | PrivilegedLayerVerificationError::LogicalVolumeStateMismatch
            | PrivilegedLayerVerificationError::FilesystemStateMismatch
    )
}

fn discover_verified_post_state(
    session: &LockedExecutionSession<'_>,
    chain: ProductionDescriptorExecutionChain<'_>,
    process_receipt: &PrivilegedProcessReceipt,
    before_identity: &TargetIdentityManifest,
) -> Result<
    (TargetIdentityManifest, PrivilegedLayerVerificationReceipt),
    ProductionVerifiedMutationStepError,
> {
    let mut last_transient_error = None;

    for attempt in 0..POST_MUTATION_REDISCOVERY_ATTEMPTS {
        let snapshot = match discover_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                last_transient_error = Some(ProductionVerifiedMutationStepError::Discovery(error));
                if attempt + 1 < POST_MUTATION_REDISCOVERY_ATTEMPTS {
                    thread::sleep(POST_MUTATION_REDISCOVERY_DELAY);
                    continue;
                }
                break;
            }
        };

        let capabilities = discover_capabilities();
        if !session.handoff().matches_capabilities(&capabilities)? {
            return Err(ProductionVerifiedMutationStepError::CapabilityInventoryMismatch);
        }

        let fresh_identity = match capture_target_identity(&snapshot, &chain.request.target) {
            Ok(identity) => identity,
            Err(error) => {
                last_transient_error = Some(ProductionVerifiedMutationStepError::Identity(error));
                if attempt + 1 < POST_MUTATION_REDISCOVERY_ATTEMPTS {
                    thread::sleep(POST_MUTATION_REDISCOVERY_DELAY);
                    continue;
                }
                break;
            }
        };

        match verify_privileged_layer_post_state(
            chain.request,
            process_receipt,
            before_identity,
            &fresh_identity,
        ) {
            Ok(receipt) => return Ok((fresh_identity, receipt)),
            Err(error) if retryable_post_state_error(&error) => {
                last_transient_error =
                    Some(ProductionVerifiedMutationStepError::Verification(error));
                if attempt + 1 < POST_MUTATION_REDISCOVERY_ATTEMPTS {
                    thread::sleep(POST_MUTATION_REDISCOVERY_DELAY);
                    continue;
                }
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(last_transient_error
        .unwrap_or(ProductionVerifiedMutationStepError::CapabilityInventoryMismatch))
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

    let verified_post_state =
        discover_verified_post_state(session, chain, &process_receipt, before_identity);
    let (fresh_identity, verification_receipt) = match verified_post_state {
        Ok(verified) => verified,
        Err(error) => {
            enter_recovery(
                session,
                "production post-mutation state did not converge to the exact verified boundary",
            )?;
            return Err(error);
        }
    };

    let durable_disposition = persist_privileged_durable_transition(
        session,
        chain.request,
        &process_receipt,
        Some(&verification_receipt),
    )?;

    let fresh_identity_digest = fresh_identity.manifest_digest.clone();
    Ok(ProductionVerifiedMutationStep {
        process_receipt,
        verification_receipt,
        durable_disposition,
        fresh_identity,
        fresh_identity_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_verified_step_feature_is_explicit() {
        assert!(cfg!(feature = "production-mutation-execution"));
    }

    #[test]
    fn only_live_state_convergence_mismatches_are_retryable() {
        assert!(retryable_post_state_error(
            &PrivilegedLayerVerificationError::LogicalVolumeStateMismatch
        ));
        assert!(retryable_post_state_error(
            &PrivilegedLayerVerificationError::FilesystemStateMismatch
        ));
        assert!(!retryable_post_state_error(
            &PrivilegedLayerVerificationError::TargetIdentityMismatch
        ));
        assert!(!retryable_post_state_error(
            &PrivilegedLayerVerificationError::ProcessBindingMismatch
        ));
    }

    #[test]
    fn convergence_window_is_bounded() {
        assert_eq!(POST_MUTATION_REDISCOVERY_ATTEMPTS, 20);
        assert_eq!(POST_MUTATION_REDISCOVERY_DELAY, Duration::from_millis(50));
    }
}
