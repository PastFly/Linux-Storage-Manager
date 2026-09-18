use lsm_core::{HostCapabilities, HostSnapshot};
use serde::Serialize;
use thiserror::Error;

use crate::{
    build_execution_guard_plan, capture_target_identity, decide_filesystem_growth,
    ExecutionGuardError, ExecutionGuardPlan, FilesystemDecisionState, FilesystemGrowthDecision,
    GuardPlanStatus, IdentityGuardError, PlanPreview, PlanStatus, PlannerError,
    TargetIdentityManifest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionHandoffStatus {
    FutureExecutorGatesRequired,
    Blocked,
}

/// Frozen M1B input bundle. It is deliberately non-deserializable and cannot authorize mutation.
///
/// The bundle binds one exact M1A preview to one target-scoped identity manifest, one filesystem
/// decision and one execution-guard plan derived from the same immutable snapshot/capability basis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenExecutionHandoff {
    pub schema_version: u32,
    pub handoff_id: String,
    pub mutation_enabled: bool,
    pub owner_acceptance_required: bool,
    pub status: ExecutionHandoffStatus,
    pub plan: PlanPreview,
    pub plan_basis_digest: String,
    pub capabilities_digest: String,
    pub target_identity: TargetIdentityManifest,
    pub filesystem_decision: FilesystemGrowthDecision,
    pub guard: ExecutionGuardPlan,
    pub blockers: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ExecutionHandoffError {
    #[error("only a preview-ready plan can enter the M1B execution handoff")]
    PlanNotPreview,
    #[error("the preview basis is stale; rediscover and build a fresh plan")]
    StalePlan,
    #[error("target identity capture failed: {0}")]
    Identity(#[from] IdentityGuardError),
    #[error("execution guard construction failed: {0}")]
    Guard(#[from] ExecutionGuardError),
    #[error("planner freshness check failed: {0}")]
    Planner(#[from] PlannerError),
}

/// Build a frozen, still non-executable handoff from one exact current M1A preview.
///
/// This performs no I/O and runs no command. The caller must later acquire the host lock,
/// rediscover, revalidate identity, satisfy filesystem/backup gates, obtain explicit owner
/// acceptance for executor rollout, and record exact plan approval before mutation can exist.
pub fn build_frozen_execution_handoff(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    plan: &PlanPreview,
) -> Result<FrozenExecutionHandoff, ExecutionHandoffError> {
    if plan.status() != PlanStatus::Preview {
        return Err(ExecutionHandoffError::PlanNotPreview);
    }
    if !plan.matches_basis(snapshot, capabilities)? {
        return Err(ExecutionHandoffError::StalePlan);
    }

    let target_identity = capture_target_identity(snapshot, plan.target())?;
    let filesystem_decision = decide_filesystem_growth(snapshot, capabilities, plan.target());
    let guard = build_execution_guard_plan(plan.plan_id(), &target_identity)?;
    let capabilities_digest = crate::fingerprint(capabilities)?;

    let mut blockers = guard.blockers.clone();
    if matches!(
        filesystem_decision.state,
        FilesystemDecisionState::Blocked | FilesystemDecisionState::AdapterRequired
    ) {
        blockers.extend(
            filesystem_decision
                .reasons
                .iter()
                .map(|reason| format!("filesystem preflight: {reason}")),
        );
        if filesystem_decision.reasons.is_empty() {
            blockers.push("filesystem preflight is not executor-ready".to_owned());
        }
    }
    blockers.sort();
    blockers.dedup();

    let status = if guard.status == GuardPlanStatus::Blocked || !blockers.is_empty() {
        ExecutionHandoffStatus::Blocked
    } else {
        ExecutionHandoffStatus::FutureExecutorGatesRequired
    };

    let mut handoff = FrozenExecutionHandoff {
        schema_version: 1,
        handoff_id: String::new(),
        mutation_enabled: false,
        owner_acceptance_required: true,
        status,
        plan: plan.clone(),
        plan_basis_digest: plan.basis_digest().to_owned(),
        capabilities_digest,
        target_identity,
        filesystem_decision,
        guard,
        blockers,
    };
    handoff.handoff_id = crate::fingerprint(&(
        handoff.schema_version,
        handoff.plan.plan_id(),
        &handoff.plan_basis_digest,
        &handoff.capabilities_digest,
        &handoff.target_identity.manifest_digest,
        &handoff.filesystem_decision,
        &handoff.guard.guard_id,
        handoff.status,
        handoff.mutation_enabled,
        handoff.owner_acceptance_required,
    ))?;
    Ok(handoff)
}
