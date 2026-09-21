use lsm_planner::{JournalPhase, Operation, Reversibility};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    preconditions::journal_digest, ExactPlanApproval, LockedExecutionSession, LockedSessionError,
    MUTATION_ENABLED,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIntentManifestStatus {
    FrozenNonExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrozenIntentRole {
    PreExecutionEvidence,
    MutationCandidate,
    Verification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FrozenIntentAction {
    RevalidateSnapshot,
    BackupLvmMetadata {
        vg_uuid: String,
    },
    BackupPartitionTableMetadata {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    ExtendPartition {
        partition: String,
        start_sector: u64,
        old_size_sectors: u64,
        new_size_sectors: u64,
        sector_size_bytes: u64,
    },
    ExtendLogicalVolume {
        lv_uuid: String,
        additional_extents: u64,
        expected_lv_size_bytes: u64,
    },
    GrowFilesystem {
        fs_type: String,
        mountpoint: String,
    },
    RediscoverAndVerify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenIntentStep {
    pub plan_step_id: u32,
    pub depends_on: Vec<u32>,
    pub reversibility: Reversibility,
    pub role: FrozenIntentRole,
    pub action: FrozenIntentAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationBarrierSpec {
    pub after_plan_step_id: u32,
    pub before_next_mutation: bool,
    pub require_fresh_target_identity: bool,
    pub require_fresh_capabilities: bool,
    pub require_expected_state_check: bool,
    pub stop_on_mismatch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FrozenExecutionIntentManifest {
    schema_version: u32,
    manifest_id: String,
    approval_id: String,
    approved_journal_id: String,
    approved_journal_digest: String,
    plan_id: String,
    evidence_bundle_id: String,
    target_manifest_digest: String,
    locked_session_id: String,
    status: ExecutionIntentManifestStatus,
    mutation_enabled: bool,
    owner_acceptance_required: bool,
    steps: Vec<FrozenIntentStep>,
    verification_barriers: Vec<VerificationBarrierSpec>,
    blockers: Vec<String>,
    future_gates: Vec<String>,
}

impl FrozenExecutionIntentManifest {
    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub fn approved_journal_id(&self) -> &str {
        &self.approved_journal_id
    }

    pub fn approved_journal_digest(&self) -> &str {
        &self.approved_journal_digest
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn evidence_bundle_id(&self) -> &str {
        &self.evidence_bundle_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.target_manifest_digest
    }

    pub fn locked_session_id(&self) -> &str {
        &self.locked_session_id
    }

    pub fn status(&self) -> ExecutionIntentManifestStatus {
        self.status
    }

    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }

    pub fn owner_acceptance_required(&self) -> bool {
        self.owner_acceptance_required
    }

    pub fn steps(&self) -> &[FrozenIntentStep] {
        &self.steps
    }

    pub fn verification_barriers(&self) -> &[VerificationBarrierSpec] {
        &self.verification_barriers
    }

    pub fn blockers(&self) -> &[String] {
        &self.blockers
    }

    pub fn future_gates(&self) -> &[String] {
        &self.future_gates
    }

    fn compute_manifest_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.approval_id,
            &self.approved_journal_id,
            &self.approved_journal_digest,
            &self.plan_id,
            &self.evidence_bundle_id,
            &self.target_manifest_digest,
            &self.locked_session_id,
            self.status,
            self.mutation_enabled,
            self.owner_acceptance_required,
            &self.steps,
            &self.verification_barriers,
            &self.blockers,
            &self.future_gates,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum ExecutionIntentError {
    #[error("execution intent requires the journal to be exactly approved")]
    SessionNotApproved,
    #[error("mutation-enabled state is forbidden during M1B13 intent freezing")]
    MutationEnabled,
    #[error("mutation may already have started; execution intent cannot be frozen")]
    MutationMayHaveStarted,
    #[error("exact approval does not match the current approved session")]
    ApprovalBindingMismatch,
    #[error("owner acceptance must remain an explicit future gate")]
    OwnerAcceptanceInvariant,
    #[error("approved operation is not yet representable as M1B13 semantic intent")]
    UnsupportedOperation,
    #[error("could not serialize frozen execution intent: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("locked-session durable state verification failed: {0}")]
    Session(#[from] LockedSessionError),
}

pub fn freeze_execution_intent(
    session: &LockedExecutionSession<'_>,
    approval: &ExactPlanApproval,
) -> Result<FrozenExecutionIntentManifest, ExecutionIntentError> {
    if session.journal().phase != JournalPhase::Approved {
        return Err(ExecutionIntentError::SessionNotApproved);
    }
    if MUTATION_ENABLED
        || session.mutation_enabled()
        || session.handoff().mutation_enabled()
        || approval.mutation_enabled()
    {
        return Err(ExecutionIntentError::MutationEnabled);
    }
    if session.journal().mutation_may_have_started {
        return Err(ExecutionIntentError::MutationMayHaveStarted);
    }
    session.require_current_durable_journal()?;

    let handoff = session.handoff();
    let binding = session
        .journal()
        .approval
        .as_ref()
        .ok_or(ExecutionIntentError::ApprovalBindingMismatch)?;

    if approval.journal_id() != session.journal().journal_id
        || approval.locked_session_id() != session.session_id()
        || approval.plan_id() != handoff.plan().plan_id()
        || approval.evidence_bundle_id() != binding.evidence_bundle_id
        || approval.target_manifest_digest() != handoff.target_identity().manifest_digest
        || binding.approval_id != approval.approval_id()
        || binding.plan_id != approval.plan_id()
        || binding.target_manifest_digest != approval.target_manifest_digest()
        || binding.locked_session_id != approval.locked_session_id()
    {
        return Err(ExecutionIntentError::ApprovalBindingMismatch);
    }
    if !approval.owner_acceptance_required() || !handoff.owner_acceptance_required() {
        return Err(ExecutionIntentError::OwnerAcceptanceInvariant);
    }

    let mut steps = Vec::with_capacity(handoff.plan().steps().len());
    let mut verification_barriers = Vec::new();
    for step in handoff.plan().steps() {
        let (role, action) = match &step.operation {
            Operation::RevalidateSnapshot => (
                FrozenIntentRole::PreExecutionEvidence,
                FrozenIntentAction::RevalidateSnapshot,
            ),
            Operation::BackupLvmMetadata { vg_uuid } => (
                FrozenIntentRole::PreExecutionEvidence,
                FrozenIntentAction::BackupLvmMetadata {
                    vg_uuid: vg_uuid.clone(),
                },
            ),
            Operation::ExtendLogicalVolume {
                lv_uuid,
                additional_extents,
                expected_lv_size_bytes,
            } => (
                FrozenIntentRole::MutationCandidate,
                FrozenIntentAction::ExtendLogicalVolume {
                    lv_uuid: lv_uuid.clone(),
                    additional_extents: *additional_extents,
                    expected_lv_size_bytes: *expected_lv_size_bytes,
                },
            ),
            Operation::GrowFilesystem {
                fs_type,
                mountpoint,
            } => (
                FrozenIntentRole::MutationCandidate,
                FrozenIntentAction::GrowFilesystem {
                    fs_type: fs_type.clone(),
                    mountpoint: mountpoint.clone(),
                },
            ),
            Operation::RediscoverAndVerify => (
                FrozenIntentRole::Verification,
                FrozenIntentAction::RediscoverAndVerify,
            ),
            Operation::BackupPartitionTableMetadata { .. } | Operation::ExtendPartition { .. } => {
                return Err(ExecutionIntentError::UnsupportedOperation);
            }
        };

        if role == FrozenIntentRole::MutationCandidate {
            verification_barriers.push(VerificationBarrierSpec {
                after_plan_step_id: step.id,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            });
        }
        steps.push(FrozenIntentStep {
            plan_step_id: step.id,
            depends_on: step.depends_on.clone(),
            reversibility: step.reversibility,
            role,
            action,
        });
    }

    let mut manifest = FrozenExecutionIntentManifest {
        schema_version: 1,
        manifest_id: String::new(),
        approval_id: approval.approval_id().to_owned(),
        approved_journal_id: session.journal().journal_id.clone(),
        approved_journal_digest: journal_digest(session.journal())?,
        plan_id: approval.plan_id().to_owned(),
        evidence_bundle_id: approval.evidence_bundle_id().to_owned(),
        target_manifest_digest: approval.target_manifest_digest().to_owned(),
        locked_session_id: approval.locked_session_id().to_owned(),
        status: ExecutionIntentManifestStatus::FrozenNonExecutable,
        mutation_enabled: false,
        owner_acceptance_required: true,
        steps,
        verification_barriers,
        blockers: Vec::new(),
        future_gates: vec![
            "explicit owner acceptance for mutation-capable rollout".to_owned(),
            "reviewed semantic-to-argv compiler".to_owned(),
            "minimal executable allowlist".to_owned(),
            "privileged-helper protocol".to_owned(),
            "per-layer rediscovery implementation".to_owned(),
            "interruption and recovery semantics".to_owned(),
            "disposable write matrix".to_owned(),
        ],
    };
    manifest.manifest_id = manifest.compute_manifest_id()?;
    Ok(manifest)
}
