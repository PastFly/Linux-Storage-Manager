use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{LayerRouteStatus, TargetIdentityManifest};

pub const HOST_STORAGE_LOCK_PATH: &str = "/run/lock/linux-storage-manager/storage.lock";
pub const JOURNAL_DIRECTORY: &str = "/var/lib/linux-storage-manager/journal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockScope {
    HostExclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationLockPlan {
    pub scope: LockScope,
    pub lock_path: String,
    pub resource_keys: Vec<String>,
    pub blocking: bool,
    pub stale_lock_recovery: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardPlanStatus {
    FutureExecutorGatesRequired,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardGateKind {
    AcquireHostLock,
    CaptureFreshSnapshot,
    RevalidateTargetIdentity,
    VerifyFilesystemDecision,
    VerifyMetadataBackups,
    RecordExactPlanApproval,
    CreateDurableJournal,
    VerifyAfterEveryMutationBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuardGate {
    pub kind: GuardGateKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionGuardPlan {
    pub schema_version: u32,
    pub guard_id: String,
    pub plan_id: String,
    pub target: String,
    pub baseline_manifest_digest: String,
    pub route_status: LayerRouteStatus,
    pub status: GuardPlanStatus,
    pub lock: OperationLockPlan,
    pub journal_path: String,
    pub gates: Vec<GuardGate>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ExecutionGuardError {
    #[error("plan ID must be nonempty and contain no control characters")]
    InvalidPlanId,
    #[error("target identity manifest digest is missing")]
    MissingManifestDigest,
    #[error("could not serialize execution guard input: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn build_execution_guard_plan(
    plan_id: &str,
    manifest: &TargetIdentityManifest,
) -> Result<ExecutionGuardPlan, ExecutionGuardError> {
    if plan_id.is_empty() || plan_id.chars().any(char::is_control) {
        return Err(ExecutionGuardError::InvalidPlanId);
    }
    if manifest.manifest_digest.is_empty() {
        return Err(ExecutionGuardError::MissingManifestDigest);
    }

    let resource_keys = resource_keys(manifest);
    let guard_id = fingerprint(&(
        1_u32,
        plan_id,
        &manifest.target,
        &manifest.manifest_digest,
        &resource_keys,
    ))?;
    let journal_path = format!("{JOURNAL_DIRECTORY}/{guard_id}.json");

    let mut blockers = Vec::new();
    if manifest.route_status != LayerRouteStatus::SupportedProfile {
        blockers.push(format!(
            "semantic route status is {:?}; a dedicated supported adapter is required before execution",
            manifest.route_status
        ));
    }

    let status = if blockers.is_empty() {
        GuardPlanStatus::FutureExecutorGatesRequired
    } else {
        GuardPlanStatus::Blocked
    };

    Ok(ExecutionGuardPlan {
        schema_version: 1,
        guard_id,
        plan_id: plan_id.to_owned(),
        target: manifest.target.clone(),
        baseline_manifest_digest: manifest.manifest_digest.clone(),
        route_status: manifest.route_status,
        status,
        lock: OperationLockPlan {
            scope: LockScope::HostExclusive,
            lock_path: HOST_STORAGE_LOCK_PATH.to_owned(),
            resource_keys,
            blocking: false,
            stale_lock_recovery:
                "use an OS-released advisory lock; never infer safety from deleting a pathname"
                    .to_owned(),
        },
        journal_path,
        gates: vec![
            gate(
                GuardGateKind::AcquireHostLock,
                "acquire the host-exclusive storage-operation lock before the final rediscovery",
            ),
            gate(
                GuardGateKind::CaptureFreshSnapshot,
                "rediscover the host while the exclusive lock is held",
            ),
            gate(
                GuardGateKind::RevalidateTargetIdentity,
                "compare the selected target identity manifest against the fresh snapshot and reject any relevant change",
            ),
            gate(
                GuardGateKind::VerifyFilesystemDecision,
                "resolve executor-grade filesystem health/features and online/offline requirements before mutation",
            ),
            gate(
                GuardGateKind::VerifyMetadataBackups,
                "create and verify required partition/LVM metadata backups before the first irreversible command",
            ),
            gate(
                GuardGateKind::RecordExactPlanApproval,
                "record approval for the exact fresh plan ID; approval for an older plan must not carry forward",
            ),
            gate(
                GuardGateKind::CreateDurableJournal,
                "durably create the operation journal before launching the first mutating command",
            ),
            gate(
                GuardGateKind::VerifyAfterEveryMutationBoundary,
                "rediscover and verify each completed storage layer before advancing to the dependent layer",
            ),
        ],
        blockers,
    })
}

fn gate(kind: GuardGateKind, message: &str) -> GuardGate {
    GuardGate {
        kind,
        message: message.to_owned(),
    }
}

fn resource_keys(manifest: &TargetIdentityManifest) -> Vec<String> {
    let mut keys = Vec::new();
    for device in &manifest.devices {
        keys.push(format!("device:{}", device.path));
    }
    for partition in &manifest.partitions {
        keys.push(format!("partition:{}", partition.partition));
    }
    for item in &manifest.lvm {
        keys.push(format!("lvm:{:?}:{}", item.kind, item.name));
    }
    if let Some(filesystem) = &manifest.filesystem {
        keys.push(format!("filesystem:{}", filesystem.device));
    }
    for mount in &manifest.mounts {
        keys.push(format!("mount:{}", mount.target));
    }
    keys.sort();
    keys.dedup();
    keys
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalPhase {
    Planned,
    HostLockHeld,
    IdentityRevalidated,
    PreconditionsVerified,
    Approved,
    Executing,
    Verifying,
    Completed,
    Aborted,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDisposition {
    RestartFromFreshPlan,
    RecoveryRequired,
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEvent {
    pub sequence: u64,
    pub from: JournalPhase,
    pub to: JournalPhase,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactApprovalBinding {
    pub schema_version: u32,
    pub approval_id: String,
    pub plan_id: String,
    pub evidence_bundle_id: String,
    pub target_manifest_digest: String,
    pub locked_session_id: String,
    pub preconditions_journal_digest: String,
}

impl ExactApprovalBinding {
    pub fn expected_approval_id(&self) -> Result<String, serde_json::Error> {
        fingerprint(&(
            self.schema_version,
            &self.plan_id,
            &self.evidence_bundle_id,
            &self.target_manifest_digest,
            &self.locked_session_id,
            &self.preconditions_journal_digest,
        ))
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.approval_id == self.expected_approval_id()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStartBinding {
    pub schema_version: u32,
    pub execution_id: String,
    pub journal_id: String,
    pub plan_id: String,
    pub approval_id: String,
    pub source_manifest_id: String,
    pub native_manifest_digest: String,
    pub fresh_identity_digest: String,
    pub mutation_step_ids: Vec<u32>,
    pub approved_journal_digest: String,
}

impl ExecutionStartBinding {
    pub fn expected_execution_id(&self) -> Result<String, serde_json::Error> {
        fingerprint(&(
            self.schema_version,
            &self.journal_id,
            &self.plan_id,
            &self.approval_id,
            &self.source_manifest_id,
            &self.native_manifest_digest,
            &self.fresh_identity_digest,
            &self.mutation_step_ids,
            &self.approved_journal_digest,
        ))
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.execution_id == self.expected_execution_id()?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedMutationBoundaryBinding {
    pub schema_version: u32,
    pub boundary_id: String,
    pub execution_id: String,
    pub completed_step_id: u32,
    pub next_step_id: u32,
    pub fresh_identity_digest: String,
}

impl VerifiedMutationBoundaryBinding {
    pub fn expected_boundary_id(&self) -> Result<String, serde_json::Error> {
        fingerprint(&(
            self.schema_version,
            &self.execution_id,
            self.completed_step_id,
            self.next_step_id,
            &self.fresh_identity_digest,
        ))
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.boundary_id == self.expected_boundary_id()?)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutionStartBindingError {
    #[error("execution start binding requires an approved journal")]
    JournalNotApproved,
    #[error("execution start binding cannot be built after mutation may have started")]
    MutationAlreadyStarted,
    #[error("approved journal is missing its exact approval binding")]
    ApprovalMissing,
    #[error("source execution-intent manifest ID is not a SHA-256 digest")]
    InvalidSourceManifestId,
    #[error("native manifest digest is not a SHA-256 digest")]
    InvalidNativeManifestDigest,
    #[error("fresh identity digest does not match the approved journal baseline")]
    FreshIdentityMismatch,
    #[error("mutation step sequence must be nonempty, nonzero and unique")]
    InvalidMutationStepSequence,
    #[error("could not serialize execution start binding: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub plan_id: String,
    pub target: String,
    pub baseline_manifest_digest: String,
    pub phase: JournalPhase,
    pub mutation_may_have_started: bool,
    pub approval: Option<ExactApprovalBinding>,
    pub execution: Option<ExecutionStartBinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_boundary: Option<VerifiedMutationBoundaryBinding>,
    pub events: Vec<JournalEvent>,
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub fn build_execution_start_binding(
    journal: &OperationJournal,
    source_manifest_id: &str,
    native_manifest_digest: &str,
    fresh_identity_digest: &str,
    mutation_step_ids: &[u32],
) -> Result<ExecutionStartBinding, ExecutionStartBindingError> {
    if journal.phase != JournalPhase::Approved {
        return Err(ExecutionStartBindingError::JournalNotApproved);
    }
    if journal.mutation_may_have_started
        || journal.execution.is_some()
        || journal.verified_boundary.is_some()
    {
        return Err(ExecutionStartBindingError::MutationAlreadyStarted);
    }
    let approval = journal
        .approval
        .as_ref()
        .ok_or(ExecutionStartBindingError::ApprovalMissing)?;
    if !is_sha256_hex(source_manifest_id) {
        return Err(ExecutionStartBindingError::InvalidSourceManifestId);
    }
    if !is_sha256_hex(native_manifest_digest) {
        return Err(ExecutionStartBindingError::InvalidNativeManifestDigest);
    }
    if fresh_identity_digest != journal.baseline_manifest_digest {
        return Err(ExecutionStartBindingError::FreshIdentityMismatch);
    }
    if mutation_step_ids.is_empty() || mutation_step_ids.contains(&0) || {
        let mut seen = std::collections::BTreeSet::new();
        mutation_step_ids
            .iter()
            .any(|step_id| !seen.insert(*step_id))
    } {
        return Err(ExecutionStartBindingError::InvalidMutationStepSequence);
    }

    let approved_journal_digest = fingerprint(journal)
        .map_err(|error| ExecutionStartBindingError::Serialization(error.to_string()))?;
    let mut binding = ExecutionStartBinding {
        schema_version: 1,
        execution_id: String::new(),
        journal_id: journal.journal_id.clone(),
        plan_id: journal.plan_id.clone(),
        approval_id: approval.approval_id.clone(),
        source_manifest_id: source_manifest_id.to_owned(),
        native_manifest_digest: native_manifest_digest.to_owned(),
        fresh_identity_digest: fresh_identity_digest.to_owned(),
        mutation_step_ids: mutation_step_ids.to_vec(),
        approved_journal_digest,
    };
    binding.execution_id = binding
        .expected_execution_id()
        .map_err(|error| ExecutionStartBindingError::Serialization(error.to_string()))?;
    Ok(binding)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalTransition<'a> {
    HostLockAcquired,
    IdentityRevalidated {
        fresh_manifest_digest: &'a str,
    },
    PreconditionsVerified,
    ExactPlanApproved {
        approved_plan_id: &'a str,
        approval: &'a ExactApprovalBinding,
    },
    ExecutionStarted {
        binding: &'a ExecutionStartBinding,
    },
    VerificationStarted,
    VerificationPassedContinue {
        completed_step_id: u32,
        next_step_id: u32,
        fresh_identity_digest: &'a str,
    },
    Completed,
    Interrupted {
        reason: &'a str,
    },
    Abort {
        reason: &'a str,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JournalError {
    #[error("journal transition {action} is invalid from phase {phase:?}")]
    InvalidTransition {
        phase: JournalPhase,
        action: &'static str,
    },
    #[error("fresh target manifest digest does not match the frozen baseline")]
    IdentityMismatch,
    #[error("approval does not match the exact frozen plan ID")]
    ApprovalMismatch,
    #[error("approval binding schema is not supported")]
    ApprovalBindingSchemaMismatch,
    #[error("approval binding does not match the journal plan ID")]
    ApprovalBindingPlanMismatch,
    #[error("approval binding does not match the journal target manifest")]
    ApprovalBindingTargetMismatch,
    #[error("approval binding fingerprint does not match its contents")]
    ApprovalBindingIntegrityMismatch,
    #[error("approval binding does not match the exact preconditions journal state")]
    ApprovalBindingJournalMismatch,
    #[error("execution binding schema is not supported")]
    ExecutionBindingSchemaMismatch,
    #[error("execution binding does not match the journal ID")]
    ExecutionBindingJournalIdMismatch,
    #[error("execution binding does not match the journal plan ID")]
    ExecutionBindingPlanMismatch,
    #[error("execution binding does not match the exact approval")]
    ExecutionBindingApprovalMismatch,
    #[error("execution binding fresh identity does not match the journal baseline")]
    ExecutionBindingIdentityMismatch,
    #[error("execution binding fingerprint does not match its contents")]
    ExecutionBindingIntegrityMismatch,
    #[error("execution binding does not match the exact approved journal state")]
    ExecutionBindingApprovedJournalMismatch,
    #[error("execution start requires an exact approval binding")]
    ExecutionBindingApprovalMissing,
    #[error("verification continuation requires the durable execution binding")]
    VerificationExecutionBindingMissing,
    #[error("verified mutation boundary does not match the ordered execution step sequence")]
    VerificationSequenceMismatch,
    #[error("verified mutation boundary identity digest is not a SHA-256 digest")]
    VerificationIdentityDigestInvalid,
    #[error("could not bind verified mutation boundary: {0}")]
    VerificationBoundarySerialization(String),
    #[error("completion requires the durable verified boundary for the final mutation step")]
    CompletionVerifiedBoundaryMismatch,
    #[error("journal is terminal and cannot advance")]
    Terminal,
}

impl OperationJournal {
    pub fn new(guard: &ExecutionGuardPlan) -> Self {
        Self {
            schema_version: 1,
            journal_id: guard.guard_id.clone(),
            plan_id: guard.plan_id.clone(),
            target: guard.target.clone(),
            baseline_manifest_digest: guard.baseline_manifest_digest.clone(),
            phase: JournalPhase::Planned,
            mutation_may_have_started: false,
            approval: None,
            execution: None,
            verified_boundary: None,
            events: Vec::new(),
        }
    }

    pub fn apply(&mut self, transition: JournalTransition<'_>) -> Result<(), JournalError> {
        if matches!(
            self.phase,
            JournalPhase::Completed | JournalPhase::Aborted | JournalPhase::RecoveryRequired
        ) {
            return Err(JournalError::Terminal);
        }

        match transition {
            JournalTransition::HostLockAcquired => self.advance(
                JournalPhase::Planned,
                JournalPhase::HostLockHeld,
                "host-lock-acquired",
                "host-exclusive storage-operation lock acquired",
            ),
            JournalTransition::IdentityRevalidated {
                fresh_manifest_digest,
            } => {
                if self.phase != JournalPhase::HostLockHeld {
                    return Err(self.invalid("identity_revalidated"));
                }
                if fresh_manifest_digest != self.baseline_manifest_digest {
                    return Err(JournalError::IdentityMismatch);
                }
                self.advance(
                    JournalPhase::HostLockHeld,
                    JournalPhase::IdentityRevalidated,
                    "identity-revalidated",
                    "fresh target identity exactly matches the frozen baseline",
                )
            }
            JournalTransition::PreconditionsVerified => self.advance(
                JournalPhase::IdentityRevalidated,
                JournalPhase::PreconditionsVerified,
                "preconditions-verified",
                "filesystem decision, backups and other future executor prerequisites verified",
            ),
            JournalTransition::ExactPlanApproved {
                approved_plan_id,
                approval,
            } => {
                if self.phase != JournalPhase::PreconditionsVerified {
                    return Err(self.invalid("exact_plan_approved"));
                }
                if approved_plan_id != self.plan_id {
                    return Err(JournalError::ApprovalMismatch);
                }
                if approval.schema_version != 1 {
                    return Err(JournalError::ApprovalBindingSchemaMismatch);
                }
                if approval.plan_id != self.plan_id {
                    return Err(JournalError::ApprovalBindingPlanMismatch);
                }
                if approval.target_manifest_digest != self.baseline_manifest_digest {
                    return Err(JournalError::ApprovalBindingTargetMismatch);
                }
                if !approval.integrity_matches().unwrap_or(false) {
                    return Err(JournalError::ApprovalBindingIntegrityMismatch);
                }
                if fingerprint(self).ok().as_deref()
                    != Some(approval.preconditions_journal_digest.as_str())
                {
                    return Err(JournalError::ApprovalBindingJournalMismatch);
                }
                self.advance(
                    JournalPhase::PreconditionsVerified,
                    JournalPhase::Approved,
                    "exact-plan-approved",
                    "approval recorded for the exact frozen plan and precondition evidence",
                )?;
                self.approval = Some(approval.clone());
                Ok(())
            }
            JournalTransition::ExecutionStarted { binding } => {
                if self.phase != JournalPhase::Approved {
                    return Err(self.invalid("execution_started"));
                }
                let approval = self
                    .approval
                    .as_ref()
                    .ok_or(JournalError::ExecutionBindingApprovalMissing)?;
                if binding.schema_version != 1 {
                    return Err(JournalError::ExecutionBindingSchemaMismatch);
                }
                if binding.journal_id != self.journal_id {
                    return Err(JournalError::ExecutionBindingJournalIdMismatch);
                }
                if binding.plan_id != self.plan_id {
                    return Err(JournalError::ExecutionBindingPlanMismatch);
                }
                if binding.approval_id != approval.approval_id {
                    return Err(JournalError::ExecutionBindingApprovalMismatch);
                }
                if binding.fresh_identity_digest != self.baseline_manifest_digest {
                    return Err(JournalError::ExecutionBindingIdentityMismatch);
                }
                if !binding.integrity_matches().unwrap_or(false) {
                    return Err(JournalError::ExecutionBindingIntegrityMismatch);
                }
                if fingerprint(self).ok().as_deref()
                    != Some(binding.approved_journal_digest.as_str())
                {
                    return Err(JournalError::ExecutionBindingApprovedJournalMismatch);
                }

                self.advance(
                    JournalPhase::Approved,
                    JournalPhase::Executing,
                    "execution-started",
                    "exact native manifest entered mutating execution; blind replay is no longer allowed",
                )?;
                // From this point a crash can occur after a mutating syscall/tool starts but before
                // the next journal write. Therefore interruption must require reconciliation.
                self.mutation_may_have_started = true;
                self.execution = Some(binding.clone());
                Ok(())
            }
            JournalTransition::VerificationStarted => self.advance(
                JournalPhase::Executing,
                JournalPhase::Verifying,
                "verification-started",
                "post-mutation rediscovery and verification started",
            ),
            JournalTransition::VerificationPassedContinue {
                completed_step_id,
                next_step_id,
                fresh_identity_digest,
            } => {
                if self.phase != JournalPhase::Verifying {
                    return Err(self.invalid("verification_passed_continue"));
                }
                let execution = self
                    .execution
                    .as_ref()
                    .ok_or(JournalError::VerificationExecutionBindingMissing)?;
                let ordered_pair = execution
                    .mutation_step_ids
                    .windows(2)
                    .any(|pair| pair[0] == completed_step_id && pair[1] == next_step_id);
                if completed_step_id == 0
                    || next_step_id == 0
                    || completed_step_id == next_step_id
                    || !ordered_pair
                {
                    return Err(JournalError::VerificationSequenceMismatch);
                }
                if !is_sha256_hex(fresh_identity_digest) {
                    return Err(JournalError::VerificationIdentityDigestInvalid);
                }

                let mut verified_boundary = VerifiedMutationBoundaryBinding {
                    schema_version: 1,
                    boundary_id: String::new(),
                    execution_id: execution.execution_id.clone(),
                    completed_step_id,
                    next_step_id,
                    fresh_identity_digest: fresh_identity_digest.to_owned(),
                };
                verified_boundary.boundary_id = verified_boundary
                    .expected_boundary_id()
                    .map_err(|error| {
                        JournalError::VerificationBoundarySerialization(error.to_string())
                    })?;

                let from = self.phase;
                self.phase = JournalPhase::Executing;
                self.verified_boundary = Some(verified_boundary);
                self.push_event(
                    from,
                    JournalPhase::Executing,
                    "verification-passed-continue",
                    &format!(
                        "mutation step {completed_step_id} verified; next mutation step {next_step_id} may proceed"
                    ),
                );
                Ok(())
            }
            JournalTransition::Completed => {
                if self.phase != JournalPhase::Verifying {
                    return Err(self.invalid("completed"));
                }
                let execution = self
                    .execution
                    .as_ref()
                    .ok_or(JournalError::VerificationExecutionBindingMissing)?;
                if execution.mutation_step_ids.len() > 1 {
                    let final_step_id = execution.mutation_step_ids.last().copied();
                    let boundary_matches = self.verified_boundary.as_ref().is_some_and(|boundary| {
                        boundary.execution_id == execution.execution_id
                            && Some(boundary.next_step_id) == final_step_id
                            && boundary.integrity_matches().unwrap_or(false)
                    });
                    if !boundary_matches {
                        return Err(JournalError::CompletionVerifiedBoundaryMismatch);
                    }
                }
                self.advance(
                    JournalPhase::Verifying,
                    JournalPhase::Completed,
                    "completed",
                    "final topology and expected invariants verified",
                )
            }
            JournalTransition::Interrupted { reason } => {
                let from = self.phase;
                if self.mutation_may_have_started
                    || matches!(
                        self.phase,
                        JournalPhase::Executing | JournalPhase::Verifying
                    )
                {
                    self.phase = JournalPhase::RecoveryRequired;
                    self.push_event(
                        from,
                        JournalPhase::RecoveryRequired,
                        "interrupted-after-mutation-boundary",
                        reason,
                    );
                } else {
                    self.phase = JournalPhase::Aborted;
                    self.push_event(
                        from,
                        JournalPhase::Aborted,
                        "interrupted-before-mutation",
                        reason,
                    );
                }
                Ok(())
            }
            JournalTransition::Abort { reason } => {
                let from = self.phase;
                if self.mutation_may_have_started {
                    self.phase = JournalPhase::RecoveryRequired;
                    self.push_event(
                        from,
                        JournalPhase::RecoveryRequired,
                        "abort-after-mutation-boundary",
                        reason,
                    );
                } else {
                    self.phase = JournalPhase::Aborted;
                    self.push_event(from, JournalPhase::Aborted, "aborted", reason);
                }
                Ok(())
            }
        }
    }

    pub fn resume_disposition(&self) -> ResumeDisposition {
        match self.phase {
            JournalPhase::Completed => ResumeDisposition::Complete,
            JournalPhase::Executing | JournalPhase::Verifying | JournalPhase::RecoveryRequired => {
                ResumeDisposition::RecoveryRequired
            }
            JournalPhase::Planned
            | JournalPhase::HostLockHeld
            | JournalPhase::IdentityRevalidated
            | JournalPhase::PreconditionsVerified
            | JournalPhase::Approved
            | JournalPhase::Aborted => ResumeDisposition::RestartFromFreshPlan,
        }
    }

    fn advance(
        &mut self,
        expected: JournalPhase,
        next: JournalPhase,
        code: &'static str,
        detail: &'static str,
    ) -> Result<(), JournalError> {
        if self.phase != expected {
            return Err(self.invalid(code));
        }
        let from = self.phase;
        self.phase = next;
        self.push_event(from, next, code, detail);
        Ok(())
    }

    fn push_event(&mut self, from: JournalPhase, to: JournalPhase, code: &str, detail: &str) {
        self.events.push(JournalEvent {
            sequence: self.events.len() as u64 + 1,
            from,
            to,
            code: code.to_owned(),
            detail: detail.to_owned(),
        });
    }

    fn invalid(&self, action: &'static str) -> JournalError {
        JournalError::InvalidTransition {
            phase: self.phase,
            action,
        }
    }
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}
