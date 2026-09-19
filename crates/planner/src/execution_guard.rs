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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub plan_id: String,
    pub target: String,
    pub baseline_manifest_digest: String,
    pub phase: JournalPhase,
    pub mutation_may_have_started: bool,
    pub events: Vec<JournalEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalTransition<'a> {
    HostLockAcquired,
    IdentityRevalidated { fresh_manifest_digest: &'a str },
    PreconditionsVerified,
    ExactPlanApproved { approved_plan_id: &'a str },
    ExecutionStarted,
    VerificationStarted,
    Completed,
    Interrupted { reason: &'a str },
    Abort { reason: &'a str },
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
            JournalTransition::ExactPlanApproved { approved_plan_id } => {
                if self.phase != JournalPhase::PreconditionsVerified {
                    return Err(self.invalid("exact_plan_approved"));
                }
                if approved_plan_id != self.plan_id {
                    return Err(JournalError::ApprovalMismatch);
                }
                self.advance(
                    JournalPhase::PreconditionsVerified,
                    JournalPhase::Approved,
                    "exact-plan-approved",
                    "approval recorded for the exact frozen plan",
                )
            }
            JournalTransition::ExecutionStarted => {
                if self.phase != JournalPhase::Approved {
                    return Err(self.invalid("execution_started"));
                }
                // From this point a crash can occur after a mutating syscall/tool starts but before
                // the next journal write. Therefore interruption must require reconciliation.
                self.mutation_may_have_started = true;
                self.advance(
                    JournalPhase::Approved,
                    JournalPhase::Executing,
                    "execution-started",
                    "mutating execution boundary entered; blind replay is no longer allowed",
                )
            }
            JournalTransition::VerificationStarted => self.advance(
                JournalPhase::Executing,
                JournalPhase::Verifying,
                "verification-started",
                "post-mutation rediscovery and verification started",
            ),
            JournalTransition::Completed => self.advance(
                JournalPhase::Verifying,
                JournalPhase::Completed,
                "completed",
                "final topology and expected invariants verified",
            ),
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
