use lsm_planner::{FilesystemDecisionState, JournalPhase};
use thiserror::Error;

use crate::{
    LockedExecutionSession, LockedSessionError, PreMutationEvidenceBundle,
    PreMutationEvidenceStatus, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreconditionsVerification {
    bundle_id: String,
    locked_session_id: String,
    journal_id: String,
}

impl PreconditionsVerification {
    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn locked_session_id(&self) -> &str {
        &self.locked_session_id
    }

    pub fn journal_id(&self) -> &str {
        &self.journal_id
    }
}

#[derive(Debug, Error)]
pub enum PreconditionsVerificationError {
    #[error("preconditions verification requires the journal to be exactly identity_revalidated")]
    SessionNotIdentityRevalidated,
    #[error("preconditions verification requires a durable journal store")]
    DurableJournalRequired,
    #[error("mutation-enabled state is forbidden during M1B11 preconditions verification")]
    MutationEnabled,
    #[error("pre-mutation evidence schema is not supported by M1B11")]
    UnsupportedEvidenceSchema,
    #[error("pre-mutation evidence bundle fingerprint does not match its contents")]
    EvidenceIntegrityMismatch,
    #[error("pre-mutation evidence belongs to a different locked execution session")]
    SessionBindingMismatch,
    #[error("pre-mutation evidence belongs to a different frozen handoff")]
    HandoffBindingMismatch,
    #[error("pre-mutation evidence belongs to a different exact plan")]
    PlanBindingMismatch,
    #[error("pre-mutation evidence belongs to a different target identity manifest")]
    TargetBindingMismatch,
    #[error("backup evidence binding is missing or malformed")]
    BackupBindingInvalid,
    #[error("backup receipt evidence was not successfully revalidated")]
    BackupReceiptNotRevalidated,
    #[error("pre-mutation evidence is not complete")]
    EvidenceIncomplete,
    #[error("pre-mutation evidence still contains blockers")]
    EvidenceBlocked,
    #[error("filesystem decision is not ready for online growth")]
    FilesystemNotReady,
    #[error("filesystem preconditions still require an explicit check or action")]
    FilesystemChecksRemain,
    #[error("owner acceptance must remain an explicit future gate")]
    OwnerAcceptanceInvariant,
    #[error("could not verify pre-mutation evidence fingerprint: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("locked-session durable transition failed: {0}")]
    Session(#[from] LockedSessionError),
}

pub fn verify_preconditions(
    session: &mut LockedExecutionSession<'_>,
    evidence: &PreMutationEvidenceBundle,
) -> Result<PreconditionsVerification, PreconditionsVerificationError> {
    if session.journal().phase != JournalPhase::IdentityRevalidated {
        return Err(PreconditionsVerificationError::SessionNotIdentityRevalidated);
    }
    if !session.durable_journal_enabled() {
        return Err(PreconditionsVerificationError::DurableJournalRequired);
    }
    if MUTATION_ENABLED || session.mutation_enabled() || session.handoff().mutation_enabled()
        || evidence.mutation_enabled()
    {
        return Err(PreconditionsVerificationError::MutationEnabled);
    }
    if evidence.schema_version() != 2 {
        return Err(PreconditionsVerificationError::UnsupportedEvidenceSchema);
    }
    if !evidence.integrity_matches()? {
        return Err(PreconditionsVerificationError::EvidenceIntegrityMismatch);
    }

    if evidence.locked_session_id() != session.session_id() {
        return Err(PreconditionsVerificationError::SessionBindingMismatch);
    }

    let handoff = session.handoff();
    if evidence.handoff_id() != handoff.handoff_id() {
        return Err(PreconditionsVerificationError::HandoffBindingMismatch);
    }
    if evidence.plan_id() != handoff.plan().plan_id() {
        return Err(PreconditionsVerificationError::PlanBindingMismatch);
    }
    if evidence.target_manifest_digest() != handoff.target_identity().manifest_digest {
        return Err(PreconditionsVerificationError::TargetBindingMismatch);
    }

    if !handoff.owner_acceptance_required() || !evidence.owner_acceptance_required() {
        return Err(PreconditionsVerificationError::OwnerAcceptanceInvariant);
    }

    if !is_lower_hex_digest(evidence.bundle_id())
        || !is_lower_hex_digest(evidence.locked_session_id())
        || !is_lower_hex_digest(evidence.handoff_id())
        || !is_lower_hex_digest(evidence.plan_id())
        || !is_lower_hex_digest(evidence.target_manifest_digest())
        || !is_lower_hex_digest(evidence.backup_manifest_id())
        || !is_lower_hex_digest(evidence.backup_receipt_id())
    {
        return Err(PreconditionsVerificationError::BackupBindingInvalid);
    }
    if !evidence.backup_receipt_revalidated() {
        return Err(PreconditionsVerificationError::BackupReceiptNotRevalidated);
    }

    if evidence.status() != PreMutationEvidenceStatus::EvidenceComplete {
        return Err(PreconditionsVerificationError::EvidenceIncomplete);
    }
    if !evidence.blockers().is_empty() {
        return Err(PreconditionsVerificationError::EvidenceBlocked);
    }

    let filesystem = evidence.filesystem_decision();
    if filesystem.state != FilesystemDecisionState::ReadyOnlineGrow {
        return Err(PreconditionsVerificationError::FilesystemNotReady);
    }
    if filesystem.read_only_check.is_some()
        || !filesystem.required_actions.is_empty()
        || evidence.future_gates().iter().any(|gate| {
            gate.starts_with("filesystem:") || gate.starts_with("filesystem check required:")
        })
    {
        return Err(PreconditionsVerificationError::FilesystemChecksRemain);
    }

    session.persist_preconditions_verified()?;
    debug_assert_eq!(session.journal().phase, JournalPhase::PreconditionsVerified);

    Ok(PreconditionsVerification {
        bundle_id: evidence.bundle_id().to_owned(),
        locked_session_id: session.session_id().to_owned(),
        journal_id: session.journal().journal_id.clone(),
    })
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_validation_is_strict() {
        assert!(is_lower_hex_digest(&"a".repeat(64)));
        assert!(!is_lower_hex_digest(&"A".repeat(64)));
        assert!(!is_lower_hex_digest(&"a".repeat(63)));
        assert!(!is_lower_hex_digest("not-a-digest"));
    }
}
