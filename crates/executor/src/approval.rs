use lsm_planner::{ExactApprovalBinding, JournalPhase};
use thiserror::Error;

use crate::{
    preconditions::journal_digest, LockedExecutionSession, LockedSessionError,
    PreconditionsVerification, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPlanApproval {
    binding: ExactApprovalBinding,
    journal_id: String,
    owner_acceptance_required: bool,
    mutation_enabled: bool,
}

impl ExactPlanApproval {
    pub fn approval_id(&self) -> &str {
        &self.binding.approval_id
    }

    pub fn plan_id(&self) -> &str {
        &self.binding.plan_id
    }

    pub fn evidence_bundle_id(&self) -> &str {
        &self.binding.evidence_bundle_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.binding.target_manifest_digest
    }

    pub fn locked_session_id(&self) -> &str {
        &self.binding.locked_session_id
    }

    pub fn preconditions_journal_digest(&self) -> &str {
        &self.binding.preconditions_journal_digest
    }

    pub fn journal_id(&self) -> &str {
        &self.journal_id
    }

    pub fn owner_acceptance_required(&self) -> bool {
        self.owner_acceptance_required
    }

    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }
}

#[derive(Debug, Error)]
pub enum ExactPlanApprovalError {
    #[error("exact plan approval requires the journal to be exactly preconditions_verified")]
    SessionNotPreconditionsVerified,
    #[error("exact plan approval requires a durable journal store")]
    DurableJournalRequired,
    #[error("mutation-enabled state is forbidden during M1B12 exact approval")]
    MutationEnabled,
    #[error("preconditions verification belongs to a different locked execution session")]
    VerificationSessionMismatch,
    #[error("preconditions verification belongs to a different durable journal")]
    VerificationJournalMismatch,
    #[error("preconditions verification belongs to a different exact plan")]
    VerificationPlanMismatch,
    #[error("preconditions verification belongs to a different target identity")]
    VerificationTargetMismatch,
    #[error("preconditions verification no longer matches the current journal state")]
    VerificationJournalStale,
    #[error("operator approval does not match the exact plan ID")]
    ApprovedPlanMismatch,
    #[error("operator approval does not match the exact pre-mutation evidence bundle ID")]
    ApprovedEvidenceMismatch,
    #[error("operator approval does not match the exact target identity manifest")]
    ApprovedTargetMismatch,
    #[error("exact approval binding contains an invalid digest identity")]
    InvalidDigestIdentity,
    #[error("owner acceptance must remain an explicit future gate")]
    OwnerAcceptanceInvariant,
    #[error("could not serialize exact approval basis: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("locked-session durable approval transition failed: {0}")]
    Session(#[from] LockedSessionError),
}

pub fn approve_exact_plan(
    session: &mut LockedExecutionSession<'_>,
    verification: &PreconditionsVerification,
    approved_plan_id: &str,
    approved_evidence_bundle_id: &str,
    approved_target_manifest_digest: &str,
) -> Result<ExactPlanApproval, ExactPlanApprovalError> {
    if session.journal().phase != JournalPhase::PreconditionsVerified {
        return Err(ExactPlanApprovalError::SessionNotPreconditionsVerified);
    }
    if !session.durable_journal_enabled() {
        return Err(ExactPlanApprovalError::DurableJournalRequired);
    }
    if MUTATION_ENABLED || session.mutation_enabled() || session.handoff().mutation_enabled() {
        return Err(ExactPlanApprovalError::MutationEnabled);
    }

    let handoff = session.handoff();
    if verification.locked_session_id() != session.session_id() {
        return Err(ExactPlanApprovalError::VerificationSessionMismatch);
    }
    if verification.journal_id() != session.journal().journal_id {
        return Err(ExactPlanApprovalError::VerificationJournalMismatch);
    }
    if verification.plan_id() != session.journal().plan_id
        || verification.plan_id() != handoff.plan().plan_id()
    {
        return Err(ExactPlanApprovalError::VerificationPlanMismatch);
    }
    if verification.target_manifest_digest() != session.journal().baseline_manifest_digest
        || verification.target_manifest_digest() != handoff.target_identity().manifest_digest
    {
        return Err(ExactPlanApprovalError::VerificationTargetMismatch);
    }

    let current_journal_digest = journal_digest(session.journal())?;
    if verification.journal_digest() != current_journal_digest {
        return Err(ExactPlanApprovalError::VerificationJournalStale);
    }

    if approved_plan_id != verification.plan_id() {
        return Err(ExactPlanApprovalError::ApprovedPlanMismatch);
    }
    if approved_evidence_bundle_id != verification.bundle_id() {
        return Err(ExactPlanApprovalError::ApprovedEvidenceMismatch);
    }
    if approved_target_manifest_digest != verification.target_manifest_digest() {
        return Err(ExactPlanApprovalError::ApprovedTargetMismatch);
    }
    if !handoff.owner_acceptance_required() {
        return Err(ExactPlanApprovalError::OwnerAcceptanceInvariant);
    }

    for value in [
        verification.bundle_id(),
        verification.locked_session_id(),
        verification.journal_id(),
        verification.plan_id(),
        verification.target_manifest_digest(),
        verification.journal_digest(),
    ] {
        if !is_lower_hex_digest(value) {
            return Err(ExactPlanApprovalError::InvalidDigestIdentity);
        }
    }

    let mut binding = ExactApprovalBinding {
        schema_version: 1,
        approval_id: String::new(),
        plan_id: verification.plan_id().to_owned(),
        evidence_bundle_id: verification.bundle_id().to_owned(),
        target_manifest_digest: verification.target_manifest_digest().to_owned(),
        locked_session_id: verification.locked_session_id().to_owned(),
        preconditions_journal_digest: verification.journal_digest().to_owned(),
    };
    binding.approval_id = binding.expected_approval_id()?;

    session.persist_exact_plan_approved(approved_plan_id, &binding)?;
    debug_assert_eq!(session.journal().phase, JournalPhase::Approved);

    Ok(ExactPlanApproval {
        binding,
        journal_id: session.journal().journal_id.clone(),
        owner_acceptance_required: true,
        mutation_enabled: false,
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
