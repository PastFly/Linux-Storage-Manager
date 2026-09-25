use std::io;
#[cfg(feature = "disposable-loop-harness")]
use std::path::Path;
#[cfg(feature = "disposable-loop-harness")]
use std::process::{Command, Stdio};

#[cfg(feature = "disposable-loop-harness")]
use lsm_core::{HostCapabilities, HostSnapshot};
#[cfg(feature = "disposable-loop-harness")]
use lsm_planner::{
    decide_filesystem_growth, revalidate_target_identity, FilesystemDecisionState, JournalPhase,
};
use lsm_planner::{FilesystemCheckKind, PlannerError, ReadOnlyFilesystemCheck};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::LockedExecutionSession;
#[cfg(feature = "disposable-loop-harness")]
use crate::{disposable_exec::exact_safe_system_tool_path, MUTATION_ENABLED};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExplicitFilesystemHealthReceipt {
    schema_version: u32,
    receipt_id: String,
    locked_session_id: String,
    handoff_id: String,
    plan_id: String,
    target_manifest_digest: String,
    kind: FilesystemCheckKind,
    tool: String,
    args: Vec<String>,
    stdout_digest: String,
    stderr_digest: String,
}

impl ExplicitFilesystemHealthReceipt {
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn locked_session_id(&self) -> &str {
        &self.locked_session_id
    }

    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.target_manifest_digest
    }

    pub fn kind(&self) -> FilesystemCheckKind {
        self.kind
    }

    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        fingerprint(&(
            self.schema_version,
            &self.locked_session_id,
            &self.handoff_id,
            &self.plan_id,
            &self.target_manifest_digest,
            self.kind,
            &self.tool,
            &self.args,
            &self.stdout_digest,
            &self.stderr_digest,
        ))
    }

    #[cfg(test)]
    pub(crate) fn test_for_check(
        session: &LockedExecutionSession<'_>,
        check: &ReadOnlyFilesystemCheck,
    ) -> Self {
        let mut receipt = Self {
            schema_version: 1,
            receipt_id: String::new(),
            locked_session_id: session.session_id().to_owned(),
            handoff_id: session.handoff().handoff_id().to_owned(),
            plan_id: session.handoff().plan().plan_id().to_owned(),
            target_manifest_digest: session.handoff().target_identity().manifest_digest.clone(),
            kind: check.kind,
            tool: check.tool.clone(),
            args: check.args.clone(),
            stdout_digest: digest_bytes(b"test-stdout"),
            stderr_digest: digest_bytes(b""),
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        receipt
    }
}

#[derive(Debug, Error)]
pub enum ExplicitFilesystemHealthError {
    #[error("explicit filesystem health check requires identity_revalidated state")]
    SessionNotRevalidated,
    #[error(
        "mutation-enabled state is forbidden while collecting explicit filesystem health evidence"
    )]
    MutationEnabled,
    #[error("fresh target identity changed before explicit filesystem health check")]
    TargetIdentityMismatch,
    #[error(
        "fresh storage-tool capability inventory changed before explicit filesystem health check"
    )]
    CapabilityInventoryMismatch,
    #[error("filesystem does not currently require a supported explicit no-modify health check")]
    UnsupportedCheck,
    #[error("selected filesystem health tool path is unsafe")]
    UnsafeToolPath,
    #[error("filesystem health check failed with status {status:?}: {stderr}")]
    CommandFailed { status: Option<i32>, stderr: String },
    #[error("planner capability verification failed: {0}")]
    Planner(#[from] PlannerError),
    #[error("filesystem health check I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("could not serialize filesystem health receipt: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[cfg(feature = "disposable-loop-harness")]
pub fn execute_explicit_filesystem_health_check(
    session: &LockedExecutionSession<'_>,
    fresh_snapshot: &HostSnapshot,
    fresh_capabilities: &HostCapabilities,
    tool_path: &Path,
) -> Result<ExplicitFilesystemHealthReceipt, ExplicitFilesystemHealthError> {
    if session.journal().phase != JournalPhase::IdentityRevalidated {
        return Err(ExplicitFilesystemHealthError::SessionNotRevalidated);
    }
    if MUTATION_ENABLED || session.mutation_enabled() || session.handoff().mutation_enabled() {
        return Err(ExplicitFilesystemHealthError::MutationEnabled);
    }

    let handoff = session.handoff();
    let identity = revalidate_target_identity(handoff.target_identity(), fresh_snapshot);
    if !identity.matches {
        return Err(ExplicitFilesystemHealthError::TargetIdentityMismatch);
    }
    if !handoff.matches_capabilities(fresh_capabilities)? {
        return Err(ExplicitFilesystemHealthError::CapabilityInventoryMismatch);
    }

    let decision =
        decide_filesystem_growth(fresh_snapshot, fresh_capabilities, handoff.plan().target());
    let check = decision
        .read_only_check
        .as_ref()
        .ok_or(ExplicitFilesystemHealthError::UnsupportedCheck)?;
    let supported = match (decision.state, check.kind) {
        (
            FilesystemDecisionState::ReadOnlyHealthCheckRequired,
            FilesystemCheckKind::XfsMountedScrubNoModify,
        ) => {
            check.tool == "xfs_scrub"
                && decision.mountpoint.is_some()
                && check.requires_mounted
                && !check.requires_unmounted
                && !check.run_automatically_on_refresh
        }
        (
            FilesystemDecisionState::OfflineHealthCheckRequired,
            FilesystemCheckKind::Ext4OfflineE2fsckNoModify,
        ) => {
            check.tool == "e2fsck"
                && decision.mountpoint.is_none()
                && !check.requires_mounted
                && check.requires_unmounted
                && !check.run_automatically_on_refresh
        }
        _ => false,
    };
    if !supported {
        return Err(ExplicitFilesystemHealthError::UnsupportedCheck);
    }

    if !exact_safe_system_tool_path(tool_path, &check.tool)? {
        return Err(ExplicitFilesystemHealthError::UnsafeToolPath);
    }
    if check.requires_unmounted {
        let checked_device = check
            .args
            .last()
            .ok_or(ExplicitFilesystemHealthError::UnsupportedCheck)?;
        let checked_device_canonical = std::fs::canonicalize(checked_device).ok();
        if fresh_snapshot.mounts.iter().any(|mount| {
            mount.source.as_deref() == Some(checked_device.as_str())
                || mount.source.as_deref().is_some_and(|source| {
                    std::fs::canonicalize(source).ok() == checked_device_canonical
                })
        }) {
            return Err(ExplicitFilesystemHealthError::UnsupportedCheck);
        }
    }

    let output = Command::new(tool_path)
        .args(&check.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(ExplicitFilesystemHealthError::CommandFailed {
            status: output.status.code(),
            stderr: stderr_summary(&output.stderr),
        });
    }

    let mut receipt = ExplicitFilesystemHealthReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        locked_session_id: session.session_id().to_owned(),
        handoff_id: handoff.handoff_id().to_owned(),
        plan_id: handoff.plan().plan_id().to_owned(),
        target_manifest_digest: handoff.target_identity().manifest_digest.clone(),
        kind: check.kind,
        tool: check.tool.clone(),
        args: check.args.clone(),
        stdout_digest: digest_bytes(&output.stdout),
        stderr_digest: digest_bytes(&output.stderr),
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

pub(crate) fn receipt_matches_exact_check(
    receipt: &ExplicitFilesystemHealthReceipt,
    session: &LockedExecutionSession<'_>,
    check: &ReadOnlyFilesystemCheck,
) -> Result<bool, serde_json::Error> {
    Ok(receipt.schema_version == 1
        && receipt.integrity_matches()?
        && receipt.locked_session_id == session.session_id()
        && receipt.handoff_id == session.handoff().handoff_id()
        && receipt.plan_id == session.handoff().plan().plan_id()
        && receipt.target_manifest_digest == session.handoff().target_identity().manifest_digest
        && receipt.kind == check.kind
        && receipt.tool == check.tool
        && receipt.args == check.args)
}

#[cfg(any(test, feature = "disposable-loop-harness"))]
fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(feature = "disposable-loop-harness")]
fn stderr_summary(stderr: &[u8]) -> String {
    const LIMIT: usize = 4096;
    let bytes = &stderr[..stderr.len().min(LIMIT)];
    String::from_utf8_lossy(bytes).into_owned()
}
