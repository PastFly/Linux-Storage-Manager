use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use lsm_planner::{
    ExactApprovalBinding, ExecutionStartBinding, JournalEvent, JournalPhase, OperationJournal,
    VerifiedMutationBoundaryBinding, JOURNAL_DIRECTORY,
};
use serde::Deserialize;
use thiserror::Error;

const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct DurableJournalStore {
    root: PathBuf,
}

#[derive(Debug, Error)]
pub enum JournalStoreError {
    #[error("journal ID must be exactly 64 lowercase hexadecimal characters")]
    InvalidJournalId,
    #[error("journal directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("journal path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("journal already exists and must not be replaced during session start: {0}")]
    AlreadyExists(String),
    #[error("journal does not exist: {0}")]
    NotFound(String),
    #[error("journal exceeds the maximum durable record size")]
    TooLarge,
    #[error("journal record is structurally invalid: {0}")]
    InvalidRecord(String),
    #[error("journal JSON is invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("journal I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Deserialize)]
struct JournalWire {
    schema_version: u32,
    journal_id: String,
    plan_id: String,
    target: String,
    baseline_manifest_digest: String,
    phase: JournalPhase,
    mutation_may_have_started: bool,
    #[serde(default)]
    approval: Option<ExactApprovalBinding>,
    #[serde(default)]
    execution: Option<ExecutionStartBinding>,
    #[serde(default)]
    verified_boundary: Option<VerifiedMutationBoundaryBinding>,
    events: Vec<JournalEvent>,
}

impl Default for DurableJournalStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from(JOURNAL_DIRECTORY),
        }
    }
}

impl DurableJournalStore {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn persist_new(&self, journal: &OperationJournal) -> Result<PathBuf, JournalStoreError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;

        let bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }

        let final_path = self.path_for(&journal.journal_id)?;
        let temp_path = self.temp_path(&journal.journal_id);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temp_path)
                .map_err(|source| io_error(&temp_path, source))?;

            file.write_all(&bytes)
                .map_err(|source| io_error(&temp_path, source))?;
            file.write_all(b"\n")
                .map_err(|source| io_error(&temp_path, source))?;
            file.sync_all()
                .map_err(|source| io_error(&temp_path, source))?;
            drop(file);

            match fs::hard_link(&temp_path, &final_path) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(JournalStoreError::AlreadyExists(
                        journal.journal_id.clone(),
                    ));
                }
                Err(source) => return Err(io_error(&final_path, source)),
            }
            fs::remove_file(&temp_path).map_err(|source| io_error(&temp_path, source))?;
            sync_directory(&self.root)?;
            Ok(final_path.clone())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    pub fn persist(&self, journal: &OperationJournal) -> Result<PathBuf, JournalStoreError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;

        let bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }

        let final_path = self.path_for(&journal.journal_id)?;
        match fs::symlink_metadata(&final_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(JournalStoreError::NotRegularFile(final_path));
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(&final_path, source)),
        }

        let temp_path = self.temp_path(&journal.journal_id);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&temp_path)
                .map_err(|source| io_error(&temp_path, source))?;

            file.write_all(&bytes)
                .map_err(|source| io_error(&temp_path, source))?;
            file.write_all(b"\n")
                .map_err(|source| io_error(&temp_path, source))?;
            file.sync_all()
                .map_err(|source| io_error(&temp_path, source))?;
            drop(file);

            fs::rename(&temp_path, &final_path).map_err(|source| io_error(&final_path, source))?;
            sync_directory(&self.root)?;
            Ok(final_path.clone())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    pub fn load(&self, journal_id: &str) -> Result<OperationJournal, JournalStoreError> {
        validate_journal_id(journal_id)?;
        ensure_secure_directory(&self.root, false)?;

        let path = self.path_for(journal_id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(JournalStoreError::NotFound(journal_id.to_owned()));
            }
            Err(source) => return Err(io_error(&path, source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(JournalStoreError::NotRegularFile(path));
        }
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let mut bytes = Vec::new();
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(&path, source))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }

        let wire: JournalWire = serde_json::from_slice(&bytes)?;
        if wire.journal_id != journal_id {
            return Err(JournalStoreError::InvalidRecord(
                "journal ID does not match the requested durable record".to_owned(),
            ));
        }

        let journal = OperationJournal {
            schema_version: wire.schema_version,
            journal_id: wire.journal_id,
            plan_id: wire.plan_id,
            target: wire.target,
            baseline_manifest_digest: wire.baseline_manifest_digest,
            phase: wire.phase,
            mutation_may_have_started: wire.mutation_may_have_started,
            approval: wire.approval,
            execution: wire.execution,
            verified_boundary: wire.verified_boundary,
            events: wire.events,
        };
        validate_journal(&journal)?;
        Ok(journal)
    }

    fn path_for(&self, journal_id: &str) -> Result<PathBuf, JournalStoreError> {
        validate_journal_id(journal_id)?;
        Ok(self.root.join(format!("{journal_id}.json")))
    }

    fn temp_path(&self, journal_id: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        self.root.join(format!(
            ".{journal_id}.tmp-{}-{sequence}",
            std::process::id()
        ))
    }
}

fn validate_journal(journal: &OperationJournal) -> Result<(), JournalStoreError> {
    if journal.schema_version != 1 {
        return Err(JournalStoreError::InvalidRecord(
            "unsupported journal schema version".to_owned(),
        ));
    }
    validate_journal_id(&journal.journal_id)?;
    validate_hex_digest(&journal.plan_id, "plan ID")?;
    validate_hex_digest(
        &journal.baseline_manifest_digest,
        "baseline manifest digest",
    )?;
    if journal.target.is_empty() || journal.target.chars().any(char::is_control) {
        return Err(JournalStoreError::InvalidRecord(
            "journal target is empty or contains control characters".to_owned(),
        ));
    }

    let mut phase = JournalPhase::Planned;
    for (index, event) in journal.events.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if event.sequence != expected_sequence {
            return Err(JournalStoreError::InvalidRecord(format!(
                "journal event sequence is not contiguous at {expected_sequence}"
            )));
        }
        if event.from != phase {
            return Err(JournalStoreError::InvalidRecord(format!(
                "journal event {} does not continue from the previous phase",
                event.sequence
            )));
        }
        if !allowed_transition(event.from, event.to) {
            return Err(JournalStoreError::InvalidRecord(format!(
                "journal event {} contains an impossible phase transition",
                event.sequence
            )));
        }
        if event.code.is_empty() || event.code.chars().any(char::is_control) {
            return Err(JournalStoreError::InvalidRecord(format!(
                "journal event {} has an invalid code",
                event.sequence
            )));
        }
        phase = event.to;
    }

    if phase != journal.phase {
        return Err(JournalStoreError::InvalidRecord(
            "journal phase does not match the event chain".to_owned(),
        ));
    }

    let mutation_expected = matches!(
        journal.phase,
        JournalPhase::Executing
            | JournalPhase::Verifying
            | JournalPhase::Completed
            | JournalPhase::RecoveryRequired
    );
    if journal.mutation_may_have_started != mutation_expected {
        return Err(JournalStoreError::InvalidRecord(
            "mutation boundary flag is inconsistent with the journal phase".to_owned(),
        ));
    }

    validate_approval_binding(journal)?;
    validate_execution_binding(journal)?;
    validate_verified_boundary_binding(journal)?;

    Ok(())
}

fn validate_approval_binding(journal: &OperationJournal) -> Result<(), JournalStoreError> {
    let approval_transition_index = journal.events.iter().position(|event| {
        event.from == JournalPhase::PreconditionsVerified && event.to == JournalPhase::Approved
    });

    match (&journal.approval, approval_transition_index) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(JournalStoreError::InvalidRecord(
            "approved journal is missing the exact approval binding".to_owned(),
        )),
        (Some(_), None) => Err(JournalStoreError::InvalidRecord(
            "journal contains an approval binding without an approval transition".to_owned(),
        )),
        (Some(binding), Some(approval_index)) => {
            if binding.schema_version != 1 {
                return Err(JournalStoreError::InvalidRecord(format!(
                    "unsupported exact approval binding schema version {}",
                    binding.schema_version
                )));
            }

            for (value, label) in [
                (binding.approval_id.as_str(), "approval ID"),
                (binding.plan_id.as_str(), "approval plan ID"),
                (
                    binding.evidence_bundle_id.as_str(),
                    "approval evidence bundle ID",
                ),
                (
                    binding.target_manifest_digest.as_str(),
                    "approval target manifest digest",
                ),
                (
                    binding.locked_session_id.as_str(),
                    "approval locked session ID",
                ),
                (
                    binding.preconditions_journal_digest.as_str(),
                    "approval preconditions journal digest",
                ),
            ] {
                validate_hex_digest(value, label)?;
            }

            if binding.plan_id != journal.plan_id {
                return Err(JournalStoreError::InvalidRecord(
                    "approval binding plan ID does not match the journal".to_owned(),
                ));
            }
            if binding.target_manifest_digest != journal.baseline_manifest_digest {
                return Err(JournalStoreError::InvalidRecord(
                    "approval binding target manifest does not match the journal".to_owned(),
                ));
            }
            if !binding.integrity_matches()? {
                return Err(JournalStoreError::InvalidRecord(
                    "approval binding fingerprint does not match its contents".to_owned(),
                ));
            }

            let mut preconditions = journal.clone();
            preconditions.phase = JournalPhase::PreconditionsVerified;
            preconditions.mutation_may_have_started = false;
            preconditions.approval = None;
            preconditions.execution = None;
            preconditions.verified_boundary = None;
            preconditions.events.truncate(approval_index);
            let expected_digest = crate::preconditions::journal_digest(&preconditions)?;
            if binding.preconditions_journal_digest != expected_digest {
                return Err(JournalStoreError::InvalidRecord(
                    "approval binding does not match the exact preconditions journal state"
                        .to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_execution_binding(journal: &OperationJournal) -> Result<(), JournalStoreError> {
    let execution_transition_index = journal.events.iter().position(|event| {
        event.from == JournalPhase::Approved && event.to == JournalPhase::Executing
    });

    match (&journal.execution, execution_transition_index) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(JournalStoreError::InvalidRecord(
            "executing journal is missing the exact execution binding".to_owned(),
        )),
        (Some(_), None) => Err(JournalStoreError::InvalidRecord(
            "journal contains an execution binding without an execution transition".to_owned(),
        )),
        (Some(binding), Some(execution_index)) => {
            if binding.schema_version != 1 {
                return Err(JournalStoreError::InvalidRecord(format!(
                    "unsupported execution binding schema version {}",
                    binding.schema_version
                )));
            }

            for (value, label) in [
                (binding.execution_id.as_str(), "execution ID"),
                (binding.journal_id.as_str(), "execution journal ID"),
                (binding.plan_id.as_str(), "execution plan ID"),
                (binding.approval_id.as_str(), "execution approval ID"),
                (
                    binding.source_manifest_id.as_str(),
                    "execution source manifest ID",
                ),
                (
                    binding.native_manifest_digest.as_str(),
                    "execution native manifest digest",
                ),
                (
                    binding.fresh_identity_digest.as_str(),
                    "execution fresh identity digest",
                ),
                (
                    binding.approved_journal_digest.as_str(),
                    "execution approved journal digest",
                ),
            ] {
                validate_hex_digest(value, label)?;
            }

            if binding.mutation_step_ids.is_empty() || binding.mutation_step_ids.contains(&0) || {
                let mut seen = std::collections::BTreeSet::new();
                binding
                    .mutation_step_ids
                    .iter()
                    .any(|step_id| !seen.insert(*step_id))
            } {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding mutation step sequence is invalid".to_owned(),
                ));
            }

            if binding.journal_id != journal.journal_id {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding journal ID does not match the journal".to_owned(),
                ));
            }
            if binding.plan_id != journal.plan_id {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding plan ID does not match the journal".to_owned(),
                ));
            }
            let Some(approval) = journal.approval.as_ref() else {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding exists without an approval binding".to_owned(),
                ));
            };
            if binding.approval_id != approval.approval_id {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding approval ID does not match the journal".to_owned(),
                ));
            }
            if binding.fresh_identity_digest != journal.baseline_manifest_digest {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding fresh identity does not match the journal baseline"
                        .to_owned(),
                ));
            }
            if !binding.integrity_matches()? {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding fingerprint does not match its contents".to_owned(),
                ));
            }

            let mut approved = journal.clone();
            approved.phase = JournalPhase::Approved;
            approved.mutation_may_have_started = false;
            approved.execution = None;
            approved.verified_boundary = None;
            approved.events.truncate(execution_index);
            let expected_digest = crate::preconditions::journal_digest(&approved)?;
            if binding.approved_journal_digest != expected_digest {
                return Err(JournalStoreError::InvalidRecord(
                    "execution binding does not match the exact approved journal state".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_verified_boundary_binding(journal: &OperationJournal) -> Result<(), JournalStoreError> {
    let has_continuation = journal
        .events
        .iter()
        .any(|event| event.code == "verification-passed-continue");
    let has_terminal_completion = journal
        .events
        .iter()
        .any(|event| event.code == "verification-passed-complete");

    match (&journal.verified_boundary, has_continuation) {
        (None, false) => Ok(()),
        (None, true) => Err(JournalStoreError::InvalidRecord(
            "verification continuation is missing the durable verified boundary binding".to_owned(),
        )),
        (Some(_), false) => Err(JournalStoreError::InvalidRecord(
            "verified boundary binding exists without a verification continuation".to_owned(),
        )),
        (Some(binding), true) => {
            if !matches!(binding.schema_version, 1 | 2) {
                return Err(JournalStoreError::InvalidRecord(format!(
                    "unsupported verified boundary binding schema version {}",
                    binding.schema_version
                )));
            }
            for (value, label) in [
                (binding.boundary_id.as_str(), "verified boundary ID"),
                (
                    binding.execution_id.as_str(),
                    "verified boundary execution ID",
                ),
                (
                    binding.fresh_identity_digest.as_str(),
                    "verified boundary fresh identity digest",
                ),
            ] {
                validate_hex_digest(value, label)?;
            }
            if binding.completed_step_id == 0
                || binding.next_step_id == 0
                || binding.completed_step_id == binding.next_step_id
            {
                return Err(JournalStoreError::InvalidRecord(
                    "verified boundary step sequence is invalid".to_owned(),
                ));
            }
            let execution = journal.execution.as_ref().ok_or_else(|| {
                JournalStoreError::InvalidRecord(
                    "verified boundary exists without the durable execution binding".to_owned(),
                )
            })?;
            if binding.execution_id != execution.execution_id {
                return Err(JournalStoreError::InvalidRecord(
                    "verified boundary execution ID does not match the journal".to_owned(),
                ));
            }
            let ordered_pair = execution.mutation_step_ids.windows(2).any(|pair| {
                pair[0] == binding.completed_step_id && pair[1] == binding.next_step_id
            });
            if !ordered_pair {
                return Err(JournalStoreError::InvalidRecord(
                    "verified boundary steps do not match the durable execution sequence"
                        .to_owned(),
                ));
            }
            if !binding.integrity_matches()? {
                return Err(JournalStoreError::InvalidRecord(
                    "verified boundary fingerprint does not match its contents".to_owned(),
                ));
            }

            match (
                binding.final_step_id,
                binding.final_identity_digest.as_deref(),
            ) {
                (None, None) => {
                    if binding.schema_version != 1
                        || has_terminal_completion
                        || (journal.phase == JournalPhase::Completed
                            && execution.mutation_step_ids.len() > 1)
                    {
                        return Err(JournalStoreError::InvalidRecord(
                            "completed multi-step execution is missing durable terminal verification"
                                .to_owned(),
                        ));
                    }
                }
                (Some(final_step_id), Some(final_identity_digest)) => {
                    if binding.schema_version != 2
                        || !has_terminal_completion
                        || journal.phase != JournalPhase::Completed
                    {
                        return Err(JournalStoreError::InvalidRecord(
                            "terminal verification binding exists without terminal completion"
                                .to_owned(),
                        ));
                    }
                    validate_hex_digest(
                        final_identity_digest,
                        "terminal verification fresh identity digest",
                    )?;
                    if execution.mutation_step_ids.last().copied() != Some(final_step_id)
                        || binding.next_step_id != final_step_id
                    {
                        return Err(JournalStoreError::InvalidRecord(
                            "terminal verification step does not match the final durable mutation step"
                                .to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(JournalStoreError::InvalidRecord(
                        "terminal verification binding is incomplete".to_owned(),
                    ));
                }
            }

            if !matches!(
                journal.phase,
                JournalPhase::Executing
                    | JournalPhase::Verifying
                    | JournalPhase::Completed
                    | JournalPhase::RecoveryRequired
            ) {
                return Err(JournalStoreError::InvalidRecord(
                    "verified boundary exists before the mutation verification boundary".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

fn allowed_transition(from: JournalPhase, to: JournalPhase) -> bool {
    matches!(
        (from, to),
        (JournalPhase::Planned, JournalPhase::HostLockHeld)
            | (
                JournalPhase::HostLockHeld,
                JournalPhase::IdentityRevalidated
            )
            | (
                JournalPhase::IdentityRevalidated,
                JournalPhase::PreconditionsVerified
            )
            | (JournalPhase::PreconditionsVerified, JournalPhase::Approved)
            | (JournalPhase::Approved, JournalPhase::Executing)
            | (JournalPhase::Executing, JournalPhase::Verifying)
            | (JournalPhase::Verifying, JournalPhase::Executing)
            | (JournalPhase::Verifying, JournalPhase::Completed)
            | (JournalPhase::Planned, JournalPhase::Aborted)
            | (JournalPhase::HostLockHeld, JournalPhase::Aborted)
            | (JournalPhase::IdentityRevalidated, JournalPhase::Aborted)
            | (JournalPhase::PreconditionsVerified, JournalPhase::Aborted)
            | (JournalPhase::Approved, JournalPhase::Aborted)
            | (JournalPhase::Executing, JournalPhase::RecoveryRequired)
            | (JournalPhase::Verifying, JournalPhase::RecoveryRequired)
    )
}

fn validate_journal_id(value: &str) -> Result<(), JournalStoreError> {
    if is_lower_hex_digest(value) {
        Ok(())
    } else {
        Err(JournalStoreError::InvalidJournalId)
    }
}

fn validate_hex_digest(value: &str, label: &str) -> Result<(), JournalStoreError> {
    if is_lower_hex_digest(value) {
        Ok(())
    } else {
        Err(JournalStoreError::InvalidRecord(format!(
            "{label} is not a SHA-256 lowercase hexadecimal digest"
        )))
    }
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn ensure_secure_directory(path: &Path, create: bool) -> Result<(), JournalStoreError> {
    if !path.is_absolute() {
        return Err(JournalStoreError::UnsafeDirectory(path.to_path_buf()));
    }

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                continue;
            }
            Component::Normal(part) => current.push(part),
            _ => return Err(JournalStoreError::UnsafeDirectory(path.to_path_buf())),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(JournalStoreError::UnsafeDirectory(current));
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound && create => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                if let Err(source) = builder.create(&current) {
                    if source.kind() != io::ErrorKind::AlreadyExists {
                        return Err(io_error(&current, source));
                    }
                }
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(JournalStoreError::UnsafeDirectory(current));
                }
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), JournalStoreError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: io::Error) -> JournalStoreError {
    JournalStoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_planner::{
        build_execution_start_binding, ExactApprovalBinding, JournalTransition, ResumeDisposition,
    };
    use serde_json::json;
    use std::os::unix::fs::symlink;

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn journal() -> OperationJournal {
        OperationJournal {
            schema_version: 1,
            journal_id: digest('a'),
            plan_id: digest('b'),
            target: "/".to_owned(),
            baseline_manifest_digest: digest('c'),
            phase: JournalPhase::Planned,
            mutation_may_have_started: false,
            approval: None,
            execution: None,
            verified_boundary: None,
            events: Vec::new(),
        }
    }

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "linux-storage-manager-journal-test-{}-{}-{name}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn persist_new_never_replaces_existing_durable_identity() {
        let root = root("persist-new-no-replace");
        let store = DurableJournalStore::at(&root);
        let mut original = journal();
        original.apply(JournalTransition::HostLockAcquired).unwrap();
        store.persist_new(&original).unwrap();

        let mut replacement = original.clone();
        let baseline = replacement.baseline_manifest_digest.clone();
        replacement
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();

        let result = store.persist_new(&replacement);
        assert!(matches!(
            result,
            Err(JournalStoreError::AlreadyExists(ref journal_id))
                if journal_id == &original.journal_id
        ));
        assert_eq!(store.load(&original.journal_id).unwrap(), original);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_round_trip_preserves_revalidated_journal() {
        let root = root("round-trip");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();

        let path = store.persist(&journal).unwrap();
        let loaded = store.load(&journal.journal_id).unwrap();

        assert_eq!(loaded, journal);
        assert_eq!(path, root.join(format!("{}.json", journal.journal_id)));
        assert_eq!(
            loaded.resume_disposition(),
            ResumeDisposition::RestartFromFreshPlan
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn durable_rewrite_atomically_replaces_previous_state() {
        let root = root("rewrite");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        store.persist(&journal).unwrap();

        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let loaded = store.load(&journal.journal_id).unwrap();
        assert_eq!(loaded.phase, JournalPhase::IdentityRevalidated);
        assert_eq!(loaded.events.len(), 2);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_impossible_transition_is_rejected() {
        let root = root("tampered");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        value["events"][0]["to"] = json!("completed");
        value["phase"] = json!("completed");
        value["mutation_may_have_started"] = json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let result = store.load(&journal.journal_id);
        assert!(matches!(result, Err(JournalStoreError::InvalidRecord(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn journal_symlink_is_rejected() {
        let root = root("symlink-file");
        ensure_secure_directory(&root, true).unwrap();
        let journal = journal();
        let store = DurableJournalStore::at(&root);
        let real = root.join("real.json");
        fs::write(&real, b"{}").unwrap();
        let link = store.path_for(&journal.journal_id).unwrap();
        symlink(&real, &link).unwrap();

        let result = store.load(&journal.journal_id);
        assert!(matches!(
            result,
            Err(JournalStoreError::NotRegularFile(path)) if path == link
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn symlink_journal_directory_is_rejected() {
        let root = root("symlink-dir");
        let real = root.with_extension("real");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, &root).unwrap();
        let store = DurableJournalStore::at(&root);

        let result = store.persist(&journal());
        assert!(matches!(
            result,
            Err(JournalStoreError::UnsafeDirectory(path)) if path == root
        ));

        let _ = fs::remove_file(&root);
        let _ = fs::remove_dir_all(real);
    }

    #[test]
    fn recomputed_approval_for_another_preconditions_journal_is_rejected_on_reload() {
        let root = root("approval-tamper");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();

        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        let mut tampered: ExactApprovalBinding =
            serde_json::from_value(value["approval"].clone()).unwrap();
        tampered.preconditions_journal_digest = digest('f');
        tampered.approval_id = tampered.expected_approval_id().unwrap();
        value["approval"] = serde_json::to_value(tampered).unwrap();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let result = store.load(&journal.journal_id);

        assert!(matches!(result, Err(JournalStoreError::InvalidRecord(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn unsupported_approval_binding_schema_is_rejected_on_reload() {
        let root = root("approval-schema");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();

        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        value["approval"]["schema_version"] = json!(2);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let result = store.load(&journal.journal_id);

        assert!(matches!(result, Err(JournalStoreError::InvalidRecord(_))));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_execution_binding_is_rejected_on_reload() {
        let root = root("execution-binding-tamper");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();

        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();

        let execution = build_execution_start_binding(
            &journal,
            &digest('f'),
            &digest('1'),
            &journal.baseline_manifest_digest,
            &[5, 6],
        )
        .unwrap();
        journal
            .apply(JournalTransition::ExecutionStarted {
                binding: &execution,
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        value["execution"]["native_manifest_digest"] = json!(digest('2'));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(matches!(
            store.load(&journal.journal_id),
            Err(JournalStoreError::InvalidRecord(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_verified_boundary_is_rejected_on_reload() {
        let root = root("verified-boundary-tamper");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();

        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();

        let execution = build_execution_start_binding(
            &journal,
            &digest('f'),
            &digest('1'),
            &journal.baseline_manifest_digest,
            &[5, 6],
        )
        .unwrap();
        journal
            .apply(JournalTransition::ExecutionStarted {
                binding: &execution,
            })
            .unwrap();
        journal
            .apply(JournalTransition::VerificationStarted)
            .unwrap();
        journal
            .apply(JournalTransition::VerificationPassedContinue {
                completed_step_id: 5,
                next_step_id: 6,
                fresh_identity_digest: &digest('2'),
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        value["verified_boundary"]["fresh_identity_digest"] = json!(digest('3'));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(matches!(
            store.load(&journal.journal_id),
            Err(JournalStoreError::InvalidRecord(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_terminal_verification_is_rejected_on_reload() {
        let root = root("terminal-verification-tamper");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();

        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();

        let execution = build_execution_start_binding(
            &journal,
            &digest('f'),
            &digest('1'),
            &journal.baseline_manifest_digest,
            &[5, 6],
        )
        .unwrap();
        journal
            .apply(JournalTransition::ExecutionStarted {
                binding: &execution,
            })
            .unwrap();
        journal
            .apply(JournalTransition::VerificationStarted)
            .unwrap();
        journal
            .apply(JournalTransition::VerificationPassedContinue {
                completed_step_id: 5,
                next_step_id: 6,
                fresh_identity_digest: &digest('2'),
            })
            .unwrap();
        journal
            .apply(JournalTransition::VerificationStarted)
            .unwrap();
        journal
            .apply(JournalTransition::VerificationPassedComplete {
                completed_step_id: 6,
                fresh_identity_digest: &digest('3'),
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let path = store.path_for(&journal.journal_id).unwrap();
        let mut value = serde_json::to_value(&journal).unwrap();
        value["verified_boundary"]["final_identity_digest"] = json!(digest('4'));
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(matches!(
            store.load(&journal.journal_id),
            Err(JournalStoreError::InvalidRecord(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_boundary_requires_recovery_after_reload() {
        let root = root("recovery");
        let store = DurableJournalStore::at(&root);
        let mut journal = journal();
        journal.apply(JournalTransition::HostLockAcquired).unwrap();
        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        journal
            .apply(JournalTransition::PreconditionsVerified)
            .unwrap();
        let plan_id = journal.plan_id.clone();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: plan_id.clone(),
            evidence_bundle_id: digest('d'),
            target_manifest_digest: journal.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&journal).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        journal
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();
        let execution = build_execution_start_binding(
            &journal,
            &digest('f'),
            &digest('1'),
            &journal.baseline_manifest_digest,
            &[5, 6],
        )
        .unwrap();
        journal
            .apply(JournalTransition::ExecutionStarted {
                binding: &execution,
            })
            .unwrap();
        journal
            .apply(JournalTransition::Interrupted {
                reason: "simulated power loss",
            })
            .unwrap();
        store.persist(&journal).unwrap();

        let loaded = store.load(&journal.journal_id).unwrap();
        assert_eq!(loaded.phase, JournalPhase::RecoveryRequired);
        assert_eq!(
            loaded.resume_disposition(),
            ResumeDisposition::RecoveryRequired
        );
        let _ = fs::remove_dir_all(root);
    }
}
