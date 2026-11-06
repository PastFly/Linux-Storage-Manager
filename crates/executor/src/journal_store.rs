#[cfg(test)]
use std::fs::OpenOptions;
use std::fs::{self, DirBuilder, File};
#[cfg(test)]
use std::io::Write;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use lsm_planner::{
    ExactApprovalBinding, ExecutionStartBinding, JournalEvent, JournalPhase,
    JournalRecoveryBinding, OperationJournal, VerifiedMutationBoundaryBinding, JOURNAL_DIRECTORY,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct DurableJournalStore {
    root: PathBuf,
}

/// A live session's own durable pending marker. Dropping it never removes the evidence.
#[derive(Debug)]
pub(crate) struct PendingBackupFinalization {
    name: std::ffi::OsString,
    journal: OperationJournal,
    file: File,
    metadata: fs::Metadata,
}

#[derive(Debug, Serialize)]
pub struct JournalInspection {
    pub unfinished: Vec<OperationJournal>,
    pub unclassified: Vec<UnclassifiedJournalEvidence>,
}

#[derive(Debug, Serialize)]
pub struct UnclassifiedJournalEvidence {
    #[serde(serialize_with = "serialize_path_lossy")]
    pub path: PathBuf,
    pub path_bytes_hex: String,
    pub identity: Option<JournalFileIdentity>,
    pub verified_duplicate_link: bool,
    pub staged_journal: Option<OperationJournal>,
    pub problem: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JournalFileIdentity {
    pub device_id: u64,
    pub inode: u64,
}

fn serialize_path_lossy<S: serde::Serializer>(
    path: &Path,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
}

fn diagnostic_entry(
    path: PathBuf,
    staged_journal: Option<OperationJournal>,
    problem: Option<String>,
    verified_duplicate_link: bool,
    identity: Option<JournalFileIdentity>,
) -> UnclassifiedJournalEvidence {
    let path_bytes_hex = path
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    UnclassifiedJournalEvidence {
        path,
        path_bytes_hex,
        identity,
        verified_duplicate_link,
        staged_journal,
        problem,
    }
}

fn staging_journal_id(name: &str) -> Option<&str> {
    let (id, suffix) = name.strip_prefix('.')?.split_once(".tmp-")?;
    validate_journal_id(id).ok()?;
    let (pid, sequence) = suffix.split_once('-')?;
    fn canonical_number(value: &str) -> bool {
        !value.is_empty()
            && value.bytes().all(|byte| byte.is_ascii_digit())
            && (value.len() == 1 || !value.starts_with('0'))
            && value.parse::<u64>().is_ok()
    }
    (canonical_number(pid) && pid != "0" && canonical_number(sequence)).then_some(id)
}

fn history_identity(name: &str) -> Option<(&str, u64, &str)> {
    let (id, rest) = name.strip_prefix('.')?.split_once(".history-")?;
    validate_journal_id(id).ok()?;
    let (sequence, digest) = rest.split_once('-')?;
    if sequence.is_empty()
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || (sequence.len() > 1 && sequence.starts_with('0'))
    {
        return None;
    }
    let sequence = sequence.parse::<u64>().ok()?;
    validate_hex_digest(digest, "history digest").ok()?;
    Some((id, sequence, digest))
}

fn journal_content_digest(journal: &OperationJournal) -> Result<String, JournalStoreError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(journal)?)
    ))
}

fn history_matches_final(history: &OperationJournal, final_journal: &OperationJournal) -> bool {
    history.schema_version == final_journal.schema_version
        && history.journal_id == final_journal.journal_id
        && history.plan_id == final_journal.plan_id
        && history.target == final_journal.target
        && history.baseline_manifest_digest == final_journal.baseline_manifest_digest
        && (history.approval.is_none() || history.approval == final_journal.approval)
        && (history.execution.is_none() || history.execution == final_journal.execution)
        && (history.recovery_binding.is_none()
            || history.recovery_binding == final_journal.recovery_binding)
        && final_journal.events.starts_with(&history.events)
        && history.events.len() < final_journal.events.len()
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
    #[error("journal directory or contents changed during inspection")]
    ChangedDuringInspection,
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
    #[serde(default, deserialize_with = "deserialize_optional_recovery_binding")]
    recovery_binding: Option<Option<JournalRecoveryBinding>>,
    events: Vec<JournalEvent>,
}

fn deserialize_optional_recovery_binding<'de, D>(
    deserializer: D,
) -> Result<Option<Option<JournalRecoveryBinding>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<JournalRecoveryBinding>::deserialize(deserializer).map(Some)
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

    /// Read-only inventory: preserve and report every unusual entry while the
    /// mutation path remains fail-closed on the strict `all` enumeration.
    pub fn inspect(&self) -> Result<JournalInspection, JournalStoreError> {
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let mut watch = directory.watch()?;
        let initial_names = directory.names()?;
        let mut result = JournalInspection {
            unfinished: Vec::new(),
            unclassified: Vec::new(),
        };
        let mut pinned = Vec::new();
        let mut primaries = Vec::new();
        let mut history = Vec::new();
        for name in &initial_names {
            let path = self.root.join(name);
            let name_text = name.to_str();
            if let Some((id, sequence, digest)) = name_text.and_then(history_identity) {
                match load_pinned_journal(&directory, name, &path, id, 1, || {}) {
                    Ok((journal, file, metadata)) => {
                        let identity = JournalFileIdentity {
                            device_id: metadata.dev(),
                            inode: metadata.ino(),
                        };
                        pinned.push((name.clone(), file, metadata));
                        if journal.events.len() as u64 != sequence
                            || journal_content_digest(&journal)? != digest
                        {
                            result.unclassified.push(diagnostic_entry(
                                path,
                                None,
                                Some("journal history does not match its name".to_owned()),
                                false,
                                Some(identity),
                            ));
                        } else {
                            history.push((path, journal, identity));
                        }
                    }
                    Err(JournalStoreError::ChangedDuringInspection) => {
                        return Err(JournalStoreError::ChangedDuringInspection)
                    }
                    Err(error) => result.unclassified.push(diagnostic_entry(
                        path,
                        None,
                        Some(error.to_string()),
                        false,
                        None,
                    )),
                }
                continue;
            }
            if let Some(id) = name_text.and_then(|name| name.strip_suffix(".json")) {
                match load_pinned_journal(&directory, name, &path, id, 1, || {}) {
                    Ok((journal, file, metadata)) => {
                        pinned.push((name.clone(), file, metadata));
                        if !matches!(
                            journal.phase,
                            JournalPhase::Completed | JournalPhase::Aborted
                        ) {
                            result.unfinished.push(journal.clone());
                        }
                        primaries.push(journal);
                    }
                    Err(JournalStoreError::ChangedDuringInspection) => {
                        return Err(JournalStoreError::ChangedDuringInspection)
                    }
                    Err(error) => result.unclassified.push(diagnostic_entry(
                        path,
                        None,
                        Some(error.to_string()),
                        false,
                        None,
                    )),
                }
                continue;
            }
            let staged_id = name_text.and_then(staging_journal_id);
            let staged = staged_id.map(|id| {
                match load_pinned_journal(&directory, name, &path, id, 1, || {}) {
                    Ok((journal, file, metadata)) => Ok((journal, file, metadata, false)),
                    Err(primary) => load_linked_from_dir(&directory, &self.root, name, id)
                        .map(|(journal, file, metadata)| (journal, file, metadata, true))
                        .map_err(|_| primary),
                }
            });
            let (staged_journal, problem, verified_duplicate_link, identity) = match staged {
                Some(Ok((journal, file, metadata, duplicate))) => {
                    let identity = JournalFileIdentity {
                        device_id: metadata.dev(),
                        inode: metadata.ino(),
                    };
                    pinned.push((name.clone(), file, metadata));
                    (Some(journal), None, duplicate, Some(identity))
                }
                Some(Err(JournalStoreError::ChangedDuringInspection)) => {
                    return Err(JournalStoreError::ChangedDuringInspection)
                }
                Some(Err(error)) => (None, Some(error.to_string()), false, None),
                None => (
                    None,
                    Some("unrecognized journal directory entry".to_owned()),
                    false,
                    None,
                ),
            };
            result.unclassified.push(diagnostic_entry(
                path,
                staged_journal,
                problem,
                verified_duplicate_link,
                identity,
            ));
        }
        if initial_names != directory.names()? {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        for (name, file, metadata) in pinned {
            let held = file
                .metadata()
                .map_err(|source| io_error(&self.root.join(&name), source))?;
            let live = directory
                .open_file(&name)
                .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
            let live = live
                .metadata()
                .map_err(|source| io_error(&self.root.join(&name), source))?;
            if !same_file_version(&metadata, &held) || !same_file_version(&held, &live) {
                return Err(JournalStoreError::ChangedDuringInspection);
            }
        }
        directory.verify_namespace()?;
        watch.require_unchanged()?;
        for (path, previous, identity) in history {
            if !primaries
                .iter()
                .any(|current| history_matches_final(&previous, current))
            {
                result.unclassified.push(diagnostic_entry(
                    path,
                    None,
                    Some("journal history does not match a current record".to_owned()),
                    false,
                    Some(identity),
                ));
            }
        }
        result
            .unfinished
            .sort_by(|a, b| a.journal_id.cmp(&b.journal_id));
        result.unclassified.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(result)
    }

    /// Inspect all durable journals. Unexpected files or invalid records are errors:
    /// ignoring either could hide evidence of an interrupted storage mutation.
    pub fn all(&self) -> Result<Vec<OperationJournal>, JournalStoreError> {
        self.all_with_hook(|| {})
    }

    fn all_with_hook(
        &self,
        hook: impl FnOnce(),
    ) -> Result<Vec<OperationJournal>, JournalStoreError> {
        self.all_with_guard(None, hook)
    }

    pub(crate) fn all_allowing_pending_backup(
        &self,
        guard: &PendingBackupFinalization,
    ) -> Result<Vec<OperationJournal>, JournalStoreError> {
        self.all_with_guard(Some(guard), || {})
    }

    fn all_with_guard(
        &self,
        guard: Option<&PendingBackupFinalization>,
        hook: impl FnOnce(),
    ) -> Result<Vec<OperationJournal>, JournalStoreError> {
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let mut watch = directory.watch()?;
        let initial_names = directory.names()?;
        let mut journals = Vec::new();
        let mut history = Vec::new();
        let mut pinned = Vec::new();
        let mut guard_seen = false;
        for name in &initial_names {
            if let Some(guard) = guard.filter(|guard| guard.name == *name) {
                let path = self.root.join(name);
                let (journal, file, metadata) = load_pinned_journal(
                    &directory,
                    name,
                    &path,
                    &guard.journal.journal_id,
                    1,
                    || {},
                )?;
                let held = guard
                    .file
                    .metadata()
                    .map_err(|source| io_error(&path, source))?;
                if journal != guard.journal
                    || !same_file_version(&guard.metadata, &held)
                    || !same_file_version(&held, &metadata)
                {
                    return Err(JournalStoreError::ChangedDuringInspection);
                }
                pinned.push((name.clone(), file, metadata));
                guard_seen = true;
                continue;
            }
            let name = name.to_str().ok_or_else(|| {
                JournalStoreError::InvalidRecord("non-UTF-8 journal directory entry".to_owned())
            })?;
            let history_key = history_identity(name);
            let id = match history_key {
                Some((id, _, _)) => id,
                None => name.strip_suffix(".json").ok_or_else(|| {
                    JournalStoreError::InvalidRecord(format!(
                        "unexpected journal directory entry: {name}"
                    ))
                })?,
            };
            let path = self.root.join(name);
            let (journal, file, metadata) =
                load_pinned_journal(&directory, std::ffi::OsStr::new(name), &path, id, 1, || {})?;
            if let Some((_, sequence, digest)) = history_key {
                if journal.events.len() as u64 != sequence
                    || journal_content_digest(&journal)? != digest
                {
                    return Err(JournalStoreError::InvalidRecord(
                        "journal history does not match its name".to_owned(),
                    ));
                }
                history.push(journal);
            } else {
                journals.push(journal);
            }
            pinned.push((std::ffi::OsString::from(name), file, metadata));
        }
        if guard.is_some() && !guard_seen {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        hook();
        if initial_names != directory.names()? {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        for (name, file, metadata) in pinned {
            let held = file
                .metadata()
                .map_err(|source| io_error(&self.root.join(&name), source))?;
            let live = directory
                .open_file(&name)
                .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
            let live = live
                .metadata()
                .map_err(|source| io_error(&self.root.join(&name), source))?;
            if !same_file_version(&metadata, &held) || !same_file_version(&held, &live) {
                return Err(JournalStoreError::ChangedDuringInspection);
            }
        }
        directory.verify_namespace()?;
        watch.require_unchanged()?;
        for previous in &history {
            let Some(current) = journals
                .iter()
                .find(|journal| journal.journal_id == previous.journal_id)
            else {
                return Err(JournalStoreError::InvalidRecord(
                    "journal history has no current record".to_owned(),
                ));
            };
            if !history_matches_final(previous, current) {
                return Err(JournalStoreError::InvalidRecord(
                    "journal history does not match the current record".to_owned(),
                ));
            }
        }
        journals.sort_by(|a, b| a.journal_id.cmp(&b.journal_id));
        Ok(journals)
    }

    pub(crate) fn create_pending_backup_finalization(
        &self,
        journal: &OperationJournal,
    ) -> Result<PendingBackupFinalization, JournalStoreError> {
        validate_journal(journal)?;
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let name = std::ffi::OsString::from(format!(
            ".{}.backup-finalization-pending",
            journal.journal_id
        ));
        let path = self.root.join(&name);
        let mut bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }
        bytes.push(b'\n');
        let file = directory.write_staged_file(&name, &bytes)?;
        let created = file.metadata().map_err(|source| io_error(&path, source))?;
        let (recorded, opened, metadata) =
            load_pinned_journal(&directory, &name, &path, &journal.journal_id, 1, || {})?;
        if recorded != *journal || !same_file_version(&created, &metadata) {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        directory.sync()?;
        directory.verify_namespace()?;
        Ok(PendingBackupFinalization {
            name,
            journal: recorded,
            file: opened,
            metadata,
        })
    }

    pub fn unfinished(&self) -> Result<Vec<OperationJournal>, JournalStoreError> {
        Ok(self
            .all()?
            .into_iter()
            .filter(|journal| {
                !matches!(
                    journal.phase,
                    JournalPhase::Completed | JournalPhase::Aborted
                )
            })
            .collect())
    }

    /// Enumerate evidence owned by other runtime journal formats. Until their
    /// typed recovery validators are connected, no entry may be treated as safe.
    pub fn unclassified_runtime_evidence(&self) -> Result<Vec<PathBuf>, JournalStoreError> {
        self.unclassified_runtime_evidence_with_hook(|| {})
    }

    fn unclassified_runtime_evidence_with_hook(
        &self,
        hook: impl FnOnce(),
    ) -> Result<Vec<PathBuf>, JournalStoreError> {
        let parent = self
            .root
            .parent()
            .ok_or_else(|| JournalStoreError::UnsafeDirectory(self.root.clone()))?;
        let parent_dir = match crate::journal_fd::JournalDir::open(parent) {
            Ok(directory) => directory,
            Err(JournalStoreError::Io { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(Vec::new())
            }
            Err(error) => return Err(error),
        };
        let mut parent_watch = parent_dir.watch()?;
        let parent_names = parent_dir.names()?;
        let mut evidence = Vec::new();
        let mut watched = Vec::new();
        let mut hook = Some(hook);
        for name in [
            "create-runtime",
            "create-mount-runtime",
            "create-persistent-config",
            "swap-runtime",
        ] {
            let directory = parent.join(name);
            if !parent_names
                .iter()
                .any(|entry| entry.as_os_str() == std::ffi::OsStr::new(name))
            {
                continue;
            }
            let opened = crate::journal_fd::JournalDir::open(&directory)?;
            let watch = opened.watch()?;
            let names = opened.names()?;
            for entry in &names {
                evidence.push(directory.join(entry));
            }
            watched.push((opened, watch, names));
            if let Some(hook) = hook.take() {
                hook();
            }
        }
        for (opened, _, names) in &watched {
            if *names != opened.names()? {
                return Err(JournalStoreError::ChangedDuringInspection);
            }
            opened.verify_namespace()?;
        }
        if parent_names != parent_dir.names()? {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        parent_dir.verify_namespace()?;
        for (_, watch, _) in &mut watched {
            watch.require_unchanged()?;
        }
        parent_watch.require_unchanged()?;
        evidence.sort();
        Ok(evidence)
    }

    pub(crate) fn prepare_directory(&self) -> Result<(), JournalStoreError> {
        ensure_secure_directory(&self.root, true)
    }

    pub fn persist_new(&self, journal: &OperationJournal) -> Result<PathBuf, JournalStoreError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let mut bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }
        bytes.push(b'\n');

        let final_path = self.path_for(&journal.journal_id)?;
        let temp_path = self.temp_path(&journal.journal_id);
        let temp_name = temp_path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(temp_path.clone()))?;
        let final_name = final_path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(final_path.clone()))?;
        let file = directory.write_staged_file(temp_name, &bytes)?;
        let created = file
            .metadata()
            .map_err(|source| io_error(&temp_path, source))?;
        if !trusted_journal_file(&created) {
            return Err(JournalStoreError::NotRegularFile(temp_path));
        }
        directory.sync()?;
        directory.verify_namespace()?;
        match directory.publish_new(temp_name, final_name) {
            Ok(()) => {}
            Err(JournalStoreError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                return Err(JournalStoreError::AlreadyExists(journal.journal_id.clone()))
            }
            Err(error) => return Err(error),
        }
        let (published, opened, _) = load_pinned_journal(
            &directory,
            final_name,
            &final_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        let published_identity = opened
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        if published != *journal
            || created.dev() != published_identity.dev()
            || created.ino() != published_identity.ino()
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        directory.sync()?;
        directory.verify_namespace()?;
        Ok(final_path)
    }

    /// Replace a journal only when the exact previous record is still present.
    /// Exchange retains the displaced inode on any uncertain outcome.
    pub(crate) fn persist_if_matches(
        &self,
        expected: &OperationJournal,
        journal: &OperationJournal,
    ) -> Result<PathBuf, JournalStoreError> {
        self.persist_if_matches_with_hooks(expected, journal, || {}, || {})
    }

    #[cfg(test)]
    fn persist_if_matches_with_hook(
        &self,
        expected: &OperationJournal,
        journal: &OperationJournal,
        hook: impl FnOnce(),
    ) -> Result<PathBuf, JournalStoreError> {
        self.persist_if_matches_with_hooks(expected, journal, hook, || {})
    }

    fn persist_if_matches_with_hooks(
        &self,
        expected: &OperationJournal,
        journal: &OperationJournal,
        hook: impl FnOnce(),
        after_exchange: impl FnOnce(),
    ) -> Result<PathBuf, JournalStoreError> {
        validate_journal(expected)?;
        validate_journal(journal)?;
        let recovery_binding_valid = match (&expected.recovery_binding, &journal.recovery_binding) {
            (Some(before), Some(after)) => before == after,
            (None, None) => true,
            (None, Some(_)) => {
                expected.schema_version == 2
                    && expected.phase == JournalPhase::IdentityRevalidated
                    && journal.phase == JournalPhase::PreconditionsVerified
                    && journal.events.len() == expected.events.len() + 1
            }
            (Some(_), None) => false,
        };
        if expected.schema_version != journal.schema_version
            || !recovery_binding_valid
            || (expected.schema_version == 2
                && expected.events.len().checked_add(1) != Some(journal.events.len()))
            || expected.journal_id != journal.journal_id
            || expected.plan_id != journal.plan_id
            || expected.target != journal.target
            || expected.baseline_manifest_digest != journal.baseline_manifest_digest
            || !journal.events.starts_with(&expected.events)
            || journal.events.len() <= expected.events.len()
        {
            return Err(JournalStoreError::InvalidRecord(
                "journal update does not extend the exact prior history".to_owned(),
            ));
        }
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let final_path = self.path_for(&journal.journal_id)?;
        let temp_path = self.temp_path(&journal.journal_id);
        let final_name = final_path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(final_path.clone()))?;
        let temp_name = temp_path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(temp_path.clone()))?;
        let (current, old_file, old_metadata) = load_pinned_journal(
            &directory,
            final_name,
            &final_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        if current != *expected {
            return Err(JournalStoreError::ChangedDuringInspection);
        }

        let mut bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }
        bytes.push(b'\n');
        let staged = directory.write_staged_file(temp_name, &bytes)?;
        let staged_metadata = staged
            .metadata()
            .map_err(|source| io_error(&temp_path, source))?;
        if !trusted_journal_file(&staged_metadata) {
            return Err(JournalStoreError::NotRegularFile(temp_path));
        }
        directory.sync()?;
        let mut watch = directory.watch()?;
        hook();
        watch.require_unchanged()?;
        directory.verify_namespace()?;
        let current_old = old_file
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        let live_old = directory
            .open_file(final_name)
            .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
        let live_old = live_old
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        if !same_file_version(&old_metadata, &current_old)
            || !same_file_version(&current_old, &live_old)
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        directory.exchange(temp_name, final_name)?;
        after_exchange();
        let mut post_exchange_watch = directory.watch()?;

        // RENAME_EXCHANGE never discards the displaced object. On any mismatch,
        // leave both names as recovery evidence and block the next operation.
        let (displaced, displaced_file, _) = load_pinned_journal(
            &directory,
            temp_name,
            &temp_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        let displaced_metadata = displaced_file
            .metadata()
            .map_err(|source| io_error(&temp_path, source))?;
        let (published, published_file, _) = load_pinned_journal(
            &directory,
            final_name,
            &final_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        let published_metadata = published_file
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        if displaced != *expected
            || published != *journal
            || displaced_metadata.dev() != old_metadata.dev()
            || displaced_metadata.ino() != old_metadata.ino()
            || published_metadata.dev() != staged_metadata.dev()
            || published_metadata.ino() != staged_metadata.ino()
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        directory.sync()?;
        directory.verify_namespace()?;
        let retained = directory
            .open_file(temp_name)
            .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
        let retained = retained
            .metadata()
            .map_err(|source| io_error(&temp_path, source))?;
        if retained.dev() != old_metadata.dev()
            || retained.ino() != old_metadata.ino()
            || !trusted_journal_file(&retained)
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        let final_live = directory
            .open_file(final_name)
            .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
        let final_live = final_live
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        if final_live.dev() != staged_metadata.dev()
            || final_live.ino() != staged_metadata.ino()
            || !trusted_journal_file(&final_live)
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        post_exchange_watch.require_unchanged()?;
        // Retain the exact displaced state permanently. There is no Linux
        // unlink-if-inode-matches primitive, so deleting by name would reopen
        // a replacement race after the last identity check.
        let history_name = format!(
            ".{}.history-{}-{}",
            journal.journal_id,
            expected.events.len(),
            journal_content_digest(expected)?
        );
        directory.publish_new(temp_name, std::ffi::OsStr::new(&history_name))?;
        directory.sync()?;
        directory.verify_namespace()?;
        let history_path = self.root.join(&history_name);
        let (archived, archived_file, _) = load_pinned_journal(
            &directory,
            std::ffi::OsStr::new(&history_name),
            &history_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        let archived_metadata = archived_file
            .metadata()
            .map_err(|source| io_error(&history_path, source))?;
        let (final_journal, final_file, _) = load_pinned_journal(
            &directory,
            final_name,
            &final_path,
            &journal.journal_id,
            1,
            || {},
        )?;
        let final_metadata = final_file
            .metadata()
            .map_err(|source| io_error(&final_path, source))?;
        if archived != *expected
            || final_journal != *journal
            || archived_metadata.dev() != old_metadata.dev()
            || archived_metadata.ino() != old_metadata.ino()
            || final_metadata.dev() != staged_metadata.dev()
            || final_metadata.ino() != staged_metadata.ino()
        {
            return Err(JournalStoreError::ChangedDuringInspection);
        }
        Ok(final_path)
    }

    /// Update an existing journal only by extending its validated durable state.
    /// New records must use `persist_new`; a missing record is never recreated.
    pub fn persist(&self, journal: &OperationJournal) -> Result<PathBuf, JournalStoreError> {
        let previous = self.load(&journal.journal_id)?;
        if previous == *journal {
            return self.path_for(&journal.journal_id);
        }
        self.persist_if_matches(&previous, journal)
    }

    #[cfg(test)]
    pub(crate) fn test_overwrite(
        &self,
        journal: &OperationJournal,
    ) -> Result<PathBuf, JournalStoreError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;

        let mut bytes = serde_json::to_vec(journal)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::TooLarge);
        }
        bytes.push(b'\n');

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
            let directory = crate::journal_fd::JournalDir::open(&self.root)?;
            let name = temp_path
                .file_name()
                .ok_or_else(|| JournalStoreError::NotRegularFile(temp_path.clone()))?;
            let file = directory.write_staged_file(name, &bytes)?;
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
        self.load_at(&path, journal_id)
    }

    fn load_at(
        &self,
        path: &Path,
        journal_id: &str,
    ) -> Result<OperationJournal, JournalStoreError> {
        self.load_at_with_links(path, journal_id, 1)
    }

    fn load_at_with_links(
        &self,
        path: &Path,
        journal_id: &str,
        allowed_links: u64,
    ) -> Result<OperationJournal, JournalStoreError> {
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let name = path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(path.to_path_buf()))?;
        if path.parent() != Some(self.root.as_path()) {
            return Err(JournalStoreError::NotRegularFile(path.to_path_buf()));
        }
        let (journal, _, _) =
            load_pinned_journal(&directory, name, path, journal_id, allowed_links, || {})?;
        directory.verify_namespace()?;
        Ok(journal)
    }

    #[cfg(test)]
    fn load_with_hook(
        &self,
        journal_id: &str,
        hook: impl FnOnce(),
    ) -> Result<OperationJournal, JournalStoreError> {
        let directory = crate::journal_fd::JournalDir::open(&self.root)?;
        let path = self.path_for(journal_id)?;
        let name = path
            .file_name()
            .ok_or_else(|| JournalStoreError::NotRegularFile(path.clone()))?;
        let (journal, _, _) = load_pinned_journal(&directory, name, &path, journal_id, 1, hook)?;
        directory.verify_namespace()?;
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

fn same_file_version(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn load_linked_from_dir(
    directory: &crate::journal_fd::JournalDir,
    root: &Path,
    staged_name: &std::ffi::OsStr,
    journal_id: &str,
) -> Result<(OperationJournal, File, fs::Metadata), JournalStoreError> {
    let staged_path = root.join(staged_name);
    let final_name = format!("{journal_id}.json");
    let final_path = root.join(&final_name);
    let (staged, staged_file, staged_metadata) =
        load_pinned_journal(directory, staged_name, &staged_path, journal_id, 2, || {})?;
    let (final_journal, _, final_metadata) = load_pinned_journal(
        directory,
        std::ffi::OsStr::new(&final_name),
        &final_path,
        journal_id,
        2,
        || {},
    )?;
    if staged != final_journal || !same_file_version(&staged_metadata, &final_metadata) {
        return Err(JournalStoreError::ChangedDuringInspection);
    }
    Ok((staged, staged_file, staged_metadata))
}

fn load_pinned_journal(
    directory: &crate::journal_fd::JournalDir,
    name: &std::ffi::OsStr,
    path: &Path,
    journal_id: &str,
    allowed_links: u64,
    hook: impl FnOnce(),
) -> Result<(OperationJournal, File, fs::Metadata), JournalStoreError> {
    validate_journal_id(journal_id)?;
    let mut file = match directory.open_file(name) {
        Err(JournalStoreError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
            return Err(JournalStoreError::NotFound(journal_id.to_owned()))
        }
        Err(JournalStoreError::Io { source, .. }) if source.raw_os_error() == Some(libc::ELOOP) => {
            return Err(JournalStoreError::NotRegularFile(path.to_path_buf()))
        }
        result => result?,
    };
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !trusted_journal_file_with_links(&metadata, allowed_links) {
        return Err(JournalStoreError::NotRegularFile(path.to_path_buf()));
    }
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(JournalStoreError::TooLarge);
    }

    hook();
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(JournalStoreError::TooLarge);
    }

    let after = file.metadata().map_err(|source| io_error(path, source))?;
    let live = directory
        .open_file(name)
        .map_err(|_| JournalStoreError::ChangedDuringInspection)?;
    let live = live.metadata().map_err(|source| io_error(path, source))?;
    if !same_file_version(&metadata, &after) || !same_file_version(&after, &live) {
        return Err(JournalStoreError::ChangedDuringInspection);
    }
    let journal = decode_journal(&bytes, journal_id)?;
    Ok((journal, file, after))
}

fn decode_journal(bytes: &[u8], journal_id: &str) -> Result<OperationJournal, JournalStoreError> {
    let wire: JournalWire = serde_json::from_slice(bytes)?;
    if wire.journal_id != journal_id {
        return Err(JournalStoreError::InvalidRecord(
            "journal ID does not match the requested durable record".to_owned(),
        ));
    }
    if wire.schema_version == 1 && wire.recovery_binding.is_some() {
        return Err(JournalStoreError::InvalidRecord(
            "legacy journal has a recovery binding field".to_owned(),
        ));
    }
    if matches!(wire.recovery_binding.as_ref(), Some(None)) {
        return Err(JournalStoreError::InvalidRecord(
            "null recovery binding is not allowed".to_owned(),
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
        recovery_binding: wire.recovery_binding.flatten(),
        events: wire.events,
    };
    validate_journal(&journal)?;
    Ok(journal)
}

fn validate_journal(journal: &OperationJournal) -> Result<(), JournalStoreError> {
    if !matches!(journal.schema_version, 1 | 2) {
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

    let reached_preconditions = journal.events.iter().any(|event| {
        event.from == JournalPhase::IdentityRevalidated
            && event.to == JournalPhase::PreconditionsVerified
    });
    match (journal.schema_version, &journal.recovery_binding) {
        (1, None) => {}
        (2, None) if !reached_preconditions => {}
        (2, Some(binding)) if reached_preconditions => {
            validate_hex_digest(&binding.record_id, "recovery record ID")?;
            validate_hex_digest(&binding.session_id, "recovery session ID")?;
            validate_hex_digest(&binding.handoff_id, "recovery handoff ID")?;
        }
        _ => {
            return Err(JournalStoreError::InvalidRecord(
                "recovery binding does not match journal schema and history".to_owned(),
            ))
        }
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
            if journal.schema_version == 2
                && journal
                    .recovery_binding
                    .as_ref()
                    .is_none_or(|recovery| recovery.session_id != binding.locked_session_id)
            {
                return Err(JournalStoreError::InvalidRecord(
                    "approval session does not match recovery binding".to_owned(),
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

pub(crate) fn trusted_journal_file(metadata: &fs::Metadata) -> bool {
    trusted_journal_file_with_links(metadata, 1)
}

fn trusted_journal_file_with_links(metadata: &fs::Metadata, allowed_links: u64) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == allowed_links
}

pub(crate) fn trusted_journal_directory(metadata: &fs::Metadata, is_root: bool) -> bool {
    let uid = metadata.uid();
    let mode = metadata.mode();
    let owner_ok = uid == 0 || uid == unsafe { libc::geteuid() };
    let safe_mode = mode & 0o022 == 0 || (!is_root && uid == 0 && mode & 0o1000 != 0);
    metadata.is_dir() && !metadata.file_type().is_symlink() && owner_ok && safe_mode
}

pub(crate) fn ensure_secure_directory(path: &Path, create: bool) -> Result<(), JournalStoreError> {
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
                if !trusted_journal_directory(&metadata, current == path) {
                    return Err(JournalStoreError::UnsafeDirectory(current));
                }
                if create {
                    let parent = current
                        .parent()
                        .ok_or_else(|| JournalStoreError::UnsafeDirectory(current.clone()))?;
                    sync_directory(parent)?;
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
                if !trusted_journal_directory(&metadata, current == path) {
                    return Err(JournalStoreError::UnsafeDirectory(current));
                }
                let parent = current
                    .parent()
                    .ok_or_else(|| JournalStoreError::UnsafeDirectory(current.clone()))?;
                sync_directory(parent)?;
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
            recovery_binding: None,
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

    fn fixture_file(root: &Path, path: &Path, bytes: &[u8]) {
        let directory = crate::journal_fd::JournalDir::open(root).unwrap();
        drop(
            directory
                .write_staged_file(path.file_name().unwrap(), bytes)
                .unwrap(),
        );
    }

    // Test-only wire fixtures, independent of a future v2 Rust constructor.
    fn preconditions_wire(schema_version: u32) -> serde_json::Value {
        let mut value = serde_json::to_value(journal()).unwrap();
        value["schema_version"] = json!(schema_version);
        value["phase"] = json!("preconditions_verified");
        value["events"] = json!([
            {"sequence":1,"from":"planned","to":"host_lock_held","code":"host-lock-acquired","detail":"lock held"},
            {"sequence":2,"from":"host_lock_held","to":"identity_revalidated","code":"identity-revalidated","detail":"identity matched"},
            {"sequence":3,"from":"identity_revalidated","to":"preconditions_verified","code":"preconditions-verified","detail":"evidence verified"}
        ]);
        value
    }

    fn recovery_binding() -> serde_json::Value {
        json!({"record_id": digest('d'), "session_id": digest('e'), "handoff_id": digest('f')})
    }

    fn decoded_wire(value: &serde_json::Value) -> Result<OperationJournal, JournalStoreError> {
        decode_journal(&serde_json::to_vec(value).unwrap(), &digest('a'))
    }

    fn append_valid_approval(mut previous: OperationJournal) -> OperationJournal {
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: previous.plan_id.clone(),
            evidence_bundle_id: digest('1'),
            target_manifest_digest: previous.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&previous).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        let plan_id = previous.plan_id.clone();
        previous
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval,
            })
            .unwrap();
        previous
    }

    fn legacy_approved_wire() -> serde_json::Value {
        let mut wire = preconditions_wire(1);
        let previous = decoded_wire(&wire).unwrap();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: previous.plan_id.clone(),
            evidence_bundle_id: digest('1'),
            target_manifest_digest: previous.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&previous).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        wire["approval"] = serde_json::to_value(approval).unwrap();
        wire["phase"] = json!("approved");
        wire["events"].as_array_mut().unwrap().push(json!({
            "sequence":4,"from":"preconditions_verified","to":"approved",
            "code":"exact-plan-approved","detail":"legacy approved"
        }));
        wire
    }

    #[test]
    fn legacy_v1_journal_serialization_and_digest_remain_identical() {
        let legacy = journal();
        let bytes = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "4e8f189cc6b5c245f14f1c5e76f1f8706b9538fdb19e25856b2c054fa12e664c"
        );
        let loaded = decode_journal(&bytes, &legacy.journal_id).unwrap();
        assert_eq!(serde_json::to_vec(&loaded).unwrap(), bytes);
        assert_eq!(
            loaded.resume_disposition(),
            ResumeDisposition::RestartFromFreshPlan
        );
    }

    #[test]
    fn journal_v2_requires_and_preserves_recovery_binding_before_approval() {
        let mut wire = preconditions_wire(2);
        assert!(decoded_wire(&wire).is_err());
        wire["recovery_binding"] = recovery_binding();
        let loaded = decoded_wire(&wire).unwrap();
        assert_eq!(loaded.phase, JournalPhase::PreconditionsVerified);
        assert_eq!(
            serde_json::to_value(&loaded).unwrap()["recovery_binding"],
            recovery_binding()
        );
        let approved = append_valid_approval(loaded);
        assert_eq!(approved.phase, JournalPhase::Approved);
        assert_eq!(
            serde_json::to_value(&approved).unwrap()["recovery_binding"],
            recovery_binding()
        );
    }

    #[test]
    fn journal_v2_rejects_binding_replacement_removal_and_schema_downgrade() {
        let root = root("v2-binding-immutable");
        let store = DurableJournalStore::at(&root);
        let mut wire = preconditions_wire(2);
        wire["recovery_binding"] = recovery_binding();
        let previous = decoded_wire(&wire).unwrap();
        store.persist_new(&previous).unwrap();

        let mut removed = wire.clone();
        removed.as_object_mut().unwrap().remove("recovery_binding");
        assert!(decoded_wire(&removed).is_err());

        let mut replaced = wire.clone();
        replaced["recovery_binding"]["record_id"] = json!(digest('2'));
        let replaced = append_valid_approval(decoded_wire(&replaced).unwrap());
        assert!(store.persist_if_matches(&previous, &replaced).is_err());
        assert_eq!(store.load(&previous.journal_id).unwrap(), previous);

        let downgraded = decoded_wire(&legacy_approved_wire()).unwrap();
        assert!(store.persist_if_matches(&previous, &downgraded).is_err());
        assert_eq!(store.load(&previous.journal_id).unwrap(), previous);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_v1_preconditions_are_readable_but_cannot_gain_new_approval() {
        let mut previous = decoded_wire(&preconditions_wire(1)).unwrap();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: previous.plan_id.clone(),
            evidence_bundle_id: digest('1'),
            target_manifest_digest: previous.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&previous).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        let plan_id = previous.plan_id.clone();
        assert!(previous
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval
            })
            .is_err());
        assert_eq!(previous.phase, JournalPhase::PreconditionsVerified);
    }

    #[test]
    fn v2_can_attach_binding_only_with_preconditions_transition() {
        let root = root("v2-attach-binding");
        let store = DurableJournalStore::at(&root);
        let mut initial = preconditions_wire(2);
        initial["phase"] = json!("identity_revalidated");
        initial["events"].as_array_mut().unwrap().pop();
        let previous = decoded_wire(&initial).unwrap();
        store.persist_new(&previous).unwrap();
        let mut next = preconditions_wire(2);
        next["recovery_binding"] = recovery_binding();
        let next = decoded_wire(&next).unwrap();
        store.persist_if_matches(&previous, &next).unwrap();
        assert_eq!(store.load(&previous.journal_id).unwrap(), next);
        assert_eq!(store.all().unwrap(), vec![next]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_v2_cannot_persist_multiple_phases_in_one_update() {
        let root = root("v2-multiple-phases");
        let store = DurableJournalStore::at(&root);
        let mut wire = preconditions_wire(2);
        wire["recovery_binding"] = recovery_binding();
        let previous = decoded_wire(&wire).unwrap();
        store.persist_new(&previous).unwrap();

        // Construct a structurally valid approval and execution in memory,
        // without persisting the intervening Approved state.
        let mut jumped = append_valid_approval(previous.clone());
        let execution = build_execution_start_binding(
            &jumped,
            &digest('2'),
            &digest('3'),
            &jumped.baseline_manifest_digest,
            &[1],
        )
        .unwrap();
        jumped
            .apply(JournalTransition::ExecutionStarted {
                binding: &execution,
            })
            .unwrap();

        let result = store.persist(&jumped);
        assert!(
            matches!(result, Err(JournalStoreError::InvalidRecord(_))),
            "one durable update must not skip the Approved phase: {result:?}"
        );
        assert_eq!(store.load(&previous.journal_id).unwrap(), previous);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_rejects_v1_binding_and_v2_binding_before_preconditions() {
        let mut legacy = serde_json::to_value(journal()).unwrap();
        legacy["recovery_binding"] = recovery_binding();
        assert!(decoded_wire(&legacy).is_err());
        let mut early = legacy;
        early["schema_version"] = json!(2);
        assert!(decoded_wire(&early).is_err());
    }

    #[test]
    fn v2_approval_must_match_recovery_binding_session() {
        let mut wire = preconditions_wire(2);
        wire["recovery_binding"] = recovery_binding();
        wire["recovery_binding"]["session_id"] = json!(digest('f'));
        let mut previous = decoded_wire(&wire).unwrap();
        let mut approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: String::new(),
            plan_id: previous.plan_id.clone(),
            evidence_bundle_id: digest('1'),
            target_manifest_digest: previous.baseline_manifest_digest.clone(),
            locked_session_id: digest('e'),
            preconditions_journal_digest: crate::preconditions::journal_digest(&previous).unwrap(),
        };
        approval.approval_id = approval.expected_approval_id().unwrap();
        let plan_id = previous.plan_id.clone();
        assert!(previous
            .apply(JournalTransition::ExactPlanApproved {
                approved_plan_id: &plan_id,
                approval: &approval
            })
            .is_err());
        assert_eq!(previous.phase, JournalPhase::PreconditionsVerified);
    }

    // This model is deliberately test-only. It does not modify the real v1
    // state machine, persist records, or establish crash safety.
    mod experimental_v2 {
        use super::*;
        use lsm_planner::ExecutionStartBinding;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Binding {
            record_id: String,
            session_id: String,
            handoff_id: String,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct State {
            schema_version: u32,
            journal_id: String,
            plan_id: String,
            target: String,
            baseline_manifest_digest: String,
            phase: JournalPhase,
            mutation_may_have_started: bool,
            approval: Option<ExactApprovalBinding>,
            execution: Option<ExecutionStartBinding>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            verified_boundary: Option<serde_json::Value>,
            events: Vec<JournalEvent>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            recovery_binding: Option<Binding>,
        }

        fn parse(wire: &serde_json::Value) -> Result<State, ()> {
            let state: State = serde_json::from_value(wire.clone()).map_err(|_| ())?;
            validate(&state)?;
            Ok(state)
        }

        fn digest_state(state: &State) -> String {
            format!("{:x}", Sha256::digest(serde_json::to_vec(state).unwrap()))
        }

        fn validate(state: &State) -> Result<(), ()> {
            let Some(binding) = &state.recovery_binding else {
                return Err(());
            };
            if state.schema_version != 2
                || state.mutation_may_have_started
                || state.execution.is_some()
                || state.verified_boundary.is_some()
                || ![
                    &state.journal_id,
                    &state.plan_id,
                    &state.baseline_manifest_digest,
                    &binding.record_id,
                    &binding.session_id,
                    &binding.handoff_id,
                ]
                .iter()
                .all(|value| validate_hex_digest(value, "test").is_ok())
                || state.target.is_empty()
            {
                return Err(());
            }
            let required = [
                (JournalPhase::Planned, JournalPhase::HostLockHeld),
                (
                    JournalPhase::HostLockHeld,
                    JournalPhase::IdentityRevalidated,
                ),
                (
                    JournalPhase::IdentityRevalidated,
                    JournalPhase::PreconditionsVerified,
                ),
            ];
            if state.events.len() < required.len()
                || !state
                    .events
                    .iter()
                    .zip(required)
                    .enumerate()
                    .all(|(i, (event, (from, to)))| {
                        event.sequence == i as u64 + 1
                            && event.from == from
                            && event.to == to
                            && !event.code.is_empty()
                    })
            {
                return Err(());
            }
            match state.phase {
                JournalPhase::PreconditionsVerified
                    if state.events.len() == 3 && state.approval.is_none() =>
                {
                    Ok(())
                }
                JournalPhase::Approved if state.events.len() == 4 => {
                    let approval = state.approval.as_ref().ok_or(())?;
                    let last = state.events.last().ok_or(())?;
                    let mut prior = state.clone();
                    prior.phase = JournalPhase::PreconditionsVerified;
                    prior.approval = None;
                    prior.events.pop();
                    if last.sequence != 4
                        || last.from != JournalPhase::PreconditionsVerified
                        || last.to != JournalPhase::Approved
                        || approval.plan_id != state.plan_id
                        || approval.target_manifest_digest != state.baseline_manifest_digest
                        || approval.locked_session_id != binding.session_id
                        || approval.preconditions_journal_digest != digest_state(&prior)
                        || !approval.integrity_matches().map_err(|_| ())?
                    {
                        return Err(());
                    }
                    Ok(())
                }
                _ => Err(()),
            }
        }

        fn approve(mut state: State) -> Result<State, ()> {
            validate(&state)?;
            if state.phase != JournalPhase::PreconditionsVerified {
                return Err(());
            }
            let binding = state.recovery_binding.as_ref().ok_or(())?;
            let mut approval = ExactApprovalBinding {
                schema_version: 1,
                approval_id: String::new(),
                plan_id: state.plan_id.clone(),
                evidence_bundle_id: digest('1'),
                target_manifest_digest: state.baseline_manifest_digest.clone(),
                locked_session_id: binding.session_id.clone(),
                preconditions_journal_digest: digest_state(&state),
            };
            approval.approval_id = approval.expected_approval_id().map_err(|_| ())?;
            state.approval = Some(approval);
            state.phase = JournalPhase::Approved;
            state.events.push(JournalEvent {
                sequence: 4,
                from: JournalPhase::PreconditionsVerified,
                to: JournalPhase::Approved,
                code: "exact-plan-approved".into(),
                detail: "experimental model".into(),
            });
            validate(&state)?;
            Ok(state)
        }

        fn accept_update(previous: &State, next: &State) -> Result<(), ()> {
            validate(previous)?;
            validate(next)?;
            if previous.schema_version != next.schema_version
                || previous.journal_id != next.journal_id
                || previous.plan_id != next.plan_id
                || previous.target != next.target
                || previous.baseline_manifest_digest != next.baseline_manifest_digest
                || previous.recovery_binding != next.recovery_binding
                || previous.phase != JournalPhase::PreconditionsVerified
                || next.phase != JournalPhase::Approved
                || next.events.len() != previous.events.len() + 1
                || !next.events.starts_with(&previous.events)
            {
                return Err(());
            }
            Ok(())
        }

        #[test]
        fn experimental_v2_requires_binding_before_approval() {
            let mut wire = preconditions_wire(2);
            assert!(parse(&wire).is_err());
            wire["recovery_binding"] = recovery_binding();
            let before = parse(&wire).unwrap();
            let approved = approve(before.clone()).unwrap();
            assert_eq!(approved.phase, JournalPhase::Approved);
            assert_eq!(approved.recovery_binding, before.recovery_binding);
            assert_eq!(
                approved
                    .approval
                    .as_ref()
                    .unwrap()
                    .preconditions_journal_digest,
                digest_state(&before)
            );
            assert!(accept_update(&before, &approved).is_ok());
        }

        #[test]
        fn experimental_v2_rejects_binding_replacement_removal_and_downgrade() {
            let mut wire = preconditions_wire(2);
            wire["recovery_binding"] = recovery_binding();
            let before = parse(&wire).unwrap();
            let mut removed = wire.clone();
            removed.as_object_mut().unwrap().remove("recovery_binding");
            assert!(parse(&removed).is_err());
            for (field, replacement) in
                [("record_id", '2'), ("session_id", '3'), ("handoff_id", '4')]
            {
                let mut replaced = wire.clone();
                replaced["recovery_binding"][field] = json!(digest(replacement));
                let approved_replacement = approve(parse(&replaced).unwrap()).unwrap();
                assert!(accept_update(&before, &approved_replacement).is_err());
            }
            let approved = approve(before.clone()).unwrap();
            let mut tampered = serde_json::to_value(approved).unwrap();
            tampered["recovery_binding"]["record_id"] = json!(digest('5'));
            assert!(parse(&tampered).is_err());
            assert!(parse(&legacy_approved_wire()).is_err());
        }

        #[test]
        fn experimental_policy_rejects_legacy_v1_for_new_approval() {
            let wire = preconditions_wire(1);
            let previous = decoded_wire(&wire).unwrap();
            assert_eq!(previous.phase, JournalPhase::PreconditionsVerified);
            assert!(parse(&wire).is_err());
            assert_eq!(
                decoded_wire(&legacy_approved_wire()).unwrap().phase,
                JournalPhase::Approved
            );
        }
    }

    #[test]
    fn pinned_load_rejects_file_replaced_after_open() {
        let root = root("load-replaced-after-open");
        let store = DurableJournalStore::at(&root);
        let original = journal();
        let final_path = store.persist_new(&original).unwrap();
        let saved = root.join("original-evidence");
        let result = store.load_with_hook(&original.journal_id, || {
            fs::rename(&final_path, &saved).unwrap();
            fs::copy(&saved, &final_path).unwrap();
        });
        assert!(result.is_err());
        assert!(saved.exists() && final_path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_load_rejects_symlink_and_deletion_after_open() {
        for delete_only in [false, true] {
            let root = root(if delete_only {
                "load-deleted"
            } else {
                "load-symlink"
            });
            let store = DurableJournalStore::at(&root);
            let original = journal();
            let final_path = store.persist_new(&original).unwrap();
            let saved = root.join("original-evidence");
            let result = store.load_with_hook(&original.journal_id, || {
                fs::rename(&final_path, &saved).unwrap();
                if !delete_only {
                    symlink(&saved, &final_path).unwrap();
                }
            });
            assert!(result.is_err());
            assert!(saved.exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn journal_inventory_fails_closed_on_concurrent_creation() {
        use std::os::unix::fs::PermissionsExt;
        let root = root("inventory-concurrent-create");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let extra = root.join(format!("{}.json", digest('d')));
        let result = store.all_with_hook(|| {
            fs::write(&extra, b"incomplete evidence").unwrap();
            fs::set_permissions(&extra, fs::Permissions::from_mode(0o600)).unwrap();
        });
        assert!(result.is_err());
        assert!(extra.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_inventory_detects_transient_creation_and_removal() {
        let root = root("inventory-transient-create");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let extra = root.join(format!("{}.json", digest('d')));
        let result = store.all_with_hook(|| {
            fs::write(&extra, b"temporary evidence").unwrap();
            fs::remove_file(&extra).unwrap();
        });
        assert!(matches!(
            result,
            Err(JournalStoreError::ChangedDuringInspection)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_inventory_detects_write_from_already_open_descriptor() {
        let root = root("inventory-existing-writer");
        let store = DurableJournalStore::at(&root);
        let path = store.persist_new(&journal()).unwrap();
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        let result = store.all_with_hook(|| {
            writer.write_all(b"changed").unwrap();
        });
        assert!(result.is_err());
        assert!(path.exists());
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_inventory_fails_closed_when_existing_writer_closes() {
        const MARKER: &str = "LSM_TEST_UNKNOWN_WRITER_CLOSE";
        if std::env::var_os(MARKER).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "journal_store::tests::journal_inventory_fails_closed_when_existing_writer_closes",
                ])
                .env(MARKER, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        let root = root("inventory-close-unchanged-writer");
        let store = DurableJournalStore::at(&root);
        let path = store.persist_new(&journal()).unwrap();
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        let result = store.all_with_hook(|| drop(writer));
        assert!(matches!(
            result,
            Err(JournalStoreError::ChangedDuringInspection)
        ));
        assert!(path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_open_rejects_fifo_without_opening_it() {
        let root = root("fifo-open");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let path = root.join("fifo");
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let watch = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(watch >= 0);
        assert!(unsafe { libc::inotify_add_watch(watch, c_path.as_ptr(), libc::IN_OPEN) } >= 0);
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        assert!(matches!(
            directory.open_file(std::ffi::OsStr::new("fifo")),
            Err(JournalStoreError::NotRegularFile(_))
        ));
        let mut event = [0_u8; 128];
        let count = unsafe { libc::read(watch, event.as_mut_ptr().cast(), event.len()) };
        assert_eq!(count, -1);
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
        unsafe {
            libc::close(watch);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delayed_close_of_own_staging_writer_does_not_invalidate_inventory() {
        use std::os::fd::AsRawFd;
        let root = root("delayed-own-writer-close");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let writer = directory
            .write_staged_file(std::ffi::OsStr::new(".staged-test"), b"record")
            .unwrap();
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
        let inherited = writer.try_clone().unwrap();
        drop(writer);
        let mut watch = directory.watch().unwrap();
        drop(inherited);
        assert!(watch.require_unchanged().is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crashed_isolated_writer_retains_staging_and_blocks_restart() {
        let root = root("crashed-staging-writer");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let name = std::ffi::OsStr::new(".staged-test");
        assert!(directory
            .write_staged_file_crashing(name, b"record")
            .is_err());
        assert!(root.join(name).exists());
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn isolated_writer_reports_io_error_and_preserves_stage() {
        let root = root("writer-enospc");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let name = std::ffi::OsStr::new(".staged-test");
        let error = directory
            .write_staged_file_failing(name, b"record", libc::ENOSPC)
            .unwrap_err();
        assert!(
            matches!(error, JournalStoreError::Io { source, .. } if source.raw_os_error() == Some(libc::ENOSPC))
        );
        assert!(root.join(name).exists());
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_fork_does_not_create_staging_evidence() {
        let root = root("writer-fork-failure");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let name = std::ffi::OsStr::new(".staged-test");
        let error = directory
            .write_staged_file_fork_fails(name, b"record")
            .unwrap_err();
        assert!(
            matches!(error, JournalStoreError::Io { source, .. } if source.raw_os_error() == Some(libc::EAGAIN))
        );
        assert!(!root.join(name).exists());
        assert_eq!(store.all().unwrap(), vec![journal()]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_writer_handshake_wakes_child_despite_duplicated_socket() {
        for shutdown_fails in [false, true] {
            let root = root("writer-handshake-failure");
            let store = DurableJournalStore::at(&root);
            store.persist_new(&journal()).unwrap();
            let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
            let name = std::ffi::OsStr::new(".staged-test");
            let error = directory
                .write_staged_file_send_fails(name, b"record", shutdown_fails)
                .unwrap_err();
            assert!(
                matches!(error, JournalStoreError::Io { source, .. } if source.raw_os_error() == Some(libc::EIO))
            );
            assert!(root.join(name).exists());
            assert!(store.all().is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn automatic_sigchld_reaping_rejects_writer_before_creating_stage() {
        const MARKER: &str = "LSM_TEST_AUTOMATIC_SIGCHLD_REAPING";
        if let Some(mode) = std::env::var_os(MARKER) {
            let root = root("ignored-sigchld");
            fs::create_dir(&root).unwrap();
            let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
            unsafe {
                let mut action = std::mem::zeroed::<libc::sigaction>();
                libc::sigemptyset(&mut action.sa_mask);
                if mode == "ignore" {
                    action.sa_sigaction = libc::SIG_IGN;
                } else {
                    action.sa_sigaction = libc::SIG_DFL;
                    action.sa_flags = libc::SA_NOCLDWAIT;
                }
                assert_eq!(
                    libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
                    0
                );
            }
            assert!(directory
                .write_staged_file(std::ffi::OsStr::new(".staged-test"), b"record")
                .is_err());
            assert!(!root.join(".staged-test").exists());
            fs::remove_dir_all(root).unwrap();
            return;
        }
        for mode in ["ignore", "no-cldwait"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "journal_store::tests::automatic_sigchld_reaping_rejects_writer_before_creating_stage",
                ])
                .env(MARKER, mode)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[test]
    fn fork_before_writer_closes_cannot_inherit_its_descriptor() {
        let root = root("fork-during-isolated-writer");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let mut ready = [-1; 2];
        let mut release_writer = [-1; 2];
        let mut release_exec = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(release_writer.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(release_exec.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                directory.write_staged_file_paused(
                    std::ffi::OsStr::new(".staged-test"),
                    b"record",
                    ready[1],
                    release_writer[0],
                )
            });
            let mut byte = 0_u8;
            assert_eq!(
                unsafe { libc::read(ready[0], (&mut byte as *mut u8).cast(), 1) },
                1
            );
            let expected = fs::metadata(root.join(".staged-test")).unwrap();
            let inode_pinned_in_parent = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| {
                    let fd = entry.file_name().to_str()?.parse::<libc::c_int>().ok()?;
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    let metadata = fs::metadata(entry.path()).ok()?;
                    Some(
                        flags >= 0
                            && flags & libc::O_ACCMODE == libc::O_RDONLY
                            && metadata.dev() == expected.dev()
                            && metadata.ino() == expected.ino(),
                    )
                })
                .any(|matches| matches);
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    if libc::read(release_exec[0], (&mut byte as *mut u8).cast(), 1) != 1 {
                        libc::_exit(1);
                    }
                    let program = b"/usr/bin/true\0";
                    let argv = [program.as_ptr().cast(), std::ptr::null()];
                    libc::execv(program.as_ptr().cast(), argv.as_ptr());
                    libc::_exit(127);
                }
            }
            assert!(pid > 0);
            assert_eq!(
                unsafe { libc::write(release_writer[1], (&byte as *const u8).cast(), 1) },
                1
            );
            let staged = writer.join().unwrap().unwrap();
            let mut watch = directory.watch().unwrap();
            assert_eq!(
                unsafe { libc::write(release_exec[1], (&byte as *const u8).cast(), 1) },
                1
            );
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
            assert!(watch.require_unchanged().is_ok());
            assert!(
                inode_pinned_in_parent,
                "staging inode must remain pinned in the parent"
            );
            drop(staged);
        });
        for fd in ready.into_iter().chain(release_writer).chain(release_exec) {
            unsafe {
                libc::close(fd);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_during_isolated_write_preserves_both_inodes() {
        let root = root("isolated-writer-replacement");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let mut ready = [-1; 2];
        let mut release = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::pipe2(release.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                directory.write_staged_file_paused(
                    std::ffi::OsStr::new(".staged-test"),
                    b"original",
                    ready[1],
                    release[0],
                )
            });
            let mut byte = 0_u8;
            assert_eq!(
                unsafe { libc::read(ready[0], (&mut byte as *mut u8).cast(), 1) },
                1
            );
            fs::rename(root.join(".staged-test"), root.join("saved-original")).unwrap();
            fs::write(root.join(".staged-test"), b"replacement").unwrap();
            assert_eq!(
                unsafe { libc::write(release[1], (&byte as *const u8).cast(), 1) },
                1
            );
            assert!(matches!(
                writer.join().unwrap(),
                Err(JournalStoreError::ChangedDuringInspection)
            ));
        });
        assert_eq!(fs::read(root.join("saved-original")).unwrap(), b"original");
        assert_eq!(fs::read(root.join(".staged-test")).unwrap(), b"replacement");
        for fd in ready.into_iter().chain(release) {
            unsafe {
                libc::close(fd);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn write_through_retained_staging_writer_invalidates_inventory() {
        let root = root("retained-own-writer-write");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let directory = crate::journal_fd::JournalDir::open(&root).unwrap();
        let staged = directory
            .write_staged_file(std::ffi::OsStr::new(".staged-test"), b"record")
            .unwrap();
        let mut inherited = OpenOptions::new()
            .write(true)
            .open(root.join(".staged-test"))
            .unwrap();
        drop(staged);
        let mut watch = directory.watch().unwrap();
        inherited.write_all(b"unexpected mutation").unwrap();
        assert!(matches!(
            watch.require_unchanged(),
            Err(JournalStoreError::ChangedDuringInspection)
        ));
        drop(inherited);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_inventory_detects_creation_in_already_scanned_directory() {
        let root = root("runtime-concurrent-create");
        fs::create_dir(&root).unwrap();
        let first = root.join("create-runtime");
        let last = root.join("swap-runtime");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&last).unwrap();
        let store = DurableJournalStore::at(root.join("journal"));
        let evidence = first.join("pending.json");
        let result = store.unclassified_runtime_evidence_with_hook(|| {
            fs::write(&evidence, b"concurrent evidence").unwrap();
        });
        assert!(result.is_err());
        assert!(evidence.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_update_preserves_replacement_and_original_evidence() {
        let root = root("exchange-replaced-evidence");
        let store = DurableJournalStore::at(&root);
        let original = journal();
        let final_path = store.persist_new(&original).unwrap();
        let saved = root.join("original-evidence");
        let mut next = original.clone();
        next.apply(JournalTransition::HostLockAcquired).unwrap();
        let result = store.persist_if_matches_with_hook(&original, &next, || {
            fs::rename(&final_path, &saved).unwrap();
            fs::copy(&saved, &final_path).unwrap();
        });
        assert!(result.is_err());
        assert!(saved.exists());
        assert!(fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp-")));
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_journal_updates_retain_and_validate_previous_states() {
        let root = root("immutable-journal-history");
        let store = DurableJournalStore::at(&root);
        let original = journal();
        store.persist_new(&original).unwrap();
        let mut next = original.clone();
        next.apply(JournalTransition::HostLockAcquired).unwrap();
        store.persist_if_matches(&original, &next).unwrap();
        let history_name = format!(
            ".{}.history-0-{}",
            original.journal_id,
            journal_content_digest(&original).unwrap()
        );
        let history_path = root.join(history_name);
        let saved = fs::read(&history_path).unwrap();
        assert_eq!(store.all().unwrap(), vec![next.clone()]);
        assert!(store.inspect().unwrap().unclassified.is_empty());
        let mut later = next.clone();
        later
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &original.baseline_manifest_digest,
            })
            .unwrap();
        store.persist_if_matches(&next, &later).unwrap();
        assert_eq!(fs::read(&history_path).unwrap(), saved);
        assert_eq!(store.all().unwrap(), vec![later]);
        fs::write(&history_path, b"corrupted historical evidence").unwrap();
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_update_never_follows_a_replaced_symlink() {
        let root = root("exchange-symlink-evidence");
        let store = DurableJournalStore::at(&root);
        let original = journal();
        let final_path = store.persist_new(&original).unwrap();
        let saved = root.join("original-evidence");
        let outside = root.with_extension("outside-evidence");
        fs::write(&outside, b"preserve unrelated file").unwrap();
        let mut next = original.clone();
        next.apply(JournalTransition::HostLockAcquired).unwrap();
        let result = store.persist_if_matches_with_hook(&original, &next, || {
            fs::rename(&final_path, &saved).unwrap();
            symlink(&outside, &final_path).unwrap();
        });
        assert!(result.is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"preserve unrelated file");
        assert!(saved.exists());
        assert!(store.all().is_err());
        fs::remove_file(outside).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_journal_exchange_preserves_both_states_and_blocks_restart() {
        let root = root("interrupted-exchange");
        let store = DurableJournalStore::at(&root);
        let original = journal();
        store.persist_new(&original).unwrap();
        let mut next = original.clone();
        next.apply(JournalTransition::HostLockAcquired).unwrap();
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.persist_if_matches_with_hooks(
                &original,
                &next,
                || {},
                || panic!("simulated interruption"),
            );
        }));
        assert!(interrupted.is_err());
        assert_eq!(store.load(&original.journal_id).unwrap(), next);
        let diagnostics = store.inspect().unwrap();
        assert!(diagnostics
            .unclassified
            .iter()
            .any(|entry| entry.staged_journal.as_ref() == Some(&original)));
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_update_refuses_deleted_and_corrupted_predecessor() {
        for corrupt in [false, true] {
            let root = root(if corrupt {
                "update-corrupt"
            } else {
                "update-deleted"
            });
            let store = DurableJournalStore::at(&root);
            let original = journal();
            let path = store.persist_new(&original).unwrap();
            let mut next = original.clone();
            next.apply(JournalTransition::HostLockAcquired).unwrap();
            if corrupt {
                fs::write(&path, b"broken evidence").unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            assert!(store.persist_if_matches(&original, &next).is_err());
            if corrupt {
                assert_eq!(fs::read(&path).unwrap(), b"broken evidence");
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn journal_creation_fails_when_parent_directory_cannot_be_synced() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let parent = root("unreadable-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
        let store = DurableJournalStore::at(parent.join("journal"));
        let result = store.persist_new(&journal());
        let retry = store.persist_new(&journal());
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(parent).unwrap();
        assert!(
            result.is_err(),
            "journal parent directory sync failure must fail closed"
        );
        assert!(
            retry.is_err(),
            "an existing unsynced directory must not make a retry succeed"
        );
    }

    #[test]
    fn inspection_reports_valid_staged_journal_without_authorizing_writes() {
        let root = root("staged-diagnostics");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        let path = store.persist_new(&journal).unwrap();
        let staging = root.join(format!(".{}.tmp-123-1", journal.journal_id));
        fixture_file(&root, &staging, &fs::read(&path).unwrap());
        let inspection = store.inspect().unwrap();
        assert_eq!(inspection.unfinished, vec![journal.clone()]);
        assert_eq!(inspection.unclassified.len(), 1);
        assert_eq!(inspection.unclassified[0].path, staging);
        assert_eq!(
            inspection.unclassified[0].staged_journal.as_ref(),
            Some(&journal)
        );
        assert!(!inspection.unclassified[0].verified_duplicate_link);
        assert!(store.all().is_err());
        assert!(staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_reports_truncated_staging_as_unclassified() {
        use std::os::unix::fs::PermissionsExt;
        let root = root("truncated-staging");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        store.persist_new(&journal).unwrap();
        let staging = root.join(format!(".{}.tmp-123-1", journal.journal_id));
        fixture_file(&root, &staging, b"{\"phase\":\"execut");
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o600)).unwrap();
        let inspection = store.inspect().unwrap();
        assert_eq!(inspection.unclassified.len(), 1);
        assert!(inspection.unclassified[0].staged_journal.is_none());
        assert!(inspection.unclassified[0]
            .problem
            .as_deref()
            .unwrap()
            .contains("JSON"));
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_recognizes_durable_hard_link_pair_without_permitting_writes() {
        let root = root("staged-hard-link");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        let final_path = store.persist_new(&journal).unwrap();
        let staging = root.join(format!(".{}.tmp-123-1", journal.journal_id));
        fs::hard_link(&final_path, &staging).unwrap();
        let inspection = store.inspect().unwrap();
        let staged = inspection
            .unclassified
            .iter()
            .find(|entry| entry.path == staging)
            .unwrap();
        assert_eq!(staged.staged_journal.as_ref(), Some(&journal));
        assert!(staged.verified_duplicate_link);
        assert!(store.all().is_err());
        assert!(final_path.exists() && staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_json_preserves_non_utf8_filename_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let root = root("nonutf8-evidence");
        let store = DurableJournalStore::at(&root);
        store.persist_new(&journal()).unwrap();
        let path = root.join(std::ffi::OsString::from_vec(vec![b'x', 0xff, b'\n']));
        fixture_file(&root, &path, b"evidence");
        let inspection = store.inspect().unwrap();
        let entry = inspection
            .unclassified
            .iter()
            .find(|entry| entry.path == path)
            .unwrap();
        assert!(entry.path_bytes_hex.ends_with("78ff0a"));
        let json = serde_json::to_string(&inspection).unwrap();
        assert!(json.contains("78ff0a"));
        assert!(store.all().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_does_not_mislabel_arbitrary_filenames_as_staging() {
        let root = root("invalid-staging-name");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        let final_path = store.persist_new(&journal).unwrap();
        let bogus = root.join(format!(".{}.tmp-garbage", journal.journal_id));
        fixture_file(&root, &bogus, &fs::read(&final_path).unwrap());
        let inspection = store.inspect().unwrap();
        let entry = inspection
            .unclassified
            .iter()
            .find(|entry| entry.path == bogus)
            .unwrap();
        assert!(entry.staged_journal.is_none());
        assert!(entry.problem.is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_with_multiple_links_is_rejected() {
        let root = root("multiple-links");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        let path = store.persist_new(&journal).unwrap();
        fs::hard_link(&path, root.join("extra-link")).unwrap();
        let result = store.load(&journal.journal_id);
        let _ = fs::remove_dir_all(root);
        assert!(matches!(result, Err(JournalStoreError::NotRegularFile(_))));
    }

    #[test]
    fn journal_read_rejects_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let root = root("unsafe-file-mode");
        let store = DurableJournalStore::at(&root);
        let journal = journal();
        let path = store.persist_new(&journal).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let result = store.load(&journal.journal_id);
        let _ = fs::remove_dir_all(root);
        assert!(matches!(result, Err(JournalStoreError::NotRegularFile(_))));
    }

    #[test]
    fn writable_journal_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let root = root("writable-directory");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        let store = DurableJournalStore::at(&root);
        let result = store.persist_new(&journal());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(
            result.is_err(),
            "unsafe writable journal directory was accepted"
        );
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

        let path = store.test_overwrite(&journal).unwrap();
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
        store.test_overwrite(&journal).unwrap();

        let baseline = journal.baseline_manifest_digest.clone();
        journal
            .apply(JournalTransition::IdentityRevalidated {
                fresh_manifest_digest: &baseline,
            })
            .unwrap();
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

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

        let result = store.test_overwrite(&journal());
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
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

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
        store.test_overwrite(&journal).unwrap();

        let loaded = store.load(&journal.journal_id).unwrap();
        assert_eq!(loaded.phase, JournalPhase::RecoveryRequired);
        assert_eq!(
            loaded.resume_disposition(),
            ResumeDisposition::RecoveryRequired
        );
        let _ = fs::remove_dir_all(root);
    }
}
