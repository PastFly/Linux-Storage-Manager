//! Opt-in, read-only recovery inspection. No restore or approval authority.
//!
//! The journal is the independent record-id anchor, not authentication against
//! arbitrary root. No inferred orphan authorizes deletion, replay, or mutation.
//! Observations are point-in-time; mount/namespace interference by a privileged
//! actor and storage failure remain outside this experiment's guarantees.
#![allow(dead_code)]

use crate::backup_recovery_record::decode;
use crate::journal_fd::{DirectoryWatch, JournalDir};
use crate::sealed_recovery::{
    bounded_names, check_file, live_metadata, require_procfs, same_file_version, same_inode,
    SealError,
};
#[cfg(test)]
use crate::LockedExecutionSession;
use crate::{DurableJournalStore, HostStorageLock, JournalStoreError};
use lsm_planner::{JournalPhase, OperationJournal};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

const MAX_RECORD_BYTES: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum InspectionError {
    #[error("journal, record, files, or trusted paths do not match")]
    Invalid,
    #[error("journal or directory inspection failed: {0}")]
    Journal(#[from] JournalStoreError),
    #[error("sealed file check failed: {0}")]
    Seal(#[from] SealError),
    #[error("recovery inspection I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Orphan paths are untrusted observations. They cannot authorize cleanup.
pub(crate) enum Inspection {
    UnboundPrewrite {
        candidates: Vec<PathBuf>,
        unrecognized: Vec<PathBuf>,
    },
    Bound {
        record_id: String,
        phase: JournalPhase,
        mutation_may_have_started: bool,
        _pins: Box<BoundPins>,
    },
}

pub(crate) struct BoundPins {
    _record: File,
    _pairs: Vec<(File, File)>,
    _record_dir: JournalDir,
    _primary_dir: JournalDir,
    _recovery_dir: JournalDir,
    _record_watch: DirectoryWatch,
    _primary_watch: DirectoryWatch,
    _recovery_watch: DirectoryWatch,
}

/// Holds the actual system host lock while the inspection's pins exist.
pub(crate) struct SystemInspection {
    result: Inspection,
    _lock: HostStorageLock,
}

impl SystemInspection {
    /// The result and its pinned FDs cannot outlive the owning host lock.
    pub(crate) fn result(&self) -> &Inspection {
        &self.result
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn journal_from_store(
    store: &DurableJournalStore,
    id: &str,
) -> Result<OperationJournal, InspectionError> {
    if !valid_digest(id) {
        return Err(InspectionError::Invalid);
    }
    // `all` rejects incomplete/conflicting history; a lone load is not enough.
    let all = store.all()?;
    let journal = all
        .into_iter()
        .find(|entry| entry.journal_id == id)
        .ok_or(InspectionError::Invalid)?;
    if store.load(id)? != journal {
        return Err(InspectionError::Invalid);
    }
    Ok(journal)
}

fn require_journal_unchanged(
    store: &DurableJournalStore,
    expected: &OperationJournal,
) -> Result<(), InspectionError> {
    if journal_from_store(store, &expected.journal_id)? != *expected {
        return Err(InspectionError::Invalid);
    }
    Ok(())
}

/// Runtime entry point accepts only a real lock for the fixed system lock path;
/// the durable store path cannot be supplied by the caller.
pub(crate) fn inspect_system(
    journal_id: &str,
    lock: HostStorageLock,
) -> Result<SystemInspection, InspectionError> {
    if unsafe { libc::geteuid() } != 0
        || lock.path() != Path::new(lsm_planner::HOST_STORAGE_LOCK_PATH)
    {
        return Err(InspectionError::Invalid);
    }
    let store = DurableJournalStore::at(lsm_planner::JOURNAL_DIRECTORY);
    let result = inspect_in_store(&store, journal_id)?;
    Ok(SystemInspection {
        result,
        _lock: lock,
    })
}

#[cfg(test)]
fn inspect_for_test(
    session: &LockedExecutionSession<'_>,
    store: &DurableJournalStore,
) -> Result<Inspection, InspectionError> {
    let expected = session
        .lock_path()
        .parent()
        .ok_or(InspectionError::Invalid)?
        .join("journal");
    if store.root() != expected {
        return Err(InspectionError::Invalid);
    }
    inspect_in_store(store, &session.journal().journal_id)
}

fn inspect_in_store(store: &DurableJournalStore, id: &str) -> Result<Inspection, InspectionError> {
    let journal = journal_from_store(store, id)?;
    if journal.schema_version != 2 {
        return Err(InspectionError::Invalid);
    }
    let result = match journal.recovery_binding.as_ref() {
        Some(binding) => inspect_bound(&journal, binding)?,
        None if !journal.mutation_may_have_started
            && matches!(
                journal.phase,
                JournalPhase::Planned
                    | JournalPhase::HostLockHeld
                    | JournalPhase::IdentityRevalidated
                    | JournalPhase::Aborted
            ) =>
        {
            inspect_unbound(&journal)?
        }
        None => return Err(InspectionError::Invalid),
    };
    require_journal_unchanged(store, &journal)?;
    Ok(result)
}

fn inspect_unbound(journal: &OperationJournal) -> Result<Inspection, InspectionError> {
    inspect_unbound_with_hook(journal, |_| {})
}

fn inspect_unbound_with_hook(
    journal: &OperationJournal,
    mut after_handoff: impl FnMut(&Path),
) -> Result<Inspection, InspectionError> {
    let root_path = Path::new(crate::BACKUP_DIRECTORY);
    let root = JournalDir::open(root_path)?;
    require_procfs(&[root.file()])?;
    let mut root_watch = root.watch_namespace()?;
    root.verify_namespace()?;
    let names = bounded_names(&root)?;
    let mut candidates = Vec::new();
    let mut unrecognized = Vec::new();
    let mut handoffs = Vec::new();
    let expected = [
        journal.journal_id.clone(),
        format!("{}.recovery", journal.journal_id),
        format!("{}.record", journal.journal_id),
    ];
    for name in &names {
        let Some(text) = name.to_str() else {
            unrecognized.push(root_path.join(name));
            continue;
        };
        if !valid_digest(text) {
            unrecognized.push(root_path.join(name));
            continue;
        }
        let handoff_path = root_path.join(name);
        let handoff = JournalDir::open(&handoff_path)?;
        require_procfs(&[handoff.file()])?;
        let mut watch = handoff.watch_namespace()?;
        handoff.verify_namespace()?;
        let entries = bounded_names(&handoff)?;
        for entry in &entries {
            if expected
                .iter()
                .any(|expected| entry == OsStr::new(expected))
            {
                candidates.push(handoff_path.join(entry));
            } else {
                // Report entries we cannot associate with this journal; they
                // are never treated as disposable by inspection.
                unrecognized.push(handoff_path.join(entry));
            }
        }
        handoff.verify_namespace()?;
        if bounded_names(&handoff)? != entries {
            return Err(InspectionError::Invalid);
        }
        watch.require_unchanged()?;
        // Keep every watch alive while later handoffs are inspected. A
        // transient change after the first scan must invalidate the result.
        handoffs.push((handoff, watch, entries));
        after_handoff(&handoff_path);
    }
    for (handoff, watch, entries) in &mut handoffs {
        handoff.verify_namespace()?;
        if bounded_names(handoff)? != *entries {
            return Err(InspectionError::Invalid);
        }
        watch.require_unchanged()?;
    }
    root.verify_namespace()?;
    if bounded_names(&root)? != names {
        return Err(InspectionError::Invalid);
    }
    root_watch.require_unchanged()?;
    Ok(Inspection::UnboundPrewrite {
        candidates,
        unrecognized,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn inspect_bound(
    journal: &OperationJournal,
    binding: &lsm_planner::JournalRecoveryBinding,
) -> Result<Inspection, InspectionError> {
    if !valid_digest(&binding.record_id)
        || !valid_digest(&binding.handoff_id)
        || !valid_digest(&binding.session_id)
    {
        return Err(InspectionError::Invalid);
    }
    let primary_path = Path::new(crate::BACKUP_DIRECTORY)
        .join(&binding.handoff_id)
        .join(&journal.journal_id);
    let mut recovery_name = primary_path
        .file_name()
        .ok_or(InspectionError::Invalid)?
        .to_os_string();
    recovery_name.push(".recovery");
    let recovery_path = primary_path.with_file_name(recovery_name);
    let mut record_name = primary_path
        .file_name()
        .ok_or(InspectionError::Invalid)?
        .to_os_string();
    record_name.push(".record");
    let record_path = primary_path.with_file_name(record_name);
    let primary_dir = JournalDir::open(&primary_path)?;
    let recovery_dir = JournalDir::open(&recovery_path)?;
    let record_dir = JournalDir::open(&record_path)?;
    require_procfs(&[primary_dir.file(), recovery_dir.file(), record_dir.file()])?;
    let mut primary_watch = primary_dir.watch_namespace()?;
    let mut recovery_watch = recovery_dir.watch_namespace()?;
    let mut record_watch = record_dir.watch_namespace()?;
    for dir in [&primary_dir, &recovery_dir, &record_dir] {
        dir.verify_namespace()?;
    }
    let pmeta = primary_dir.file().metadata()?;
    let rmeta = recovery_dir.file().metadata()?;
    let dmeta = record_dir.file().metadata()?;
    if same_inode(&pmeta, &rmeta) || same_inode(&pmeta, &dmeta) || same_inode(&rmeta, &dmeta) {
        return Err(InspectionError::Invalid);
    }
    let final_name = format!("{}.json", binding.record_id);
    let pending_name = format!(".{}.pending", binding.record_id);
    let mut expected_record_names =
        vec![OsString::from(&final_name), OsString::from(&pending_name)];
    expected_record_names.sort();
    if bounded_names(&record_dir)? != expected_record_names {
        return Err(InspectionError::Invalid);
    }
    let record_file = record_dir.open_file(OsStr::new(&final_name))?;
    let before = record_file.metadata()?;
    let pending = live_metadata(&record_dir, OsStr::new(&pending_name))?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 2
        || before.len() == 0
        || before.len() > MAX_RECORD_BYTES
        || !same_file_version(&before, &pending)
    {
        return Err(InspectionError::Invalid);
    }
    // fs-verity verifies reads, but its record measurement is not journaled;
    // the independently journaled record_id binds the record bytes.
    let record_verity = crate::backup_verity::measure(&record_file)?;
    let mut bytes = vec![0_u8; before.len() as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = record_file.read_at(&mut bytes[offset..], offset as u64)?;
        if n == 0 {
            return Err(InspectionError::Invalid);
        }
        offset += n;
    }
    let record = decode(&bytes, &binding.record_id).map_err(|_| InspectionError::Invalid)?;
    let context = record.binding();
    if record.schema_version() != 3
        || record.encode().map_err(|_| InspectionError::Invalid)? != bytes
        || context.journal_id != journal.journal_id
        || context.session_id != binding.session_id
        || context.handoff_id != binding.handoff_id
        || context.plan_id != journal.plan_id
        || context.target_manifest_digest != journal.baseline_manifest_digest
        || crate::backup_verity::measure(&record_file)? != record_verity
        || !same_file_version(&before, &record_file.metadata()?)
        || !same_file_version(
            &before,
            &live_metadata(&record_dir, OsStr::new(&final_name))?,
        )
        || !same_file_version(
            &before,
            &live_metadata(&record_dir, OsStr::new(&pending_name))?,
        )
    {
        return Err(InspectionError::Invalid);
    }
    let mut primary_names = Vec::new();
    let mut recovery_names = Vec::new();
    let mut ids = BTreeSet::new();
    let mut pairs = Vec::new();
    for artifact in record.artifacts() {
        let p = Path::new(&artifact.primary_path);
        let r = Path::new(&artifact.recovery_path);
        if p.parent() != Some(primary_path.as_path()) || r.parent() != Some(recovery_path.as_path())
        {
            return Err(InspectionError::Invalid);
        }
        let pn = p.file_name().ok_or(InspectionError::Invalid)?;
        let rn = r.file_name().ok_or(InspectionError::Invalid)?;
        let mut canonical_recovery_name = pn.to_os_string();
        canonical_recovery_name.push(".recovery");
        if rn != canonical_recovery_name {
            return Err(InspectionError::Invalid);
        }
        let pfile = primary_dir.open_file(pn)?;
        let rfile = recovery_dir.open_file(rn)?;
        let pmeta = check_file(
            &pfile,
            &primary_dir,
            pn,
            artifact.size_bytes,
            &artifact.sha256,
        )?;
        let rmeta = check_file(
            &rfile,
            &recovery_dir,
            rn,
            artifact.size_bytes,
            &artifact.sha256,
        )?;
        let verity = artifact.verity.as_ref().ok_or(InspectionError::Invalid)?;
        if !ids.insert((pmeta.dev(), pmeta.ino()))
            || !ids.insert((rmeta.dev(), rmeta.ino()))
            || hex(&crate::backup_verity::measure(&pfile)?) != verity.primary_sha256
            || hex(&crate::backup_verity::measure(&rfile)?) != verity.recovery_sha256
        {
            return Err(InspectionError::Invalid);
        }
        primary_names.push(pn.to_os_string());
        recovery_names.push(rn.to_os_string());
        pairs.push((pfile, rfile));
    }
    primary_names.sort();
    recovery_names.sort();
    if bounded_names(&primary_dir)? != primary_names
        || bounded_names(&recovery_dir)? != recovery_names
        || bounded_names(&record_dir)? != expected_record_names
    {
        return Err(InspectionError::Invalid);
    }
    for dir in [&primary_dir, &recovery_dir, &record_dir] {
        dir.verify_namespace()?;
    }
    primary_watch.require_unchanged()?;
    recovery_watch.require_unchanged()?;
    record_watch.require_unchanged()?;
    Ok(Inspection::Bound {
        record_id: binding.record_id.clone(),
        phase: journal.phase,
        mutation_may_have_started: journal.mutation_may_have_started,
        _pins: Box::new(BoundPins {
            _record: record_file,
            _pairs: pairs,
            _record_dir: record_dir,
            _primary_dir: primary_dir,
            _recovery_dir: recovery_dir,
            _record_watch: record_watch,
            _primary_watch: primary_watch,
            _recovery_watch: recovery_watch,
        }),
    })
}

#[cfg(test)]
#[path = "recovery_inspector_tests.rs"]
mod tests;

#[cfg(test)]
struct TestAdmission<'a> {
    _session: &'a LockedExecutionSession<'a>,
}

#[cfg(test)]
impl TestAdmission<'_> {
    fn revalidate(&mut self) -> Result<(), InspectionError> {
        Err(InspectionError::Invalid)
    }
}

#[cfg(test)]
fn admit_for_test<'a>(
    _session: &'a LockedExecutionSession<'a>,
    _store: &DurableJournalStore,
) -> Result<TestAdmission<'a>, InspectionError> {
    Err(InspectionError::Invalid)
}

#[cfg(test)]
#[path = "recovery_admission_tests.rs"]
mod admission_tests;
