use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProductionCreateActivationIntent, ProductionCreateExecutionPermit,
    ProductionCreateRuntimeLaunchSpec, ProductionCreateRuntimePreflightReceipt,
};

pub const PRODUCTION_CREATE_RUNTIME_JOURNAL_COMPILED: bool =
    cfg!(feature = "production-create-runtime-journal");
pub const PRODUCTION_CREATE_RUNTIME_JOURNAL_DIRECTORY: &str =
    "/var/lib/linux-storage-manager/create-runtime";
const MAX_CREATE_RUNTIME_JOURNAL_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionCreateRuntimePhase {
    Prepared,
    WritingPartitionTable,
    PartitionTableWrittenAwaitingRediscovery,
    PartitionMappedVerified,
    FormattingFilesystem,
    FilesystemFormattedAwaitingVerification,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionCreateRuntimeTransition {
    BeginPartitionTableWrite,
    PartitionTableWriteSucceeded,
    PartitionRediscoveryVerified,
    BeginFilesystemFormat,
    FilesystemFormatSucceeded,
    FilesystemRediscoveryVerified,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreateRuntimeJournalEvent {
    pub sequence: u32,
    pub phase: ProductionCreateRuntimePhase,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreateRuntimeJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub preflight_receipt_id: String,
    pub launch_id: String,
    pub create_intent_id: String,
    pub disk: String,
    pub partition_device: String,
    pub partition_table: String,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub phase: ProductionCreateRuntimePhase,
    pub mutation_may_have_started: bool,
    pub partition_table_may_have_changed: bool,
    pub filesystem_may_have_changed: bool,
    pub events: Vec<ProductionCreateRuntimeJournalEvent>,
}

#[derive(Serialize)]
struct JournalIdPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    preflight_receipt_id: &'a str,
    launch_id: &'a str,
    create_intent_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    partition_table: &'a str,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
}

impl ProductionCreateRuntimeJournal {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.journal_id == self.expected_journal_id()?)
    }

    fn expected_journal_id(&self) -> Result<String, serde_json::Error> {
        let payload = JournalIdPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            execution_permit_id: &self.execution_permit_id,
            preflight_receipt_id: &self.preflight_receipt_id,
            launch_id: &self.launch_id,
            create_intent_id: &self.create_intent_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            partition_table: &self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ProductionCreateRuntimeJournalStore {
    root: PathBuf,
}

impl Default for ProductionCreateRuntimeJournalStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from(PRODUCTION_CREATE_RUNTIME_JOURNAL_DIRECTORY),
        }
    }
}

impl ProductionCreateRuntimeJournalStore {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(
        &self,
        journal_id: &str,
    ) -> Result<ProductionCreateRuntimeJournal, ProductionCreateRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
        ensure_secure_directory(&self.root, false)?;
        let path = self.path_for(journal_id)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        validate_journal_file_metadata(&path, &metadata)?;
        if metadata.len() > MAX_CREATE_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionCreateRuntimeJournalError::TooLarge);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let mut bytes = Vec::new();
        file.take(MAX_CREATE_RUNTIME_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(&path, source))?;
        if bytes.len() as u64 > MAX_CREATE_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionCreateRuntimeJournalError::TooLarge);
        }
        let journal: ProductionCreateRuntimeJournal = serde_json::from_slice(&bytes)?;
        if journal.journal_id != journal_id {
            return Err(ProductionCreateRuntimeJournalError::InvalidRecord(
                "journal ID does not match requested record".into(),
            ));
        }
        validate_journal(&journal)?;
        Ok(journal)
    }

    fn persist_new(
        &self,
        journal: &ProductionCreateRuntimeJournal,
    ) -> Result<PathBuf, ProductionCreateRuntimeJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let final_path = self.path_for(&journal.journal_id)?;
        if final_path.exists() {
            return Err(ProductionCreateRuntimeJournalError::AlreadyExists(
                journal.journal_id.clone(),
            ));
        }
        write_atomic_new(&self.root, &final_path, journal)?;
        Ok(final_path)
    }

    fn persist(
        &self,
        journal: &ProductionCreateRuntimeJournal,
    ) -> Result<PathBuf, ProductionCreateRuntimeJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, false)?;
        let final_path = self.path_for(&journal.journal_id)?;
        let metadata =
            fs::symlink_metadata(&final_path).map_err(|source| io_error(&final_path, source))?;
        validate_journal_file_metadata(&final_path, &metadata)?;
        write_atomic_replace(&self.root, &final_path, journal)?;
        Ok(final_path)
    }

    fn path_for(
        &self,
        journal_id: &str,
    ) -> Result<PathBuf, ProductionCreateRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
        Ok(self.root.join(format!("{journal_id}.json")))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateRuntimeJournalError {
    #[error("production create runtime journal feature is not compiled")]
    FeatureDisabled,
    #[error("create activation/permit/preflight/launch integrity is invalid")]
    AuthorizationInvalid,
    #[error("create journal bindings do not exactly match the frozen launch chain")]
    BindingMismatch,
    #[error("create runtime journal record is structurally invalid: {0}")]
    InvalidRecord(String),
    #[error("create runtime journal transition is invalid from {from:?} via {transition:?}")]
    InvalidTransition {
        from: ProductionCreateRuntimePhase,
        transition: ProductionCreateRuntimeTransition,
    },
    #[error("create runtime journal already exists: {0}")]
    AlreadyExists(String),
    #[error("create runtime journal path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("create runtime journal directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("create runtime journal exceeds maximum record size")]
    TooLarge,
    #[error("create runtime journal JSON is invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("create runtime journal I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> ProductionCreateRuntimeJournalError {
    ProductionCreateRuntimeJournalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_digest(
    value: &str,
    label: &str,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProductionCreateRuntimeJournalError::InvalidRecord(format!(
            "{label} is not a lowercase SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn ensure_secure_directory(
    root: &Path,
    create: bool,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ProductionCreateRuntimeJournalError::UnsafeDirectory(
                    root.to_path_buf(),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound && create => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(root)
                .map_err(|source| io_error(root, source))?;
            sync_parent(root)?;
            let metadata = fs::symlink_metadata(root).map_err(|source| io_error(root, source))?;
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
                || !metadata.is_dir()
            {
                return Err(ProductionCreateRuntimeJournalError::UnsafeDirectory(
                    root.to_path_buf(),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(ProductionCreateRuntimeJournalError::UnsafeDirectory(
                root.to_path_buf(),
            ));
        }
        Err(source) => return Err(io_error(root, source)),
    }
    Ok(())
}

fn validate_journal_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProductionCreateRuntimeJournalError::UnsafePath(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn encode_journal(
    journal: &ProductionCreateRuntimeJournal,
) -> Result<Vec<u8>, ProductionCreateRuntimeJournalError> {
    let mut bytes = serde_json::to_vec(journal)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_CREATE_RUNTIME_JOURNAL_BYTES {
        return Err(ProductionCreateRuntimeJournalError::TooLarge);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), ProductionCreateRuntimeJournalError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory.sync_all().map_err(|source| io_error(path, source))
}

fn sync_parent(path: &Path) -> Result<(), ProductionCreateRuntimeJournalError> {
    let parent = path.parent().ok_or_else(|| {
        ProductionCreateRuntimeJournalError::UnsafeDirectory(path.to_path_buf())
    })?;
    sync_directory(parent)
}

fn temp_path(root: &Path, final_path: &Path) -> Result<PathBuf, ProductionCreateRuntimeJournalError> {
    let name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ProductionCreateRuntimeJournalError::UnsafePath(final_path.to_path_buf()))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(".{name}.tmp-{}-{sequence}", std::process::id())))
}

fn write_atomic_new(
    root: &Path,
    final_path: &Path,
    journal: &ProductionCreateRuntimeJournal,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    let bytes = encode_journal(journal)?;
    let temp = temp_path(root, final_path)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|source| io_error(&temp, source))?;
        file.write_all(&bytes)
            .map_err(|source| io_error(&temp, source))?;
        file.sync_all().map_err(|source| io_error(&temp, source))?;
        drop(file);
        match fs::hard_link(&temp, final_path) {
            Ok(()) => {}
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ProductionCreateRuntimeJournalError::AlreadyExists(
                    journal.journal_id.clone(),
                ));
            }
            Err(source) => return Err(io_error(final_path, source)),
        }
        fs::remove_file(&temp).map_err(|source| io_error(&temp, source))?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_atomic_replace(
    root: &Path,
    final_path: &Path,
    journal: &ProductionCreateRuntimeJournal,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    let bytes = encode_journal(journal)?;
    let temp = temp_path(root, final_path)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|source| io_error(&temp, source))?;
        file.write_all(&bytes)
            .map_err(|source| io_error(&temp, source))?;
        file.sync_all().map_err(|source| io_error(&temp, source))?;
        drop(file);
        fs::rename(&temp, final_path).map_err(|source| io_error(final_path, source))?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_authorization(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    launch: &ProductionCreateRuntimeLaunchSpec,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || preflight.schema_version != 1
        || launch.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !preflight.runtime_ready
        || activation.execution_enabled
        || permit.mutation_enabled
        || permit.process_spawned
        || preflight.mutation_enabled
        || preflight.process_spawned
        || launch.mutation_enabled
        || launch.process_spawned
        || launch.partition_table_changed
        || launch.filesystem_formatted
        || !launch.require_partition_rediscovery_before_mkfs
    {
        return Err(ProductionCreateRuntimeJournalError::AuthorizationInvalid);
    }

    if permit.activation_id != activation.activation_id
        || preflight.activation_id != activation.activation_id
        || launch.activation_id != activation.activation_id
        || preflight.execution_permit_id != permit.permit_id
        || launch.execution_permit_id != permit.permit_id
        || launch.preflight_receipt_id != preflight.receipt_id
        || permit.create_intent_id != activation.create_intent_id
        || preflight.create_intent_id != activation.create_intent_id
        || launch.create_intent_id != activation.create_intent_id
        || launch.disk != activation.disk
        || launch.partition_table != activation.partition_table
        || launch.partition_start_sector != activation.partition_start_sector
        || launch.partition_sector_count != activation.partition_sector_count
        || launch.partition_size_bytes != activation.partition_size_bytes
        || launch.filesystem != activation.filesystem
    {
        return Err(ProductionCreateRuntimeJournalError::BindingMismatch);
    }
    Ok(())
}

fn partition_table_name(activation: &ProductionCreateActivationIntent) -> &'static str {
    match activation.partition_table {
        lsm_planner::CreatePartitionTablePolicy::Gpt => "gpt",
        lsm_planner::CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn validate_journal(
    journal: &ProductionCreateRuntimeJournal,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    if journal.schema_version != 1
        || !journal.integrity_matches().unwrap_or(false)
        || journal.disk.is_empty()
        || !journal.disk.starts_with("/dev/")
        || journal.partition_device.is_empty()
        || !journal.partition_device.starts_with("/dev/")
        || !matches!(journal.partition_table.as_str(), "gpt" | "dos")
        || journal.partition_start_sector == 0
        || journal.partition_sector_count == 0
        || journal.partition_size_bytes == 0
        || !matches!(journal.filesystem.as_str(), "ext4" | "xfs")
    {
        return Err(ProductionCreateRuntimeJournalError::InvalidRecord(
            "journal identity or frozen create geometry is invalid".into(),
        ));
    }
    validate_digest(&journal.activation_id, "activation ID")?;
    validate_digest(&journal.execution_permit_id, "execution permit ID")?;
    validate_digest(&journal.preflight_receipt_id, "preflight receipt ID")?;
    validate_digest(&journal.launch_id, "launch ID")?;
    validate_digest(&journal.create_intent_id, "create intent ID")?;

    let expected_sequence = journal.events.len() as u32;
    if journal
        .events
        .iter()
        .enumerate()
        .any(|(index, event)| event.sequence != index as u32 + 1)
        || journal.events.last().is_some_and(|event| event.sequence != expected_sequence)
    {
        return Err(ProductionCreateRuntimeJournalError::InvalidRecord(
            "journal event sequence is invalid".into(),
        ));
    }

    let mutation_phase = !matches!(journal.phase, ProductionCreateRuntimePhase::Prepared);
    if mutation_phase != journal.mutation_may_have_started {
        return Err(ProductionCreateRuntimeJournalError::InvalidRecord(
            "mutation-start flag does not match durable phase".into(),
        ));
    }
    if journal.filesystem_may_have_changed
        && !journal.partition_table_may_have_changed
    {
        return Err(ProductionCreateRuntimeJournalError::InvalidRecord(
            "filesystem mutation cannot precede partition-table mutation".into(),
        ));
    }
    Ok(())
}

/// Build the exact durable create state machine before any storage mutation.
///
/// The resulting journal is Prepared and records no mutation. A future
/// executor must durably cross BeginPartitionTableWrite before sfdisk, prove a
/// fresh partition rediscovery before BeginFilesystemFormat, and only reach
/// Completed after fresh filesystem verification.
pub fn build_production_create_runtime_journal(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    launch: &ProductionCreateRuntimeLaunchSpec,
) -> Result<ProductionCreateRuntimeJournal, ProductionCreateRuntimeJournalError> {
    if !PRODUCTION_CREATE_RUNTIME_JOURNAL_COMPILED {
        return Err(ProductionCreateRuntimeJournalError::FeatureDisabled);
    }
    validate_authorization(activation, permit, preflight, launch)?;

    let mut journal = ProductionCreateRuntimeJournal {
        schema_version: 1,
        journal_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        launch_id: launch.launch_id.clone(),
        create_intent_id: activation.create_intent_id.clone(),
        disk: activation.disk.clone(),
        partition_device: launch.partition_device.clone(),
        partition_table: partition_table_name(activation).into(),
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        phase: ProductionCreateRuntimePhase::Prepared,
        mutation_may_have_started: false,
        partition_table_may_have_changed: false,
        filesystem_may_have_changed: false,
        events: Vec::new(),
    };
    journal.journal_id = journal.expected_journal_id()?;
    validate_journal(&journal)?;
    Ok(journal)
}

pub fn persist_new_production_create_runtime_journal(
    store: &ProductionCreateRuntimeJournalStore,
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    launch: &ProductionCreateRuntimeLaunchSpec,
) -> Result<ProductionCreateRuntimeJournal, ProductionCreateRuntimeJournalError> {
    let journal = build_production_create_runtime_journal(activation, permit, preflight, launch)?;
    store.persist_new(&journal)?;
    Ok(journal)
}

fn transition_target(
    phase: ProductionCreateRuntimePhase,
    transition: ProductionCreateRuntimeTransition,
) -> Option<(ProductionCreateRuntimePhase, &'static str)> {
    use ProductionCreateRuntimePhase as P;
    use ProductionCreateRuntimeTransition as T;
    match (phase, transition) {
        (P::Prepared, T::BeginPartitionTableWrite) => {
            Some((P::WritingPartitionTable, "partition-table-write-started"))
        }
        (P::WritingPartitionTable, T::PartitionTableWriteSucceeded) => Some((
            P::PartitionTableWrittenAwaitingRediscovery,
            "partition-table-write-succeeded",
        )),
        (
            P::PartitionTableWrittenAwaitingRediscovery,
            T::PartitionRediscoveryVerified,
        ) => Some((P::PartitionMappedVerified, "partition-rediscovery-verified")),
        (P::PartitionMappedVerified, T::BeginFilesystemFormat) => {
            Some((P::FormattingFilesystem, "filesystem-format-started"))
        }
        (P::FormattingFilesystem, T::FilesystemFormatSucceeded) => Some((
            P::FilesystemFormattedAwaitingVerification,
            "filesystem-format-succeeded",
        )),
        (
            P::FilesystemFormattedAwaitingVerification,
            T::FilesystemRediscoveryVerified,
        ) => Some((P::Completed, "filesystem-rediscovery-verified")),
        (P::WritingPartitionTable, T::RecoveryRequired)
        | (P::PartitionTableWrittenAwaitingRediscovery, T::RecoveryRequired)
        | (P::PartitionMappedVerified, T::RecoveryRequired)
        | (P::FormattingFilesystem, T::RecoveryRequired)
        | (P::FilesystemFormattedAwaitingVerification, T::RecoveryRequired) => {
            Some((P::RecoveryRequired, "recovery-required"))
        }
        _ => None,
    }
}

fn apply_transition(
    journal: &mut ProductionCreateRuntimeJournal,
    transition: ProductionCreateRuntimeTransition,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    let from = journal.phase;
    let (phase, code) = transition_target(from, transition).ok_or(
        ProductionCreateRuntimeJournalError::InvalidTransition { from, transition },
    )?;

    journal.phase = phase;
    if matches!(
        transition,
        ProductionCreateRuntimeTransition::BeginPartitionTableWrite
    ) {
        journal.mutation_may_have_started = true;
        journal.partition_table_may_have_changed = true;
    }
    if matches!(
        transition,
        ProductionCreateRuntimeTransition::BeginFilesystemFormat
    ) {
        journal.filesystem_may_have_changed = true;
    }

    let sequence = journal.events.len() as u32 + 1;
    journal.events.push(ProductionCreateRuntimeJournalEvent {
        sequence,
        phase,
        code: code.into(),
    });
    validate_journal(journal)
}

/// Persist one typed create boundary before exposing the new in-memory state.
///
/// Crashes after the first mutation boundary therefore leave a durable phase
/// that requires explicit rediscovery/recovery instead of blind replay.
pub(crate) fn persist_production_create_runtime_transition(
    store: &ProductionCreateRuntimeJournalStore,
    journal: &mut ProductionCreateRuntimeJournal,
    transition: ProductionCreateRuntimeTransition,
) -> Result<(), ProductionCreateRuntimeJournalError> {
    let mut candidate = journal.clone();
    apply_transition(&mut candidate, transition)?;
    store.persist(&candidate)?;
    *journal = candidate;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn fixture_journal() -> ProductionCreateRuntimeJournal {
        let mut journal = ProductionCreateRuntimeJournal {
            schema_version: 1,
            journal_id: String::new(),
            activation_id: digest('a'),
            execution_permit_id: digest('b'),
            preflight_receipt_id: digest('c'),
            launch_id: digest('d'),
            create_intent_id: digest('e'),
            disk: "/dev/loop7".into(),
            partition_device: "/dev/loop7p1".into(),
            partition_table: "gpt".into(),
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            phase: ProductionCreateRuntimePhase::Prepared,
            mutation_may_have_started: false,
            partition_table_may_have_changed: false,
            filesystem_may_have_changed: false,
            events: Vec::new(),
        };
        journal.journal_id = journal.expected_journal_id().unwrap();
        journal
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lsm-create-journal-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn create_state_machine_requires_partition_rediscovery_before_mkfs() {
        let mut journal = fixture_journal();
        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::BeginPartitionTableWrite,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::PartitionTableWriteSucceeded,
        )
        .unwrap();

        assert!(matches!(
            apply_transition(
                &mut journal,
                ProductionCreateRuntimeTransition::BeginFilesystemFormat,
            ),
            Err(ProductionCreateRuntimeJournalError::InvalidTransition { .. })
        ));

        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::PartitionRediscoveryVerified,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::BeginFilesystemFormat,
        )
        .unwrap();
        assert!(journal.filesystem_may_have_changed);
    }

    #[test]
    fn durable_transition_updates_memory_only_after_persist() {
        let root = temp_root("persist");
        let store = ProductionCreateRuntimeJournalStore::at(&root);
        let mut journal = fixture_journal();
        store.persist_new(&journal).unwrap();

        persist_production_create_runtime_transition(
            &store,
            &mut journal,
            ProductionCreateRuntimeTransition::BeginPartitionTableWrite,
        )
        .unwrap();

        assert_eq!(journal.phase, ProductionCreateRuntimePhase::WritingPartitionTable);
        assert_eq!(
            store.load(&journal.journal_id).unwrap().phase,
            ProductionCreateRuntimePhase::WritingPartitionTable
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_is_available_only_after_mutation_boundary() {
        let mut journal = fixture_journal();
        assert!(apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::RecoveryRequired,
        )
        .is_err());

        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::BeginPartitionTableWrite,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreateRuntimeTransition::RecoveryRequired,
        )
        .unwrap();
        assert_eq!(journal.phase, ProductionCreateRuntimePhase::RecoveryRequired);
    }

    #[test]
    fn duplicate_new_journal_is_rejected() {
        let root = temp_root("duplicate");
        let store = ProductionCreateRuntimeJournalStore::at(&root);
        let journal = fixture_journal();
        store.persist_new(&journal).unwrap();
        assert!(matches!(
            store.persist_new(&journal),
            Err(ProductionCreateRuntimeJournalError::AlreadyExists(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_RUNTIME_JOURNAL_COMPILED,
            cfg!(feature = "production-create-runtime-journal")
        );
    }
}
