use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProductionSwapReplacementActivationIntent, ProductionSwapReplacementExecutionPermit,
    ProductionSwapRuntimeLaunchSpec, ProductionSwapRuntimePreflightReceipt,
};

pub const PRODUCTION_SWAP_RUNTIME_JOURNAL_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-runtime-journal");
pub const PRODUCTION_SWAP_RUNTIME_JOURNAL_DIRECTORY: &str =
    "/var/lib/linux-storage-manager/swap-runtime";
const MAX_SWAP_RUNTIME_JOURNAL_BYTES: u64 = 256 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSwapRuntimePhase {
    Prepared,
    SwapfileCreated,
    ReplacementFormatted,
    ReplacementActive,
    OldSwapDeactivated,
    PersistentConfigUpdated,
    PartitionsRemoved,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProductionSwapRuntimeTransition {
    SwapfileCreated,
    ReplacementFormatted,
    ReplacementActiveVerified,
    OldSwapDeactivatedVerified,
    PersistentConfigUpdatedVerified,
    PartitionsRemovedVerified,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSwapRuntimeJournalEvent {
    pub sequence: u64,
    pub from: ProductionSwapRuntimePhase,
    pub to: ProductionSwapRuntimePhase,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSwapRuntimeJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub preflight_receipt_id: String,
    pub launch_id: String,
    pub swap_replacement_intent_id: String,
    pub target: String,
    pub disk: String,
    pub retiring_swap_device: String,
    pub retiring_swap_bytes: u64,
    pub retiring_swap_priority: i32,
    pub swapfile_path: String,
    pub swapfile_mode: u32,
    pub phase: ProductionSwapRuntimePhase,
    pub mutation_may_have_started: bool,
    pub persistent_config_may_have_changed: bool,
    pub partition_table_may_have_changed: bool,
    pub events: Vec<ProductionSwapRuntimeJournalEvent>,
}

#[derive(Serialize)]
struct JournalIdPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    preflight_receipt_id: &'a str,
    launch_id: &'a str,
    swap_replacement_intent_id: &'a str,
    target: &'a str,
    disk: &'a str,
    retiring_swap_device: &'a str,
    retiring_swap_bytes: u64,
    retiring_swap_priority: i32,
    swapfile_path: &'a str,
    swapfile_mode: u32,
}

impl ProductionSwapRuntimeJournal {
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
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            target: &self.target,
            disk: &self.disk,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_bytes: self.retiring_swap_bytes,
            retiring_swap_priority: self.retiring_swap_priority,
            swapfile_path: &self.swapfile_path,
            swapfile_mode: self.swapfile_mode,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ProductionSwapRuntimeJournalStore {
    root: PathBuf,
}

impl Default for ProductionSwapRuntimeJournalStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from(PRODUCTION_SWAP_RUNTIME_JOURNAL_DIRECTORY),
        }
    }
}

impl ProductionSwapRuntimeJournalStore {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn persist_new(
        &self,
        journal: &ProductionSwapRuntimeJournal,
    ) -> Result<PathBuf, ProductionSwapRuntimeJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let bytes = encode_journal(journal)?;
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
                    return Err(ProductionSwapRuntimeJournalError::AlreadyExists(
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

    pub(crate) fn persist(
        &self,
        journal: &ProductionSwapRuntimeJournal,
    ) -> Result<PathBuf, ProductionSwapRuntimeJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let bytes = encode_journal(journal)?;
        let final_path = self.path_for(&journal.journal_id)?;

        match fs::symlink_metadata(&final_path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(ProductionSwapRuntimeJournalError::NotRegularFile(
                        final_path,
                    ));
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(ProductionSwapRuntimeJournalError::NotFound(
                    journal.journal_id.clone(),
                ));
            }
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

    pub fn load(
        &self,
        journal_id: &str,
    ) -> Result<ProductionSwapRuntimeJournal, ProductionSwapRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
        ensure_secure_directory(&self.root, false)?;
        let path = self.path_for(journal_id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(ProductionSwapRuntimeJournalError::NotFound(
                    journal_id.to_owned(),
                ));
            }
            Err(source) => return Err(io_error(&path, source)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProductionSwapRuntimeJournalError::NotRegularFile(path));
        }
        if metadata.len() > MAX_SWAP_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionSwapRuntimeJournalError::TooLarge);
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let mut bytes = Vec::new();
        file.take(MAX_SWAP_RUNTIME_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(&path, source))?;
        if bytes.len() as u64 > MAX_SWAP_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionSwapRuntimeJournalError::TooLarge);
        }

        let journal: ProductionSwapRuntimeJournal = serde_json::from_slice(&bytes)?;
        if journal.journal_id != journal_id {
            return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
                "journal ID does not match requested record".into(),
            ));
        }
        validate_journal(&journal)?;
        Ok(journal)
    }

    fn path_for(&self, journal_id: &str) -> Result<PathBuf, ProductionSwapRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
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

#[derive(Debug, Error)]
pub enum ProductionSwapRuntimeJournalError {
    #[error("production swap runtime journal feature is not compiled")]
    FeatureDisabled,
    #[error("swap runtime authorization/launch integrity is invalid")]
    AuthorizationInvalid,
    #[error("swap runtime authorization/launch bindings do not match")]
    BindingMismatch,
    #[error("swap runtime journal record is structurally invalid: {0}")]
    InvalidRecord(String),
    #[error("swap runtime journal transition is invalid from {from:?} to {to:?}")]
    InvalidTransition {
        from: ProductionSwapRuntimePhase,
        to: ProductionSwapRuntimePhase,
    },
    #[error("swap runtime journal already exists: {0}")]
    AlreadyExists(String),
    #[error("swap runtime journal does not exist: {0}")]
    NotFound(String),
    #[error("swap runtime journal path is not a regular file: {0}")]
    NotRegularFile(PathBuf),
    #[error("swap runtime journal directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("swap runtime journal exceeds maximum record size")]
    TooLarge,
    #[error("swap runtime journal JSON is invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("swap runtime journal I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn validate_authorization(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    launch: &ProductionSwapRuntimeLaunchSpec,
) -> Result<(), ProductionSwapRuntimeJournalError> {
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
        || launch.swapfile_created
    {
        return Err(ProductionSwapRuntimeJournalError::AuthorizationInvalid);
    }

    if permit.activation_id != activation.activation_id
        || preflight.activation_id != activation.activation_id
        || launch.activation_id != activation.activation_id
        || preflight.execution_permit_id != permit.permit_id
        || launch.execution_permit_id != permit.permit_id
        || launch.preflight_receipt_id != preflight.receipt_id
        || permit.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || preflight.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || launch.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || launch.swapfile.path != activation.swapfile_path
        || launch.swapfile.size_bytes != activation.retiring_swap_bytes
        || launch.swapfile.mode != activation.swapfile_mode
        || !launch.swapfile.create_new
        || !launch.swapfile.no_follow
        || !launch.swapfile.fully_allocate
        || !launch.require_dual_active_verification_before_swapoff
    {
        return Err(ProductionSwapRuntimeJournalError::BindingMismatch);
    }
    Ok(())
}

/// Create the exact durable state machine that must exist before a future
/// production swap runtime crossing. No file or swap state is changed here.
pub fn build_production_swap_runtime_journal(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    launch: &ProductionSwapRuntimeLaunchSpec,
) -> Result<ProductionSwapRuntimeJournal, ProductionSwapRuntimeJournalError> {
    if !PRODUCTION_SWAP_RUNTIME_JOURNAL_COMPILED {
        return Err(ProductionSwapRuntimeJournalError::FeatureDisabled);
    }
    validate_authorization(activation, permit, preflight, launch)?;

    let mut journal = ProductionSwapRuntimeJournal {
        schema_version: 1,
        journal_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        launch_id: launch.launch_id.clone(),
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        target: activation.target.clone(),
        disk: activation.disk.clone(),
        retiring_swap_device: activation.retiring_swap_device.clone(),
        retiring_swap_bytes: activation.retiring_swap_bytes,
        retiring_swap_priority: activation.retiring_swap_priority,
        swapfile_path: activation.swapfile_path.clone(),
        swapfile_mode: activation.swapfile_mode,
        phase: ProductionSwapRuntimePhase::Prepared,
        mutation_may_have_started: false,
        persistent_config_may_have_changed: false,
        partition_table_may_have_changed: false,
        events: Vec::new(),
    };
    journal.journal_id = journal.expected_journal_id()?;
    validate_journal(&journal)?;
    Ok(journal)
}

pub fn persist_new_production_swap_runtime_journal(
    store: &ProductionSwapRuntimeJournalStore,
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    launch: &ProductionSwapRuntimeLaunchSpec,
) -> Result<ProductionSwapRuntimeJournal, ProductionSwapRuntimeJournalError> {
    let journal = build_production_swap_runtime_journal(activation, permit, preflight, launch)?;
    store.persist_new(&journal)?;
    Ok(journal)
}

/// Persist a typed runtime boundary. The in-memory journal is changed only
/// after the candidate state has been fsync-persisted successfully.
pub(crate) fn persist_production_swap_runtime_transition(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    transition: ProductionSwapRuntimeTransition,
) -> Result<(), ProductionSwapRuntimeJournalError> {
    let mut candidate = journal.clone();
    apply_transition(&mut candidate, transition)?;
    store.persist(&candidate)?;
    *journal = candidate;
    Ok(())
}

fn transition_target(
    phase: ProductionSwapRuntimePhase,
    transition: ProductionSwapRuntimeTransition,
) -> Option<(ProductionSwapRuntimePhase, &'static str)> {
    use ProductionSwapRuntimePhase as P;
    use ProductionSwapRuntimeTransition as T;

    match (phase, transition) {
        (P::Prepared, T::SwapfileCreated) => Some((P::SwapfileCreated, "swapfile-created")),
        (P::SwapfileCreated, T::ReplacementFormatted) => {
            Some((P::ReplacementFormatted, "replacement-formatted"))
        }
        (P::ReplacementFormatted, T::ReplacementActiveVerified) => {
            Some((P::ReplacementActive, "replacement-active-verified"))
        }
        (P::ReplacementActive, T::OldSwapDeactivatedVerified) => {
            Some((P::OldSwapDeactivated, "old-swap-deactivated-verified"))
        }
        (P::OldSwapDeactivated, T::PersistentConfigUpdatedVerified) => {
            Some((P::PersistentConfigUpdated, "persistent-config-updated-verified"))
        }
        (P::PersistentConfigUpdated, T::PartitionsRemovedVerified) => {
            Some((P::PartitionsRemoved, "partitions-removed-verified"))
        }
        (P::PartitionsRemoved, T::Completed) => Some((P::Completed, "completed")),
        (
            P::SwapfileCreated
            | P::ReplacementFormatted
            | P::ReplacementActive
            | P::OldSwapDeactivated
            | P::PersistentConfigUpdated
            | P::PartitionsRemoved,
            T::RecoveryRequired,
        ) => Some((P::RecoveryRequired, "recovery-required")),
        _ => None,
    }
}

fn apply_transition(
    journal: &mut ProductionSwapRuntimeJournal,
    transition: ProductionSwapRuntimeTransition,
) -> Result<(), ProductionSwapRuntimeJournalError> {
    validate_journal(journal)?;
    let from = journal.phase;
    let Some((to, code)) = transition_target(from, transition) else {
        return Err(ProductionSwapRuntimeJournalError::InvalidTransition {
            from,
            to: transition_phase_hint(transition),
        });
    };

    journal.events.push(ProductionSwapRuntimeJournalEvent {
        sequence: journal.events.len() as u64 + 1,
        from,
        to,
        code: code.to_owned(),
    });
    journal.phase = to;
    recompute_flags(journal);
    validate_journal(journal)
}

fn transition_phase_hint(transition: ProductionSwapRuntimeTransition) -> ProductionSwapRuntimePhase {
    use ProductionSwapRuntimePhase as P;
    use ProductionSwapRuntimeTransition as T;
    match transition {
        T::SwapfileCreated => P::SwapfileCreated,
        T::ReplacementFormatted => P::ReplacementFormatted,
        T::ReplacementActiveVerified => P::ReplacementActive,
        T::OldSwapDeactivatedVerified => P::OldSwapDeactivated,
        T::PersistentConfigUpdatedVerified => P::PersistentConfigUpdated,
        T::PartitionsRemovedVerified => P::PartitionsRemoved,
        T::Completed => P::Completed,
        T::RecoveryRequired => P::RecoveryRequired,
    }
}

fn recompute_flags(journal: &mut ProductionSwapRuntimeJournal) {
    journal.mutation_may_have_started = !journal.events.is_empty();
    journal.persistent_config_may_have_changed = journal.events.iter().any(|event| {
        matches!(
            event.to,
            ProductionSwapRuntimePhase::PersistentConfigUpdated
                | ProductionSwapRuntimePhase::PartitionsRemoved
                | ProductionSwapRuntimePhase::Completed
        )
    });
    journal.partition_table_may_have_changed = journal.events.iter().any(|event| {
        matches!(
            event.to,
            ProductionSwapRuntimePhase::PartitionsRemoved | ProductionSwapRuntimePhase::Completed
        )
    });
}

fn validate_journal(
    journal: &ProductionSwapRuntimeJournal,
) -> Result<(), ProductionSwapRuntimeJournalError> {
    if journal.schema_version != 1 {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "unsupported schema version".into(),
        ));
    }
    validate_digest(&journal.journal_id, "journal ID")?;
    for (value, label) in [
        (journal.activation_id.as_str(), "activation ID"),
        (journal.execution_permit_id.as_str(), "execution permit ID"),
        (journal.preflight_receipt_id.as_str(), "preflight receipt ID"),
        (journal.launch_id.as_str(), "launch ID"),
        (
            journal.swap_replacement_intent_id.as_str(),
            "swap replacement intent ID",
        ),
    ] {
        validate_digest(value, label)?;
    }
    for (value, label) in [
        (journal.target.as_str(), "target"),
        (journal.disk.as_str(), "disk"),
        (journal.retiring_swap_device.as_str(), "retiring swap device"),
        (journal.swapfile_path.as_str(), "swapfile path"),
    ] {
        if value.is_empty()
            || !value.starts_with('/')
            || value.chars().any(char::is_control)
            || value.as_bytes().contains(&0)
        {
            return Err(ProductionSwapRuntimeJournalError::InvalidRecord(format!(
                "{label} is not a safe absolute path"
            )));
        }
    }
    if journal.retiring_swap_bytes == 0 || journal.swapfile_mode != 0o600 {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "swap size/mode binding is invalid".into(),
        ));
    }
    if !journal.integrity_matches()? {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "journal immutable binding digest does not match contents".into(),
        ));
    }

    let mut phase = ProductionSwapRuntimePhase::Prepared;
    for (index, event) in journal.events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.from != phase
            || event.code.is_empty()
            || event.code.chars().any(char::is_control)
        {
            return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
                "journal event chain is invalid".into(),
            ));
        }
        let allowed = match (event.from, event.to, event.code.as_str()) {
            (ProductionSwapRuntimePhase::Prepared, ProductionSwapRuntimePhase::SwapfileCreated, "swapfile-created") => true,
            (ProductionSwapRuntimePhase::SwapfileCreated, ProductionSwapRuntimePhase::ReplacementFormatted, "replacement-formatted") => true,
            (ProductionSwapRuntimePhase::ReplacementFormatted, ProductionSwapRuntimePhase::ReplacementActive, "replacement-active-verified") => true,
            (ProductionSwapRuntimePhase::ReplacementActive, ProductionSwapRuntimePhase::OldSwapDeactivated, "old-swap-deactivated-verified") => true,
            (ProductionSwapRuntimePhase::OldSwapDeactivated, ProductionSwapRuntimePhase::PersistentConfigUpdated, "persistent-config-updated-verified") => true,
            (ProductionSwapRuntimePhase::PersistentConfigUpdated, ProductionSwapRuntimePhase::PartitionsRemoved, "partitions-removed-verified") => true,
            (ProductionSwapRuntimePhase::PartitionsRemoved, ProductionSwapRuntimePhase::Completed, "completed") => true,
            (
                ProductionSwapRuntimePhase::SwapfileCreated
                | ProductionSwapRuntimePhase::ReplacementFormatted
                | ProductionSwapRuntimePhase::ReplacementActive
                | ProductionSwapRuntimePhase::OldSwapDeactivated
                | ProductionSwapRuntimePhase::PersistentConfigUpdated
                | ProductionSwapRuntimePhase::PartitionsRemoved,
                ProductionSwapRuntimePhase::RecoveryRequired,
                "recovery-required",
            ) => true,
            _ => false,
        };
        if !allowed {
            return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
                "journal contains an impossible transition".into(),
            ));
        }
        phase = event.to;
    }
    if phase != journal.phase {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "journal phase does not match event chain".into(),
        ));
    }
    if matches!(
        journal.phase,
        ProductionSwapRuntimePhase::Completed | ProductionSwapRuntimePhase::RecoveryRequired
    ) && journal.events.is_empty()
    {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "terminal phase cannot exist before a runtime boundary".into(),
        ));
    }

    let mutation_expected = !journal.events.is_empty();
    let persistent_expected = journal.events.iter().any(|event| {
        matches!(
            event.to,
            ProductionSwapRuntimePhase::PersistentConfigUpdated
                | ProductionSwapRuntimePhase::PartitionsRemoved
                | ProductionSwapRuntimePhase::Completed
        )
    });
    let partition_expected = journal.events.iter().any(|event| {
        matches!(
            event.to,
            ProductionSwapRuntimePhase::PartitionsRemoved | ProductionSwapRuntimePhase::Completed
        )
    });
    if journal.mutation_may_have_started != mutation_expected
        || journal.persistent_config_may_have_changed != persistent_expected
        || journal.partition_table_may_have_changed != partition_expected
    {
        return Err(ProductionSwapRuntimeJournalError::InvalidRecord(
            "journal risk flags do not match the durable event chain".into(),
        ));
    }

    Ok(())
}

fn encode_journal(
    journal: &ProductionSwapRuntimeJournal,
) -> Result<Vec<u8>, ProductionSwapRuntimeJournalError> {
    let bytes = serde_json::to_vec(journal)?;
    if bytes.len() as u64 > MAX_SWAP_RUNTIME_JOURNAL_BYTES {
        return Err(ProductionSwapRuntimeJournalError::TooLarge);
    }
    Ok(bytes)
}

fn validate_digest(value: &str, label: &str) -> Result<(), ProductionSwapRuntimeJournalError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ProductionSwapRuntimeJournalError::InvalidRecord(format!(
            "{label} is not a lowercase SHA-256 digest"
        )))
    }
}

fn ensure_secure_directory(
    path: &Path,
    create: bool,
) -> Result<(), ProductionSwapRuntimeJournalError> {
    if !path.is_absolute() {
        return Err(ProductionSwapRuntimeJournalError::UnsafeDirectory(
            path.to_path_buf(),
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                continue;
            }
            Component::Normal(part) => current.push(part),
            _ => {
                return Err(ProductionSwapRuntimeJournalError::UnsafeDirectory(
                    path.to_path_buf(),
                ))
            }
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProductionSwapRuntimeJournalError::UnsafeDirectory(current));
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
                    return Err(ProductionSwapRuntimeJournalError::UnsafeDirectory(current));
                }
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProductionSwapRuntimeJournalError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: io::Error) -> ProductionSwapRuntimeJournalError {
    ProductionSwapRuntimeJournalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn fixture_journal() -> ProductionSwapRuntimeJournal {
        let mut journal = ProductionSwapRuntimeJournal {
            schema_version: 1,
            journal_id: String::new(),
            activation_id: digest('a'),
            execution_permit_id: digest('b'),
            preflight_receipt_id: digest('c'),
            launch_id: digest('d'),
            swap_replacement_intent_id: digest('e'),
            target: "/data".into(),
            disk: "/dev/loop7".into(),
            retiring_swap_device: "/dev/loop7p5".into(),
            retiring_swap_bytes: 64 * 1024 * 1024,
            retiring_swap_priority: 7,
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            swapfile_mode: 0o600,
            phase: ProductionSwapRuntimePhase::Prepared,
            mutation_may_have_started: false,
            persistent_config_may_have_changed: false,
            partition_table_may_have_changed: false,
            events: vec![],
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
            "lsm-swap-runtime-journal-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn prepared_journal_round_trips_durably() {
        let root = temp_root("roundtrip");
        let store = ProductionSwapRuntimeJournalStore::at(&root);
        let journal = fixture_journal();
        store.persist_new(&journal).unwrap();

        let loaded = store.load(&journal.journal_id).unwrap();
        assert_eq!(loaded, journal);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transitions_are_strict_and_risk_flags_are_monotonic() {
        let mut journal = fixture_journal();
        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::SwapfileCreated,
        )
        .unwrap();
        assert!(journal.mutation_may_have_started);
        assert!(!journal.persistent_config_may_have_changed);
        assert!(!journal.partition_table_may_have_changed);

        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::ReplacementFormatted,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::ReplacementActiveVerified,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::OldSwapDeactivatedVerified,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::PersistentConfigUpdatedVerified,
        )
        .unwrap();
        assert!(journal.persistent_config_may_have_changed);
        assert!(!journal.partition_table_may_have_changed);

        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::PartitionsRemovedVerified,
        )
        .unwrap();
        assert!(journal.partition_table_may_have_changed);
        apply_transition(&mut journal, ProductionSwapRuntimeTransition::Completed).unwrap();
        assert_eq!(journal.phase, ProductionSwapRuntimePhase::Completed);
    }

    #[test]
    fn skipped_runtime_boundary_is_rejected() {
        let mut journal = fixture_journal();
        assert!(matches!(
            apply_transition(
                &mut journal,
                ProductionSwapRuntimeTransition::ReplacementActiveVerified
            ),
            Err(ProductionSwapRuntimeJournalError::InvalidTransition { .. })
        ));
        assert_eq!(journal.phase, ProductionSwapRuntimePhase::Prepared);
        assert!(journal.events.is_empty());
    }

    #[test]
    fn recovery_after_replacement_activation_preserves_precise_risk_scope() {
        let mut journal = fixture_journal();
        for transition in [
            ProductionSwapRuntimeTransition::SwapfileCreated,
            ProductionSwapRuntimeTransition::ReplacementFormatted,
            ProductionSwapRuntimeTransition::ReplacementActiveVerified,
        ] {
            apply_transition(&mut journal, transition).unwrap();
        }
        apply_transition(
            &mut journal,
            ProductionSwapRuntimeTransition::RecoveryRequired,
        )
        .unwrap();

        assert_eq!(journal.phase, ProductionSwapRuntimePhase::RecoveryRequired);
        assert!(journal.mutation_may_have_started);
        assert!(!journal.persistent_config_may_have_changed);
        assert!(!journal.partition_table_may_have_changed);
    }

    #[test]
    fn persist_transition_updates_memory_only_after_durable_write() {
        let root = temp_root("persist-transition");
        let store = ProductionSwapRuntimeJournalStore::at(&root);
        let mut journal = fixture_journal();
        store.persist_new(&journal).unwrap();

        persist_production_swap_runtime_transition(
            &store,
            &mut journal,
            ProductionSwapRuntimeTransition::SwapfileCreated,
        )
        .unwrap();
        assert_eq!(journal.phase, ProductionSwapRuntimePhase::SwapfileCreated);
        assert_eq!(
            store.load(&journal.journal_id).unwrap().phase,
            ProductionSwapRuntimePhase::SwapfileCreated
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn symlink_journal_record_is_rejected() {
        let root = temp_root("symlink");
        fs::create_dir_all(&root).unwrap();
        let store = ProductionSwapRuntimeJournalStore::at(&root);
        let journal = fixture_journal();
        let target = root.join("real.json");
        fs::write(&target, b"{}").unwrap();
        let link = root.join(format!("{}.json", journal.journal_id));
        symlink(&target, &link).unwrap();

        assert!(matches!(
            store.load(&journal.journal_id),
            Err(ProductionSwapRuntimeJournalError::NotRegularFile(_))
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn default_build_keeps_swap_runtime_journal_disabled() {
        assert_eq!(
            PRODUCTION_SWAP_RUNTIME_JOURNAL_COMPILED,
            cfg!(feature = "production-swap-replacement-runtime-journal")
        );
    }
}
