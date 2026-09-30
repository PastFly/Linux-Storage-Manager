use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProductionCreateActivationIntent, ProductionCreateMountActivationIntent,
    ProductionCreateMountRuntimeExecutionReceipt, ProductionCreateMountRuntimeJournal,
    ProductionCreateMountRuntimePhase,
};

pub const PRODUCTION_CREATE_PERSISTENT_CONFIG_JOURNAL_COMPILED: bool =
    cfg!(feature = "production-create-persistent-config-journal");
pub const PRODUCTION_CREATE_PERSISTENT_CONFIG_JOURNAL_DIRECTORY: &str =
    "/var/lib/linux-storage-manager/create-persistent-config";
const MAX_PERSISTENT_CONFIG_JOURNAL_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionCreatePersistentConfigPhase {
    Prepared,
    UpdatingFstab,
    FstabWrittenAwaitingVerification,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionCreatePersistentConfigTransition {
    BeginPersistentConfigUpdate,
    PersistentConfigWriteSucceeded,
    PersistentConfigRediscoveryVerified,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreatePersistentConfigJournalEvent {
    pub sequence: u32,
    pub from: ProductionCreatePersistentConfigPhase,
    pub to: ProductionCreatePersistentConfigPhase,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreatePersistentConfigJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub mount_activation_id: String,
    pub mount_execution_receipt_id: String,
    pub mount_runtime_journal_id: String,
    pub create_activation_id: String,
    pub disk: String,
    pub partition_device: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub mountpoint: String,
    pub fstab_source: String,
    pub fstab_options: Vec<String>,
    pub fstab_dump: u32,
    pub fstab_pass: u32,
    pub phase: ProductionCreatePersistentConfigPhase,
    pub mutation_may_have_started: bool,
    pub persistent_config_may_have_changed: bool,
    pub events: Vec<ProductionCreatePersistentConfigJournalEvent>,
}

#[derive(Serialize)]
struct JournalIdPayload<'a> {
    schema_version: u32,
    mount_activation_id: &'a str,
    mount_execution_receipt_id: &'a str,
    mount_runtime_journal_id: &'a str,
    create_activation_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    filesystem: &'a str,
    filesystem_uuid: &'a str,
    mountpoint: &'a str,
    fstab_source: &'a str,
    fstab_options: &'a [String],
    fstab_dump: u32,
    fstab_pass: u32,
}

impl ProductionCreatePersistentConfigJournal {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.journal_id == self.expected_journal_id()?)
    }

    fn expected_journal_id(&self) -> Result<String, serde_json::Error> {
        let payload = JournalIdPayload {
            schema_version: self.schema_version,
            mount_activation_id: &self.mount_activation_id,
            mount_execution_receipt_id: &self.mount_execution_receipt_id,
            mount_runtime_journal_id: &self.mount_runtime_journal_id,
            create_activation_id: &self.create_activation_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            filesystem: &self.filesystem,
            filesystem_uuid: &self.filesystem_uuid,
            mountpoint: &self.mountpoint,
            fstab_source: &self.fstab_source,
            fstab_options: &self.fstab_options,
            fstab_dump: self.fstab_dump,
            fstab_pass: self.fstab_pass,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ProductionCreatePersistentConfigJournalStore {
    root: PathBuf,
}

impl Default for ProductionCreatePersistentConfigJournalStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from(PRODUCTION_CREATE_PERSISTENT_CONFIG_JOURNAL_DIRECTORY),
        }
    }
}

impl ProductionCreatePersistentConfigJournalStore {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(
        &self,
        journal_id: &str,
    ) -> Result<ProductionCreatePersistentConfigJournal, ProductionCreatePersistentConfigJournalError>
    {
        validate_digest(journal_id, "journal ID")?;
        ensure_secure_directory(&self.root, false)?;
        let path = self.path_for(journal_id)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        validate_journal_file_metadata(&path, &metadata)?;
        if metadata.len() > MAX_PERSISTENT_CONFIG_JOURNAL_BYTES {
            return Err(ProductionCreatePersistentConfigJournalError::TooLarge);
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let mut bytes = Vec::new();
        file.take(MAX_PERSISTENT_CONFIG_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(&path, source))?;
        if bytes.len() as u64 > MAX_PERSISTENT_CONFIG_JOURNAL_BYTES {
            return Err(ProductionCreatePersistentConfigJournalError::TooLarge);
        }

        let journal: ProductionCreatePersistentConfigJournal = serde_json::from_slice(&bytes)?;
        if journal.journal_id != journal_id {
            return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
                "journal ID does not match requested durable record".into(),
            ));
        }
        validate_journal(&journal)?;
        Ok(journal)
    }

    fn persist_new(
        &self,
        journal: &ProductionCreatePersistentConfigJournal,
    ) -> Result<PathBuf, ProductionCreatePersistentConfigJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let final_path = self.path_for(&journal.journal_id)?;
        if final_path.exists() {
            return Err(ProductionCreatePersistentConfigJournalError::AlreadyExists(
                journal.journal_id.clone(),
            ));
        }
        write_atomic_new(&self.root, &final_path, journal)?;
        Ok(final_path)
    }

    fn persist(
        &self,
        journal: &ProductionCreatePersistentConfigJournal,
    ) -> Result<PathBuf, ProductionCreatePersistentConfigJournalError> {
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
    ) -> Result<PathBuf, ProductionCreatePersistentConfigJournalError> {
        validate_digest(journal_id, "journal ID")?;
        Ok(self.root.join(format!("{journal_id}.json")))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreatePersistentConfigJournalError {
    #[error("production create persistent-config journal feature is not compiled")]
    FeatureDisabled,
    #[error("completed mount authorization/receipt/journal chain is invalid")]
    AuthorizationInvalid,
    #[error("persistent-config journal bindings do not match the completed mount scope")]
    BindingMismatch,
    #[error("persistent-config journal record is structurally invalid: {0}")]
    InvalidRecord(String),
    #[error("persistent-config journal transition is invalid from {from:?} via {transition:?}")]
    InvalidTransition {
        from: ProductionCreatePersistentConfigPhase,
        transition: ProductionCreatePersistentConfigTransition,
    },
    #[error("persistent-config journal already exists: {0}")]
    AlreadyExists(String),
    #[error("persistent-config journal path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("persistent-config journal directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("persistent-config journal exceeds maximum record size")]
    TooLarge,
    #[error("persistent-config journal JSON is invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("persistent-config journal I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> ProductionCreatePersistentConfigJournalError {
    ProductionCreatePersistentConfigJournalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_digest(
    value: &str,
    label: &str,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
            format!("{label} is not a lowercase SHA-256 hex digest"),
        ));
    }
    Ok(())
}

fn ensure_secure_directory(
    root: &Path,
    create: bool,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(
                    ProductionCreatePersistentConfigJournalError::UnsafeDirectory(
                        root.to_path_buf(),
                    ),
                );
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound && create => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(root)
                .map_err(|source| io_error(root, source))?;
            sync_directory(root)?;
        }
        Err(source) => return Err(io_error(root, source)),
    }
    Ok(())
}

fn validate_journal_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProductionCreatePersistentConfigJournalError::UnsafePath(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn temp_path(
    root: &Path,
    final_path: &Path,
) -> Result<PathBuf, ProductionCreatePersistentConfigJournalError> {
    let name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ProductionCreatePersistentConfigJournalError::UnsafePath(final_path.to_path_buf())
        })?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(".{name}.tmp-{}-{sequence}", std::process::id())))
}

fn encode_journal(
    journal: &ProductionCreatePersistentConfigJournal,
) -> Result<Vec<u8>, ProductionCreatePersistentConfigJournalError> {
    let mut bytes = serde_json::to_vec(journal)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_PERSISTENT_CONFIG_JOURNAL_BYTES {
        return Err(ProductionCreatePersistentConfigJournalError::TooLarge);
    }
    Ok(bytes)
}

fn write_atomic_new(
    root: &Path,
    final_path: &Path,
    journal: &ProductionCreatePersistentConfigJournal,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
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
                return Err(ProductionCreatePersistentConfigJournalError::AlreadyExists(
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
    journal: &ProductionCreatePersistentConfigJournal,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
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
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_journal: &ProductionCreateMountRuntimeJournal,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    let expected_source = format!("UUID={}", activation.filesystem_uuid);
    let expected_pass = if activation.filesystem == "ext4" { 2 } else { 0 };
    if create.schema_version != 1
        || activation.schema_version != 1
        || receipt.schema_version != 1
        || mount_journal.schema_version != 1
        || !create.integrity_matches().unwrap_or(false)
        || !activation.integrity_matches().unwrap_or(false)
        || !receipt.integrity_matches().unwrap_or(false)
        || !mount_journal.integrity_matches().unwrap_or(false)
        || !activation.persist_to_fstab
        || activation.execution_enabled
        || activation.mount_performed
        || activation.fstab_changed
        || !receipt.mounted_verified
        || receipt.fstab_changed
        || mount_journal.phase != ProductionCreateMountRuntimePhase::Completed
        || !mount_journal.mutation_may_have_started
        || !mount_journal.mount_may_have_changed
        || mount_journal.fstab_may_have_changed
        || activation.create_activation_id != create.activation_id
        || receipt.mount_activation_id != activation.mount_activation_id
        || receipt.mount_journal_id != mount_journal.journal_id
        || receipt.mount_launch_id != mount_journal.launch_id
        || mount_journal.mount_activation_id != activation.mount_activation_id
        || mount_journal.create_activation_id != create.activation_id
        || mount_journal.disk != create.disk
        || mount_journal.disk != activation.disk
        || mount_journal.partition_device != activation.partition_device
        || mount_journal.filesystem != activation.filesystem
        || !mount_journal
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || mount_journal.mountpoint != activation.mountpoint
        || receipt.partition_device != activation.partition_device
        || receipt.filesystem != activation.filesystem
        || !receipt
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || receipt.mountpoint != activation.mountpoint
        || activation.fstab_source != expected_source
        || activation.fstab_options != ["defaults".to_owned(), "nofail".to_owned()]
        || activation.fstab_dump != 0
        || activation.fstab_pass != expected_pass
    {
        return Err(ProductionCreatePersistentConfigJournalError::AuthorizationInvalid);
    }
    Ok(())
}

fn validate_journal(
    journal: &ProductionCreatePersistentConfigJournal,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    if journal.schema_version != 1
        || !journal.integrity_matches().unwrap_or(false)
        || !journal.disk.starts_with("/dev/")
        || !journal.partition_device.starts_with("/dev/")
        || !matches!(journal.filesystem.as_str(), "ext4" | "xfs")
        || journal.filesystem_uuid.is_empty()
        || journal.mountpoint.is_empty()
        || !journal.mountpoint.starts_with('/')
        || journal.fstab_source != format!("UUID={}", journal.filesystem_uuid)
        || journal.fstab_options != ["defaults".to_owned(), "nofail".to_owned()]
        || journal.fstab_dump != 0
        || journal.fstab_pass != if journal.filesystem == "ext4" { 2 } else { 0 }
    {
        return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
            "journal identity or frozen persistent-config scope is invalid".into(),
        ));
    }

    for (value, label) in [
        (journal.mount_activation_id.as_str(), "mount activation ID"),
        (
            journal.mount_execution_receipt_id.as_str(),
            "mount execution receipt ID",
        ),
        (
            journal.mount_runtime_journal_id.as_str(),
            "mount runtime journal ID",
        ),
        (journal.create_activation_id.as_str(), "create activation ID"),
    ] {
        validate_digest(value, label)?;
    }

    let mut phase = ProductionCreatePersistentConfigPhase::Prepared;
    for (index, event) in journal.events.iter().enumerate() {
        if event.sequence != index as u32 + 1 || event.from != phase {
            return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
                "journal event sequence or phase chain is invalid".into(),
            ));
        }
        let Some((expected_to, expected_code)) =
            transition_target_for_validation(event.from, event.to)
        else {
            return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
                "journal event contains an impossible phase transition".into(),
            ));
        };
        if expected_to != event.to || expected_code != event.code {
            return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
                "journal event code does not match its phase transition".into(),
            ));
        }
        phase = event.to;
    }
    if phase != journal.phase {
        return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
            "journal phase does not match its event chain".into(),
        ));
    }

    let mutation_expected =
        !matches!(journal.phase, ProductionCreatePersistentConfigPhase::Prepared);
    if journal.mutation_may_have_started != mutation_expected
        || journal.persistent_config_may_have_changed != mutation_expected
    {
        return Err(ProductionCreatePersistentConfigJournalError::InvalidRecord(
            "persistent-config mutation flags do not match durable phase".into(),
        ));
    }
    Ok(())
}

fn transition_target_for_validation(
    from: ProductionCreatePersistentConfigPhase,
    to: ProductionCreatePersistentConfigPhase,
) -> Option<(ProductionCreatePersistentConfigPhase, &'static str)> {
    use ProductionCreatePersistentConfigPhase as P;
    match (from, to) {
        (P::Prepared, P::UpdatingFstab) => {
            Some((P::UpdatingFstab, "persistent-config-update-started"))
        }
        (P::UpdatingFstab, P::FstabWrittenAwaitingVerification) => Some((
            P::FstabWrittenAwaitingVerification,
            "persistent-config-write-succeeded",
        )),
        (P::FstabWrittenAwaitingVerification, P::Completed) => {
            Some((P::Completed, "persistent-config-rediscovery-verified"))
        }
        (P::UpdatingFstab, P::RecoveryRequired)
        | (P::FstabWrittenAwaitingVerification, P::RecoveryRequired) => {
            Some((P::RecoveryRequired, "recovery-required"))
        }
        _ => None,
    }
}

fn transition_target(
    phase: ProductionCreatePersistentConfigPhase,
    transition: ProductionCreatePersistentConfigTransition,
) -> Option<(ProductionCreatePersistentConfigPhase, &'static str)> {
    use ProductionCreatePersistentConfigPhase as P;
    use ProductionCreatePersistentConfigTransition as T;
    match (phase, transition) {
        (P::Prepared, T::BeginPersistentConfigUpdate) => {
            Some((P::UpdatingFstab, "persistent-config-update-started"))
        }
        (P::UpdatingFstab, T::PersistentConfigWriteSucceeded) => Some((
            P::FstabWrittenAwaitingVerification,
            "persistent-config-write-succeeded",
        )),
        (P::FstabWrittenAwaitingVerification, T::PersistentConfigRediscoveryVerified) => {
            Some((P::Completed, "persistent-config-rediscovery-verified"))
        }
        (P::UpdatingFstab, T::RecoveryRequired)
        | (P::FstabWrittenAwaitingVerification, T::RecoveryRequired) => {
            Some((P::RecoveryRequired, "recovery-required"))
        }
        _ => None,
    }
}

fn apply_transition(
    journal: &mut ProductionCreatePersistentConfigJournal,
    transition: ProductionCreatePersistentConfigTransition,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
    let from = journal.phase;
    let (to, code) = transition_target(from, transition)
        .ok_or(ProductionCreatePersistentConfigJournalError::InvalidTransition {
            from,
            transition,
        })?;
    journal.phase = to;
    journal.mutation_may_have_started = true;
    journal.persistent_config_may_have_changed = true;
    journal
        .events
        .push(ProductionCreatePersistentConfigJournalEvent {
            sequence: journal.events.len() as u32 + 1,
            from,
            to,
            code: code.into(),
        });
    validate_journal(journal)
}

pub fn build_production_create_persistent_config_journal(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_journal: &ProductionCreateMountRuntimeJournal,
) -> Result<ProductionCreatePersistentConfigJournal, ProductionCreatePersistentConfigJournalError> {
    if !PRODUCTION_CREATE_PERSISTENT_CONFIG_JOURNAL_COMPILED {
        return Err(ProductionCreatePersistentConfigJournalError::FeatureDisabled);
    }
    validate_authorization(create, activation, receipt, mount_journal)?;

    let mut journal = ProductionCreatePersistentConfigJournal {
        schema_version: 1,
        journal_id: String::new(),
        mount_activation_id: activation.mount_activation_id.clone(),
        mount_execution_receipt_id: receipt.receipt_id.clone(),
        mount_runtime_journal_id: mount_journal.journal_id.clone(),
        create_activation_id: create.activation_id.clone(),
        disk: activation.disk.clone(),
        partition_device: activation.partition_device.clone(),
        filesystem: activation.filesystem.clone(),
        filesystem_uuid: activation.filesystem_uuid.clone(),
        mountpoint: activation.mountpoint.clone(),
        fstab_source: activation.fstab_source.clone(),
        fstab_options: activation.fstab_options.clone(),
        fstab_dump: activation.fstab_dump,
        fstab_pass: activation.fstab_pass,
        phase: ProductionCreatePersistentConfigPhase::Prepared,
        mutation_may_have_started: false,
        persistent_config_may_have_changed: false,
        events: Vec::new(),
    };
    journal.journal_id = journal.expected_journal_id()?;
    validate_journal(&journal)?;
    Ok(journal)
}

pub fn persist_new_production_create_persistent_config_journal(
    store: &ProductionCreatePersistentConfigJournalStore,
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_journal: &ProductionCreateMountRuntimeJournal,
) -> Result<ProductionCreatePersistentConfigJournal, ProductionCreatePersistentConfigJournalError> {
    let journal =
        build_production_create_persistent_config_journal(create, activation, receipt, mount_journal)?;
    store.persist_new(&journal)?;
    Ok(journal)
}

pub(crate) fn persist_production_create_persistent_config_transition(
    store: &ProductionCreatePersistentConfigJournalStore,
    journal: &mut ProductionCreatePersistentConfigJournal,
    transition: ProductionCreatePersistentConfigTransition,
) -> Result<(), ProductionCreatePersistentConfigJournalError> {
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

    fn fixture_journal() -> ProductionCreatePersistentConfigJournal {
        let mut journal = ProductionCreatePersistentConfigJournal {
            schema_version: 1,
            journal_id: String::new(),
            mount_activation_id: digest('a'),
            mount_execution_receipt_id: digest('b'),
            mount_runtime_journal_id: digest('c'),
            create_activation_id: digest('d'),
            disk: "/dev/loop7".into(),
            partition_device: "/dev/loop7p1".into(),
            filesystem: "ext4".into(),
            filesystem_uuid: "123e4567-e89b-12d3-a456-426614174000".into(),
            mountpoint: "/mnt/data".into(),
            fstab_source: "UUID=123e4567-e89b-12d3-a456-426614174000".into(),
            fstab_options: vec!["defaults".into(), "nofail".into()],
            fstab_dump: 0,
            fstab_pass: 2,
            phase: ProductionCreatePersistentConfigPhase::Prepared,
            mutation_may_have_started: false,
            persistent_config_may_have_changed: false,
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
            "lsm-create-persistent-journal-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn persistence_journal_requires_write_and_rediscovery_before_completion() {
        let mut journal = fixture_journal();
        apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::BeginPersistentConfigUpdate,
        )
        .unwrap();
        assert!(apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::PersistentConfigRediscoveryVerified,
        )
        .is_err());
        apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::PersistentConfigWriteSucceeded,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::PersistentConfigRediscoveryVerified,
        )
        .unwrap();
        assert_eq!(
            journal.phase,
            ProductionCreatePersistentConfigPhase::Completed
        );
        assert!(journal.persistent_config_may_have_changed);
    }

    #[test]
    fn recovery_is_only_available_after_fstab_boundary() {
        let mut journal = fixture_journal();
        assert!(apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::RecoveryRequired,
        )
        .is_err());
        apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::BeginPersistentConfigUpdate,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreatePersistentConfigTransition::RecoveryRequired,
        )
        .unwrap();
        assert_eq!(
            journal.phase,
            ProductionCreatePersistentConfigPhase::RecoveryRequired
        );
    }

    #[test]
    fn durable_transition_updates_memory_only_after_persist() {
        let root = temp_root("persist");
        let store = ProductionCreatePersistentConfigJournalStore::at(&root);
        let mut journal = fixture_journal();
        store.persist_new(&journal).unwrap();
        persist_production_create_persistent_config_transition(
            &store,
            &mut journal,
            ProductionCreatePersistentConfigTransition::BeginPersistentConfigUpdate,
        )
        .unwrap();
        assert_eq!(
            journal.phase,
            ProductionCreatePersistentConfigPhase::UpdatingFstab
        );
        assert_eq!(
            store.load(&journal.journal_id).unwrap().phase,
            ProductionCreatePersistentConfigPhase::UpdatingFstab
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_new_journal_is_rejected() {
        let root = temp_root("duplicate");
        let store = ProductionCreatePersistentConfigJournalStore::at(&root);
        let journal = fixture_journal();
        store.persist_new(&journal).unwrap();
        assert!(matches!(
            store.persist_new(&journal),
            Err(ProductionCreatePersistentConfigJournalError::AlreadyExists(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_PERSISTENT_CONFIG_JOURNAL_COMPILED,
            cfg!(feature = "production-create-persistent-config-journal")
        );
    }
}
