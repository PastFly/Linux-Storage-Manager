use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use lsm_core::FstabEntry;
use lsm_discovery::{discover_snapshot, parse_fstab};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::production_create_mount_exec::verify_mounted_snapshot;
use crate::production_create_persistent_journal::persist_production_create_persistent_config_transition;
use crate::{
    build_production_create_persistent_config_journal, HostStorageLock,
    ProductionCreateActivationIntent, ProductionCreateMountActivationIntent,
    ProductionCreateMountRuntimeExecutionReceipt, ProductionCreateMountRuntimeJournal,
    ProductionCreateMountRuntimeJournalError, ProductionCreateMountRuntimeJournalStore,
    ProductionCreatePersistentConfigJournal, ProductionCreatePersistentConfigJournalError,
    ProductionCreatePersistentConfigJournalStore, ProductionCreatePersistentConfigPhase,
    ProductionCreatePersistentConfigTransition,
};

pub const PRODUCTION_CREATE_PERSISTENT_CONFIG_COMPILED: bool =
    cfg!(feature = "production-create-persistent-config");
pub const PRODUCTION_CREATE_FSTAB_PATH: &str = "/etc/fstab";
const MAX_FSTAB_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreatePersistentConfigReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub persistent_config_journal_id: String,
    pub mount_activation_id: String,
    pub mount_execution_receipt_id: String,
    pub mount_runtime_journal_id: String,
    pub fstab_path: String,
    pub backup_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub fstab_source: String,
    pub mountpoint: String,
    pub filesystem: String,
    pub fstab_options: Vec<String>,
    pub fstab_dump: u32,
    pub fstab_pass: u32,
    pub persistent_config_updated: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    persistent_config_journal_id: &'a str,
    mount_activation_id: &'a str,
    mount_execution_receipt_id: &'a str,
    mount_runtime_journal_id: &'a str,
    fstab_path: &'a str,
    backup_path: &'a str,
    before_sha256: &'a str,
    after_sha256: &'a str,
    fstab_source: &'a str,
    mountpoint: &'a str,
    filesystem: &'a str,
    fstab_options: &'a [String],
    fstab_dump: u32,
    fstab_pass: u32,
    persistent_config_updated: bool,
}

impl ProductionCreatePersistentConfigReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            persistent_config_journal_id: &self.persistent_config_journal_id,
            mount_activation_id: &self.mount_activation_id,
            mount_execution_receipt_id: &self.mount_execution_receipt_id,
            mount_runtime_journal_id: &self.mount_runtime_journal_id,
            fstab_path: &self.fstab_path,
            backup_path: &self.backup_path,
            before_sha256: &self.before_sha256,
            after_sha256: &self.after_sha256,
            fstab_source: &self.fstab_source,
            mountpoint: &self.mountpoint,
            filesystem: &self.filesystem,
            fstab_options: &self.fstab_options,
            fstab_dump: self.fstab_dump,
            fstab_pass: self.fstab_pass,
            persistent_config_updated: self.persistent_config_updated,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreatePersistentConfigError {
    #[error("production create persistent-config feature is not compiled")]
    FeatureDisabled,
    #[error("production create persistent-config update requires root")]
    RootRequired,
    #[error("completed mount authorization/receipt/journal chain is invalid")]
    AuthorizationInvalid,
    #[error("completed mount runtime journal is not the exact persisted record")]
    MountJournalMismatch,
    #[error("completed mount runtime journal reload failed: {0}")]
    MountJournal(#[from] ProductionCreateMountRuntimeJournalError),
    #[error("persistent-config journal is not the exact persisted Prepared record")]
    PersistenceJournalMismatch,
    #[error("fresh mounted filesystem no longer matches the exact completed Create scope: {0}")]
    LiveMountVerification(String),
    #[error("fstab path or metadata is unsafe")]
    UnsafeFstab,
    #[error("fstab exceeds maximum supported size")]
    FstabTooLarge,
    #[error("fstab already contains a conflicting source or mountpoint binding")]
    FstabConflict,
    #[error("persistent fstab readback or rediscovery verification failed")]
    PersistentConfigVerificationFailed,
    #[error("persistent-config backup is unsafe or does not match current fstab")]
    BackupMismatch,
    #[error("persistent-config journal transition failed: {0}")]
    Journal(#[from] ProductionCreatePersistentConfigJournalError),
    #[error("persistent-config I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("persistent-config parser rejected current or rewritten fstab: {0}")]
    Parse(String),
    #[error("persistent-config read-only runtime discovery failed: {0}")]
    Discovery(String),
    #[error(
        "persistent-config write failed and RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}"
    )]
    RecoveryPersistenceFailed { runtime: String, journal: String },
    #[error("persistent-config receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn io_error(path: &Path, source: io::Error) -> ProductionCreatePersistentConfigError {
    ProductionCreatePersistentConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_safe_regular(
    path: &Path,
    required_uid: u32,
) -> Result<(Vec<u8>, fs::Metadata), ProductionCreatePersistentConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != required_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionCreatePersistentConfigError::UnsafeFstab);
    }
    if metadata.len() > MAX_FSTAB_BYTES {
        return Err(ProductionCreatePersistentConfigError::FstabTooLarge);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    if opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
        || opened.uid() != metadata.uid()
        || opened.gid() != metadata.gid()
        || opened.mode() != metadata.mode()
        || opened.nlink() != metadata.nlink()
        || opened.len() != metadata.len()
    {
        return Err(ProductionCreatePersistentConfigError::UnsafeFstab);
    }

    let mut bytes = Vec::new();
    file.take(MAX_FSTAB_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_FSTAB_BYTES {
        return Err(ProductionCreatePersistentConfigError::FstabTooLarge);
    }
    Ok((bytes, metadata))
}

fn parse_entries(bytes: &[u8]) -> Result<Vec<FstabEntry>, ProductionCreatePersistentConfigError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ProductionCreatePersistentConfigError::Parse(error.to_string()))?;
    parse_fstab(text)
        .map_err(|error| ProductionCreatePersistentConfigError::Parse(error.to_string()))
}

fn source_matches(entry: &FstabEntry, activation: &ProductionCreateMountActivationIntent) -> bool {
    entry.source == activation.partition_device
        || entry
            .source
            .eq_ignore_ascii_case(activation.fstab_source.as_str())
}

fn exact_entry(entry: &FstabEntry, activation: &ProductionCreateMountActivationIntent) -> bool {
    entry
        .source
        .eq_ignore_ascii_case(activation.fstab_source.as_str())
        && entry.target == activation.mountpoint
        && entry.fs_type == activation.filesystem
        && entry.options == activation.fstab_options
        && entry.dump == activation.fstab_dump
        && entry.pass == activation.fstab_pass
}

fn ensure_no_fstab_conflict(
    bytes: &[u8],
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreatePersistentConfigError> {
    if parse_entries(bytes)?
        .iter()
        .any(|entry| entry.target == activation.mountpoint || source_matches(entry, activation))
    {
        return Err(ProductionCreatePersistentConfigError::FstabConflict);
    }
    Ok(())
}

fn verify_exact_fstab(
    bytes: &[u8],
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreatePersistentConfigError> {
    let entries = parse_entries(bytes)?;
    let exact_count = entries
        .iter()
        .filter(|entry| exact_entry(entry, activation))
        .count();
    if exact_count != 1
        || entries.iter().any(|entry| {
            !exact_entry(entry, activation)
                && (entry.target == activation.mountpoint || source_matches(entry, activation))
        })
    {
        return Err(ProductionCreatePersistentConfigError::PersistentConfigVerificationFailed);
    }
    Ok(())
}

fn escape_fstab_field(value: &str) -> String {
    value
        .replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
}

fn fstab_line(activation: &ProductionCreateMountActivationIntent) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}",
        escape_fstab_field(&activation.fstab_source),
        escape_fstab_field(&activation.mountpoint),
        activation.filesystem,
        activation.fstab_options.join(","),
        activation.fstab_dump,
        activation.fstab_pass
    )
}

fn append_exact_fstab_entry(
    before: &[u8],
    activation: &ProductionCreateMountActivationIntent,
) -> Result<Vec<u8>, ProductionCreatePersistentConfigError> {
    ensure_no_fstab_conflict(before, activation)?;
    let mut after = before.to_vec();
    if !after.is_empty() && !after.ends_with(b"\n") {
        after.push(b'\n');
    }
    after.extend_from_slice(fstab_line(activation).as_bytes());
    after.push(b'\n');
    verify_exact_fstab(&after, activation)?;
    if after.len() as u64 > MAX_FSTAB_BYTES {
        return Err(ProductionCreatePersistentConfigError::FstabTooLarge);
    }
    Ok(after)
}

fn sync_directory(path: &Path) -> Result<(), ProductionCreatePersistentConfigError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn ensure_backup(
    store: &ProductionCreatePersistentConfigJournalStore,
    journal: &ProductionCreatePersistentConfigJournal,
    before: &[u8],
    required_uid: u32,
) -> Result<PathBuf, ProductionCreatePersistentConfigError> {
    let root = store.root();
    let backup = root.join(format!("{}.fstab.backup", journal.journal_id));

    match fs::symlink_metadata(&backup) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != required_uid
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != before.len() as u64
            {
                return Err(ProductionCreatePersistentConfigError::BackupMismatch);
            }
            let existing = fs::read(&backup).map_err(|source| io_error(&backup, source))?;
            if existing != before {
                return Err(ProductionCreatePersistentConfigError::BackupMismatch);
            }
            Ok(backup)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&backup)
                .map_err(|source| io_error(&backup, source))?;
            file.write_all(before)
                .map_err(|source| io_error(&backup, source))?;
            file.sync_all()
                .map_err(|source| io_error(&backup, source))?;
            drop(file);
            sync_directory(root)?;
            Ok(backup)
        }
        Err(source) => Err(io_error(&backup, source)),
    }
}

fn metadata_matches(current: &fs::Metadata, original: &fs::Metadata) -> bool {
    current.dev() == original.dev()
        && current.ino() == original.ino()
        && current.uid() == original.uid()
        && current.gid() == original.gid()
        && current.mode() == original.mode()
        && current.nlink() == original.nlink()
        && current.len() == original.len()
}

fn atomic_replace(
    path: &Path,
    bytes: &[u8],
    before: &[u8],
    original: &fs::Metadata,
    required_uid: u32,
    journal_id: &str,
) -> Result<(), ProductionCreatePersistentConfigError> {
    let parent = path
        .parent()
        .ok_or(ProductionCreatePersistentConfigError::UnsafeFstab)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProductionCreatePersistentConfigError::UnsafeFstab)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|source| io_error(parent, source))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != required_uid
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(ProductionCreatePersistentConfigError::UnsafeFstab);
    }
    let suffix = journal_id.get(..12).unwrap_or("invalid");
    let temp = parent.join(format!(
        ".{file_name}.linux-storage-manager-{suffix}-{}",
        std::process::id()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(original.mode() & 0o777)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|source| io_error(&temp, source))?;
        file.set_permissions(fs::Permissions::from_mode(original.mode() & 0o777))
            .map_err(|source| io_error(&temp, source))?;
        file.write_all(bytes)
            .map_err(|source| io_error(&temp, source))?;
        file.sync_all().map_err(|source| io_error(&temp, source))?;

        let metadata = file.metadata().map_err(|source| io_error(&temp, source))?;
        if metadata.uid() != required_uid
            || metadata.mode() & 0o777 != original.mode() & 0o777
            || metadata.nlink() != 1
            || metadata.len() != bytes.len() as u64
        {
            return Err(ProductionCreatePersistentConfigError::UnsafeFstab);
        }
        drop(file);

        let (current_bytes, current_metadata) = read_safe_regular(path, required_uid)?;
        if !metadata_matches(&current_metadata, original) || current_bytes != before {
            return Err(ProductionCreatePersistentConfigError::UnsafeFstab);
        }

        fs::rename(&temp, path).map_err(|source| io_error(path, source))?;
        sync_directory(parent)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn validate_bindings(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_journal: &ProductionCreateMountRuntimeJournal,
    journal: &ProductionCreatePersistentConfigJournal,
) -> Result<(), ProductionCreatePersistentConfigError> {
    if !activation.persist_to_fstab
        || !receipt.integrity_matches().unwrap_or(false)
        || !receipt.mounted_verified
        || receipt.fstab_changed
        || journal.phase != ProductionCreatePersistentConfigPhase::Prepared
        || journal.mutation_may_have_started
        || journal.persistent_config_may_have_changed
    {
        return Err(ProductionCreatePersistentConfigError::AuthorizationInvalid);
    }

    let expected = build_production_create_persistent_config_journal(
        create,
        activation,
        receipt,
        mount_journal,
    )?;
    if expected != *journal {
        return Err(ProductionCreatePersistentConfigError::AuthorizationInvalid);
    }
    Ok(())
}

fn verify_live_without_persistent_config(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreatePersistentConfigError> {
    let snapshot = discover_snapshot()
        .map_err(|error| ProductionCreatePersistentConfigError::Discovery(error.to_string()))?;
    verify_mounted_snapshot(create, activation, &snapshot).map_err(|error| {
        ProductionCreatePersistentConfigError::LiveMountVerification(error.to_string())
    })
}

fn verify_live_with_persistent_config(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreatePersistentConfigError> {
    let snapshot = discover_snapshot()
        .map_err(|error| ProductionCreatePersistentConfigError::Discovery(error.to_string()))?;

    let exact_count = snapshot
        .fstab
        .iter()
        .filter(|entry| exact_entry(entry, activation))
        .count();
    if exact_count != 1
        || snapshot.fstab.iter().any(|entry| {
            !exact_entry(entry, activation)
                && (entry.target == activation.mountpoint || source_matches(entry, activation))
        })
    {
        return Err(ProductionCreatePersistentConfigError::PersistentConfigVerificationFailed);
    }

    let mut without_persistent_entry = snapshot.clone();
    without_persistent_entry
        .fstab
        .retain(|entry| !exact_entry(entry, activation));
    verify_mounted_snapshot(create, activation, &without_persistent_entry).map_err(|error| {
        ProductionCreatePersistentConfigError::LiveMountVerification(error.to_string())
    })
}

fn persist_recovery(
    store: &ProductionCreatePersistentConfigJournalStore,
    journal: &mut ProductionCreatePersistentConfigJournal,
    runtime: ProductionCreatePersistentConfigError,
) -> ProductionCreatePersistentConfigError {
    match persist_production_create_persistent_config_transition(
        store,
        journal,
        ProductionCreatePersistentConfigTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => ProductionCreatePersistentConfigError::RecoveryPersistenceFailed {
            runtime: runtime.to_string(),
            journal: journal_error.to_string(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn update_persistent_config_at(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_store: &ProductionCreateMountRuntimeJournalStore,
    mount_journal: &ProductionCreateMountRuntimeJournal,
    store: &ProductionCreatePersistentConfigJournalStore,
    journal: &mut ProductionCreatePersistentConfigJournal,
    fstab_path: &Path,
) -> Result<ProductionCreatePersistentConfigReceipt, ProductionCreatePersistentConfigError> {
    validate_bindings(create, activation, receipt, mount_journal, journal)?;

    let persisted_mount = mount_store.load(&mount_journal.journal_id)?;
    if persisted_mount != *mount_journal {
        return Err(ProductionCreatePersistentConfigError::MountJournalMismatch);
    }
    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionCreatePersistentConfigError::PersistenceJournalMismatch);
    }

    verify_live_without_persistent_config(create, activation)?;

    let (before, metadata) = read_safe_regular(fstab_path, 0)?;
    let rewritten = append_exact_fstab_entry(&before, activation)?;
    let backup = ensure_backup(store, journal, &before, 0)?;

    persist_production_create_persistent_config_transition(
        store,
        journal,
        ProductionCreatePersistentConfigTransition::BeginPersistentConfigUpdate,
    )?;

    if let Err(error) = atomic_replace(
        fstab_path,
        &rewritten,
        &before,
        &metadata,
        0,
        &journal.journal_id,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = persist_production_create_persistent_config_transition(
        store,
        journal,
        ProductionCreatePersistentConfigTransition::PersistentConfigWriteSucceeded,
    ) {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreatePersistentConfigError::Journal(error),
        ));
    }

    let (after, after_metadata) = match read_safe_regular(fstab_path, 0) {
        Ok(value) => value,
        Err(error) => return Err(persist_recovery(store, journal, error)),
    };
    if after != rewritten
        || after_metadata.uid() != metadata.uid()
        || after_metadata.gid() != metadata.gid()
        || after_metadata.mode() & 0o777 != metadata.mode() & 0o777
    {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreatePersistentConfigError::PersistentConfigVerificationFailed,
        ));
    }
    if let Err(error) = verify_exact_fstab(&after, activation) {
        return Err(persist_recovery(store, journal, error));
    }
    if let Err(error) = verify_live_with_persistent_config(create, activation) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = persist_production_create_persistent_config_transition(
        store,
        journal,
        ProductionCreatePersistentConfigTransition::PersistentConfigRediscoveryVerified,
    ) {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreatePersistentConfigError::Journal(error),
        ));
    }

    let mut result = ProductionCreatePersistentConfigReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        persistent_config_journal_id: journal.journal_id.clone(),
        mount_activation_id: activation.mount_activation_id.clone(),
        mount_execution_receipt_id: receipt.receipt_id.clone(),
        mount_runtime_journal_id: mount_journal.journal_id.clone(),
        fstab_path: fstab_path.to_string_lossy().into_owned(),
        backup_path: backup.to_string_lossy().into_owned(),
        before_sha256: sha256(&before),
        after_sha256: sha256(&after),
        fstab_source: activation.fstab_source.clone(),
        mountpoint: activation.mountpoint.clone(),
        filesystem: activation.filesystem.clone(),
        fstab_options: activation.fstab_options.clone(),
        fstab_dump: activation.fstab_dump,
        fstab_pass: activation.fstab_pass,
        persistent_config_updated: true,
    };
    result.receipt_id = result.expected_receipt_id()?;
    Ok(result)
}

pub fn revalidate_production_create_persistent_config_receipt(
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreatePersistentConfigReceipt,
) -> Result<(), ProductionCreatePersistentConfigError> {
    if !receipt.integrity_matches().unwrap_or(false)
        || !receipt.persistent_config_updated
        || receipt.mount_activation_id != activation.mount_activation_id
        || receipt.fstab_source != activation.fstab_source
        || receipt.mountpoint != activation.mountpoint
        || receipt.filesystem != activation.filesystem
        || receipt.fstab_options != activation.fstab_options
        || receipt.fstab_dump != activation.fstab_dump
        || receipt.fstab_pass != activation.fstab_pass
    {
        return Err(ProductionCreatePersistentConfigError::AuthorizationInvalid);
    }
    let path = Path::new(&receipt.fstab_path);
    let (bytes, _) = read_safe_regular(path, 0)?;
    if sha256(&bytes) != receipt.after_sha256 {
        return Err(ProductionCreatePersistentConfigError::PersistentConfigVerificationFailed);
    }
    verify_exact_fstab(&bytes, activation)
}

/// Atomically append the exact sealed UUID-based Create mount entry to /etc/fstab.
///
/// This boundary is reachable only from an integrity-valid M2A12 activation that
/// explicitly sealed persist_to_fstab=true, an exact completed M2A14 mount receipt
/// and durable mount journal, plus a separately persisted M2A15 Prepared journal.
/// The original fstab is backed up and fsynced before the M2A15 journal enters
/// UpdatingFstab. The replacement uses a same-directory create-new temp file,
/// file fsync, exact original inode/content recheck, atomic rename and directory
/// fsync. Completion requires parse/readback plus fresh full storage rediscovery
/// proving both the live mount and exactly one sealed persistent entry.
#[allow(clippy::too_many_arguments)]
pub fn update_production_create_persistent_config(
    _host_lock: &HostStorageLock,
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    receipt: &ProductionCreateMountRuntimeExecutionReceipt,
    mount_store: &ProductionCreateMountRuntimeJournalStore,
    mount_journal: &ProductionCreateMountRuntimeJournal,
    store: &ProductionCreatePersistentConfigJournalStore,
    journal: &mut ProductionCreatePersistentConfigJournal,
) -> Result<ProductionCreatePersistentConfigReceipt, ProductionCreatePersistentConfigError> {
    if !PRODUCTION_CREATE_PERSISTENT_CONFIG_COMPILED {
        return Err(ProductionCreatePersistentConfigError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionCreatePersistentConfigError::RootRequired);
    }
    update_persistent_config_at(
        create,
        activation,
        receipt,
        mount_store,
        mount_journal,
        store,
        journal,
        Path::new(PRODUCTION_CREATE_FSTAB_PATH),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn activation() -> ProductionCreateMountActivationIntent {
        ProductionCreateMountActivationIntent {
            schema_version: 1,
            mount_activation_id: "a".repeat(64),
            create_activation_id: "b".repeat(64),
            filesystem_receipt_id: "c".repeat(64),
            journal_id: "d".repeat(64),
            launch_id: "e".repeat(64),
            disk: "/dev/loop7".into(),
            partition_device: "/dev/loop7p1".into(),
            filesystem: "ext4".into(),
            filesystem_uuid: "123e4567-e89b-12d3-a456-426614174000".into(),
            mountpoint: "/mnt/data".into(),
            mountpoint_device_id: 1,
            mountpoint_inode: 2,
            mountpoint_uid: 0,
            mountpoint_mode: libc::S_IFDIR | 0o755,
            fstab_source: "UUID=123e4567-e89b-12d3-a456-426614174000".into(),
            fstab_options: vec!["defaults".into(), "nofail".into()],
            fstab_dump: 0,
            fstab_pass: 2,
            persist_to_fstab: true,
            compile_feature_enabled: true,
            execution_enabled: false,
            mount_performed: false,
            fstab_changed: false,
        }
    }

    fn temp_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lsm-create-persistent-config-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn append_preserves_existing_bytes_and_adds_exact_uuid_entry() {
        let activation = activation();
        let before = b"# header\nUUID=root / ext4 defaults 0 1\n";
        let after = append_exact_fstab_entry(before, &activation).unwrap();
        assert!(after.starts_with(before));
        assert!(String::from_utf8(after.clone()).unwrap().contains(
            "UUID=123e4567-e89b-12d3-a456-426614174000\t/mnt/data\text4\tdefaults,nofail\t0\t2\n"
        ));
        verify_exact_fstab(&after, &activation).unwrap();
    }

    #[test]
    fn conflicting_source_or_mountpoint_fails_closed() {
        let activation = activation();
        for before in [
            b"UUID=123e4567-e89b-12d3-a456-426614174000 /other ext4 defaults 0 2\n".as_slice(),
            b"UUID=other /mnt/data ext4 defaults 0 2\n".as_slice(),
        ] {
            assert!(matches!(
                append_exact_fstab_entry(before, &activation),
                Err(ProductionCreatePersistentConfigError::FstabConflict)
            ));
        }
    }

    #[test]
    fn mountpoint_is_fstab_escaped() {
        let mut activation = activation();
        activation.mountpoint = "/mnt/data set".into();
        assert!(fstab_line(&activation).contains("/mnt/data\\040set"));
    }

    #[test]
    fn atomic_replace_rechecks_original_content_and_preserves_mode() {
        let root = temp_root("atomic");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("fstab");
        fs::write(&path, b"UUID=root / ext4 defaults 0 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let uid = unsafe { libc::geteuid() };
        let (before, metadata) = read_safe_regular(&path, uid).unwrap();
        let after = b"UUID=root / ext4 defaults 0 1\nUUID=data /mnt/data ext4 defaults 0 2\n";
        atomic_replace(&path, after, &before, &metadata, uid, "0123456789abcdef").unwrap();
        let (installed, installed_metadata) = read_safe_regular(&path, uid).unwrap();
        assert_eq!(installed, after);
        assert_eq!(installed_metadata.mode() & 0o777, 0o644);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn persistent_config_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_PERSISTENT_CONFIG_COMPILED,
            cfg!(feature = "production-create-persistent-config")
        );
    }
}
