use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use lsm_discovery::{discover_swaps, parse_fstab};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::production_swap_runtime_journal::{
    persist_production_swap_runtime_transition, ProductionSwapRuntimeTransition,
};
use crate::{
    revalidate_pinned_production_swap_replacement_consent, HostStorageLock,
    PinnedProductionSwapReplacementConsent, ProductionSwapReplacementActivationIntent,
    ProductionSwapReplacementConsentLeaseError, ProductionSwapRuntimeExecutionReceipt,
    ProductionSwapRuntimeJournal, ProductionSwapRuntimeJournalError,
    ProductionSwapRuntimeJournalStore, ProductionSwapRuntimePhase,
};

pub const PRODUCTION_SWAP_PERSISTENT_CONFIG_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-persistent-config");
pub const PRODUCTION_SWAP_FSTAB_PATH: &str = "/etc/fstab";
const MAX_FSTAB_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapPersistentConfigReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub journal_id: String,
    pub fstab_path: String,
    pub backup_path: String,
    pub before_sha256: String,
    pub after_sha256: String,
    pub retiring_swap_source: String,
    pub replacement_swapfile: String,
    pub persistent_config_updated: bool,
    pub partition_table_changed: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    journal_id: &'a str,
    fstab_path: &'a str,
    backup_path: &'a str,
    before_sha256: &'a str,
    after_sha256: &'a str,
    retiring_swap_source: &'a str,
    replacement_swapfile: &'a str,
    persistent_config_updated: bool,
    partition_table_changed: bool,
}

impl ProductionSwapPersistentConfigReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            journal_id: &self.journal_id,
            fstab_path: &self.fstab_path,
            backup_path: &self.backup_path,
            before_sha256: &self.before_sha256,
            after_sha256: &self.after_sha256,
            retiring_swap_source: &self.retiring_swap_source,
            replacement_swapfile: &self.replacement_swapfile,
            persistent_config_updated: self.persistent_config_updated,
            partition_table_changed: self.partition_table_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapPersistentConfigError {
    #[error("production swap persistent-config feature is not compiled")]
    FeatureDisabled,
    #[error("production swap persistent-config update requires root")]
    RootRequired,
    #[error("swap runtime journal is not the exact persisted OldSwapDeactivated record")]
    JournalMismatch,
    #[error("swap activation, runtime receipt, and journal bindings do not match")]
    BindingMismatch,
    #[error("pinned swap consent revalidation failed: {0}")]
    Consent(#[from] ProductionSwapReplacementConsentLeaseError),
    #[error("fresh runtime swap state does not match the completed M1B64 crossing")]
    RuntimeSwapStateMismatch,
    #[error("fstab path or metadata is unsafe")]
    UnsafeFstab,
    #[error("fstab exceeds maximum supported size")]
    FstabTooLarge,
    #[error("retiring persistent swap entry is absent, ambiguous, or changed")]
    RetiringEntryMismatch,
    #[error("replacement persistent swap entry verification failed")]
    ReplacementVerificationFailed,
    #[error("persistent-config backup is unsafe or does not match current fstab")]
    BackupMismatch,
    #[error("persistent-config journal transition failed: {0}")]
    Journal(#[from] ProductionSwapRuntimeJournalError),
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
    #[error("persistent-config receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("persistent-config write failed and RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}")]
    RecoveryPersistenceFailed { runtime: String, journal: String },
}

fn io_error(path: &Path, source: io::Error) -> ProductionSwapPersistentConfigError {
    ProductionSwapPersistentConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_safe_regular(
    path: &Path,
) -> Result<(Vec<u8>, fs::Metadata), ProductionSwapPersistentConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionSwapPersistentConfigError::UnsafeFstab);
    }
    if metadata.len() > MAX_FSTAB_BYTES {
        return Err(ProductionSwapPersistentConfigError::FstabTooLarge);
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
        || opened.mode() != metadata.mode()
        || opened.len() != metadata.len()
    {
        return Err(ProductionSwapPersistentConfigError::UnsafeFstab);
    }

    let mut bytes = Vec::new();
    file.take(MAX_FSTAB_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_FSTAB_BYTES {
        return Err(ProductionSwapPersistentConfigError::FstabTooLarge);
    }
    Ok((bytes, metadata))
}

fn exact_entry(
    entry: &lsm_core::FstabEntry,
    activation: &ProductionSwapReplacementActivationIntent,
) -> bool {
    entry.source == activation.persistent_swap_source
        && entry.target == activation.persistent_swap_target
        && entry.fs_type == "swap"
        && entry.options == activation.persistent_swap_options
        && entry.dump == activation.persistent_swap_dump
        && entry.pass == activation.persistent_swap_pass
}

fn escape_fstab_field(value: &str) -> String {
    value
        .replace('\\', "\\134")
        .replace(' ', "\\040")
        .replace('\t', "\\011")
}

fn replacement_line(activation: &ProductionSwapReplacementActivationIntent) -> String {
    format!(
        "{}\t{}\tswap\t{}\t{}\t{}",
        escape_fstab_field(&activation.swapfile_path),
        escape_fstab_field(&activation.persistent_swap_target),
        activation.persistent_swap_options.join(","),
        activation.persistent_swap_dump,
        activation.persistent_swap_pass
    )
}

fn rewrite_exact_swap_entry(
    input: &[u8],
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<Vec<u8>, ProductionSwapPersistentConfigError> {
    let text = std::str::from_utf8(input)
        .map_err(|error| ProductionSwapPersistentConfigError::Parse(error.to_string()))?;
    let mut output = String::with_capacity(text.len() + 128);
    let mut exact_matches = 0_usize;

    for segment in text.split_inclusive('\n') {
        let (line, ending) = segment
            .strip_suffix('\n')
            .map(|line| (line, "\n"))
            .unwrap_or((segment, ""));
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            output.push_str(line);
            output.push_str(ending);
            continue;
        }

        let parsed = parse_fstab(line)
            .map_err(|error| ProductionSwapPersistentConfigError::Parse(error.to_string()))?;
        if parsed.len() != 1 {
            return Err(ProductionSwapPersistentConfigError::RetiringEntryMismatch);
        }
        let entry = &parsed[0];

        if exact_entry(entry, activation) {
            exact_matches += 1;
            output.push_str(&replacement_line(activation));
            output.push_str(ending);
        } else {
            if entry.fs_type == "swap" && entry.source == activation.persistent_swap_source {
                return Err(ProductionSwapPersistentConfigError::RetiringEntryMismatch);
            }
            output.push_str(line);
            output.push_str(ending);
        }
    }

    if exact_matches != 1 {
        return Err(ProductionSwapPersistentConfigError::RetiringEntryMismatch);
    }
    Ok(output.into_bytes())
}

fn verify_rewritten(
    bytes: &[u8],
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<(), ProductionSwapPersistentConfigError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ProductionSwapPersistentConfigError::Parse(error.to_string()))?;
    let entries = parse_fstab(text)
        .map_err(|error| ProductionSwapPersistentConfigError::Parse(error.to_string()))?;

    if entries
        .iter()
        .any(|entry| entry.fs_type == "swap" && entry.source == activation.persistent_swap_source)
    {
        return Err(ProductionSwapPersistentConfigError::ReplacementVerificationFailed);
    }

    let replacement = entries
        .iter()
        .filter(|entry| {
            entry.fs_type == "swap"
                && entry.source == activation.swapfile_path
                && entry.target == activation.persistent_swap_target
                && entry.options == activation.persistent_swap_options
                && entry.dump == activation.persistent_swap_dump
                && entry.pass == activation.persistent_swap_pass
        })
        .count();
    if replacement != 1 {
        return Err(ProductionSwapPersistentConfigError::ReplacementVerificationFailed);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProductionSwapPersistentConfigError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn ensure_backup(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &ProductionSwapRuntimeJournal,
    before: &[u8],
) -> Result<PathBuf, ProductionSwapPersistentConfigError> {
    let root = store.root();
    let backup = root.join(format!("{}.fstab.backup", journal.journal_id));

    match fs::symlink_metadata(&backup) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() != before.len() as u64
            {
                return Err(ProductionSwapPersistentConfigError::BackupMismatch);
            }
            let existing = fs::read(&backup).map_err(|source| io_error(&backup, source))?;
            if existing != before {
                return Err(ProductionSwapPersistentConfigError::BackupMismatch);
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

fn atomic_replace(
    path: &Path,
    bytes: &[u8],
    original: &fs::Metadata,
) -> Result<(), ProductionSwapPersistentConfigError> {
    let parent = path
        .parent()
        .ok_or(ProductionSwapPersistentConfigError::UnsafeFstab)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ProductionSwapPersistentConfigError::UnsafeFstab)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|source| io_error(parent, source))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(ProductionSwapPersistentConfigError::UnsafeFstab);
    }
    let temp = parent.join(format!(
        ".{file_name}.linux-storage-manager-{}",
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
        if metadata.uid() != 0
            || metadata.mode() & 0o777 != original.mode() & 0o777
            || metadata.nlink() != 1
            || metadata.len() != bytes.len() as u64
        {
            return Err(ProductionSwapPersistentConfigError::UnsafeFstab);
        }
        drop(file);

        let current = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
        if current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != original.dev()
            || current.ino() != original.ino()
            || current.uid() != original.uid()
            || current.mode() != original.mode()
            || current.nlink() != original.nlink()
            || current.len() != original.len()
        {
            return Err(ProductionSwapPersistentConfigError::UnsafeFstab);
        }

        fs::rename(&temp, path).map_err(|source| io_error(path, source))?;
        sync_directory(parent)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

pub(crate) fn revalidate_production_swap_persistent_config_receipt(
    activation: &ProductionSwapReplacementActivationIntent,
    receipt: &ProductionSwapPersistentConfigReceipt,
) -> Result<(), ProductionSwapPersistentConfigError> {
    if !receipt.integrity_matches().unwrap_or(false)
        || !receipt.persistent_config_updated
        || receipt.partition_table_changed
        || receipt.retiring_swap_source != activation.persistent_swap_source
        || receipt.replacement_swapfile != activation.swapfile_path
    {
        return Err(ProductionSwapPersistentConfigError::BindingMismatch);
    }

    let path = Path::new(&receipt.fstab_path);
    let (bytes, _) = read_safe_regular(path)?;
    if sha256(&bytes) != receipt.after_sha256 {
        return Err(ProductionSwapPersistentConfigError::ReplacementVerificationFailed);
    }
    verify_rewritten(&bytes, activation)
}

fn persist_recovery(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    runtime: ProductionSwapPersistentConfigError,
) -> ProductionSwapPersistentConfigError {
    match persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => ProductionSwapPersistentConfigError::RecoveryPersistenceFailed {
            runtime: runtime.to_string(),
            journal: journal_error.to_string(),
        },
    }
}

fn validate_bindings(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    journal: &ProductionSwapRuntimeJournal,
) -> Result<(), ProductionSwapPersistentConfigError> {
    if !activation.integrity_matches().unwrap_or(false)
        || !runtime.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || journal.phase != ProductionSwapRuntimePhase::OldSwapDeactivated
        || !journal.mutation_may_have_started
        || journal.persistent_config_may_have_changed
        || journal.partition_table_may_have_changed
        || journal.activation_id != activation.activation_id
        || journal.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || journal.retiring_swap_device != activation.retiring_swap_device
        || journal.retiring_swap_bytes != activation.retiring_swap_bytes
        || journal.retiring_swap_priority != activation.retiring_swap_priority
        || journal.swapfile_path != activation.swapfile_path
        || runtime.journal_id != journal.journal_id
        || runtime.launch_id != journal.launch_id
        || runtime.retiring_swap_device != journal.retiring_swap_device
        || runtime.swapfile_path != journal.swapfile_path
        || runtime.priority != journal.retiring_swap_priority
        || runtime.old_swap_active
        || !runtime.replacement_swap_active
        || runtime.persistent_config_changed
        || runtime.partition_table_changed
    {
        return Err(ProductionSwapPersistentConfigError::BindingMismatch);
    }
    Ok(())
}

fn verify_runtime_swap_state(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
) -> Result<(), ProductionSwapPersistentConfigError> {
    let swaps = discover_swaps()
        .map_err(|error| ProductionSwapPersistentConfigError::Discovery(error.to_string()))?;
    if swaps
        .iter()
        .any(|entry| entry.name == activation.retiring_swap_device)
    {
        return Err(ProductionSwapPersistentConfigError::RuntimeSwapStateMismatch);
    }
    let replacements = swaps
        .iter()
        .filter(|entry| entry.name == activation.swapfile_path)
        .collect::<Vec<_>>();
    if replacements.len() != 1
        || replacements[0].priority != activation.retiring_swap_priority
        || replacements[0].size_bytes != runtime.replacement_reported_swap_bytes
    {
        return Err(ProductionSwapPersistentConfigError::RuntimeSwapStateMismatch);
    }
    Ok(())
}

fn update_persistent_config_at(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    fstab_path: &Path,
) -> Result<ProductionSwapPersistentConfigReceipt, ProductionSwapPersistentConfigError> {
    validate_bindings(activation, runtime, journal)?;

    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionSwapPersistentConfigError::JournalMismatch);
    }

    let (before, metadata) = read_safe_regular(fstab_path)?;
    let rewritten = rewrite_exact_swap_entry(&before, activation)?;
    verify_rewritten(&rewritten, activation)?;
    let backup = ensure_backup(store, journal, &before)?;

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginPersistentConfigUpdate,
    )?;

    if let Err(error) = atomic_replace(fstab_path, &rewritten, &metadata) {
        return Err(persist_recovery(store, journal, error));
    }

    let (after, after_metadata) = match read_safe_regular(fstab_path) {
        Ok(value) => value,
        Err(error) => return Err(persist_recovery(store, journal, error)),
    };
    if after_metadata.mode() & 0o777 != metadata.mode() & 0o777
        || after_metadata.uid() != metadata.uid()
        || after != rewritten
    {
        return Err(persist_recovery(
            store,
            journal,
            ProductionSwapPersistentConfigError::ReplacementVerificationFailed,
        ));
    }
    if let Err(error) = verify_rewritten(&after, activation) {
        return Err(persist_recovery(store, journal, error));
    }

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::PersistentConfigUpdatedVerified,
    )?;

    let mut receipt = ProductionSwapPersistentConfigReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        journal_id: journal.journal_id.clone(),
        fstab_path: fstab_path.to_string_lossy().into_owned(),
        backup_path: backup.to_string_lossy().into_owned(),
        before_sha256: sha256(&before),
        after_sha256: sha256(&after),
        retiring_swap_source: activation.persistent_swap_source.clone(),
        replacement_swapfile: activation.swapfile_path.clone(),
        persistent_config_updated: true,
        partition_table_changed: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Atomically replace the exact frozen retiring swap line in /etc/fstab.
///
/// This stage requires the runtime journal to be durably OldSwapDeactivated.
/// It never removes or rewrites any partition table.
#[cfg(feature = "production-swap-loop-harness")]
pub fn update_production_swap_persistent_config_at_path(
    _host_lock: &HostStorageLock,
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    consent: &PinnedProductionSwapReplacementConsent,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    fstab_path: &Path,
) -> Result<ProductionSwapPersistentConfigReceipt, ProductionSwapPersistentConfigError> {
    if !PRODUCTION_SWAP_PERSISTENT_CONFIG_COMPILED {
        return Err(ProductionSwapPersistentConfigError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionSwapPersistentConfigError::RootRequired);
    }
    let _consent = revalidate_pinned_production_swap_replacement_consent(activation, consent)?;
    verify_runtime_swap_state(activation, runtime)?;
    update_persistent_config_at(activation, runtime, store, journal, fstab_path)
}

pub fn update_production_swap_persistent_config(
    _host_lock: &HostStorageLock,
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    consent: &PinnedProductionSwapReplacementConsent,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
) -> Result<ProductionSwapPersistentConfigReceipt, ProductionSwapPersistentConfigError> {
    if !PRODUCTION_SWAP_PERSISTENT_CONFIG_COMPILED {
        return Err(ProductionSwapPersistentConfigError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionSwapPersistentConfigError::RootRequired);
    }
    let _consent = revalidate_pinned_production_swap_replacement_consent(activation, consent)?;
    verify_runtime_swap_state(activation, runtime)?;
    update_persistent_config_at(
        activation,
        runtime,
        store,
        journal,
        Path::new(PRODUCTION_SWAP_FSTAB_PATH),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation() -> ProductionSwapReplacementActivationIntent {
        let mut value = ProductionSwapReplacementActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: crate::ProductionSwapReplacementProfile::TailSwapPartitionToExt4Swapfile,
            swap_replacement_intent_id: "a".repeat(64),
            target: "/data".into(),
            disk: "/dev/sda".into(),
            retiring_swap_device: "/dev/sda5".into(),
            retiring_swap_bytes: 64 * 1024 * 1024,
            retiring_swap_priority: 7,
            persistent_swap_source: "UUID=old-swap".into(),
            persistent_swap_target: "none".into(),
            persistent_swap_options: vec!["sw".into(), "pri=7".into()],
            persistent_swap_dump: 0,
            persistent_swap_pass: 0,
            destination_mount: "/data".into(),
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            destination_filesystem: "ext4".into(),
            destination_available_bytes: 128 * 1024 * 1024,
            swapfile_mode: 0o600,
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    #[test]
    fn rewrite_preserves_comments_and_unrelated_lines() {
        let activation = activation();
        let input =
            b"# header\nUUID=root / ext4 defaults 0 1\nUUID=old-swap none swap sw,pri=7 0 0\n\n";
        let output = rewrite_exact_swap_entry(input, &activation).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("# header\nUUID=root / ext4 defaults 0 1\n"));
        assert!(text.contains("/data/.linux-storage-manager.swap\tnone\tswap\tsw,pri=7\t0\t0\n"));
        assert!(!text.contains("UUID=old-swap none swap"));
        verify_rewritten(text.as_bytes(), &activation).unwrap();
    }

    #[test]
    fn ambiguous_retiring_entry_fails_closed() {
        let activation = activation();
        let input = b"UUID=old-swap none swap sw,pri=7 0 0\nUUID=old-swap none swap sw,pri=7 0 0\n";
        assert!(matches!(
            rewrite_exact_swap_entry(input, &activation),
            Err(ProductionSwapPersistentConfigError::RetiringEntryMismatch)
        ));
    }

    #[test]
    fn changed_retiring_entry_fails_closed() {
        let activation = activation();
        let input = b"UUID=old-swap none swap sw,pri=8 0 0\n";
        assert!(matches!(
            rewrite_exact_swap_entry(input, &activation),
            Err(ProductionSwapPersistentConfigError::RetiringEntryMismatch)
        ));
    }

    #[test]
    fn replacement_path_is_fstab_escaped() {
        let mut activation = activation();
        activation.swapfile_path = "/data/path with space/swap".into();
        assert_eq!(
            replacement_line(&activation),
            "/data/path\\040with\\040space/swap\tnone\tswap\tsw,pri=7\t0\t0"
        );
    }
}
