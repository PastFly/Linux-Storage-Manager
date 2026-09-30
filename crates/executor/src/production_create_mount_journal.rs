use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PrivilegedProgram, ProductionCreateMountActivationIntent, ProductionCreateMountRuntimeLaunchSpec,
    ProductionCreateMountRuntimePreflightReceipt,
};

pub const PRODUCTION_CREATE_MOUNT_RUNTIME_JOURNAL_COMPILED: bool =
    cfg!(feature = "production-create-mount-runtime-journal");
pub const PRODUCTION_CREATE_MOUNT_RUNTIME_JOURNAL_DIRECTORY: &str =
    "/var/lib/linux-storage-manager/create-mount-runtime";
const MAX_MOUNT_RUNTIME_JOURNAL_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionCreateMountRuntimePhase {
    Prepared,
    Mounting,
    MountedAwaitingVerification,
    Completed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionCreateMountRuntimeTransition {
    BeginMount,
    MountProcessSucceeded,
    MountRediscoveryVerified,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreateMountRuntimeJournalEvent {
    pub sequence: u32,
    pub from: ProductionCreateMountRuntimePhase,
    pub to: ProductionCreateMountRuntimePhase,
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionCreateMountRuntimeJournal {
    pub schema_version: u32,
    pub journal_id: String,
    pub mount_activation_id: String,
    pub preflight_receipt_id: String,
    pub launch_id: String,
    pub create_activation_id: String,
    pub filesystem_receipt_id: String,
    pub create_journal_id: String,
    pub create_launch_id: String,
    pub disk: String,
    pub partition_device: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub mountpoint: String,
    pub mountpoint_device_id: u64,
    pub mountpoint_inode: u64,
    pub phase: ProductionCreateMountRuntimePhase,
    pub mutation_may_have_started: bool,
    pub mount_may_have_changed: bool,
    pub fstab_may_have_changed: bool,
    pub events: Vec<ProductionCreateMountRuntimeJournalEvent>,
}

#[derive(Serialize)]
struct JournalIdPayload<'a> {
    schema_version: u32,
    mount_activation_id: &'a str,
    preflight_receipt_id: &'a str,
    launch_id: &'a str,
    create_activation_id: &'a str,
    filesystem_receipt_id: &'a str,
    create_journal_id: &'a str,
    create_launch_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    filesystem: &'a str,
    filesystem_uuid: &'a str,
    mountpoint: &'a str,
    mountpoint_device_id: u64,
    mountpoint_inode: u64,
}

impl ProductionCreateMountRuntimeJournal {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.journal_id == self.expected_journal_id()?)
    }

    fn expected_journal_id(&self) -> Result<String, serde_json::Error> {
        let payload = JournalIdPayload {
            schema_version: self.schema_version,
            mount_activation_id: &self.mount_activation_id,
            preflight_receipt_id: &self.preflight_receipt_id,
            launch_id: &self.launch_id,
            create_activation_id: &self.create_activation_id,
            filesystem_receipt_id: &self.filesystem_receipt_id,
            create_journal_id: &self.create_journal_id,
            create_launch_id: &self.create_launch_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            filesystem: &self.filesystem,
            filesystem_uuid: &self.filesystem_uuid,
            mountpoint: &self.mountpoint,
            mountpoint_device_id: self.mountpoint_device_id,
            mountpoint_inode: self.mountpoint_inode,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ProductionCreateMountRuntimeJournalStore {
    root: PathBuf,
}

impl Default for ProductionCreateMountRuntimeJournalStore {
    fn default() -> Self {
        Self {
            root: PathBuf::from(PRODUCTION_CREATE_MOUNT_RUNTIME_JOURNAL_DIRECTORY),
        }
    }
}

impl ProductionCreateMountRuntimeJournalStore {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(
        &self,
        journal_id: &str,
    ) -> Result<ProductionCreateMountRuntimeJournal, ProductionCreateMountRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
        ensure_secure_directory(&self.root, false)?;
        let path = self.path_for(journal_id)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
        validate_journal_file_metadata(&path, &metadata)?;
        if metadata.len() > MAX_MOUNT_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionCreateMountRuntimeJournalError::TooLarge);
        }

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error(&path, source))?;
        let mut bytes = Vec::new();
        file.take(MAX_MOUNT_RUNTIME_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error(&path, source))?;
        if bytes.len() as u64 > MAX_MOUNT_RUNTIME_JOURNAL_BYTES {
            return Err(ProductionCreateMountRuntimeJournalError::TooLarge);
        }

        let journal: ProductionCreateMountRuntimeJournal = serde_json::from_slice(&bytes)?;
        if journal.journal_id != journal_id {
            return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
                "journal ID does not match requested durable record".into(),
            ));
        }
        validate_journal(&journal)?;
        Ok(journal)
    }

    fn persist_new(
        &self,
        journal: &ProductionCreateMountRuntimeJournal,
    ) -> Result<PathBuf, ProductionCreateMountRuntimeJournalError> {
        validate_journal(journal)?;
        ensure_secure_directory(&self.root, true)?;
        let final_path = self.path_for(&journal.journal_id)?;
        if final_path.exists() {
            return Err(ProductionCreateMountRuntimeJournalError::AlreadyExists(
                journal.journal_id.clone(),
            ));
        }
        write_atomic_new(&self.root, &final_path, journal)?;
        Ok(final_path)
    }

    fn persist(
        &self,
        journal: &ProductionCreateMountRuntimeJournal,
    ) -> Result<PathBuf, ProductionCreateMountRuntimeJournalError> {
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
    ) -> Result<PathBuf, ProductionCreateMountRuntimeJournalError> {
        validate_digest(journal_id, "journal ID")?;
        Ok(self.root.join(format!("{journal_id}.json")))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateMountRuntimeJournalError {
    #[error("production create mount runtime journal feature is not compiled")]
    FeatureDisabled,
    #[error("mount activation/preflight/launch integrity is invalid")]
    AuthorizationInvalid,
    #[error("mount runtime journal bindings do not match the frozen launch chain")]
    BindingMismatch,
    #[error("mount runtime journal record is structurally invalid: {0}")]
    InvalidRecord(String),
    #[error("mount runtime journal transition is invalid from {from:?} via {transition:?}")]
    InvalidTransition {
        from: ProductionCreateMountRuntimePhase,
        transition: ProductionCreateMountRuntimeTransition,
    },
    #[error("mount runtime journal already exists: {0}")]
    AlreadyExists(String),
    #[error("mount runtime journal path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("mount runtime journal directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("mount runtime journal exceeds maximum record size")]
    TooLarge,
    #[error("mount runtime journal JSON is invalid: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("mount runtime journal I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> ProductionCreateMountRuntimeJournalError {
    ProductionCreateMountRuntimeJournalError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn validate_digest(
    value: &str,
    label: &str,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
            format!("{label} is not a lowercase SHA-256 hex digest"),
        ));
    }
    Ok(())
}

fn ensure_secure_directory(
    root: &Path,
    create: bool,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ProductionCreateMountRuntimeJournalError::UnsafeDirectory(
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
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ProductionCreateMountRuntimeJournalError::UnsafeDirectory(
                    root.to_path_buf(),
                ));
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(ProductionCreateMountRuntimeJournalError::UnsafeDirectory(
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
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(ProductionCreateMountRuntimeJournalError::UnsafePath(
            path.to_path_buf(),
        ));
    }
    Ok(())
}

fn encode_journal(
    journal: &ProductionCreateMountRuntimeJournal,
) -> Result<Vec<u8>, ProductionCreateMountRuntimeJournalError> {
    let mut bytes = serde_json::to_vec(journal)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_MOUNT_RUNTIME_JOURNAL_BYTES {
        return Err(ProductionCreateMountRuntimeJournalError::TooLarge);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(path, source))
}

fn sync_parent(path: &Path) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    let parent = path
        .parent()
        .ok_or_else(|| ProductionCreateMountRuntimeJournalError::UnsafeDirectory(path.to_path_buf()))?;
    sync_directory(parent)
}

fn temp_path(
    root: &Path,
    final_path: &Path,
) -> Result<PathBuf, ProductionCreateMountRuntimeJournalError> {
    let name = final_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ProductionCreateMountRuntimeJournalError::UnsafePath(final_path.to_path_buf()))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    Ok(root.join(format!(".{name}.tmp-{}-{sequence}", std::process::id())))
}

fn write_atomic_new(
    root: &Path,
    final_path: &Path,
    journal: &ProductionCreateMountRuntimeJournal,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
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
                return Err(ProductionCreateMountRuntimeJournalError::AlreadyExists(
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
    journal: &ProductionCreateMountRuntimeJournal,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
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
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    launch: &ProductionCreateMountRuntimeLaunchSpec,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    if activation.schema_version != 1
        || preflight.schema_version != 1
        || launch.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !preflight.runtime_ready
        || activation.execution_enabled
        || activation.mount_performed
        || activation.fstab_changed
        || preflight.execution_enabled
        || preflight.process_spawned
        || preflight.mount_performed
        || preflight.fstab_changed
        || launch.execution_enabled
        || launch.process_spawned
        || launch.mount_performed
        || launch.fstab_changed
        || launch.mtab_write_enabled
        || !launch.require_mountpoint_identity_revalidation_before_spawn
        || launch.mount.program != PrivilegedProgram::Mount
    {
        return Err(ProductionCreateMountRuntimeJournalError::AuthorizationInvalid);
    }

    if preflight.mount_activation_id != activation.mount_activation_id
        || launch.mount_activation_id != activation.mount_activation_id
        || launch.preflight_receipt_id != preflight.receipt_id
        || preflight.create_activation_id != activation.create_activation_id
        || preflight.filesystem_receipt_id != activation.filesystem_receipt_id
        || preflight.journal_id != activation.journal_id
        || preflight.create_launch_id != activation.launch_id
        || launch.disk != activation.disk
        || launch.partition_device != activation.partition_device
        || launch.filesystem != activation.filesystem
        || !launch
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || launch.mountpoint != activation.mountpoint
        || launch.fstab_source != activation.fstab_source
        || preflight.mountpoint_device_id != activation.mountpoint_device_id
        || preflight.mountpoint_inode != activation.mountpoint_inode
    {
        return Err(ProductionCreateMountRuntimeJournalError::BindingMismatch);
    }
    Ok(())
}

fn validate_journal(
    journal: &ProductionCreateMountRuntimeJournal,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    if journal.schema_version != 1
        || !journal.integrity_matches().unwrap_or(false)
        || !journal.disk.starts_with("/dev/")
        || !journal.partition_device.starts_with("/dev/")
        || !matches!(journal.filesystem.as_str(), "ext4" | "xfs")
        || journal.filesystem_uuid.is_empty()
        || journal.mountpoint.is_empty()
        || !journal.mountpoint.starts_with('/')
        || journal.fstab_may_have_changed
    {
        return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
            "journal identity or frozen mount scope is invalid".into(),
        ));
    }

    for (value, label) in [
        (journal.mount_activation_id.as_str(), "mount activation ID"),
        (journal.preflight_receipt_id.as_str(), "preflight receipt ID"),
        (journal.launch_id.as_str(), "launch ID"),
        (journal.create_activation_id.as_str(), "create activation ID"),
        (journal.filesystem_receipt_id.as_str(), "filesystem receipt ID"),
        (journal.create_journal_id.as_str(), "create journal ID"),
        (journal.create_launch_id.as_str(), "create launch ID"),
    ] {
        validate_digest(value, label)?;
    }

    let mut phase = ProductionCreateMountRuntimePhase::Prepared;
    for (index, event) in journal.events.iter().enumerate() {
        if event.sequence != index as u32 + 1 || event.from != phase {
            return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
                "journal event sequence or phase chain is invalid".into(),
            ));
        }
        let Some((expected_to, expected_code)) = transition_target_for_validation(event.from, event.to)
        else {
            return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
                "journal event contains an impossible phase transition".into(),
            ));
        };
        if expected_to != event.to || expected_code != event.code {
            return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
                "journal event code does not match its phase transition".into(),
            ));
        }
        phase = event.to;
    }
    if phase != journal.phase {
        return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
            "journal phase does not match its event chain".into(),
        ));
    }

    let mutation_expected = !matches!(journal.phase, ProductionCreateMountRuntimePhase::Prepared);
    if mutation_expected != journal.mutation_may_have_started
        || mutation_expected != journal.mount_may_have_changed
    {
        return Err(ProductionCreateMountRuntimeJournalError::InvalidRecord(
            "mount mutation flags do not match durable phase".into(),
        ));
    }
    Ok(())
}

fn transition_target_for_validation(
    from: ProductionCreateMountRuntimePhase,
    to: ProductionCreateMountRuntimePhase,
) -> Option<(ProductionCreateMountRuntimePhase, &'static str)> {
    use ProductionCreateMountRuntimePhase as P;
    match (from, to) {
        (P::Prepared, P::Mounting) => Some((P::Mounting, "mount-started")),
        (P::Mounting, P::MountedAwaitingVerification) => {
            Some((P::MountedAwaitingVerification, "mount-process-succeeded"))
        }
        (P::MountedAwaitingVerification, P::Completed) => {
            Some((P::Completed, "mount-rediscovery-verified"))
        }
        (P::Mounting, P::RecoveryRequired)
        | (P::MountedAwaitingVerification, P::RecoveryRequired) => {
            Some((P::RecoveryRequired, "recovery-required"))
        }
        _ => None,
    }
}

fn transition_target(
    phase: ProductionCreateMountRuntimePhase,
    transition: ProductionCreateMountRuntimeTransition,
) -> Option<(ProductionCreateMountRuntimePhase, &'static str)> {
    use ProductionCreateMountRuntimePhase as P;
    use ProductionCreateMountRuntimeTransition as T;
    match (phase, transition) {
        (P::Prepared, T::BeginMount) => Some((P::Mounting, "mount-started")),
        (P::Mounting, T::MountProcessSucceeded) => {
            Some((P::MountedAwaitingVerification, "mount-process-succeeded"))
        }
        (P::MountedAwaitingVerification, T::MountRediscoveryVerified) => {
            Some((P::Completed, "mount-rediscovery-verified"))
        }
        (P::Mounting, T::RecoveryRequired)
        | (P::MountedAwaitingVerification, T::RecoveryRequired) => {
            Some((P::RecoveryRequired, "recovery-required"))
        }
        _ => None,
    }
}

fn apply_transition(
    journal: &mut ProductionCreateMountRuntimeJournal,
    transition: ProductionCreateMountRuntimeTransition,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
    let from = journal.phase;
    let (to, code) = transition_target(from, transition)
        .ok_or(ProductionCreateMountRuntimeJournalError::InvalidTransition { from, transition })?;
    journal.phase = to;
    journal.mutation_may_have_started = true;
    journal.mount_may_have_changed = true;
    journal.events.push(ProductionCreateMountRuntimeJournalEvent {
        sequence: journal.events.len() as u32 + 1,
        from,
        to,
        code: code.into(),
    });
    validate_journal(journal)
}

pub fn build_production_create_mount_runtime_journal(
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    launch: &ProductionCreateMountRuntimeLaunchSpec,
) -> Result<ProductionCreateMountRuntimeJournal, ProductionCreateMountRuntimeJournalError> {
    if !PRODUCTION_CREATE_MOUNT_RUNTIME_JOURNAL_COMPILED {
        return Err(ProductionCreateMountRuntimeJournalError::FeatureDisabled);
    }
    validate_authorization(activation, preflight, launch)?;

    let mut journal = ProductionCreateMountRuntimeJournal {
        schema_version: 1,
        journal_id: String::new(),
        mount_activation_id: activation.mount_activation_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        launch_id: launch.launch_id.clone(),
        create_activation_id: activation.create_activation_id.clone(),
        filesystem_receipt_id: activation.filesystem_receipt_id.clone(),
        create_journal_id: activation.journal_id.clone(),
        create_launch_id: activation.launch_id.clone(),
        disk: activation.disk.clone(),
        partition_device: activation.partition_device.clone(),
        filesystem: activation.filesystem.clone(),
        filesystem_uuid: activation.filesystem_uuid.clone(),
        mountpoint: activation.mountpoint.clone(),
        mountpoint_device_id: activation.mountpoint_device_id,
        mountpoint_inode: activation.mountpoint_inode,
        phase: ProductionCreateMountRuntimePhase::Prepared,
        mutation_may_have_started: false,
        mount_may_have_changed: false,
        fstab_may_have_changed: false,
        events: Vec::new(),
    };
    journal.journal_id = journal.expected_journal_id()?;
    validate_journal(&journal)?;
    Ok(journal)
}

pub fn persist_new_production_create_mount_runtime_journal(
    store: &ProductionCreateMountRuntimeJournalStore,
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    launch: &ProductionCreateMountRuntimeLaunchSpec,
) -> Result<ProductionCreateMountRuntimeJournal, ProductionCreateMountRuntimeJournalError> {
    let journal = build_production_create_mount_runtime_journal(activation, preflight, launch)?;
    store.persist_new(&journal)?;
    Ok(journal)
}

pub(crate) fn persist_production_create_mount_runtime_transition(
    store: &ProductionCreateMountRuntimeJournalStore,
    journal: &mut ProductionCreateMountRuntimeJournal,
    transition: ProductionCreateMountRuntimeTransition,
) -> Result<(), ProductionCreateMountRuntimeJournalError> {
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

    fn fixture_journal() -> ProductionCreateMountRuntimeJournal {
        let mut journal = ProductionCreateMountRuntimeJournal {
            schema_version: 1,
            journal_id: String::new(),
            mount_activation_id: digest('a'),
            preflight_receipt_id: digest('b'),
            launch_id: digest('c'),
            create_activation_id: digest('d'),
            filesystem_receipt_id: digest('e'),
            create_journal_id: digest('f'),
            create_launch_id: digest('1'),
            disk: "/dev/loop7".into(),
            partition_device: "/dev/loop7p1".into(),
            filesystem: "ext4".into(),
            filesystem_uuid: "123e4567-e89b-12d3-a456-426614174000".into(),
            mountpoint: "/mnt/data".into(),
            mountpoint_device_id: 1,
            mountpoint_inode: 2,
            phase: ProductionCreateMountRuntimePhase::Prepared,
            mutation_may_have_started: false,
            mount_may_have_changed: false,
            fstab_may_have_changed: false,
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
            "lsm-create-mount-journal-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn mount_journal_requires_verification_before_completion() {
        let mut journal = fixture_journal();
        apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::BeginMount,
        )
        .unwrap();
        assert!(apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::MountRediscoveryVerified,
        )
        .is_err());
        apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::MountProcessSucceeded,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::MountRediscoveryVerified,
        )
        .unwrap();
        assert_eq!(journal.phase, ProductionCreateMountRuntimePhase::Completed);
        assert!(!journal.fstab_may_have_changed);
    }

    #[test]
    fn recovery_is_only_available_after_mount_boundary() {
        let mut journal = fixture_journal();
        assert!(apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::RecoveryRequired,
        )
        .is_err());
        apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::BeginMount,
        )
        .unwrap();
        apply_transition(
            &mut journal,
            ProductionCreateMountRuntimeTransition::RecoveryRequired,
        )
        .unwrap();
        assert_eq!(
            journal.phase,
            ProductionCreateMountRuntimePhase::RecoveryRequired
        );
    }

    #[test]
    fn durable_transition_updates_memory_after_persist() {
        let root = temp_root("persist");
        let store = ProductionCreateMountRuntimeJournalStore::at(&root);
        let mut journal = fixture_journal();
        store.persist_new(&journal).unwrap();
        persist_production_create_mount_runtime_transition(
            &store,
            &mut journal,
            ProductionCreateMountRuntimeTransition::BeginMount,
        )
        .unwrap();
        assert_eq!(journal.phase, ProductionCreateMountRuntimePhase::Mounting);
        assert_eq!(
            store.load(&journal.journal_id).unwrap().phase,
            ProductionCreateMountRuntimePhase::Mounting
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_new_journal_is_rejected() {
        let root = temp_root("duplicate");
        let store = ProductionCreateMountRuntimeJournalStore::at(&root);
        let journal = fixture_journal();
        store.persist_new(&journal).unwrap();
        assert!(matches!(
            store.persist_new(&journal),
            Err(ProductionCreateMountRuntimeJournalError::AlreadyExists(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_MOUNT_RUNTIME_JOURNAL_COMPILED,
            cfg!(feature = "production-create-mount-runtime-journal")
        );
    }
}
