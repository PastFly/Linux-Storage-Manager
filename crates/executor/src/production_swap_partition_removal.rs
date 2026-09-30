use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use lsm_core::{HostSnapshot, PartitionRecord};
use lsm_discovery::discover_snapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    production_swap_persistent_config::revalidate_production_swap_persistent_config_receipt,
    revalidate_pinned_production_swap_replacement_consent, HostStorageLock,
    PinnedProductionSwapReplacementConsent, ProductionSwapPersistentConfigReceipt,
    ProductionSwapReplacementActivationIntent, ProductionSwapReplacementConsentLeaseError,
    ProductionSwapRuntimeExecutionReceipt, ProductionSwapRuntimeJournal,
    ProductionSwapRuntimeJournalError, ProductionSwapRuntimeJournalStore,
    ProductionSwapRuntimePhase,
};

pub const PRODUCTION_SWAP_PARTITION_REMOVAL_PREFLIGHT_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-partition-removal-preflight");
const MAX_PARTITION_BACKUP_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapPartitionRemovalPreflight {
    pub schema_version: u32,
    pub preflight_id: String,
    pub journal_id: String,
    pub activation_id: String,
    pub persistent_config_receipt_id: String,
    pub disk: String,
    pub table_label: String,
    pub table_id: Option<String>,
    pub sector_size_bytes: u64,
    pub retiring_swap_device: String,
    pub retiring_swap_partition_number: u32,
    pub retiring_swap_start_sector: u64,
    pub retiring_swap_size_sectors: u64,
    pub extended_partition_device: String,
    pub extended_partition_number: u32,
    pub extended_start_sector: u64,
    pub extended_size_sectors: u64,
    pub partition_backup_path: String,
    pub partition_backup_sha256: String,
    pub mutation_enabled: bool,
    pub partition_table_changed: bool,
}

#[derive(Serialize)]
struct PreflightDigestPayload<'a> {
    schema_version: u32,
    journal_id: &'a str,
    activation_id: &'a str,
    persistent_config_receipt_id: &'a str,
    disk: &'a str,
    table_label: &'a str,
    table_id: &'a Option<String>,
    sector_size_bytes: u64,
    retiring_swap_device: &'a str,
    retiring_swap_partition_number: u32,
    retiring_swap_start_sector: u64,
    retiring_swap_size_sectors: u64,
    extended_partition_device: &'a str,
    extended_partition_number: u32,
    extended_start_sector: u64,
    extended_size_sectors: u64,
    partition_backup_path: &'a str,
    partition_backup_sha256: &'a str,
    mutation_enabled: bool,
    partition_table_changed: bool,
}

impl ProductionSwapPartitionRemovalPreflight {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.preflight_id == self.expected_preflight_id()?)
    }

    pub(crate) fn expected_preflight_id(&self) -> Result<String, serde_json::Error> {
        let payload = PreflightDigestPayload {
            schema_version: self.schema_version,
            journal_id: &self.journal_id,
            activation_id: &self.activation_id,
            persistent_config_receipt_id: &self.persistent_config_receipt_id,
            disk: &self.disk,
            table_label: &self.table_label,
            table_id: &self.table_id,
            sector_size_bytes: self.sector_size_bytes,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_partition_number: self.retiring_swap_partition_number,
            retiring_swap_start_sector: self.retiring_swap_start_sector,
            retiring_swap_size_sectors: self.retiring_swap_size_sectors,
            extended_partition_device: &self.extended_partition_device,
            extended_partition_number: self.extended_partition_number,
            extended_start_sector: self.extended_start_sector,
            extended_size_sectors: self.extended_size_sectors,
            partition_backup_path: &self.partition_backup_path,
            partition_backup_sha256: &self.partition_backup_sha256,
            mutation_enabled: self.mutation_enabled,
            partition_table_changed: self.partition_table_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapPartitionRemovalPreflightError {
    #[error("production swap partition-removal preflight feature is not compiled")]
    FeatureDisabled,
    #[error("production swap partition-removal preflight requires root")]
    RootRequired,
    #[error("persistent-config/runtime/journal binding is invalid")]
    BindingMismatch,
    #[error("swap runtime journal is not the exact persisted PersistentConfigUpdated record")]
    JournalMismatch,
    #[error("pinned swap consent revalidation failed: {0}")]
    Consent(#[from] ProductionSwapReplacementConsentLeaseError),
    #[error("fresh storage discovery failed: {0}")]
    Discovery(String),
    #[error("retiring swap partition geometry is absent, ambiguous or changed")]
    RetiringSwapGeometryMismatch,
    #[error(
        "extended partition geometry is absent, ambiguous or contains another logical partition"
    )]
    ExtendedPartitionGeometryMismatch,
    #[error("partition-table backup is unsafe or invalid")]
    BackupMismatch,
    #[error("partition-removal preflight I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("partition-removal preflight serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("swap runtime journal access failed: {0}")]
    Journal(#[from] ProductionSwapRuntimeJournalError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactRemovalGeometry {
    table_label: String,
    table_id: Option<String>,
    sector_size_bytes: u64,
    swap: PartitionRecord,
    swap_number: u32,
    extended: PartitionRecord,
    extended_number: u32,
}

fn io_error(path: &Path, source: io::Error) -> ProductionSwapPartitionRemovalPreflightError {
    ProductionSwapPartitionRemovalPreflightError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn parse_dos_type(raw: &str) -> Option<u8> {
    let trimmed = raw.trim();
    let value = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if value.is_empty() || value.len() > 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u8::from_str_radix(value, 16).ok()
}

fn partition_number(partition: &str, disk: &str) -> Option<u32> {
    let suffix = partition.strip_prefix(disk)?;
    let digits = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        suffix.strip_prefix('p')?
    } else {
        suffix.strip_prefix('p').unwrap_or(suffix)
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = digits.parse::<u32>().ok()?;
    (number > 0).then_some(number)
}

fn contains(container: &PartitionRecord, child: &PartitionRecord) -> bool {
    let Some(container_end) = container.start_sector.checked_add(container.size_sectors) else {
        return false;
    };
    let Some(child_end) = child.start_sector.checked_add(child.size_sectors) else {
        return false;
    };
    child.start_sector >= container.start_sector && child_end <= container_end
}

fn exact_removal_geometry(
    snapshot: &HostSnapshot,
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<ExactRemovalGeometry, ProductionSwapPartitionRemovalPreflightError> {
    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == activation.disk)
        .collect::<Vec<_>>();
    let [table] = tables.as_slice() else {
        return Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch);
    };
    if table.label.as_deref() != Some("dos") {
        return Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch);
    }
    let sector = table
        .sector_size_bytes
        .filter(|sector| matches!(*sector, 512 | 4096))
        .ok_or(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch)?;

    let swaps = table
        .partitions
        .iter()
        .filter(|record| record.node == activation.retiring_swap_device)
        .collect::<Vec<_>>();
    let [swap] = swaps.as_slice() else {
        return Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch);
    };
    if parse_dos_type(swap.partition_type.as_deref().unwrap_or("")) != Some(0x82)
        || swap
            .size_sectors
            .checked_mul(sector)
            .filter(|bytes| *bytes == activation.retiring_swap_bytes)
            .is_none()
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch);
    }
    let swap_number = partition_number(&swap.node, &activation.disk)
        .ok_or(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch)?;
    if swap_number < 5 {
        return Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch);
    }

    let extended = table
        .partitions
        .iter()
        .filter(|record| {
            matches!(
                parse_dos_type(record.partition_type.as_deref().unwrap_or("")),
                Some(0x05) | Some(0x0f) | Some(0x85)
            ) && contains(record, swap)
        })
        .collect::<Vec<_>>();
    let [extended] = extended.as_slice() else {
        return Err(
            ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch,
        );
    };
    let extended_number = partition_number(&extended.node, &activation.disk)
        .ok_or(ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch)?;
    if extended_number >= 5 || extended_number == swap_number {
        return Err(
            ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch,
        );
    }

    if table.partitions.iter().any(|record| {
        record.node != extended.node && record.node != swap.node && contains(extended, record)
    }) {
        return Err(
            ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch,
        );
    }

    Ok(ExactRemovalGeometry {
        table_label: "dos".to_owned(),
        table_id: table.id.clone(),
        sector_size_bytes: sector,
        swap: (*swap).clone(),
        swap_number,
        extended: (*extended).clone(),
        extended_number,
    })
}

fn validate_bindings(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    persistent: &ProductionSwapPersistentConfigReceipt,
    journal: &ProductionSwapRuntimeJournal,
) -> Result<(), ProductionSwapPartitionRemovalPreflightError> {
    if !activation.integrity_matches().unwrap_or(false)
        || !runtime.integrity_matches().unwrap_or(false)
        || !persistent.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || journal.phase != ProductionSwapRuntimePhase::PersistentConfigUpdated
        || !journal.mutation_may_have_started
        || !journal.persistent_config_may_have_changed
        || journal.partition_table_may_have_changed
        || journal.activation_id != activation.activation_id
        || journal.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || journal.retiring_swap_device != activation.retiring_swap_device
        || journal.retiring_swap_bytes != activation.retiring_swap_bytes
        || journal.retiring_swap_priority != activation.retiring_swap_priority
        || journal.swapfile_path != activation.swapfile_path
        || runtime.journal_id != journal.journal_id
        || runtime.launch_id != journal.launch_id
        || runtime.old_swap_active
        || !runtime.replacement_swap_active
        || !persistent.persistent_config_updated
        || persistent.partition_table_changed
        || persistent.journal_id != journal.journal_id
        || persistent.retiring_swap_source != activation.persistent_swap_source
        || persistent.replacement_swapfile != activation.swapfile_path
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::BindingMismatch);
    }
    Ok(())
}

fn ensure_secure_backup(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &ProductionSwapRuntimeJournal,
    disk: &str,
) -> Result<(PathBuf, String), ProductionSwapPartitionRemovalPreflightError> {
    let path = store.root().join(format!(
        "{}.pre-partition-removal.sfdisk",
        journal.journal_id
    ));

    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() == 0
                || metadata.len() > MAX_PARTITION_BACKUP_BYTES
            {
                return Err(ProductionSwapPartitionRemovalPreflightError::BackupMismatch);
            }
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|source| io_error(&path, source))?;
            let stdout = file.try_clone().map_err(|source| io_error(&path, source))?;
            let status = Command::new("sfdisk")
                .arg("--dump")
                .arg(disk)
                .stdin(Stdio::null())
                .stdout(Stdio::from(stdout))
                .stderr(Stdio::null())
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .status()
                .map_err(|source| io_error(Path::new("sfdisk"), source))?;
            if !status.success() {
                let _ = fs::remove_file(&path);
                return Err(ProductionSwapPartitionRemovalPreflightError::BackupMismatch);
            }
            file.sync_all().map_err(|source| io_error(&path, source))?;
            File::open(store.root())
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error(store.root(), source))?;
        }
        Err(source) => return Err(io_error(&path, source)),
    }

    let metadata = fs::symlink_metadata(&path).map_err(|source| io_error(&path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_PARTITION_BACKUP_BYTES
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::BackupMismatch);
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|source| io_error(&path, source))?
        .take(MAX_PARTITION_BACKUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(&path, source))?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_PARTITION_BACKUP_BYTES
        || !String::from_utf8_lossy(&bytes).contains(disk)
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::BackupMismatch);
    }
    Ok((path, sha256(&bytes)))
}

/// Freeze the exact old logical-swap plus DOS extended-container removal boundary.
///
/// This function is intentionally non-mutating. It may only discover current
/// state and capture an fsynced sfdisk dump recovery artifact. The runtime
/// journal remains PersistentConfigUpdated.
pub fn prepare_production_swap_partition_removal(
    _host_lock: &HostStorageLock,
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    persistent: &ProductionSwapPersistentConfigReceipt,
    consent: &PinnedProductionSwapReplacementConsent,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &ProductionSwapRuntimeJournal,
) -> Result<ProductionSwapPartitionRemovalPreflight, ProductionSwapPartitionRemovalPreflightError> {
    if !PRODUCTION_SWAP_PARTITION_REMOVAL_PREFLIGHT_COMPILED {
        return Err(ProductionSwapPartitionRemovalPreflightError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionSwapPartitionRemovalPreflightError::RootRequired);
    }

    validate_bindings(activation, runtime, persistent, journal)?;
    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionSwapPartitionRemovalPreflightError::JournalMismatch);
    }
    let _consent = revalidate_pinned_production_swap_replacement_consent(activation, consent)?;
    revalidate_production_swap_persistent_config_receipt(activation, persistent)
        .map_err(|_| ProductionSwapPartitionRemovalPreflightError::BindingMismatch)?;

    let snapshot = discover_snapshot().map_err(|error| {
        ProductionSwapPartitionRemovalPreflightError::Discovery(error.to_string())
    })?;
    if snapshot
        .swaps
        .iter()
        .any(|entry| entry.name == activation.retiring_swap_device)
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::BindingMismatch);
    }
    let replacements = snapshot
        .swaps
        .iter()
        .filter(|entry| entry.name == activation.swapfile_path)
        .collect::<Vec<_>>();
    if replacements.len() != 1
        || replacements[0].priority != activation.retiring_swap_priority
        || replacements[0].size_bytes != runtime.replacement_reported_swap_bytes
    {
        return Err(ProductionSwapPartitionRemovalPreflightError::BindingMismatch);
    }

    let geometry = exact_removal_geometry(&snapshot, activation)?;
    let (backup_path, backup_sha256) = ensure_secure_backup(store, journal, &activation.disk)?;

    let mut result = ProductionSwapPartitionRemovalPreflight {
        schema_version: 1,
        preflight_id: String::new(),
        journal_id: journal.journal_id.clone(),
        activation_id: activation.activation_id.clone(),
        persistent_config_receipt_id: persistent.receipt_id.clone(),
        disk: activation.disk.clone(),
        table_label: geometry.table_label,
        table_id: geometry.table_id,
        sector_size_bytes: geometry.sector_size_bytes,
        retiring_swap_device: geometry.swap.node.clone(),
        retiring_swap_partition_number: geometry.swap_number,
        retiring_swap_start_sector: geometry.swap.start_sector,
        retiring_swap_size_sectors: geometry.swap.size_sectors,
        extended_partition_device: geometry.extended.node.clone(),
        extended_partition_number: geometry.extended_number,
        extended_start_sector: geometry.extended.start_sector,
        extended_size_sectors: geometry.extended.size_sectors,
        partition_backup_path: backup_path.to_string_lossy().into_owned(),
        partition_backup_sha256: backup_sha256,
        mutation_enabled: false,
        partition_table_changed: false,
    };
    result.preflight_id = result.expected_preflight_id()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::PartitionTable;
    use serde_json::json;

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
            destination_available_bytes: 256 * 1024 * 1024,
            swapfile_mode: 0o600,
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    fn snapshot() -> HostSnapshot {
        serde_json::from_value(json!({
            "storage": {"block_devices":[]},
            "partition_tables":[{
                "device":"/dev/sda","label":"dos","id":"0x12345678","unit":"sectors",
                "first_lba":null,"last_lba":null,"sector_size_bytes":512,
                "partitions":[
                    {"node":"/dev/sda1","start_sector":2048,"size_sectors":700000,
                     "partition_type":"83","uuid":null,"name":null,"attrs":null,"bootable":false},
                    {"node":"/dev/sda2","start_sector":704048,"size_sectors":140000,
                     "partition_type":"05","uuid":null,"name":null,"attrs":null,"bootable":false},
                    {"node":"/dev/sda5","start_sector":706096,"size_sectors":131072,
                     "partition_type":"82","uuid":null,"name":null,"attrs":null,"bootable":false}
                ]
            }],
            "mounts":[],
            "fstab":[],
            "swaps":[],
            "lvm":null,
            "filesystem_preflight":[],
            "diagnostics":[],
            "collectors":[]
        }))
        .unwrap()
    }

    #[test]
    fn exact_dos_tail_swap_geometry_is_frozen() {
        let geometry = exact_removal_geometry(&snapshot(), &activation()).unwrap();
        assert_eq!(geometry.swap.node, "/dev/sda5");
        assert_eq!(geometry.swap_number, 5);
        assert_eq!(geometry.extended.node, "/dev/sda2");
        assert_eq!(geometry.extended_number, 2);
        assert_eq!(geometry.sector_size_bytes, 512);
    }

    #[test]
    fn another_logical_partition_inside_extended_container_blocks_removal() {
        let mut snapshot = snapshot();
        let table: &mut PartitionTable = &mut snapshot.partition_tables[0];
        table.partitions.push(PartitionRecord {
            node: "/dev/sda6".into(),
            start_sector: 838000,
            size_sectors: 2048,
            partition_type: Some("83".into()),
            uuid: None,
            name: None,
            attrs: None,
            bootable: Some(false),
        });
        assert!(matches!(
            exact_removal_geometry(&snapshot, &activation()),
            Err(ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch)
        ));
    }

    #[test]
    fn changed_swap_size_blocks_removal() {
        let mut snapshot = snapshot();
        snapshot.partition_tables[0].partitions[2].size_sectors -= 1;
        assert!(matches!(
            exact_removal_geometry(&snapshot, &activation()),
            Err(ProductionSwapPartitionRemovalPreflightError::RetiringSwapGeometryMismatch)
        ));
    }

    #[test]
    fn extended_partition_that_does_not_contain_swap_is_rejected() {
        let mut snapshot = snapshot();
        snapshot.partition_tables[0].partitions[1].size_sectors = 1024;
        assert!(matches!(
            exact_removal_geometry(&snapshot, &activation()),
            Err(ProductionSwapPartitionRemovalPreflightError::ExtendedPartitionGeometryMismatch)
        ));
    }
}
