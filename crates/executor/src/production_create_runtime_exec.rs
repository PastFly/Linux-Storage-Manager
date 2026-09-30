use std::thread;
use std::time::Duration;

use lsm_core::{CollectorState, HostSnapshot, NodeKind};
use lsm_discovery::discover_snapshot;
use lsm_planner::CreatePartitionTablePolicy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_exec::execute_descriptor_stage;
use crate::production_create_journal::persist_production_create_runtime_transition;
use crate::{
    revalidate_pinned_production_create_consent, DescriptorExecOutcome, HostStorageLock,
    PinnedProductionCreateConsent, PinnedProductionCreateTools, PrivilegedDescriptorExecError,
    PrivilegedProgram, ProductionCreateActivationIntent, ProductionCreateConsentLeaseError,
    ProductionCreateExecutionPermit, ProductionCreateRuntimeJournal,
    ProductionCreateRuntimeJournalError, ProductionCreateRuntimeJournalStore,
    ProductionCreateRuntimeLaunchSpec, ProductionCreateRuntimePhase,
    ProductionCreateRuntimePreflightReceipt, ProductionCreateRuntimeTransition,
    ProductionCreateToolLeaseError,
};

pub const PRODUCTION_CREATE_RUNTIME_EXECUTION_COMPILED: bool =
    cfg!(feature = "production-create-runtime-execution");

const POST_CREATE_REDISCOVERY_ATTEMPTS: usize = 20;
const POST_CREATE_REDISCOVERY_DELAY: Duration = Duration::from_millis(50);
const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";
const GPT_LINUX_FILESYSTEM_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
const DOS_LINUX_FILESYSTEM_TYPE: &str = "83";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreatePartitionExecutionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub journal_id: String,
    pub launch_id: String,
    pub disk: String,
    pub partition_device: String,
    pub partition_table: String,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub partition_mapped_verified: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    journal_id: &'a str,
    launch_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    partition_table: &'a str,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    partition_mapped_verified: bool,
    filesystem_formatted: bool,
}

impl ProductionCreatePartitionExecutionReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            journal_id: &self.journal_id,
            launch_id: &self.launch_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            partition_table: &self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            partition_mapped_verified: self.partition_mapped_verified,
            filesystem_formatted: self.filesystem_formatted,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreatePartitionExecutionError {
    #[error("production create partition execution feature is not compiled")]
    FeatureDisabled,
    #[error("production create partition crossing requires root")]
    RootRequired,
    #[error("create partition authorization chain is invalid or no longer exact")]
    AuthorizationInvalid,
    #[error("create runtime journal is not the exact persisted Prepared record")]
    JournalMismatch,
    #[error("pinned create consent revalidation failed: {0}")]
    Consent(#[from] ProductionCreateConsentLeaseError),
    #[error("pinned create executable revalidation failed: {0}")]
    ToolLease(#[from] ProductionCreateToolLeaseError),
    #[error("create partition descriptor execution failed: {0}")]
    Descriptor(#[from] PrivilegedDescriptorExecError),
    #[error("create runtime journal transition failed: {0}")]
    Journal(#[from] ProductionCreateRuntimeJournalError),
    #[error("{stage} exited with status {exit_code}: {stderr}")]
    StageFailed {
        stage: &'static str,
        exit_code: i32,
        stderr: String,
    },
    #[error("post-partition storage rediscovery did not converge: {0}")]
    Rediscovery(String),
    #[error("fresh partition table or mapped partition does not match the frozen create geometry")]
    PartitionGeometryMismatch,
    #[error("fresh mapped partition unexpectedly contains filesystem, mount, fstab or swap state")]
    UnexpectedPartitionUse,
    #[error(
        "create partition crossing failed and durable RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}"
    )]
    RecoveryPersistenceFailed { runtime: String, journal: String },
    #[error("create partition execution receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn expected_partition_table(policy: CreatePartitionTablePolicy) -> &'static str {
    match policy {
        CreatePartitionTablePolicy::Gpt => "gpt",
        CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn expected_partition_type(policy: CreatePartitionTablePolicy) -> &'static str {
    match policy {
        CreatePartitionTablePolicy::Gpt => GPT_LINUX_FILESYSTEM_TYPE,
        CreatePartitionTablePolicy::Dos => DOS_LINUX_FILESYSTEM_TYPE,
    }
}

fn bounded_stderr(outcome: &DescriptorExecOutcome) -> String {
    const LIMIT: usize = 4096;
    String::from_utf8_lossy(&outcome.stderr[..outcome.stderr.len().min(LIMIT)]).into_owned()
}

fn validate_launch_stage_contract(
    activation: &ProductionCreateActivationIntent,
    launch: &ProductionCreateRuntimeLaunchSpec,
) -> Result<(), ProductionCreatePartitionExecutionError> {
    let expected_sfdisk = [
        "sfdisk",
        "--lock=yes",
        "--no-reread",
        "--no-tell-kernel",
        activation.disk.as_str(),
    ];
    let expected_partx = ["partx", "--add", "--nr", "1", activation.disk.as_str()];

    let expected_stdin_sha256 = format!("{:x}", Sha256::digest(launch.sfdisk_script.as_bytes()));

    if launch.sfdisk.program != PrivilegedProgram::Sfdisk
        || launch.partx.program != PrivilegedProgram::Partx
        || launch
            .sfdisk
            .argv
            .iter()
            .map(String::as_str)
            .ne(expected_sfdisk)
        || launch
            .partx
            .argv
            .iter()
            .map(String::as_str)
            .ne(expected_partx)
        || launch.fixed_path != FIXED_PATH
        || launch.fixed_locale != FIXED_LOCALE
        || launch.descriptor_exec_api != "fexecve"
        || launch.sfdisk.stdin_len != launch.sfdisk_script.len() as u64
        || launch.sfdisk.stdin_sha256.as_deref() != Some(expected_stdin_sha256.as_str())
        || launch.partx.stdin_len != 0
        || launch.partx.stdin_sha256.is_some()
    {
        return Err(ProductionCreatePartitionExecutionError::AuthorizationInvalid);
    }
    Ok(())
}

fn validate_crossing(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    launch: &ProductionCreateRuntimeLaunchSpec,
    journal: &ProductionCreateRuntimeJournal,
) -> Result<(), ProductionCreatePartitionExecutionError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || preflight.schema_version != 1
        || launch.schema_version != 1
        || journal.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !permit.compile_feature_enabled
        || !preflight.runtime_ready
        || activation.execution_enabled
        || permit.mutation_enabled
        || permit.process_spawned
        || preflight.mutation_enabled
        || preflight.process_spawned
        || launch.mutation_enabled
        || launch.process_spawned
        || activation.partition_table_changed
        || activation.filesystem_formatted
        || permit.partition_table_changed
        || permit.filesystem_formatted
        || preflight.partition_table_changed
        || preflight.filesystem_formatted
        || launch.partition_table_changed
        || launch.filesystem_formatted
        || !launch.require_partition_rediscovery_before_mkfs
        || journal.phase != ProductionCreateRuntimePhase::Prepared
        || journal.mutation_may_have_started
        || journal.partition_table_may_have_changed
        || journal.filesystem_may_have_changed
    {
        return Err(ProductionCreatePartitionExecutionError::AuthorizationInvalid);
    }

    if permit.activation_id != activation.activation_id
        || preflight.activation_id != activation.activation_id
        || launch.activation_id != activation.activation_id
        || journal.activation_id != activation.activation_id
        || preflight.execution_permit_id != permit.permit_id
        || launch.execution_permit_id != permit.permit_id
        || journal.execution_permit_id != permit.permit_id
        || launch.preflight_receipt_id != preflight.receipt_id
        || journal.preflight_receipt_id != preflight.receipt_id
        || journal.launch_id != launch.launch_id
        || permit.create_intent_id != activation.create_intent_id
        || preflight.create_intent_id != activation.create_intent_id
        || launch.create_intent_id != activation.create_intent_id
        || journal.create_intent_id != activation.create_intent_id
        || permit.disk != activation.disk
        || preflight.disk != activation.disk
        || launch.disk != activation.disk
        || journal.disk != activation.disk
        || permit.partition_table != activation.partition_table
        || preflight.partition_table != activation.partition_table
        || launch.partition_table != activation.partition_table
        || journal.partition_table != expected_partition_table(activation.partition_table)
        || permit.partition_start_sector != activation.partition_start_sector
        || preflight.partition_start_sector != activation.partition_start_sector
        || launch.partition_start_sector != activation.partition_start_sector
        || journal.partition_start_sector != activation.partition_start_sector
        || permit.partition_sector_count != activation.partition_sector_count
        || preflight.partition_sector_count != activation.partition_sector_count
        || launch.partition_sector_count != activation.partition_sector_count
        || journal.partition_sector_count != activation.partition_sector_count
        || permit.partition_size_bytes != activation.partition_size_bytes
        || preflight.partition_size_bytes != activation.partition_size_bytes
        || launch.partition_size_bytes != activation.partition_size_bytes
        || journal.partition_size_bytes != activation.partition_size_bytes
        || permit.filesystem != activation.filesystem
        || preflight.filesystem != activation.filesystem
        || launch.filesystem != activation.filesystem
        || journal.filesystem != activation.filesystem
        || journal.partition_device != launch.partition_device
    {
        return Err(ProductionCreatePartitionExecutionError::AuthorizationInvalid);
    }

    validate_launch_stage_contract(activation, launch)
}

fn run_stage(
    stage: &'static str,
    file: &std::fs::File,
    launch_stage: &crate::ProductionCreateLaunchStage,
    fixed_path: &str,
    fixed_locale: &str,
    stdin_payload: Option<&[u8]>,
) -> Result<DescriptorExecOutcome, ProductionCreatePartitionExecutionError> {
    let outcome = execute_descriptor_stage(
        file,
        launch_stage.program,
        &launch_stage.argv,
        fixed_path,
        fixed_locale,
        stdin_payload,
    )?;
    if outcome.exit_code != 0 {
        return Err(ProductionCreatePartitionExecutionError::StageFailed {
            stage,
            exit_code: outcome.exit_code,
            stderr: bounded_stderr(&outcome),
        });
    }
    Ok(outcome)
}

fn verify_partition_snapshot(
    activation: &ProductionCreateActivationIntent,
    launch: &ProductionCreateRuntimeLaunchSpec,
    snapshot: &HostSnapshot,
) -> Result<(), ProductionCreatePartitionExecutionError> {
    let collectors = snapshot
        .collectors
        .iter()
        .filter(|status| status.component == "partition_tables")
        .collect::<Vec<_>>();
    if collectors.len() != 1 || collectors[0].state != CollectorState::Complete {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }

    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == activation.disk)
        .collect::<Vec<_>>();
    if tables.len() != 1 {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }
    let table = tables[0];
    let expected_label = expected_partition_table(activation.partition_table);
    if table.label.as_deref() != Some(expected_label)
        || table.unit.as_deref() != Some("sectors")
        || table.sector_size_bytes != Some(activation.logical_sector_bytes)
        || table.partitions.len() != 1
    {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }
    let partition = &table.partitions[0];
    if partition.node != launch.partition_device
        || partition.start_sector != activation.partition_start_sector
        || partition.size_sectors != activation.partition_sector_count
        || partition.partition_type.as_deref().is_none_or(|value| {
            !value.eq_ignore_ascii_case(expected_partition_type(activation.partition_table))
        })
    {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }

    let disks = snapshot
        .storage
        .block_devices
        .iter()
        .filter(|device| device.path.as_deref() == Some(activation.disk.as_str()))
        .collect::<Vec<_>>();
    if disks.len() != 1 {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }
    let disk = disks[0];
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
        || disk.size_bytes != activation.disk_size_bytes
        || disk.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || disk.model != activation.disk_model
        || disk.serial != activation.disk_serial
        || disk.partition_table.as_deref() != Some(expected_label)
        || disk.children.len() != 1
    {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }

    let child = &disk.children[0];
    let expected_size = activation
        .partition_sector_count
        .checked_mul(activation.logical_sector_bytes)
        .ok_or(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch)?;
    if child.path.as_deref() != Some(launch.partition_device.as_str())
        || child.kind != NodeKind::Partition
        || child.size_bytes != expected_size
        || child.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || child.parent_kernel_name != disk.kernel_name
    {
        return Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch);
    }

    let mount_or_fstab = snapshot.mounts.iter().any(|mount| {
        mount.source.as_deref() == Some(activation.disk.as_str())
            || mount.source.as_deref() == Some(launch.partition_device.as_str())
    }) || snapshot
        .fstab
        .iter()
        .any(|entry| entry.source == activation.disk || entry.source == launch.partition_device);
    let swap_active = snapshot
        .swaps
        .iter()
        .any(|entry| entry.name == activation.disk || entry.name == launch.partition_device);
    if child.filesystem.is_some() || !child.mountpoints.is_empty() || mount_or_fstab || swap_active
    {
        return Err(ProductionCreatePartitionExecutionError::UnexpectedPartitionUse);
    }

    Ok(())
}

fn discover_exact_partition(
    activation: &ProductionCreateActivationIntent,
    launch: &ProductionCreateRuntimeLaunchSpec,
) -> Result<(), ProductionCreatePartitionExecutionError> {
    let mut last_error = None;
    for attempt in 0..POST_CREATE_REDISCOVERY_ATTEMPTS {
        match discover_snapshot() {
            Ok(snapshot) => match verify_partition_snapshot(activation, launch, &snapshot) {
                Ok(()) => return Ok(()),
                Err(error @ ProductionCreatePartitionExecutionError::UnexpectedPartitionUse) => {
                    return Err(error);
                }
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
        if attempt + 1 < POST_CREATE_REDISCOVERY_ATTEMPTS {
            thread::sleep(POST_CREATE_REDISCOVERY_DELAY);
        }
    }
    Err(ProductionCreatePartitionExecutionError::Rediscovery(
        last_error.unwrap_or_else(|| "fresh partition state was not observable".into()),
    ))
}

fn persist_recovery(
    store: &ProductionCreateRuntimeJournalStore,
    journal: &mut ProductionCreateRuntimeJournal,
    runtime: ProductionCreatePartitionExecutionError,
) -> ProductionCreatePartitionExecutionError {
    match persist_production_create_runtime_transition(
        store,
        journal,
        ProductionCreateRuntimeTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => ProductionCreatePartitionExecutionError::RecoveryPersistenceFailed {
            runtime: runtime.to_string(),
            journal: journal_error.to_string(),
        },
    }
}

fn execute_partition_crossing(
    activation: &ProductionCreateActivationIntent,
    launch: &ProductionCreateRuntimeLaunchSpec,
    tools: &PinnedProductionCreateTools,
    store: &ProductionCreateRuntimeJournalStore,
    journal: &mut ProductionCreateRuntimeJournal,
) -> Result<ProductionCreatePartitionExecutionReceipt, ProductionCreatePartitionExecutionError> {
    persist_production_create_runtime_transition(
        store,
        journal,
        ProductionCreateRuntimeTransition::BeginPartitionTableWrite,
    )?;

    if let Err(error) = run_stage(
        "sfdisk",
        tools.sfdisk_file(),
        &launch.sfdisk,
        &launch.fixed_path,
        &launch.fixed_locale,
        Some(launch.sfdisk_script.as_bytes()),
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = run_stage(
        "partx",
        tools.partx_file(),
        &launch.partx,
        &launch.fixed_path,
        &launch.fixed_locale,
        None,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    persist_production_create_runtime_transition(
        store,
        journal,
        ProductionCreateRuntimeTransition::PartitionTableWriteSucceeded,
    )?;

    if let Err(error) = discover_exact_partition(activation, launch) {
        return Err(persist_recovery(store, journal, error));
    }

    persist_production_create_runtime_transition(
        store,
        journal,
        ProductionCreateRuntimeTransition::PartitionRediscoveryVerified,
    )?;

    let mut receipt = ProductionCreatePartitionExecutionReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        journal_id: journal.journal_id.clone(),
        launch_id: launch.launch_id.clone(),
        disk: activation.disk.clone(),
        partition_device: launch.partition_device.clone(),
        partition_table: expected_partition_table(activation.partition_table).into(),
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        partition_mapped_verified: true,
        filesystem_formatted: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Cross only the first irreversible production Create boundary.
///
/// This function may write the exact frozen partition table and add partition 1
/// to the kernel map. It stops after fresh exact partition rediscovery is
/// durably recorded. The pinned mkfs descriptor is deliberately never executed
/// by this layer.
#[allow(clippy::too_many_arguments)]
pub fn execute_production_create_partition_crossing(
    _host_lock: &HostStorageLock,
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    launch: &ProductionCreateRuntimeLaunchSpec,
    consent: &PinnedProductionCreateConsent,
    tools: &PinnedProductionCreateTools,
    store: &ProductionCreateRuntimeJournalStore,
    journal: &mut ProductionCreateRuntimeJournal,
) -> Result<ProductionCreatePartitionExecutionReceipt, ProductionCreatePartitionExecutionError> {
    if !PRODUCTION_CREATE_RUNTIME_EXECUTION_COMPILED {
        return Err(ProductionCreatePartitionExecutionError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionCreatePartitionExecutionError::RootRequired);
    }

    validate_crossing(activation, permit, preflight, launch, journal)?;

    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionCreatePartitionExecutionError::JournalMismatch);
    }

    let consent_receipt = revalidate_pinned_production_create_consent(activation, consent)?;
    if consent_receipt.receipt_id != preflight.consent_receipt_id {
        return Err(ProductionCreatePartitionExecutionError::AuthorizationInvalid);
    }
    tools.revalidate(preflight)?;

    execute_partition_crossing(activation, launch, tools, store, journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{BlockDevice, CollectorStatus, PartitionRecord, PartitionTable, StorageGraph};

    fn activation() -> ProductionCreateActivationIntent {
        ProductionCreateActivationIntent {
            schema_version: 1,
            activation_id: "a".repeat(64),
            profile: crate::ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
            create_intent_id: "b".repeat(64),
            create_plan_id: "c".repeat(64),
            source_id: "space-".to_owned() + &"d".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            partition_table: CreatePartitionTablePolicy::Gpt,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        }
    }

    fn snapshot(activation: &ProductionCreateActivationIntent) -> HostSnapshot {
        let partition_device = "/dev/loop7p1".to_owned();
        let disk = BlockDevice {
            name: "loop7".into(),
            kernel_name: Some("loop7".into()),
            path: Some(activation.disk.clone()),
            kind: NodeKind::Loop,
            size_bytes: activation.disk_size_bytes,
            start_512_sector: None,
            logical_sector_bytes: Some(activation.logical_sector_bytes),
            filesystem: None,
            mountpoints: vec![],
            parent_kernel_name: None,
            model: activation.disk_model.clone(),
            serial: activation.disk_serial.clone(),
            uuid: None,
            partition_uuid: None,
            partition_table: Some("gpt".into()),
            children: vec![BlockDevice {
                name: "loop7p1".into(),
                kernel_name: Some("loop7p1".into()),
                path: Some(partition_device.clone()),
                kind: NodeKind::Partition,
                size_bytes: activation.partition_size_bytes,
                start_512_sector: Some(activation.partition_start_sector),
                logical_sector_bytes: Some(activation.logical_sector_bytes),
                filesystem: None,
                mountpoints: vec![],
                parent_kernel_name: Some("loop7".into()),
                model: None,
                serial: None,
                uuid: None,
                partition_uuid: None,
                partition_table: None,
                children: vec![],
            }],
        };
        HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![disk],
            },
            partition_tables: vec![PartitionTable {
                device: activation.disk.clone(),
                label: Some("gpt".into()),
                id: Some("fixture".into()),
                unit: Some("sectors".into()),
                first_lba: Some(2048),
                last_lba: Some(1_048_542),
                sector_size_bytes: Some(activation.logical_sector_bytes),
                partitions: vec![PartitionRecord {
                    node: partition_device,
                    start_sector: activation.partition_start_sector,
                    size_sectors: activation.partition_sector_count,
                    partition_type: Some(GPT_LINUX_FILESYSTEM_TYPE.into()),
                    uuid: Some("fixture-partuuid".into()),
                    name: None,
                    attrs: None,
                    bootable: None,
                }],
            }],
            mounts: vec![],
            fstab: vec![],
            swaps: vec![],
            lvm: None,
            filesystem_preflight: vec![],
            diagnostics: vec![],
            collectors: vec![CollectorStatus {
                component: "partition_tables".into(),
                state: CollectorState::Complete,
                detail: None,
            }],
        }
    }

    fn launch(activation: &ProductionCreateActivationIntent) -> ProductionCreateRuntimeLaunchSpec {
        ProductionCreateRuntimeLaunchSpec {
            schema_version: 1,
            launch_id: "e".repeat(64),
            activation_id: activation.activation_id.clone(),
            execution_permit_id: "f".repeat(64),
            preflight_receipt_id: "1".repeat(64),
            create_intent_id: activation.create_intent_id.clone(),
            disk: activation.disk.clone(),
            partition_device: "/dev/loop7p1".into(),
            partition_table: activation.partition_table,
            partition_start_sector: activation.partition_start_sector,
            partition_sector_count: activation.partition_sector_count,
            partition_size_bytes: activation.partition_size_bytes,
            filesystem: activation.filesystem.clone(),
            sfdisk_script: String::new(),
            sfdisk: crate::ProductionCreateLaunchStage {
                program: PrivilegedProgram::Sfdisk,
                argv: vec![],
                executable: crate::TrustedToolIdentity {
                    program: PrivilegedProgram::Sfdisk,
                    requested_path: "/usr/sbin/sfdisk".into(),
                    canonical_path: "/usr/sbin/sfdisk".into(),
                    device_id: 1,
                    inode: 1,
                    uid: 0,
                    mode: libc::S_IFREG | 0o755,
                    size_bytes: 1,
                    sha256: "2".repeat(64),
                },
                elf: crate::ElfExecutionIdentity {
                    class: crate::ElfClass::Elf64,
                    data_encoding: crate::ElfDataEncoding::LittleEndian,
                    version: 1,
                },
                stdin_len: 0,
                stdin_sha256: None,
            },
            partx: crate::ProductionCreateLaunchStage {
                program: PrivilegedProgram::Partx,
                argv: vec![],
                executable: crate::TrustedToolIdentity {
                    program: PrivilegedProgram::Partx,
                    requested_path: "/usr/bin/partx".into(),
                    canonical_path: "/usr/bin/partx".into(),
                    device_id: 1,
                    inode: 2,
                    uid: 0,
                    mode: libc::S_IFREG | 0o755,
                    size_bytes: 1,
                    sha256: "3".repeat(64),
                },
                elf: crate::ElfExecutionIdentity {
                    class: crate::ElfClass::Elf64,
                    data_encoding: crate::ElfDataEncoding::LittleEndian,
                    version: 1,
                },
                stdin_len: 0,
                stdin_sha256: None,
            },
            mkfs: crate::ProductionCreateLaunchStage {
                program: PrivilegedProgram::MkfsExt4,
                argv: vec![],
                executable: crate::TrustedToolIdentity {
                    program: PrivilegedProgram::MkfsExt4,
                    requested_path: "/usr/sbin/mkfs.ext4".into(),
                    canonical_path: "/usr/sbin/mkfs.ext4".into(),
                    device_id: 1,
                    inode: 3,
                    uid: 0,
                    mode: libc::S_IFREG | 0o755,
                    size_bytes: 1,
                    sha256: "4".repeat(64),
                },
                elf: crate::ElfExecutionIdentity {
                    class: crate::ElfClass::Elf64,
                    data_encoding: crate::ElfDataEncoding::LittleEndian,
                    version: 1,
                },
                stdin_len: 0,
                stdin_sha256: None,
            },
            fixed_path: FIXED_PATH.into(),
            fixed_locale: FIXED_LOCALE.into(),
            descriptor_exec_api: "fexecve".into(),
            require_partition_rediscovery_before_mkfs: true,
            mutation_enabled: false,
            process_spawned: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        }
    }

    #[test]
    fn exact_partition_rediscovery_accepts_the_frozen_geometry() {
        let activation = activation();
        let launch = launch(&activation);
        assert!(verify_partition_snapshot(&activation, &launch, &snapshot(&activation)).is_ok());
    }

    #[test]
    fn changed_partition_geometry_fails_closed() {
        let activation = activation();
        let launch = launch(&activation);
        let mut snapshot = snapshot(&activation);
        snapshot.partition_tables[0].partitions[0].size_sectors += 1;
        assert!(matches!(
            verify_partition_snapshot(&activation, &launch, &snapshot),
            Err(ProductionCreatePartitionExecutionError::PartitionGeometryMismatch)
        ));
    }

    #[test]
    fn filesystem_state_before_mkfs_is_rejected() {
        let activation = activation();
        let launch = launch(&activation);
        let mut snapshot = snapshot(&activation);
        snapshot.storage.block_devices[0].children[0].filesystem = Some(lsm_core::Filesystem {
            fs_type: "ext4".into(),
            version: None,
        });
        assert!(matches!(
            verify_partition_snapshot(&activation, &launch, &snapshot),
            Err(ProductionCreatePartitionExecutionError::UnexpectedPartitionUse)
        ));
    }

    #[test]
    fn partition_crossing_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_RUNTIME_EXECUTION_COMPILED,
            cfg!(feature = "production-create-runtime-execution")
        );
    }
}
