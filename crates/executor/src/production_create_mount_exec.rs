use std::thread;
use std::time::Duration;

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind};
use lsm_discovery::discover_snapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_exec::execute_descriptor_stage;
use crate::production_create_mount_journal::persist_production_create_mount_runtime_transition;
use crate::{
    build_production_create_mount_runtime_launch_spec,
    prepare_production_create_mount_runtime_preflight, HostStorageLock,
    PinnedProductionCreateMountTool, PrivilegedDescriptorExecError, PrivilegedProgram,
    ProductionCreateActivationIntent, ProductionCreateMountActivationIntent,
    ProductionCreateMountRuntimeJournal, ProductionCreateMountRuntimeJournalError,
    ProductionCreateMountRuntimeJournalStore, ProductionCreateMountRuntimeLaunchError,
    ProductionCreateMountRuntimeLaunchSpec, ProductionCreateMountRuntimePhase,
    ProductionCreateMountRuntimePreflightError, ProductionCreateMountRuntimePreflightReceipt,
    ProductionCreateMountRuntimeTransition,
};

pub const PRODUCTION_CREATE_MOUNT_RUNTIME_EXECUTION_COMPILED: bool =
    cfg!(feature = "production-create-mount-runtime-execution");

const POST_MOUNT_REDISCOVERY_ATTEMPTS: usize = 20;
const POST_MOUNT_REDISCOVERY_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateMountRuntimeExecutionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub mount_journal_id: String,
    pub mount_launch_id: String,
    pub mount_activation_id: String,
    pub partition_device: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub mountpoint: String,
    pub mounted_verified: bool,
    pub fstab_changed: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    mount_journal_id: &'a str,
    mount_launch_id: &'a str,
    mount_activation_id: &'a str,
    partition_device: &'a str,
    filesystem: &'a str,
    filesystem_uuid: &'a str,
    mountpoint: &'a str,
    mounted_verified: bool,
    fstab_changed: bool,
}

impl ProductionCreateMountRuntimeExecutionReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            mount_journal_id: &self.mount_journal_id,
            mount_launch_id: &self.mount_launch_id,
            mount_activation_id: &self.mount_activation_id,
            partition_device: &self.partition_device,
            filesystem: &self.filesystem,
            filesystem_uuid: &self.filesystem_uuid,
            mountpoint: &self.mountpoint,
            mounted_verified: self.mounted_verified,
            fstab_changed: self.fstab_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateMountRuntimeExecutionError {
    #[error("production create mount runtime execution feature is not compiled")]
    FeatureDisabled,
    #[error("production create mount runtime execution requires root")]
    RootRequired,
    #[error("mount runtime authorization chain is invalid")]
    AuthorizationInvalid,
    #[error("mount runtime journal is not the exact persisted Prepared record")]
    JournalMismatch,
    #[error("fresh mount runtime preflight failed: {0}")]
    Preflight(#[from] ProductionCreateMountRuntimePreflightError),
    #[error("fresh mount runtime launch revalidation failed: {0}")]
    Launch(#[from] ProductionCreateMountRuntimeLaunchError),
    #[error("mount descriptor execution failed: {0}")]
    Descriptor(#[from] PrivilegedDescriptorExecError),
    #[error("mount runtime journal transition failed: {0}")]
    Journal(#[from] ProductionCreateMountRuntimeJournalError),
    #[error("mount exited with status {exit_code}: {stderr}")]
    StageFailed { exit_code: i32, stderr: String },
    #[error("post-mount storage rediscovery did not converge: {0}")]
    Rediscovery(String),
    #[error("fresh mounted filesystem no longer matches the exact Create scope")]
    MountVerificationMismatch,
    #[error("mount crossing unexpectedly changed persistent fstab state")]
    PersistentConfigChanged,
    #[error(
        "mount crossing failed and durable RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}"
    )]
    RecoveryPersistenceFailed { runtime: String, journal: String },
    #[error("mount execution receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn flatten<'a>(devices: &'a [BlockDevice], output: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        output.push(device);
        flatten(&device.children, output);
    }
}

fn expected_partition_table(policy: lsm_planner::CreatePartitionTablePolicy) -> &'static str {
    match policy {
        lsm_planner::CreatePartitionTablePolicy::Gpt => "gpt",
        lsm_planner::CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn required_collectors_complete(snapshot: &HostSnapshot) -> bool {
    ["lsblk", "partition_tables", "mounts", "fstab", "swap"]
        .into_iter()
        .all(|component| {
            let matches = snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component)
                .collect::<Vec<_>>();
            matches.len() == 1 && matches[0].state == CollectorState::Complete
        })
}

fn validate_static_chain(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    launch: &ProductionCreateMountRuntimeLaunchSpec,
    journal: &ProductionCreateMountRuntimeJournal,
) -> Result<(), ProductionCreateMountRuntimeExecutionError> {
    if create.schema_version != 1
        || activation.schema_version != 1
        || preflight.schema_version != 1
        || launch.schema_version != 1
        || journal.schema_version != 1
        || !create.integrity_matches().unwrap_or(false)
        || !activation.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || !create.compile_feature_enabled
        || !activation.compile_feature_enabled
        || !preflight.runtime_ready
        || create.execution_enabled
        || create.partition_table_changed
        || create.filesystem_formatted
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
        || journal.phase != ProductionCreateMountRuntimePhase::Prepared
        || journal.mutation_may_have_started
        || journal.mount_may_have_changed
        || journal.fstab_may_have_changed
    {
        return Err(ProductionCreateMountRuntimeExecutionError::AuthorizationInvalid);
    }

    if activation.create_activation_id != create.activation_id
        || preflight.create_activation_id != create.activation_id
        || preflight.mount_activation_id != activation.mount_activation_id
        || launch.mount_activation_id != activation.mount_activation_id
        || journal.mount_activation_id != activation.mount_activation_id
        || launch.preflight_receipt_id != preflight.receipt_id
        || journal.preflight_receipt_id != preflight.receipt_id
        || journal.launch_id != launch.launch_id
        || activation.disk != create.disk
        || preflight.disk != create.disk
        || launch.disk != create.disk
        || journal.disk != create.disk
        || activation.partition_device != launch.partition_device
        || journal.partition_device != activation.partition_device
        || activation.filesystem != create.filesystem
        || preflight.filesystem != create.filesystem
        || launch.filesystem != create.filesystem
        || journal.filesystem != create.filesystem
        || !preflight
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || !launch
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || !journal
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || preflight.mountpoint != activation.mountpoint
        || launch.mountpoint != activation.mountpoint
        || journal.mountpoint != activation.mountpoint
        || journal.mountpoint_device_id != activation.mountpoint_device_id
        || journal.mountpoint_inode != activation.mountpoint_inode
        || journal.create_activation_id != activation.create_activation_id
        || journal.filesystem_receipt_id != activation.filesystem_receipt_id
        || journal.create_journal_id != activation.journal_id
        || journal.create_launch_id != activation.launch_id
    {
        return Err(ProductionCreateMountRuntimeExecutionError::AuthorizationInvalid);
    }
    Ok(())
}

fn mount_source_matches(source: Option<&str>, partition: &str, uuid: &str) -> bool {
    let uuid_source = format!("UUID={uuid}");
    source
        .is_some_and(|value| value == partition || value.eq_ignore_ascii_case(uuid_source.as_str()))
}

fn verify_mounted_snapshot(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    snapshot: &HostSnapshot,
) -> Result<(), ProductionCreateMountRuntimeExecutionError> {
    if !required_collectors_complete(snapshot) {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }

    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == create.disk)
        .collect::<Vec<_>>();
    if tables.len() != 1 {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }
    let table = tables[0];
    if table.label.as_deref() != Some(expected_partition_table(create.partition_table))
        || table.unit.as_deref() != Some("sectors")
        || table.sector_size_bytes != Some(create.logical_sector_bytes)
        || table.partitions.len() != 1
        || table.partitions[0].node != activation.partition_device
        || table.partitions[0].start_sector != create.partition_start_sector
        || table.partitions[0].size_sectors != create.partition_sector_count
    {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }

    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let disks = nodes
        .iter()
        .copied()
        .filter(|device| device.path.as_deref() == Some(create.disk.as_str()))
        .collect::<Vec<_>>();
    let partitions = nodes
        .iter()
        .copied()
        .filter(|device| device.path.as_deref() == Some(activation.partition_device.as_str()))
        .collect::<Vec<_>>();
    if disks.len() != 1 || partitions.len() != 1 {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }
    let disk = disks[0];
    let partition = partitions[0];
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
        || disk.size_bytes != create.disk_size_bytes
        || disk.logical_sector_bytes != Some(create.logical_sector_bytes)
        || disk.model != create.disk_model
        || disk.serial != create.disk_serial
        || disk.partition_table.as_deref() != Some(expected_partition_table(create.partition_table))
        || partition.kind != NodeKind::Partition
        || partition.size_bytes != create.partition_size_bytes
        || partition.logical_sector_bytes != Some(create.logical_sector_bytes)
        || partition.parent_kernel_name != disk.kernel_name
        || partition
            .filesystem
            .as_ref()
            .is_none_or(|filesystem| filesystem.fs_type != create.filesystem)
        || partition
            .uuid
            .as_deref()
            .is_none_or(|uuid| !uuid.eq_ignore_ascii_case(&activation.filesystem_uuid))
        || partition.mountpoints.len() != 1
        || partition.mountpoints[0] != activation.mountpoint
    {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }

    let target_mounts = snapshot
        .mounts
        .iter()
        .filter(|entry| entry.target == activation.mountpoint)
        .collect::<Vec<_>>();
    if target_mounts.len() != 1 {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }
    let mounted = target_mounts[0];
    if !mount_source_matches(
        mounted.source.as_deref(),
        &activation.partition_device,
        &activation.filesystem_uuid,
    ) || mounted.fs_type.as_deref() != Some(activation.filesystem.as_str())
        || !mounted.options.iter().any(|option| option == "rw")
        || mounted.options.iter().any(|option| option == "ro")
    {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }

    let extra_source_mount = snapshot.mounts.iter().any(|entry| {
        entry.target != activation.mountpoint
            && mount_source_matches(
                entry.source.as_deref(),
                &activation.partition_device,
                &activation.filesystem_uuid,
            )
    });
    if extra_source_mount {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }

    let uuid_source = format!("UUID={}", activation.filesystem_uuid);
    if snapshot.fstab.iter().any(|entry| {
        entry.target == activation.mountpoint
            || entry.source == activation.partition_device
            || entry.source.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountRuntimeExecutionError::PersistentConfigChanged);
    }
    if snapshot.swaps.iter().any(|entry| {
        entry.name == activation.partition_device || entry.name.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountRuntimeExecutionError::MountVerificationMismatch);
    }
    Ok(())
}

fn discover_exact_mount(
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreateMountRuntimeExecutionError> {
    let mut last_error = None;
    for attempt in 0..POST_MOUNT_REDISCOVERY_ATTEMPTS {
        match discover_snapshot() {
            Ok(snapshot) => match verify_mounted_snapshot(create, activation, &snapshot) {
                Ok(()) => return Ok(()),
                Err(
                    error @ ProductionCreateMountRuntimeExecutionError::PersistentConfigChanged,
                ) => {
                    return Err(error);
                }
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
        if attempt + 1 < POST_MOUNT_REDISCOVERY_ATTEMPTS {
            thread::sleep(POST_MOUNT_REDISCOVERY_DELAY);
        }
    }
    Err(ProductionCreateMountRuntimeExecutionError::Rediscovery(
        last_error.unwrap_or_else(|| "fresh mounted state was not observable".into()),
    ))
}

fn bounded_stderr(outcome: &crate::DescriptorExecOutcome) -> String {
    const LIMIT: usize = 4096;
    String::from_utf8_lossy(&outcome.stderr[..outcome.stderr.len().min(LIMIT)]).into_owned()
}

fn persist_recovery(
    store: &ProductionCreateMountRuntimeJournalStore,
    journal: &mut ProductionCreateMountRuntimeJournal,
    runtime: ProductionCreateMountRuntimeExecutionError,
) -> ProductionCreateMountRuntimeExecutionError {
    match persist_production_create_mount_runtime_transition(
        store,
        journal,
        ProductionCreateMountRuntimeTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => {
            ProductionCreateMountRuntimeExecutionError::RecoveryPersistenceFailed {
                runtime: runtime.to_string(),
                journal: journal_error.to_string(),
            }
        }
    }
}

/// Execute only the exact M2A13 descriptor-pinned mount stage.
///
/// The full read-only M2A13 preflight and launch are recomputed immediately
/// before the durable crossing and must be byte-for-byte identical to the
/// supplied authorization chain. The journal is fsync-persisted at Mounting
/// before fexecve. A zero exit is not completion: bounded fresh rediscovery
/// must prove the exact device/UUID/filesystem/target and unchanged fstab.
/// Any ambiguous failure after BeginMount is forced into RecoveryRequired.
#[allow(clippy::too_many_arguments)]
pub fn execute_production_create_mount_crossing(
    _host_lock: &HostStorageLock,
    create: &ProductionCreateActivationIntent,
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    launch: &ProductionCreateMountRuntimeLaunchSpec,
    tool: &PinnedProductionCreateMountTool,
    store: &ProductionCreateMountRuntimeJournalStore,
    journal: &mut ProductionCreateMountRuntimeJournal,
) -> Result<ProductionCreateMountRuntimeExecutionReceipt, ProductionCreateMountRuntimeExecutionError>
{
    if !PRODUCTION_CREATE_MOUNT_RUNTIME_EXECUTION_COMPILED {
        return Err(ProductionCreateMountRuntimeExecutionError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionCreateMountRuntimeExecutionError::RootRequired);
    }

    validate_static_chain(create, activation, preflight, launch, journal)?;
    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionCreateMountRuntimeExecutionError::JournalMismatch);
    }

    let fresh_preflight = prepare_production_create_mount_runtime_preflight(create, activation)?;
    if fresh_preflight != *preflight {
        return Err(ProductionCreateMountRuntimeExecutionError::AuthorizationInvalid);
    }
    let fresh_launch =
        build_production_create_mount_runtime_launch_spec(activation, &fresh_preflight, tool)?;
    if fresh_launch != *launch {
        return Err(ProductionCreateMountRuntimeExecutionError::AuthorizationInvalid);
    }

    persist_production_create_mount_runtime_transition(
        store,
        journal,
        ProductionCreateMountRuntimeTransition::BeginMount,
    )?;

    let outcome = match execute_descriptor_stage(
        tool.mount_file(),
        launch.mount.program,
        &launch.mount.argv,
        &launch.fixed_path,
        &launch.fixed_locale,
        None,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            return Err(persist_recovery(
                store,
                journal,
                ProductionCreateMountRuntimeExecutionError::Descriptor(error),
            ))
        }
    };
    if outcome.exit_code != 0 {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreateMountRuntimeExecutionError::StageFailed {
                exit_code: outcome.exit_code,
                stderr: bounded_stderr(&outcome),
            },
        ));
    }

    if let Err(error) = persist_production_create_mount_runtime_transition(
        store,
        journal,
        ProductionCreateMountRuntimeTransition::MountProcessSucceeded,
    ) {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreateMountRuntimeExecutionError::Journal(error),
        ));
    }

    if let Err(error) = discover_exact_mount(create, activation) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = persist_production_create_mount_runtime_transition(
        store,
        journal,
        ProductionCreateMountRuntimeTransition::MountRediscoveryVerified,
    ) {
        return Err(persist_recovery(
            store,
            journal,
            ProductionCreateMountRuntimeExecutionError::Journal(error),
        ));
    }

    let mut receipt = ProductionCreateMountRuntimeExecutionReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        mount_journal_id: journal.journal_id.clone(),
        mount_launch_id: launch.launch_id.clone(),
        mount_activation_id: activation.mount_activation_id.clone(),
        partition_device: activation.partition_device.clone(),
        filesystem: activation.filesystem.clone(),
        filesystem_uuid: activation.filesystem_uuid.clone(),
        mountpoint: activation.mountpoint.clone(),
        mounted_verified: true,
        fstab_changed: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_source_accepts_exact_partition_or_uuid_only() {
        assert!(mount_source_matches(
            Some("/dev/loop7p1"),
            "/dev/loop7p1",
            "abc-def"
        ));
        assert!(mount_source_matches(
            Some("UUID=ABC-DEF"),
            "/dev/loop7p1",
            "abc-def"
        ));
        assert!(!mount_source_matches(
            Some("/dev/loop8p1"),
            "/dev/loop7p1",
            "abc-def"
        ));
    }

    #[test]
    fn mount_execution_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_MOUNT_RUNTIME_EXECUTION_COMPILED,
            cfg!(feature = "production-create-mount-runtime-execution")
        );
    }
}
