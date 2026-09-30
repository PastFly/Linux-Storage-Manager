use lsm_discovery::discover_snapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_exec::execute_descriptor_stage;
use crate::production_swap_runtime_journal::{
    persist_production_swap_runtime_transition, ProductionSwapRuntimeTransition,
};
use crate::{
    production_swap_persistent_config::revalidate_production_swap_persistent_config_receipt,
    prepare_production_swap_partition_removal,
    revalidate_pinned_production_swap_replacement_consent, DescriptorExecOutcome, HostStorageLock,
    PinnedProductionSwapPartitionRemovalTools, PinnedProductionSwapReplacementConsent,
    PrivilegedDescriptorExecError, ProductionSwapPartitionRemovalLaunchSpec,
    ProductionSwapPartitionRemovalPreflight, ProductionSwapPartitionRemovalPreflightError,
    ProductionSwapPartitionRemovalToolLeaseError, ProductionSwapPersistentConfigReceipt,
    ProductionSwapReplacementActivationIntent, ProductionSwapReplacementConsentLeaseError,
    ProductionSwapRuntimeExecutionReceipt, ProductionSwapRuntimeJournal,
    ProductionSwapRuntimeJournalError, ProductionSwapRuntimeJournalStore,
    ProductionSwapRuntimePhase,
};

pub const PRODUCTION_SWAP_PARTITION_REMOVAL_EXECUTION_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-partition-removal-execution");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapPartitionRemovalExecutionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub journal_id: String,
    pub launch_id: String,
    pub preflight_id: String,
    pub disk: String,
    pub retiring_swap_device: String,
    pub extended_partition_device: String,
    pub retiring_swap_partition_removed: bool,
    pub extended_partition_removed: bool,
    pub replacement_swap_active: bool,
    pub persistent_config_preserved: bool,
    pub partition_table_changed: bool,
    pub completed: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    journal_id: &'a str,
    launch_id: &'a str,
    preflight_id: &'a str,
    disk: &'a str,
    retiring_swap_device: &'a str,
    extended_partition_device: &'a str,
    retiring_swap_partition_removed: bool,
    extended_partition_removed: bool,
    replacement_swap_active: bool,
    persistent_config_preserved: bool,
    partition_table_changed: bool,
    completed: bool,
}

impl ProductionSwapPartitionRemovalExecutionReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            journal_id: &self.journal_id,
            launch_id: &self.launch_id,
            preflight_id: &self.preflight_id,
            disk: &self.disk,
            retiring_swap_device: &self.retiring_swap_device,
            extended_partition_device: &self.extended_partition_device,
            retiring_swap_partition_removed: self.retiring_swap_partition_removed,
            extended_partition_removed: self.extended_partition_removed,
            replacement_swap_active: self.replacement_swap_active,
            persistent_config_preserved: self.persistent_config_preserved,
            partition_table_changed: self.partition_table_changed,
            completed: self.completed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapPartitionRemovalExecutionError {
    #[error("production swap partition-removal execution feature is not compiled")]
    FeatureDisabled,
    #[error("production swap partition-removal execution requires root")]
    RootRequired,
    #[error("partition-removal authorization chain is invalid or no longer exact")]
    AuthorizationInvalid,
    #[error("swap runtime journal is not the exact persisted PersistentConfigUpdated record")]
    JournalMismatch,
    #[error("fresh partition-removal preflight no longer matches the frozen contract")]
    FreshPreflightMismatch,
    #[error("pinned swap consent revalidation failed: {0}")]
    Consent(#[from] ProductionSwapReplacementConsentLeaseError),
    #[error("partition-removal preflight failed: {0}")]
    Preflight(#[from] ProductionSwapPartitionRemovalPreflightError),
    #[error("pinned partition-removal tool lease failed: {0}")]
    ToolLease(#[from] ProductionSwapPartitionRemovalToolLeaseError),
    #[error("partition-removal descriptor execution failed: {0}")]
    Descriptor(#[from] PrivilegedDescriptorExecError),
    #[error("{stage} exited with status {exit_code}: {stderr}")]
    StageFailed {
        stage: &'static str,
        exit_code: i32,
        stderr: String,
    },
    #[error("post-removal storage state does not match the exact required result")]
    PostStateMismatch,
    #[error("swap runtime journal transition failed: {0}")]
    Journal(#[from] ProductionSwapRuntimeJournalError),
    #[error("partition removal failed and durable RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}")]
    RecoveryPersistenceFailed { runtime: String, journal: String },
    #[error("partition-removal execution receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn bounded_stderr(outcome: &DescriptorExecOutcome) -> String {
    const LIMIT: usize = 4096;
    String::from_utf8_lossy(&outcome.stderr[..outcome.stderr.len().min(LIMIT)]).into_owned()
}

fn validate_authorization(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    persistent: &ProductionSwapPersistentConfigReceipt,
    preflight: &ProductionSwapPartitionRemovalPreflight,
    tools: &PinnedProductionSwapPartitionRemovalTools,
    launch: &ProductionSwapPartitionRemovalLaunchSpec,
    journal: &ProductionSwapRuntimeJournal,
) -> Result<(), ProductionSwapPartitionRemovalExecutionError> {
    if activation.schema_version != 1
        || runtime.schema_version != 1
        || persistent.schema_version != 1
        || preflight.schema_version != 1
        || launch.schema_version != 1
        || journal.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !runtime.integrity_matches().unwrap_or(false)
        || !persistent.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !launch.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || journal.phase != ProductionSwapRuntimePhase::PersistentConfigUpdated
        || !journal.mutation_may_have_started
        || !journal.persistent_config_may_have_changed
        || journal.partition_table_may_have_changed
        || preflight.mutation_enabled
        || preflight.partition_table_changed
        || launch.process_spawned
        || launch.partition_table_changed
        || runtime.old_swap_active
        || !runtime.replacement_swap_active
        || !persistent.persistent_config_updated
        || persistent.partition_table_changed
    {
        return Err(ProductionSwapPartitionRemovalExecutionError::AuthorizationInvalid);
    }

    if journal.activation_id != activation.activation_id
        || journal.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || journal.retiring_swap_device != activation.retiring_swap_device
        || journal.retiring_swap_bytes != activation.retiring_swap_bytes
        || journal.retiring_swap_priority != activation.retiring_swap_priority
        || journal.swapfile_path != activation.swapfile_path
        || runtime.journal_id != journal.journal_id
        || persistent.journal_id != journal.journal_id
        || preflight.journal_id != journal.journal_id
        || launch.journal_id != journal.journal_id
        || preflight.activation_id != activation.activation_id
        || preflight.persistent_config_receipt_id != persistent.receipt_id
        || launch.preflight_id != preflight.preflight_id
        || launch.disk != preflight.disk
        || launch.retiring_swap_partition_number != preflight.retiring_swap_partition_number
        || launch.extended_partition_number != preflight.extended_partition_number
        || launch.sfdisk_delete.tool != tools.sfdisk
        || launch.partx_update.tool != tools.partx
        || launch.sfdisk_delete.program != crate::PrivilegedProgram::Sfdisk
        || launch.partx_update.program != crate::PrivilegedProgram::Partx
    {
        return Err(ProductionSwapPartitionRemovalExecutionError::AuthorizationInvalid);
    }
    Ok(())
}

fn run_stage(
    stage: &'static str,
    file: &std::fs::File,
    launch_stage: &crate::ProductionSwapPartitionRemovalLaunchStage,
    fixed_path: &str,
    fixed_locale: &str,
) -> Result<DescriptorExecOutcome, ProductionSwapPartitionRemovalExecutionError> {
    let outcome = execute_descriptor_stage(
        file,
        launch_stage.program,
        &launch_stage.argv,
        fixed_path,
        fixed_locale,
        None,
    )?;
    if outcome.exit_code != 0 {
        return Err(ProductionSwapPartitionRemovalExecutionError::StageFailed {
            stage,
            exit_code: outcome.exit_code,
            stderr: bounded_stderr(&outcome),
        });
    }
    Ok(outcome)
}

fn persist_recovery(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    runtime: ProductionSwapPartitionRemovalExecutionError,
) -> ProductionSwapPartitionRemovalExecutionError {
    match persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => {
            ProductionSwapPartitionRemovalExecutionError::RecoveryPersistenceFailed {
                runtime: runtime.to_string(),
                journal: journal_error.to_string(),
            }
        }
    }
}

fn verify_post_state(
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    persistent: &ProductionSwapPersistentConfigReceipt,
    preflight: &ProductionSwapPartitionRemovalPreflight,
) -> Result<(), ProductionSwapPartitionRemovalExecutionError> {
    let snapshot = discover_snapshot()
        .map_err(|_| ProductionSwapPartitionRemovalExecutionError::PostStateMismatch)?;

    let table_matches = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == preflight.disk)
        .collect::<Vec<_>>();
    let [table] = table_matches.as_slice() else {
        return Err(ProductionSwapPartitionRemovalExecutionError::PostStateMismatch);
    };
    if table.label.as_deref() != Some("dos")
        || table.id != preflight.table_id
        || table.sector_size_bytes != Some(preflight.sector_size_bytes)
        || table.partitions.iter().any(|record| {
            record.node == preflight.retiring_swap_device
                || record.node == preflight.extended_partition_device
        })
    {
        return Err(ProductionSwapPartitionRemovalExecutionError::PostStateMismatch);
    }

    if snapshot
        .swaps
        .iter()
        .any(|entry| entry.name == activation.retiring_swap_device)
    {
        return Err(ProductionSwapPartitionRemovalExecutionError::PostStateMismatch);
    }
    let replacement = snapshot
        .swaps
        .iter()
        .filter(|entry| entry.name == activation.swapfile_path)
        .collect::<Vec<_>>();
    if replacement.len() != 1
        || replacement[0].priority != activation.retiring_swap_priority
        || replacement[0].size_bytes != runtime.replacement_reported_swap_bytes
    {
        return Err(ProductionSwapPartitionRemovalExecutionError::PostStateMismatch);
    }

    revalidate_production_swap_persistent_config_receipt(activation, persistent)
        .map_err(|_| ProductionSwapPartitionRemovalExecutionError::PostStateMismatch)?;

    Ok(())
}

/// Execute the final retired logical-swap and DOS extended-container removal.
///
/// The journal is durably moved to RemovingPartitions before the first
/// descriptor execution. Any failure from that point is persisted as
/// RecoveryRequired. Completed is reachable only after exact storage, swap and
/// persistent-config post-state verification.
pub fn execute_production_swap_partition_removal(
    host_lock: &HostStorageLock,
    activation: &ProductionSwapReplacementActivationIntent,
    runtime: &ProductionSwapRuntimeExecutionReceipt,
    persistent: &ProductionSwapPersistentConfigReceipt,
    consent: &PinnedProductionSwapReplacementConsent,
    preflight: &ProductionSwapPartitionRemovalPreflight,
    tools: &PinnedProductionSwapPartitionRemovalTools,
    launch: &ProductionSwapPartitionRemovalLaunchSpec,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
) -> Result<
    ProductionSwapPartitionRemovalExecutionReceipt,
    ProductionSwapPartitionRemovalExecutionError,
> {
    if !PRODUCTION_SWAP_PARTITION_REMOVAL_EXECUTION_COMPILED {
        return Err(ProductionSwapPartitionRemovalExecutionError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionSwapPartitionRemovalExecutionError::RootRequired);
    }

    validate_authorization(
        activation, runtime, persistent, preflight, tools, launch, journal,
    )?;
    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionSwapPartitionRemovalExecutionError::JournalMismatch);
    }
    revalidate_pinned_production_swap_replacement_consent(activation, consent)?;
    tools.revalidate(preflight)?;

    let fresh = prepare_production_swap_partition_removal(
        host_lock, activation, runtime, persistent, consent, store, journal,
    )?;
    if fresh != *preflight {
        return Err(ProductionSwapPartitionRemovalExecutionError::FreshPreflightMismatch);
    }

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginPartitionRemoval,
    )?;

    if let Err(error) = run_stage(
        "sfdisk-delete",
        tools.sfdisk_file(),
        &launch.sfdisk_delete,
        &launch.fixed_path,
        &launch.fixed_locale,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = run_stage(
        "partx-update",
        tools.partx_file(),
        &launch.partx_update,
        &launch.fixed_path,
        &launch.fixed_locale,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = verify_post_state(activation, runtime, persistent, preflight) {
        return Err(persist_recovery(store, journal, error));
    }

    if let Err(error) = persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::PartitionsRemovedVerified,
    ) {
        return Err(error.into());
    }
    if let Err(error) = persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::Completed,
    ) {
        let runtime_error = ProductionSwapPartitionRemovalExecutionError::Journal(error);
        return Err(persist_recovery(store, journal, runtime_error));
    }

    let mut receipt = ProductionSwapPartitionRemovalExecutionReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        journal_id: journal.journal_id.clone(),
        launch_id: launch.launch_id.clone(),
        preflight_id: preflight.preflight_id.clone(),
        disk: preflight.disk.clone(),
        retiring_swap_device: preflight.retiring_swap_device.clone(),
        extended_partition_device: preflight.extended_partition_device.clone(),
        retiring_swap_partition_removed: true,
        extended_partition_removed: true,
        replacement_swap_active: true,
        persistent_config_preserved: true,
        partition_table_changed: true,
        completed: journal.phase == ProductionSwapRuntimePhase::Completed,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_build_does_not_compile_partition_removal_execution() {
        if !PRODUCTION_SWAP_PARTITION_REMOVAL_EXECUTION_COMPILED {
            assert!(!PRODUCTION_SWAP_PARTITION_REMOVAL_EXECUTION_COMPILED);
        }
    }

    #[test]
    fn receipt_integrity_detects_completion_tampering() {
        let mut receipt = ProductionSwapPartitionRemovalExecutionReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            journal_id: "1".repeat(64),
            launch_id: "2".repeat(64),
            preflight_id: "3".repeat(64),
            disk: "/dev/sda".into(),
            retiring_swap_device: "/dev/sda5".into(),
            extended_partition_device: "/dev/sda2".into(),
            retiring_swap_partition_removed: true,
            extended_partition_removed: true,
            replacement_swap_active: true,
            persistent_config_preserved: true,
            partition_table_changed: true,
            completed: true,
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        assert!(receipt.integrity_matches().unwrap());
        receipt.completed = false;
        assert!(!receipt.integrity_matches().unwrap());
    }
}
