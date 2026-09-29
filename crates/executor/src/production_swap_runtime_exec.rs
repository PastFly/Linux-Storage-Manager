use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use lsm_discovery::discover_swaps;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::production_swap_runtime_journal::{
    persist_production_swap_runtime_transition, ProductionSwapRuntimeTransition,
};
use crate::privileged_exec::execute_descriptor_stage;
use crate::{
    revalidate_pinned_production_swap_replacement_consent, DescriptorExecOutcome, HostStorageLock,
    PinnedProductionSwapReplacementConsent, PinnedProductionSwapRuntimeTools,
    PrivilegedDescriptorExecError, ProductionSwapReplacementActivationIntent,
    ProductionSwapReplacementConsentLeaseError, ProductionSwapReplacementExecutionPermit,
    ProductionSwapRuntimeJournal, ProductionSwapRuntimeJournalError,
    ProductionSwapRuntimeJournalStore, ProductionSwapRuntimeLaunchError,
    ProductionSwapRuntimeLaunchSpec, ProductionSwapRuntimePhase, ProductionSwapRuntimePreflightReceipt,
    ProductionSwapRuntimeToolLeaseError,
};

pub const PRODUCTION_SWAP_RUNTIME_EXECUTION_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-runtime-execution");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapRuntimeExecutionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub journal_id: String,
    pub launch_id: String,
    pub retiring_swap_device: String,
    pub swapfile_path: String,
    pub retiring_reported_swap_bytes: u64,
    pub replacement_reported_swap_bytes: u64,
    pub priority: i32,
    pub old_swap_active: bool,
    pub replacement_swap_active: bool,
    pub persistent_config_changed: bool,
    pub partition_table_changed: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    journal_id: &'a str,
    launch_id: &'a str,
    retiring_swap_device: &'a str,
    swapfile_path: &'a str,
    retiring_reported_swap_bytes: u64,
    replacement_reported_swap_bytes: u64,
    priority: i32,
    old_swap_active: bool,
    replacement_swap_active: bool,
    persistent_config_changed: bool,
    partition_table_changed: bool,
}

impl ProductionSwapRuntimeExecutionReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            journal_id: &self.journal_id,
            launch_id: &self.launch_id,
            retiring_swap_device: &self.retiring_swap_device,
            swapfile_path: &self.swapfile_path,
            retiring_reported_swap_bytes: self.retiring_reported_swap_bytes,
            replacement_reported_swap_bytes: self.replacement_reported_swap_bytes,
            priority: self.priority,
            old_swap_active: self.old_swap_active,
            replacement_swap_active: self.replacement_swap_active,
            persistent_config_changed: self.persistent_config_changed,
            partition_table_changed: self.partition_table_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapRuntimeExecutionError {
    #[error("production swap runtime execution feature is not compiled")]
    FeatureDisabled,
    #[error("production swap runtime crossing requires root")]
    RootRequired,
    #[error("swap runtime authorization chain is invalid or no longer exact")]
    AuthorizationInvalid,
    #[error("swap runtime journal is not the exact persisted Prepared record")]
    JournalMismatch,
    #[error("pinned swap consent revalidation failed: {0}")]
    Consent(#[from] ProductionSwapReplacementConsentLeaseError),
    #[error("pinned swap runtime executable revalidation failed: {0}")]
    ToolLease(#[from] ProductionSwapRuntimeToolLeaseError),
    #[error("swap runtime descriptor execution failed: {0}")]
    Descriptor(#[from] PrivilegedDescriptorExecError),
    #[error("swap runtime journal transition failed: {0}")]
    Journal(#[from] ProductionSwapRuntimeJournalError),
    #[error("swap runtime launch contract is invalid: {0}")]
    Launch(#[from] ProductionSwapRuntimeLaunchError),
    #[error("swapfile creation or verification failed: {0}")]
    FileIo(#[from] io::Error),
    #[error("swapfile allocation or metadata no longer matches the frozen contract")]
    SwapfileAllocationMismatch,
    #[error("mkswap completed but the exact swap signature was not observed")]
    SwapSignatureMismatch,
    #[error("{stage} exited with status {exit_code}: {stderr}")]
    StageFailed {
        stage: &'static str,
        exit_code: i32,
        stderr: String,
    },
    #[error("replacement and retiring swap were not both active with the frozen priority")]
    DualActiveVerificationFailed,
    #[error("old swapoff post-state verification failed")]
    OldSwapoffVerificationFailed,
    #[error("runtime crossing failed and durable RecoveryRequired could not be persisted: runtime={runtime}; journal={journal}")]
    RecoveryPersistenceFailed { runtime: String, journal: String },
    #[error("swap runtime execution receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn bounded_stderr(outcome: &DescriptorExecOutcome) -> String {
    const LIMIT: usize = 4096;
    String::from_utf8_lossy(&outcome.stderr[..outcome.stderr.len().min(LIMIT)]).into_owned()
}

fn validate_crossing(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    launch: &ProductionSwapRuntimeLaunchSpec,
    journal: &ProductionSwapRuntimeJournal,
) -> Result<(), ProductionSwapRuntimeExecutionError> {
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
        || !preflight.runtime_ready
        || activation.execution_enabled
        || permit.mutation_enabled
        || permit.process_spawned
        || preflight.mutation_enabled
        || preflight.process_spawned
        || launch.mutation_enabled
        || launch.process_spawned
        || launch.swapfile_created
        || journal.phase != ProductionSwapRuntimePhase::Prepared
        || journal.mutation_may_have_started
        || journal.persistent_config_may_have_changed
        || journal.partition_table_may_have_changed
    {
        return Err(ProductionSwapRuntimeExecutionError::AuthorizationInvalid);
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
        || journal.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || launch.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || journal.retiring_swap_device != activation.retiring_swap_device
        || journal.retiring_swap_bytes != activation.retiring_swap_bytes
        || journal.retiring_swap_priority != activation.retiring_swap_priority
        || journal.swapfile_path != activation.swapfile_path
        || journal.swapfile_mode != activation.swapfile_mode
        || launch.swapfile.path != activation.swapfile_path
        || launch.swapfile.size_bytes != activation.retiring_swap_bytes
        || launch.swapfile.mode != activation.swapfile_mode
        || !launch.swapfile.create_new
        || !launch.swapfile.no_follow
        || !launch.swapfile.fully_allocate
        || !launch.require_dual_active_verification_before_swapoff
    {
        return Err(ProductionSwapRuntimeExecutionError::AuthorizationInvalid);
    }
    Ok(())
}

fn create_exact_swapfile(
    path: &Path,
    bytes: u64,
    mode: u32,
) -> Result<(File, (u64, u64)), ProductionSwapRuntimeExecutionError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;

    let length = libc::off_t::try_from(bytes)
        .map_err(|_| ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch)?;
    let allocation = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
    if allocation != 0 {
        return Err(io::Error::from_raw_os_error(allocation).into());
    }
    file.sync_all()?;

    let metadata = file.metadata()?;
    let allocated_bytes = metadata
        .blocks()
        .checked_mul(512)
        .ok_or(ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != mode
        || metadata.nlink() != 1
        || metadata.len() != bytes
        || allocated_bytes < bytes
    {
        return Err(ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch);
    }

    let parent = path
        .parent()
        .ok_or(ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch)?;
    File::open(parent)?.sync_all()?;
    Ok((file, (metadata.dev(), metadata.ino())))
}

fn revalidate_swapfile(
    file: &File,
    identity: (u64, u64),
    bytes: u64,
    mode: u32,
) -> Result<(), ProductionSwapRuntimeExecutionError> {
    let metadata = file.metadata()?;
    let allocated_bytes = metadata
        .blocks()
        .checked_mul(512)
        .ok_or(ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch)?;
    if !metadata.is_file()
        || metadata.dev() != identity.0
        || metadata.ino() != identity.1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != mode
        || metadata.nlink() != 1
        || metadata.len() != bytes
        || allocated_bytes < bytes
    {
        return Err(ProductionSwapRuntimeExecutionError::SwapfileAllocationMismatch);
    }
    Ok(())
}

fn verify_swap_signature(file: &File) -> Result<(), ProductionSwapRuntimeExecutionError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 10 {
        return Err(ProductionSwapRuntimeExecutionError::SwapSignatureMismatch);
    }
    let offset = u64::try_from(page_size - 10)
        .map_err(|_| ProductionSwapRuntimeExecutionError::SwapSignatureMismatch)?;
    let mut signature = [0_u8; 10];
    let read = file.read_at(&mut signature, offset)?;
    if read != signature.len()
        || !matches!(&signature, b"SWAPSPACE2" | b"SWAP-SPACE")
    {
        return Err(ProductionSwapRuntimeExecutionError::SwapSignatureMismatch);
    }
    Ok(())
}

fn run_stage(
    stage: &'static str,
    file: &File,
    launch_stage: &crate::ProductionSwapRuntimeLaunchStage,
    fixed_path: &str,
    fixed_locale: &str,
) -> Result<DescriptorExecOutcome, ProductionSwapRuntimeExecutionError> {
    let outcome = execute_descriptor_stage(
        file,
        launch_stage.program,
        &launch_stage.argv,
        fixed_path,
        fixed_locale,
        None,
    )?;
    if outcome.exit_code != 0 {
        return Err(ProductionSwapRuntimeExecutionError::StageFailed {
            stage,
            exit_code: outcome.exit_code,
            stderr: bounded_stderr(&outcome),
        });
    }
    Ok(outcome)
}

fn exact_swap_entries(
    retiring: &str,
    replacement: &str,
) -> Result<(lsm_core::SwapEntry, lsm_core::SwapEntry), ProductionSwapRuntimeExecutionError> {
    let swaps = discover_swaps()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let retiring_matches = swaps
        .iter()
        .filter(|entry| entry.name == retiring)
        .collect::<Vec<_>>();
    let replacement_matches = swaps
        .iter()
        .filter(|entry| entry.name == replacement)
        .collect::<Vec<_>>();
    if retiring_matches.len() != 1 || replacement_matches.len() != 1 {
        return Err(ProductionSwapRuntimeExecutionError::DualActiveVerificationFailed);
    }
    Ok((retiring_matches[0].clone(), replacement_matches[0].clone()))
}

fn persist_recovery(
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
    runtime: ProductionSwapRuntimeExecutionError,
) -> ProductionSwapRuntimeExecutionError {
    match persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::RecoveryRequired,
    ) {
        Ok(()) => runtime,
        Err(journal_error) => ProductionSwapRuntimeExecutionError::RecoveryPersistenceFailed {
            runtime: runtime.to_string(),
            journal: journal_error.to_string(),
        },
    }
}

fn execute_mutating_runtime(
    launch: &ProductionSwapRuntimeLaunchSpec,
    tools: &PinnedProductionSwapRuntimeTools,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
) -> Result<ProductionSwapRuntimeExecutionReceipt, ProductionSwapRuntimeExecutionError> {
    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginSwapfileCreation,
    )?;

    let path = Path::new(&launch.swapfile.path);
    let (swapfile, identity) = match create_exact_swapfile(
        path,
        launch.swapfile.size_bytes,
        launch.swapfile.mode,
    ) {
        Ok(value) => value,
        Err(error) => return Err(persist_recovery(store, journal, error)),
    };
    if let Err(error) = revalidate_swapfile(
        &swapfile,
        identity,
        launch.swapfile.size_bytes,
        launch.swapfile.mode,
    ) {
        return Err(persist_recovery(store, journal, error));
    }
    if let Err(error) = persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::SwapfileCreatedVerified,
    ) {
        return Err(error.into());
    }

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginReplacementFormatting,
    )?;
    if let Err(error) = run_stage(
        "mkswap",
        tools.mkswap_file(),
        &launch.mkswap,
        &launch.fixed_path,
        &launch.fixed_locale,
    ) {
        return Err(persist_recovery(store, journal, error));
    }
    if let Err(error) = revalidate_swapfile(
        &swapfile,
        identity,
        launch.swapfile.size_bytes,
        launch.swapfile.mode,
    )
    .and_then(|_| verify_swap_signature(&swapfile))
    {
        return Err(persist_recovery(store, journal, error));
    }
    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::ReplacementFormattedVerified,
    )?;

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginReplacementActivation,
    )?;
    if let Err(error) = run_stage(
        "swapon",
        tools.swapon_file(),
        &launch.swapon,
        &launch.fixed_path,
        &launch.fixed_locale,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    let (old_active, replacement_active) = match exact_swap_entries(
        &journal.retiring_swap_device,
        &journal.swapfile_path,
    ) {
        Ok(value) => value,
        Err(error) => return Err(persist_recovery(store, journal, error)),
    };
    if old_active.priority != journal.retiring_swap_priority
        || replacement_active.priority != journal.retiring_swap_priority
        || replacement_active.size_bytes != old_active.size_bytes
    {
        return Err(persist_recovery(
            store,
            journal,
            ProductionSwapRuntimeExecutionError::DualActiveVerificationFailed,
        ));
    }
    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::ReplacementActiveVerified,
    )?;

    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::BeginOldSwapDeactivation,
    )?;
    if let Err(error) = run_stage(
        "swapoff",
        tools.swapoff_file(),
        &launch.swapoff,
        &launch.fixed_path,
        &launch.fixed_locale,
    ) {
        return Err(persist_recovery(store, journal, error));
    }

    let swaps = discover_swaps()
        .map_err(|error| io::Error::other(error.to_string()))?;
    let old_still_active = swaps
        .iter()
        .any(|entry| entry.name == journal.retiring_swap_device);
    let replacements = swaps
        .iter()
        .filter(|entry| entry.name == journal.swapfile_path)
        .collect::<Vec<_>>();
    if old_still_active
        || replacements.len() != 1
        || replacements[0].priority != journal.retiring_swap_priority
        || replacements[0].size_bytes != replacement_active.size_bytes
    {
        return Err(persist_recovery(
            store,
            journal,
            ProductionSwapRuntimeExecutionError::OldSwapoffVerificationFailed,
        ));
    }
    persist_production_swap_runtime_transition(
        store,
        journal,
        ProductionSwapRuntimeTransition::OldSwapDeactivatedVerified,
    )?;

    let mut receipt = ProductionSwapRuntimeExecutionReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        journal_id: journal.journal_id.clone(),
        launch_id: launch.launch_id.clone(),
        retiring_swap_device: journal.retiring_swap_device.clone(),
        swapfile_path: journal.swapfile_path.clone(),
        retiring_reported_swap_bytes: old_active.size_bytes,
        replacement_reported_swap_bytes: replacements[0].size_bytes,
        priority: journal.retiring_swap_priority,
        old_swap_active: false,
        replacement_swap_active: true,
        persistent_config_changed: false,
        partition_table_changed: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Cross the production swap runtime boundary through replacement activation
/// and old-swap deactivation only.
///
/// Persistent fstab mutation and partition removal are intentionally absent.
/// Every mutation-capable action is preceded by an fsync-persisted M1B63 phase,
/// and any ambiguous runtime failure after crossing begins is forced into
/// durable RecoveryRequired.
pub fn execute_production_swap_runtime_replacement(
    _host_lock: &HostStorageLock,
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    launch: &ProductionSwapRuntimeLaunchSpec,
    consent: &PinnedProductionSwapReplacementConsent,
    tools: &PinnedProductionSwapRuntimeTools,
    store: &ProductionSwapRuntimeJournalStore,
    journal: &mut ProductionSwapRuntimeJournal,
) -> Result<ProductionSwapRuntimeExecutionReceipt, ProductionSwapRuntimeExecutionError> {
    if !PRODUCTION_SWAP_RUNTIME_EXECUTION_COMPILED {
        return Err(ProductionSwapRuntimeExecutionError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionSwapRuntimeExecutionError::RootRequired);
    }

    validate_crossing(activation, permit, preflight, launch, journal)?;

    let persisted = store.load(&journal.journal_id)?;
    if persisted != *journal {
        return Err(ProductionSwapRuntimeExecutionError::JournalMismatch);
    }

    let consent_receipt =
        revalidate_pinned_production_swap_replacement_consent(activation, consent)?;
    if consent_receipt.receipt_id != preflight.consent_receipt_id {
        return Err(ProductionSwapRuntimeExecutionError::AuthorizationInvalid);
    }
    tools.revalidate(preflight)?;

    execute_mutating_runtime(launch, tools, store, journal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "lsm-swap-runtime-exec-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn exact_swapfile_allocation_is_create_new_and_fully_allocated() {
        let path = temp_path("swapfile");
        let (file, identity) = create_exact_swapfile(&path, 1024 * 1024, 0o600).unwrap();
        revalidate_swapfile(&file, identity, 1024 * 1024, 0o600).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 1024 * 1024);
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn swap_signature_check_accepts_current_kernel_page_signature_location() {
        let path = temp_path("signature");
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let mut bytes = vec![0_u8; page_size.max(4096)];
        let start = page_size - 10;
        bytes[start..start + 10].copy_from_slice(b"SWAPSPACE2");
        fs::write(&path, &bytes).unwrap();
        let file = File::open(&path).unwrap();
        verify_swap_signature(&file).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn runtime_crossing_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_SWAP_RUNTIME_EXECUTION_COMPILED,
            cfg!(feature = "production-swap-replacement-runtime-execution")
        );
    }
}
