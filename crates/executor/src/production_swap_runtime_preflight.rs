use lsm_core::{
    FilesystemSpaceEvidence, HibernationResumeEvidence, HostSnapshot, PathOccupancyEvidence,
};
use lsm_discovery::{
    discover_filesystem_space, discover_hibernation_resume_evidence, discover_path_occupancy,
    discover_snapshot,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    resolve_trusted_privileged_tool, revalidate_pinned_production_swap_replacement_consent,
    PinnedProductionSwapReplacementConsent, PrivilegedProgram,
    ProductionSwapReplacementActivationIntent, ProductionSwapReplacementConsentLeaseError,
    ProductionSwapReplacementExecutionPermit, TrustedToolError, TrustedToolIdentity,
};

pub const PRODUCTION_SWAP_RUNTIME_PREFLIGHT_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-runtime-preflight");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapRuntimePreflightReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub consent_receipt_id: String,
    pub swap_replacement_intent_id: String,
    pub target: String,
    pub retiring_swap_device: String,
    pub retiring_swap_bytes: u64,
    pub retiring_swap_priority: i32,
    pub destination_mount: String,
    pub swapfile_path: String,
    pub destination_available_bytes: u64,
    pub mkswap: TrustedToolIdentity,
    pub swapon: TrustedToolIdentity,
    pub swapoff: TrustedToolIdentity,
    pub runtime_ready: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
}

#[derive(Serialize)]
struct ReceiptDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    consent_receipt_id: &'a str,
    swap_replacement_intent_id: &'a str,
    target: &'a str,
    retiring_swap_device: &'a str,
    retiring_swap_bytes: u64,
    retiring_swap_priority: i32,
    destination_mount: &'a str,
    swapfile_path: &'a str,
    destination_available_bytes: u64,
    mkswap: &'a TrustedToolIdentity,
    swapon: &'a TrustedToolIdentity,
    swapoff: &'a TrustedToolIdentity,
    runtime_ready: bool,
    mutation_enabled: bool,
    process_spawned: bool,
}

impl ProductionSwapRuntimePreflightReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ReceiptDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            execution_permit_id: &self.execution_permit_id,
            consent_receipt_id: &self.consent_receipt_id,
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            target: &self.target,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_bytes: self.retiring_swap_bytes,
            retiring_swap_priority: self.retiring_swap_priority,
            destination_mount: &self.destination_mount,
            swapfile_path: &self.swapfile_path,
            destination_available_bytes: self.destination_available_bytes,
            mkswap: &self.mkswap,
            swapon: &self.swapon,
            swapoff: &self.swapoff,
            runtime_ready: self.runtime_ready,
            mutation_enabled: self.mutation_enabled,
            process_spawned: self.process_spawned,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapRuntimePreflightError {
    #[error("production swap runtime preflight feature is not compiled")]
    FeatureDisabled,
    #[error("swap activation or execution-permit integrity check failed")]
    AuthorizationInvalid,
    #[error("swap execution permit does not bind the exact activation")]
    AuthorizationBindingMismatch,
    #[error("upstream swap authorization unexpectedly enables mutation or spawning")]
    UpstreamAlreadyEnabled,
    #[error("pinned swap consent revalidation failed: {0}")]
    Consent(#[from] ProductionSwapReplacementConsentLeaseError),
    #[error("fresh hibernation/resume evidence blocks swap runtime crossing")]
    ResumeConfigured,
    #[error("fresh retiring swap runtime identity is absent, ambiguous or changed")]
    RetiringSwapChanged,
    #[error("fresh persistent swap configuration is absent, ambiguous or changed")]
    PersistentSwapChanged,
    #[error("fresh swapfile destination mount is absent, ambiguous or changed")]
    DestinationMountChanged,
    #[error("fresh destination capacity is insufficient or bound to another path")]
    DestinationCapacityChanged,
    #[error("replacement swapfile path is no longer vacant")]
    SwapfilePathOccupied,
    #[error("trusted swap runtime tool resolution failed: {0}")]
    Tool(#[from] TrustedToolError),
    #[error("read-only runtime discovery failed: {0}")]
    Discovery(String),
    #[error("swap runtime preflight serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_authorization(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
) -> Result<(), ProductionSwapRuntimePreflightError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !permit.compile_feature_enabled
    {
        return Err(ProductionSwapRuntimePreflightError::AuthorizationInvalid);
    }
    if activation.execution_enabled || permit.mutation_enabled || permit.process_spawned {
        return Err(ProductionSwapRuntimePreflightError::UpstreamAlreadyEnabled);
    }
    if permit.activation_id != activation.activation_id
        || permit.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || permit.target != activation.target
        || permit.disk != activation.disk
        || permit.retiring_swap_device != activation.retiring_swap_device
        || permit.retiring_swap_bytes != activation.retiring_swap_bytes
        || permit.retiring_swap_priority != activation.retiring_swap_priority
        || permit.swapfile_path != activation.swapfile_path
        || permit.swapfile_mode != activation.swapfile_mode
    {
        return Err(ProductionSwapRuntimePreflightError::AuthorizationBindingMismatch);
    }
    Ok(())
}

fn validate_runtime_evidence(
    activation: &ProductionSwapReplacementActivationIntent,
    snapshot: &HostSnapshot,
    resume: &HibernationResumeEvidence,
    space: &FilesystemSpaceEvidence,
    path: &PathOccupancyEvidence,
) -> Result<(), ProductionSwapRuntimePreflightError> {
    if resume.configured() {
        return Err(ProductionSwapRuntimePreflightError::ResumeConfigured);
    }

    let swaps = snapshot
        .swaps
        .iter()
        .filter(|entry| entry.name == activation.retiring_swap_device)
        .collect::<Vec<_>>();
    if swaps.len() != 1
        || swaps[0].kind != "partition"
        || swaps[0].size_bytes != activation.retiring_swap_bytes
        || swaps[0].priority != activation.retiring_swap_priority
    {
        return Err(ProductionSwapRuntimePreflightError::RetiringSwapChanged);
    }

    let persistent = snapshot
        .fstab
        .iter()
        .filter(|entry| {
            entry.fs_type == "swap"
                && entry.source == activation.persistent_swap_source
                && entry.target == activation.persistent_swap_target
        })
        .collect::<Vec<_>>();
    if persistent.len() != 1
        || persistent[0].options != activation.persistent_swap_options
        || persistent[0].dump != activation.persistent_swap_dump
        || persistent[0].pass != activation.persistent_swap_pass
    {
        return Err(ProductionSwapRuntimePreflightError::PersistentSwapChanged);
    }

    let mounts = snapshot
        .mounts
        .iter()
        .filter(|mount| mount.target == activation.destination_mount)
        .collect::<Vec<_>>();
    if mounts.len() != 1
        || mounts[0].fs_type.as_deref() != Some("ext4")
        || !mounts[0].options.iter().any(|option| option == "rw")
        || mounts[0].options.iter().any(|option| option == "ro")
        || mounts[0].source.as_deref() == Some(activation.retiring_swap_device.as_str())
    {
        return Err(ProductionSwapRuntimePreflightError::DestinationMountChanged);
    }

    if space.path != activation.destination_mount
        || space.available_bytes < activation.retiring_swap_bytes
    {
        return Err(ProductionSwapRuntimePreflightError::DestinationCapacityChanged);
    }

    if path.path != activation.swapfile_path || path.exists {
        return Err(ProductionSwapRuntimePreflightError::SwapfilePathOccupied);
    }

    Ok(())
}

/// Revalidate the exact swap replacement authorization and all mutable live
/// evidence immediately before a future runtime crossing. This function does
/// not create a file and does not execute mkswap/swapon/swapoff.
pub fn prepare_production_swap_runtime_preflight(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    consent_lease: &PinnedProductionSwapReplacementConsent,
) -> Result<ProductionSwapRuntimePreflightReceipt, ProductionSwapRuntimePreflightError> {
    if !PRODUCTION_SWAP_RUNTIME_PREFLIGHT_COMPILED {
        return Err(ProductionSwapRuntimePreflightError::FeatureDisabled);
    }
    validate_authorization(activation, permit)?;

    let consent = revalidate_pinned_production_swap_replacement_consent(activation, consent_lease)?;
    if consent.receipt_id != permit.consent_receipt_id {
        return Err(ProductionSwapRuntimePreflightError::AuthorizationBindingMismatch);
    }

    let snapshot = discover_snapshot()
        .map_err(|error| ProductionSwapRuntimePreflightError::Discovery(error.to_string()))?;
    let resume = discover_hibernation_resume_evidence()
        .map_err(|error| ProductionSwapRuntimePreflightError::Discovery(error.to_string()))?;
    let space = discover_filesystem_space(&activation.destination_mount)
        .map_err(|error| ProductionSwapRuntimePreflightError::Discovery(error.to_string()))?;
    let path = discover_path_occupancy(&activation.swapfile_path)
        .map_err(|error| ProductionSwapRuntimePreflightError::Discovery(error.to_string()))?;
    validate_runtime_evidence(activation, &snapshot, &resume, &space, &path)?;

    let mkswap = resolve_trusted_privileged_tool(PrivilegedProgram::Mkswap)?;
    let swapon = resolve_trusted_privileged_tool(PrivilegedProgram::Swapon)?;
    let swapoff = resolve_trusted_privileged_tool(PrivilegedProgram::Swapoff)?;

    let mut receipt = ProductionSwapRuntimePreflightReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        consent_receipt_id: consent.receipt_id,
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        target: activation.target.clone(),
        retiring_swap_device: activation.retiring_swap_device.clone(),
        retiring_swap_bytes: activation.retiring_swap_bytes,
        retiring_swap_priority: activation.retiring_swap_priority,
        destination_mount: activation.destination_mount.clone(),
        swapfile_path: activation.swapfile_path.clone(),
        destination_available_bytes: space.available_bytes,
        mkswap,
        swapon,
        swapoff,
        runtime_ready: true,
        mutation_enabled: false,
        process_spawned: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{FstabEntry, MountEntry, StorageGraph, SwapEntry};

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
            persistent_swap_source: "UUID=swap".into(),
            persistent_swap_target: "none".into(),
            persistent_swap_options: vec!["sw".into()],
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

    fn snapshot() -> HostSnapshot {
        HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![],
            },
            partition_tables: vec![],
            mounts: vec![MountEntry {
                source: Some("/dev/sda1".into()),
                target: "/data".into(),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            }],
            fstab: vec![FstabEntry {
                source: "UUID=swap".into(),
                target: "none".into(),
                fs_type: "swap".into(),
                options: vec!["sw".into()],
                dump: 0,
                pass: 0,
            }],
            swaps: vec![SwapEntry {
                name: "/dev/sda5".into(),
                kind: "partition".into(),
                size_bytes: 64 * 1024 * 1024,
                used_bytes: 4096,
                priority: 7,
            }],
            lvm: None,
            filesystem_preflight: vec![],
            diagnostics: vec![],
            collectors: vec![],
        }
    }

    fn space() -> FilesystemSpaceEvidence {
        FilesystemSpaceEvidence {
            path: "/data".into(),
            block_size_bytes: 4096,
            total_bytes: 512 * 1024 * 1024,
            available_bytes: 128 * 1024 * 1024,
        }
    }

    fn vacant() -> PathOccupancyEvidence {
        PathOccupancyEvidence {
            path: "/data/.linux-storage-manager.swap".into(),
            exists: false,
            kind: None,
            uid: None,
            mode: None,
            size_bytes: None,
        }
    }

    #[test]
    fn exact_live_evidence_is_ready_for_nonmutating_runtime_preflight() {
        assert!(validate_runtime_evidence(
            &activation(),
            &snapshot(),
            &HibernationResumeEvidence::default(),
            &space(),
            &vacant()
        )
        .is_ok());
    }

    #[test]
    fn hibernation_resume_configuration_fails_closed() {
        let resume = HibernationResumeEvidence {
            kernel_resume_targets: vec!["UUID=swap".into()],
            ..HibernationResumeEvidence::default()
        };
        assert!(matches!(
            validate_runtime_evidence(&activation(), &snapshot(), &resume, &space(), &vacant()),
            Err(ProductionSwapRuntimePreflightError::ResumeConfigured)
        ));
    }

    #[test]
    fn occupied_swapfile_path_fails_closed() {
        let mut occupied = vacant();
        occupied.exists = true;
        assert!(matches!(
            validate_runtime_evidence(
                &activation(),
                &snapshot(),
                &HibernationResumeEvidence::default(),
                &space(),
                &occupied
            ),
            Err(ProductionSwapRuntimePreflightError::SwapfilePathOccupied)
        ));
    }

    #[test]
    fn changed_swap_priority_fails_closed() {
        let mut snapshot = snapshot();
        snapshot.swaps[0].priority = 8;
        assert!(matches!(
            validate_runtime_evidence(
                &activation(),
                &snapshot,
                &HibernationResumeEvidence::default(),
                &space(),
                &vacant()
            ),
            Err(ProductionSwapRuntimePreflightError::RetiringSwapChanged)
        ));
    }

    #[test]
    fn default_build_keeps_runtime_preflight_disabled() {
        assert_eq!(
            PRODUCTION_SWAP_RUNTIME_PREFLIGHT_COMPILED,
            cfg!(feature = "production-swap-replacement-runtime-preflight")
        );
    }
}
