use std::path::{Component, Path};

use lsm_planner::{CreatePartitionTablePolicy, FrozenBlankDiskFilesystemIntent, PlanStatus};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// M2A2 only seals a non-executing activation contract.
/// It cannot write a partition table, create a partition or run mkfs.
pub const PRODUCTION_CREATE_ACTIVATION_COMPILED: bool =
    cfg!(feature = "production-create-activation");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionCreateProfile {
    BlankDiskSinglePartitionFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateActivationReadiness {
    pub schema_version: u32,
    pub profile: ProductionCreateProfile,
    pub compile_feature_enabled: bool,
    pub intent_ready: bool,
    pub intent_integrity_verified: bool,
    pub exact_profile: bool,
    pub blockers: Vec<String>,
}

impl ProductionCreateActivationReadiness {
    pub fn ready(&self) -> bool {
        self.compile_feature_enabled
            && self.intent_ready
            && self.intent_integrity_verified
            && self.exact_profile
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateActivationIntent {
    pub schema_version: u32,
    pub activation_id: String,
    pub profile: ProductionCreateProfile,
    pub create_intent_id: String,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub disk_model: Option<String>,
    pub disk_serial: Option<String>,
    pub partition_table: CreatePartitionTablePolicy,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct ActivationDigestPayload<'a> {
    schema_version: u32,
    profile: ProductionCreateProfile,
    create_intent_id: &'a str,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    disk_model: &'a Option<String>,
    disk_serial: &'a Option<String>,
    partition_table: CreatePartitionTablePolicy,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    compile_feature_enabled: bool,
    execution_enabled: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionCreateActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.activation_id == self.expected_activation_id()?)
    }

    fn expected_activation_id(&self) -> Result<String, serde_json::Error> {
        let payload = ActivationDigestPayload {
            schema_version: self.schema_version,
            profile: self.profile,
            create_intent_id: &self.create_intent_id,
            create_plan_id: &self.create_plan_id,
            source_id: &self.source_id,
            disk: &self.disk,
            disk_size_bytes: self.disk_size_bytes,
            logical_sector_bytes: self.logical_sector_bytes,
            disk_model: &self.disk_model,
            disk_serial: &self.disk_serial,
            partition_table: self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            compile_feature_enabled: self.compile_feature_enabled,
            execution_enabled: self.execution_enabled,
            partition_table_changed: self.partition_table_changed,
            filesystem_formatted: self.filesystem_formatted,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionCreateActivationError {
    #[error("production create activation feature is not compiled")]
    FeatureDisabled,
    #[error("frozen create intent is not ready")]
    IntentNotReady,
    #[error("frozen create intent integrity verification failed")]
    IntentIntegrityMismatch,
    #[error("frozen create intent is outside the exact M2A2 production profile")]
    UnsupportedProfile,
    #[error("production create activation serialization failed: {0}")]
    Serialization(String),
}

fn safe_device_path(value: &str) -> bool {
    if value.is_empty() || value.as_bytes().contains(&0) || !value.starts_with("/dev/") {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn no_controls(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn exact_profile(intent: &FrozenBlankDiskFilesystemIntent) -> bool {
    let Some(end_sector) = intent
        .partition_start_sector
        .checked_add(intent.partition_sector_count)
    else {
        return false;
    };
    let disk_sectors = if intent.logical_sector_bytes > 0 {
        intent.disk_size_bytes / intent.logical_sector_bytes
    } else {
        0
    };
    let Some(expected_partition_bytes) = intent
        .partition_sector_count
        .checked_mul(intent.logical_sector_bytes)
    else {
        return false;
    };

    intent.schema_version == 1
        && intent.status == PlanStatus::Preview
        && !intent.executable
        && intent.blockers.is_empty()
        && safe_device_path(&intent.disk)
        && intent.disk_size_bytes > 0
        && matches!(intent.logical_sector_bytes, 512 | 4096)
        && intent.disk_size_bytes % intent.logical_sector_bytes == 0
        && intent.partition_start_sector > 0
        && intent.partition_sector_count > 0
        && end_sector <= disk_sectors
        && intent.partition_size_bytes == expected_partition_bytes
        && matches!(
            intent.partition_table,
            CreatePartitionTablePolicy::Gpt | CreatePartitionTablePolicy::Dos
        )
        && matches!(intent.filesystem.as_str(), "ext4" | "xfs")
        && intent.mountpoint.is_none()
        && no_controls(&intent.create_plan_id)
        && intent.source_id.starts_with("space-")
        && no_controls(&intent.source_id)
        && intent
            .disk_model
            .as_deref()
            .is_none_or(|value| !value.chars().any(char::is_control))
        && intent
            .disk_serial
            .as_deref()
            .is_none_or(|value| !value.chars().any(char::is_control))
        && !intent.ordered_future_steps.is_empty()
}

pub fn inspect_production_create_activation_readiness(
    intent: &FrozenBlankDiskFilesystemIntent,
) -> ProductionCreateActivationReadiness {
    let mut blockers = Vec::new();

    let intent_ready = intent.ready();
    if !intent_ready {
        blockers.push("create-intent-not-ready".to_owned());
    }

    let intent_integrity_verified = intent.integrity_matches().unwrap_or(false);
    if !intent_integrity_verified {
        blockers.push("create-intent-integrity-mismatch".to_owned());
    }

    let exact_profile = exact_profile(intent);
    if !exact_profile {
        blockers.push("unsupported-create-profile".to_owned());
    }

    if !PRODUCTION_CREATE_ACTIVATION_COMPILED {
        blockers.push("production-create-activation-feature-disabled".to_owned());
    }

    ProductionCreateActivationReadiness {
        schema_version: 1,
        profile: ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
        compile_feature_enabled: PRODUCTION_CREATE_ACTIVATION_COMPILED,
        intent_ready,
        intent_integrity_verified,
        exact_profile,
        blockers,
    }
}

pub fn seal_production_create_activation_intent(
    intent: &FrozenBlankDiskFilesystemIntent,
) -> Result<ProductionCreateActivationIntent, ProductionCreateActivationError> {
    if !PRODUCTION_CREATE_ACTIVATION_COMPILED {
        return Err(ProductionCreateActivationError::FeatureDisabled);
    }
    if !intent.ready() {
        return Err(ProductionCreateActivationError::IntentNotReady);
    }
    if !intent.integrity_matches().unwrap_or(false) {
        return Err(ProductionCreateActivationError::IntentIntegrityMismatch);
    }
    if !exact_profile(intent) {
        return Err(ProductionCreateActivationError::UnsupportedProfile);
    }

    let mut activation = ProductionCreateActivationIntent {
        schema_version: 1,
        activation_id: String::new(),
        profile: ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
        create_intent_id: intent.intent_id.clone(),
        create_plan_id: intent.create_plan_id.clone(),
        source_id: intent.source_id.clone(),
        disk: intent.disk.clone(),
        disk_size_bytes: intent.disk_size_bytes,
        logical_sector_bytes: intent.logical_sector_bytes,
        disk_model: intent.disk_model.clone(),
        disk_serial: intent.disk_serial.clone(),
        partition_table: intent.partition_table,
        partition_start_sector: intent.partition_start_sector,
        partition_sector_count: intent.partition_sector_count,
        partition_size_bytes: intent.partition_size_bytes,
        filesystem: intent.filesystem.clone(),
        compile_feature_enabled: true,
        execution_enabled: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    activation.activation_id = activation
        .expected_activation_id()
        .map_err(|error| ProductionCreateActivationError::Serialization(error.to_string()))?;
    Ok(activation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::HostSnapshot;
    use lsm_planner::{
        freeze_blank_disk_filesystem_create_intent, list_provisioning_opportunities, plan_create,
        CreatePurpose, CreateRequest, Growth, ProvisioningSpaceKind,
    };
    use serde_json::json;

    fn snapshot() -> HostSnapshot {
        serde_json::from_value(json!({
            "storage": {"block_devices":[{
                "name":"loop7","kernel_name":"loop7","path":"/dev/loop7","kind":"loop",
                "size_bytes":536870912u64,"start_512_sector":null,"logical_sector_bytes":512,
                "filesystem":null,"mountpoints":[],"parent_kernel_name":null,
                "model":"loop-test","serial":"fixture-001","uuid":null,"partition_uuid":null,
                "partition_table":null,"children":[]
            }]},
            "partition_tables":[],
            "mounts":[],
            "fstab":[],
            "swaps":[],
            "lvm":null,
            "filesystem_preflight":[],
            "diagnostics":[],
            "collectors":[{"component":"partition_tables","state":"complete","detail":null}]
        }))
        .unwrap()
    }

    fn valid_intent() -> FrozenBlankDiskFilesystemIntent {
        let snapshot = snapshot();
        let source = list_provisioning_opportunities(&snapshot)
            .into_iter()
            .find(|source| source.kind == ProvisioningSpaceKind::BlankDisk)
            .unwrap();
        let plan = plan_create(
            &snapshot,
            CreateRequest {
                source_id: source.id,
                size: Growth::ByBytes(128 * 1024 * 1024),
                purpose: CreatePurpose::Filesystem,
                filesystem: Some("ext4".into()),
                mountpoint: None,
                partition_table: Some(CreatePartitionTablePolicy::Gpt),
            },
        )
        .unwrap();
        freeze_blank_disk_filesystem_create_intent(&snapshot, &plan).unwrap()
    }

    #[test]
    fn readiness_separates_profile_integrity_and_compile_gate() {
        let intent = valid_intent();
        let readiness = inspect_production_create_activation_readiness(&intent);
        assert!(readiness.intent_ready);
        assert!(readiness.intent_integrity_verified);
        assert!(readiness.exact_profile);
        assert_eq!(
            readiness.compile_feature_enabled,
            PRODUCTION_CREATE_ACTIVATION_COMPILED
        );
    }

    #[test]
    fn exact_intent_seals_nonexecuting_activation_when_feature_is_compiled() {
        let intent = valid_intent();
        if PRODUCTION_CREATE_ACTIVATION_COMPILED {
            let activation = seal_production_create_activation_intent(&intent).unwrap();
            assert!(activation.integrity_matches().unwrap());
            assert_eq!(activation.create_intent_id, intent.intent_id);
            assert!(!activation.execution_enabled);
            assert!(!activation.partition_table_changed);
            assert!(!activation.filesystem_formatted);
        } else {
            assert_eq!(
                seal_production_create_activation_intent(&intent),
                Err(ProductionCreateActivationError::FeatureDisabled)
            );
        }
    }

    #[test]
    fn tampered_frozen_intent_is_rejected_before_activation() {
        let mut intent = valid_intent();
        intent.partition_sector_count += 1;
        let readiness = inspect_production_create_activation_readiness(&intent);
        assert!(!readiness.intent_integrity_verified);
        if PRODUCTION_CREATE_ACTIVATION_COMPILED {
            assert_eq!(
                seal_production_create_activation_intent(&intent),
                Err(ProductionCreateActivationError::IntentIntegrityMismatch)
            );
        }
    }

    #[test]
    fn mount_or_unknown_filesystem_profile_stays_blocked() {
        let mut intent = valid_intent();
        intent.filesystem = "btrfs".into();
        assert!(!inspect_production_create_activation_readiness(&intent).exact_profile);
    }
}
