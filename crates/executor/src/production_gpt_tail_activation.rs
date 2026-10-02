use std::path::{Component, Path};

use lsm_planner::{FrozenGptTailFilesystemIntent, PlanStatus};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// M2B2 seals only a non-executing production activation around an M2B1
/// verified existing-GPT-tail Create intent. It cannot choose a partition
/// number, construct a mutation command, spawn a process, write GPT or run mkfs.
pub const PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED: bool =
    cfg!(feature = "production-gpt-tail-activation");

const CREATE_PARTITION_ALIGNMENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionGptTailCreateProfile {
    ExistingGptTailFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateActivationReadiness {
    pub schema_version: u32,
    pub profile: ProductionGptTailCreateProfile,
    pub compile_feature_enabled: bool,
    pub intent_ready: bool,
    pub intent_integrity_verified: bool,
    pub exact_profile: bool,
    pub blockers: Vec<String>,
}

impl ProductionGptTailCreateActivationReadiness {
    pub fn ready(&self) -> bool {
        self.compile_feature_enabled
            && self.intent_ready
            && self.intent_integrity_verified
            && self.exact_profile
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateActivationIntent {
    pub schema_version: u32,
    pub activation_id: String,
    pub profile: ProductionGptTailCreateProfile,
    pub create_intent_id: String,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub disk_model: Option<String>,
    pub disk_serial: Option<String>,
    pub gpt_disk_id: String,
    pub gpt_first_lba: u64,
    pub gpt_last_lba: u64,
    pub gpt_sector_size_bytes: u64,
    pub gpt_table_sha256: String,
    pub existing_partition_count: u32,
    pub source_start_sector: u64,
    pub source_sector_count: u64,
    pub source_size_bytes: u64,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub partition_slot_deferred: bool,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct ActivationDigestPayload<'a> {
    schema_version: u32,
    profile: ProductionGptTailCreateProfile,
    create_intent_id: &'a str,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    disk_model: &'a Option<String>,
    disk_serial: &'a Option<String>,
    gpt_disk_id: &'a str,
    gpt_first_lba: u64,
    gpt_last_lba: u64,
    gpt_sector_size_bytes: u64,
    gpt_table_sha256: &'a str,
    existing_partition_count: u32,
    source_start_sector: u64,
    source_sector_count: u64,
    source_size_bytes: u64,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    partition_slot_deferred: bool,
    compile_feature_enabled: bool,
    execution_enabled: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionGptTailCreateActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.activation_id == self.expected_activation_id()?)
    }

    pub(crate) fn expected_activation_id(&self) -> Result<String, serde_json::Error> {
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
            gpt_disk_id: &self.gpt_disk_id,
            gpt_first_lba: self.gpt_first_lba,
            gpt_last_lba: self.gpt_last_lba,
            gpt_sector_size_bytes: self.gpt_sector_size_bytes,
            gpt_table_sha256: &self.gpt_table_sha256,
            existing_partition_count: self.existing_partition_count,
            source_start_sector: self.source_start_sector,
            source_sector_count: self.source_sector_count,
            source_size_bytes: self.source_size_bytes,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            partition_slot_deferred: self.partition_slot_deferred,
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
pub enum ProductionGptTailCreateActivationError {
    #[error("production GPT-tail create activation feature is not compiled")]
    FeatureDisabled,
    #[error("frozen GPT-tail create intent is not ready")]
    IntentNotReady,
    #[error("frozen GPT-tail create intent integrity verification failed")]
    IntentIntegrityMismatch,
    #[error("frozen GPT-tail create intent is outside the exact M2B2 production profile")]
    UnsupportedProfile,
    #[error("production GPT-tail create activation serialization failed: {0}")]
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

fn digest64(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

fn exact_profile(intent: &FrozenGptTailFilesystemIntent) -> bool {
    let sector = intent.disk.logical_sector_bytes;
    if !(512..=4096).contains(&sector) || !sector.is_power_of_two() {
        return false;
    }
    let Some(source_bytes) = intent.allocation.source_sector_count.checked_mul(sector) else {
        return false;
    };
    let Some(partition_bytes) = intent.allocation.partition_sector_count.checked_mul(sector) else {
        return false;
    };
    let Some(source_end) = intent
        .allocation
        .source_start_sector
        .checked_add(intent.allocation.source_sector_count)
    else {
        return false;
    };
    let Some(partition_end) = intent
        .allocation
        .partition_start_sector
        .checked_add(intent.allocation.partition_sector_count)
    else {
        return false;
    };
    let Some(gpt_limit) = intent.gpt.last_lba.checked_add(1) else {
        return false;
    };
    if CREATE_PARTITION_ALIGNMENT_BYTES % sector != 0 {
        return false;
    }
    let alignment_sectors = CREATE_PARTITION_ALIGNMENT_BYTES / sector;

    intent.schema_version == 1
        && intent.status == PlanStatus::Preview
        && intent.blockers.is_empty()
        && !intent.executable
        && intent.partition_slot_deferred
        && !intent.partition_table_write_authorized
        && !intent.filesystem_format_authorized
        && safe_device_path(&intent.disk.path)
        && intent.disk.size_bytes > 0
        && intent.disk.size_bytes % sector == 0
        && intent.gpt.label == "gpt"
        && intent.gpt.unit == "sectors"
        && no_controls(&intent.gpt.id)
        && intent.gpt.first_lba > 0
        && intent.gpt.last_lba >= intent.gpt.first_lba
        && intent.gpt.sector_size_bytes == sector
        && digest64(&intent.gpt.table_sha256)
        && intent.allocation.source_start_sector >= intent.gpt.first_lba
        && intent.allocation.source_sector_count > 0
        && intent.allocation.source_size_bytes == source_bytes
        && source_end <= gpt_limit
        && intent.allocation.partition_start_sector == intent.allocation.source_start_sector
        && intent.allocation.partition_sector_count > 0
        && intent.allocation.partition_sector_count <= intent.allocation.source_sector_count
        && intent.allocation.partition_size_bytes == partition_bytes
        && partition_end <= source_end
        && intent.allocation.partition_start_sector % alignment_sectors == 0
        && matches!(intent.filesystem.as_str(), "ext4" | "xfs")
        && intent.mountpoint.is_none()
        && no_controls(&intent.create_plan_id)
        && intent.source_id.starts_with("space-")
        && no_controls(&intent.source_id)
        && intent
            .disk
            .model
            .as_deref()
            .is_none_or(|value| !value.chars().any(char::is_control))
        && intent
            .disk
            .serial
            .as_deref()
            .is_none_or(|value| !value.chars().any(char::is_control))
        && !intent.ordered_future_steps.is_empty()
}

pub fn inspect_production_gpt_tail_create_activation_readiness(
    intent: &FrozenGptTailFilesystemIntent,
) -> ProductionGptTailCreateActivationReadiness {
    let mut blockers = Vec::new();

    let intent_ready = intent.ready();
    if !intent_ready {
        blockers.push("gpt-tail-create-intent-not-ready".to_owned());
    }

    let intent_integrity_verified = intent.integrity_matches().unwrap_or(false);
    if !intent_integrity_verified {
        blockers.push("gpt-tail-create-intent-integrity-mismatch".to_owned());
    }

    let exact_profile = exact_profile(intent);
    if !exact_profile {
        blockers.push("unsupported-gpt-tail-create-profile".to_owned());
    }

    if !PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED {
        blockers.push("production-gpt-tail-create-activation-feature-disabled".to_owned());
    }

    ProductionGptTailCreateActivationReadiness {
        schema_version: 1,
        profile: ProductionGptTailCreateProfile::ExistingGptTailFilesystem,
        compile_feature_enabled: PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED,
        intent_ready,
        intent_integrity_verified,
        exact_profile,
        blockers,
    }
}

pub fn seal_production_gpt_tail_create_activation_intent(
    intent: &FrozenGptTailFilesystemIntent,
) -> Result<ProductionGptTailCreateActivationIntent, ProductionGptTailCreateActivationError> {
    if !PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED {
        return Err(ProductionGptTailCreateActivationError::FeatureDisabled);
    }
    if !intent.ready() {
        return Err(ProductionGptTailCreateActivationError::IntentNotReady);
    }
    if !intent.integrity_matches().unwrap_or(false) {
        return Err(ProductionGptTailCreateActivationError::IntentIntegrityMismatch);
    }
    if !exact_profile(intent) {
        return Err(ProductionGptTailCreateActivationError::UnsupportedProfile);
    }

    let mut activation = ProductionGptTailCreateActivationIntent {
        schema_version: 1,
        activation_id: String::new(),
        profile: ProductionGptTailCreateProfile::ExistingGptTailFilesystem,
        create_intent_id: intent.intent_id.clone(),
        create_plan_id: intent.create_plan_id.clone(),
        source_id: intent.source_id.clone(),
        disk: intent.disk.path.clone(),
        disk_size_bytes: intent.disk.size_bytes,
        logical_sector_bytes: intent.disk.logical_sector_bytes,
        disk_model: intent.disk.model.clone(),
        disk_serial: intent.disk.serial.clone(),
        gpt_disk_id: intent.gpt.id.clone(),
        gpt_first_lba: intent.gpt.first_lba,
        gpt_last_lba: intent.gpt.last_lba,
        gpt_sector_size_bytes: intent.gpt.sector_size_bytes,
        gpt_table_sha256: intent.gpt.table_sha256.clone(),
        existing_partition_count: intent.gpt.existing_partition_count,
        source_start_sector: intent.allocation.source_start_sector,
        source_sector_count: intent.allocation.source_sector_count,
        source_size_bytes: intent.allocation.source_size_bytes,
        partition_start_sector: intent.allocation.partition_start_sector,
        partition_sector_count: intent.allocation.partition_sector_count,
        partition_size_bytes: intent.allocation.partition_size_bytes,
        filesystem: intent.filesystem.clone(),
        partition_slot_deferred: true,
        compile_feature_enabled: true,
        execution_enabled: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    activation.activation_id = activation.expected_activation_id().map_err(|error| {
        ProductionGptTailCreateActivationError::Serialization(error.to_string())
    })?;
    Ok(activation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::HostSnapshot;
    use lsm_planner::{
        freeze_gpt_tail_filesystem_create_intent, list_provisioning_opportunities, plan_create,
        CreatePurpose, CreateRequest, Growth, ProvisioningSpaceKind,
    };
    use serde_json::json;

    const MIB: u64 = 1024 * 1024;

    fn valid_intent() -> FrozenGptTailFilesystemIntent {
        let disk_bytes = 512 * MIB;
        let sector = 512_u64;
        let disk_sectors = disk_bytes / sector;
        let first_start = 2048_u64;
        let first_size_sectors = 64 * MIB / sector;
        let snapshot: HostSnapshot = serde_json::from_value(json!({
            "storage":{"block_devices":[{
                "name":"loop7","kernel_name":"loop7","path":"/dev/loop7","kind":"loop",
                "size_bytes":disk_bytes,"start_512_sector":null,"logical_sector_bytes":sector,
                "filesystem":null,"mountpoints":[],"parent_kernel_name":null,
                "model":"loop-test","serial":"fixture-001","uuid":null,"partition_uuid":null,
                "partition_table":"gpt","children":[{
                    "name":"loop7p1","kernel_name":"loop7p1","path":"/dev/loop7p1","kind":"partition",
                    "size_bytes":64*MIB,"start_512_sector":first_start,
                    "logical_sector_bytes":sector,"filesystem":{"fs_type":"ext4","version":null},
                    "mountpoints":[],"parent_kernel_name":"loop7","model":null,"serial":null,
                    "uuid":"11111111-1111-1111-1111-111111111111",
                    "partition_uuid":"22222222-2222-2222-2222-222222222222",
                    "partition_table":null,"children":[]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/loop7","label":"gpt",
                "id":"12345678-1234-1234-1234-123456789abc","unit":"sectors",
                "first_lba":34,"last_lba":disk_sectors-34,"sector_size_bytes":sector,
                "partitions":[{
                    "node":"/dev/loop7p1","start_sector":first_start,
                    "size_sectors":first_size_sectors,
                    "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                    "uuid":"22222222-2222-2222-2222-222222222222",
                    "name":null,"attrs":null,"bootable":null
                }]
            }],
            "mounts":[],"fstab":[],"swaps":[],"lvm":null,
            "filesystem_preflight":[],"diagnostics":[],
            "collectors":[
                {"component":"lsblk","state":"complete","detail":null},
                {"component":"partition_tables","state":"complete","detail":null}
            ]
        }))
        .unwrap();

        let source = list_provisioning_opportunities(&snapshot)
            .into_iter()
            .find(|source| source.kind == ProvisioningSpaceKind::DiskTail)
            .unwrap();
        let plan = plan_create(
            &snapshot,
            CreateRequest {
                source_id: source.id,
                size: Growth::ByBytes(64 * MIB),
                purpose: CreatePurpose::Filesystem,
                filesystem: Some("ext4".into()),
                mountpoint: None,
                partition_table: None,
            },
        )
        .unwrap();
        freeze_gpt_tail_filesystem_create_intent(&snapshot, &plan).unwrap()
    }

    #[test]
    fn readiness_separates_integrity_profile_and_compile_gate() {
        let intent = valid_intent();
        let readiness = inspect_production_gpt_tail_create_activation_readiness(&intent);
        assert!(readiness.intent_ready);
        assert!(readiness.intent_integrity_verified);
        assert!(readiness.exact_profile);
        assert_eq!(
            readiness.compile_feature_enabled,
            PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED
        );
    }

    #[test]
    fn exact_intent_seals_nonexecuting_activation_when_compiled() {
        let intent = valid_intent();
        if PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED {
            let activation = seal_production_gpt_tail_create_activation_intent(&intent).unwrap();
            assert!(activation.integrity_matches().unwrap());
            assert_eq!(activation.create_intent_id, intent.intent_id);
            assert_eq!(activation.gpt_disk_id, intent.gpt.id);
            assert_eq!(activation.gpt_table_sha256, intent.gpt.table_sha256);
            assert!(activation.partition_slot_deferred);
            assert!(!activation.execution_enabled);
            assert!(!activation.partition_table_changed);
            assert!(!activation.filesystem_formatted);
        } else {
            assert_eq!(
                seal_production_gpt_tail_create_activation_intent(&intent),
                Err(ProductionGptTailCreateActivationError::FeatureDisabled)
            );
        }
    }

    #[test]
    fn upstream_mutation_authorization_is_rejected() {
        let mut intent = valid_intent();
        intent.partition_table_write_authorized = true;
        let readiness = inspect_production_gpt_tail_create_activation_readiness(&intent);
        assert!(!readiness.intent_integrity_verified);
        assert!(!readiness.exact_profile);
        assert!(!readiness.ready());
    }

    #[test]
    fn activation_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_GPT_TAIL_CREATE_ACTIVATION_COMPILED,
            cfg!(feature = "production-gpt-tail-activation")
        );
    }
}
