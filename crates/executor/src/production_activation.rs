use lsm_planner::{ExecutionStartBinding, LayerRouteStatus, TargetIdentityManifest};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{FrozenIntentRole, NativeOperationSpec, ValidatedNativeManifest};

/// This feature only permits constructing a production-activation intent.
/// It does not change MUTATION_ENABLED and cannot spawn storage tools by itself.
pub const PRODUCTION_MUTATION_ACTIVATION_COMPILED: bool =
    cfg!(feature = "production-mutation-activation");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionMutationProfile {
    ExistingSinglePvLvmFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionActivationReadiness {
    pub schema_version: u32,
    pub profile: ProductionMutationProfile,
    pub compile_feature_enabled: bool,
    pub topology_eligible: bool,
    pub exact_execution_binding: bool,
    pub exact_identity_binding: bool,
    pub mutation_step_ids: Vec<u32>,
    pub blockers: Vec<String>,
}

impl ProductionActivationReadiness {
    pub fn ready(&self) -> bool {
        self.compile_feature_enabled
            && self.topology_eligible
            && self.exact_execution_binding
            && self.exact_identity_binding
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationActivationIntent {
    pub schema_version: u32,
    pub activation_id: String,
    pub profile: ProductionMutationProfile,
    pub execution_id: String,
    pub source_manifest_id: String,
    pub native_manifest_digest: String,
    pub fresh_identity_digest: String,
    pub target: String,
    pub resolved_device: String,
    pub lv_step_id: u32,
    pub filesystem_step_id: u32,
    pub filesystem_type: String,
    pub filesystem_mountpoint: Option<String>,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
}

impl ProductionMutationActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.activation_id == self.expected_activation_id()?)
    }

    fn expected_activation_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            self.profile,
            &self.execution_id,
            &self.source_manifest_id,
            &self.native_manifest_digest,
            &self.fresh_identity_digest,
            &self.target,
            &self.resolved_device,
            self.lv_step_id,
            self.filesystem_step_id,
            &self.filesystem_type,
            &self.filesystem_mountpoint,
            self.compile_feature_enabled,
            self.execution_enabled,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionActivationError {
    #[error("production mutation activation feature is not compiled")]
    FeatureDisabled,
    #[error("execution binding is invalid or does not match the validated manifest")]
    ExecutionBindingMismatch,
    #[error("fresh target identity does not match the execution binding")]
    FreshIdentityMismatch,
    #[error("production activation is limited to the exact existing-LVM LV -> filesystem profile")]
    UnsupportedProfile,
    #[error("production activation requires an exact two-step mutation sequence")]
    MutationSequenceMismatch,
    #[error("filesystem identity does not match the authorized filesystem mutation")]
    FilesystemIdentityMismatch,
    #[error("activation intent serialization failed: {0}")]
    Serialization(String),
}

fn mutation_steps(validated: &ValidatedNativeManifest) -> Vec<&crate::NativeCompiledStep> {
    validated
        .manifest()
        .steps
        .iter()
        .filter(|step| step.role == FrozenIntentRole::MutationCandidate)
        .collect()
}

fn exact_profile(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
) -> Result<(u32, u32, String, String, Option<String>), ProductionActivationError> {
    let mutations = mutation_steps(validated);
    if mutations.len() != 2 || execution.mutation_step_ids.len() != 2 {
        return Err(ProductionActivationError::MutationSequenceMismatch);
    }

    let lv = mutations[0];
    let filesystem = mutations[1];
    if execution.mutation_step_ids != [lv.plan_step_id, filesystem.plan_step_id] {
        return Err(ProductionActivationError::MutationSequenceMismatch);
    }
    if !filesystem.depends_on.contains(&lv.plan_step_id) {
        return Err(ProductionActivationError::UnsupportedProfile);
    }

    match (&lv.operation, &filesystem.operation) {
        (
            NativeOperationSpec::ExtendLogicalVolume { lv_uuid, .. },
            NativeOperationSpec::GrowFilesystem {
                fs_type,
                mountpoint,
            },
        ) if matches!(fs_type.as_str(), "ext4" | "xfs")
            && (fs_type == "ext4" || mountpoint.is_some()) =>
        {
            Ok((
                lv.plan_step_id,
                filesystem.plan_step_id,
                lv_uuid.clone(),
                fs_type.clone(),
                mountpoint.clone(),
            ))
        }
        _ => Err(ProductionActivationError::UnsupportedProfile),
    }
}

fn validate_execution_binding(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
) -> Result<(), ProductionActivationError> {
    if execution.schema_version != 1
        || !execution.integrity_matches().unwrap_or(false)
        || execution.source_manifest_id != validated.manifest().source_manifest_id
        || execution.native_manifest_digest != validated.digest()
    {
        return Err(ProductionActivationError::ExecutionBindingMismatch);
    }
    Ok(())
}

fn validate_identity_binding(
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
    lv_uuid: &str,
    filesystem_type: &str,
    filesystem_mountpoint: Option<&str>,
) -> Result<(), ProductionActivationError> {
    if identity.manifest_digest != execution.fresh_identity_digest
        || identity.route_status != LayerRouteStatus::SupportedProfile
        || identity.target.is_empty()
        || identity.resolved_device.is_empty()
    {
        return Err(ProductionActivationError::FreshIdentityMismatch);
    }

    let logical_volumes = identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == lsm_planner::LvmIdentityKind::LogicalVolume
                && entry.uuid.as_deref() == Some(lv_uuid)
        })
        .count();
    let physical_volumes = identity
        .lvm
        .iter()
        .filter(|entry| entry.kind == lsm_planner::LvmIdentityKind::PhysicalVolume)
        .count();
    let single_pv_vg = identity.lvm.iter().any(|entry| {
        entry.kind == lsm_planner::LvmIdentityKind::VolumeGroup && entry.pv_count == Some(1)
    });
    if logical_volumes != 1 || physical_volumes != 1 || !single_pv_vg {
        return Err(ProductionActivationError::FreshIdentityMismatch);
    }

    let filesystem = identity
        .filesystem
        .as_ref()
        .ok_or(ProductionActivationError::FilesystemIdentityMismatch)?;
    if filesystem.device != identity.resolved_device
        || filesystem.fs_type != filesystem_type
        || filesystem.uuid.is_none()
    {
        return Err(ProductionActivationError::FilesystemIdentityMismatch);
    }

    match filesystem_mountpoint {
        Some(expected) => {
            let matches = identity
                .mounts
                .iter()
                .filter(|mount| {
                    mount.target == expected && mount.fs_type.as_deref() == Some(filesystem_type)
                })
                .count();
            if matches != 1 {
                return Err(ProductionActivationError::FilesystemIdentityMismatch);
            }
        }
        None => {
            if filesystem_type != "ext4" || !identity.mounts.is_empty() {
                return Err(ProductionActivationError::FilesystemIdentityMismatch);
            }
        }
    }

    Ok(())
}

/// Inspect whether the exact first production profile is eligible without
/// enabling mutation. The only initially admitted scope is an already-created
/// single-PV LVM logical volume using existing VG extents followed by ext4/XFS
/// filesystem growth. Partition/PV mutation is intentionally excluded.
pub fn inspect_production_activation_readiness(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
) -> ProductionActivationReadiness {
    let mut blockers = Vec::new();

    let execution_ok = validate_execution_binding(validated, execution).is_ok();
    if !execution_ok {
        blockers.push("execution-binding-mismatch".to_owned());
    }

    let profile = exact_profile(validated, execution);
    let topology_eligible = profile.is_ok();
    if !topology_eligible {
        blockers.push("unsupported-production-profile".to_owned());
    }

    let identity_ok = match &profile {
        Ok((_, _, lv_uuid, fs_type, mountpoint)) => {
            validate_identity_binding(execution, identity, lv_uuid, fs_type, mountpoint.as_deref())
                .is_ok()
        }
        Err(_) => false,
    };
    if !identity_ok {
        blockers.push("fresh-identity-mismatch".to_owned());
    }

    if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
        blockers.push("production-activation-feature-disabled".to_owned());
    }

    ProductionActivationReadiness {
        schema_version: 1,
        profile: ProductionMutationProfile::ExistingSinglePvLvmFilesystem,
        compile_feature_enabled: PRODUCTION_MUTATION_ACTIVATION_COMPILED,
        topology_eligible,
        exact_execution_binding: execution_ok,
        exact_identity_binding: identity_ok,
        mutation_step_ids: execution.mutation_step_ids.clone(),
        blockers,
    }
}

/// Seal the exact production-activation intent.
///
/// Even with the compile-time feature enabled this object explicitly records
/// execution_enabled=false. A later reviewed gate must consume this intent
/// before MUTATION_ENABLED can ever become true.
pub fn seal_production_mutation_activation_intent(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
) -> Result<ProductionMutationActivationIntent, ProductionActivationError> {
    if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
        return Err(ProductionActivationError::FeatureDisabled);
    }
    validate_execution_binding(validated, execution)?;
    let (lv_step_id, filesystem_step_id, lv_uuid, filesystem_type, filesystem_mountpoint) =
        exact_profile(validated, execution)?;
    validate_identity_binding(
        execution,
        identity,
        &lv_uuid,
        &filesystem_type,
        filesystem_mountpoint.as_deref(),
    )?;

    let mut intent = ProductionMutationActivationIntent {
        schema_version: 1,
        activation_id: String::new(),
        profile: ProductionMutationProfile::ExistingSinglePvLvmFilesystem,
        execution_id: execution.execution_id.clone(),
        source_manifest_id: execution.source_manifest_id.clone(),
        native_manifest_digest: execution.native_manifest_digest.clone(),
        fresh_identity_digest: execution.fresh_identity_digest.clone(),
        target: identity.target.clone(),
        resolved_device: identity.resolved_device.clone(),
        lv_step_id,
        filesystem_step_id,
        filesystem_type,
        filesystem_mountpoint,
        compile_feature_enabled: true,
        execution_enabled: false,
    };
    intent.activation_id = intent
        .expected_activation_id()
        .map_err(|error| ProductionActivationError::Serialization(error.to_string()))?;
    Ok(intent)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionChainedMutationProfile {
    SinglePvPartitionTailLvmFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionChainedActivationReadiness {
    pub schema_version: u32,
    pub profile: ProductionChainedMutationProfile,
    pub compile_feature_enabled: bool,
    pub topology_eligible: bool,
    pub exact_execution_binding: bool,
    pub exact_identity_binding: bool,
    pub mutation_step_ids: Vec<u32>,
    pub blockers: Vec<String>,
}

impl ProductionChainedActivationReadiness {
    pub fn ready(&self) -> bool {
        self.compile_feature_enabled
            && self.topology_eligible
            && self.exact_execution_binding
            && self.exact_identity_binding
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionChainedMutationActivationIntent {
    pub schema_version: u32,
    pub activation_id: String,
    pub profile: ProductionChainedMutationProfile,
    pub execution_id: String,
    pub source_manifest_id: String,
    pub native_manifest_digest: String,
    pub fresh_identity_digest: String,
    pub target: String,
    pub resolved_device: String,
    pub partition_step_id: u32,
    pub pv_step_id: u32,
    pub lv_step_id: u32,
    pub filesystem_step_id: u32,
    pub partition: String,
    pub pv_uuid: String,
    pub lv_uuid: String,
    pub filesystem_type: String,
    pub filesystem_mountpoint: Option<String>,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
}

#[derive(Serialize)]
struct ProductionChainedActivationDigestPayload<'a> {
    schema_version: u32,
    profile: ProductionChainedMutationProfile,
    execution_id: &'a str,
    source_manifest_id: &'a str,
    native_manifest_digest: &'a str,
    fresh_identity_digest: &'a str,
    target: &'a str,
    resolved_device: &'a str,
    partition_step_id: u32,
    pv_step_id: u32,
    lv_step_id: u32,
    filesystem_step_id: u32,
    partition: &'a str,
    pv_uuid: &'a str,
    lv_uuid: &'a str,
    filesystem_type: &'a str,
    filesystem_mountpoint: &'a Option<String>,
    compile_feature_enabled: bool,
    execution_enabled: bool,
}

impl ProductionChainedMutationActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.activation_id == self.expected_activation_id()?)
    }

    fn expected_activation_id(&self) -> Result<String, serde_json::Error> {
        let payload = ProductionChainedActivationDigestPayload {
            schema_version: self.schema_version,
            profile: self.profile,
            execution_id: &self.execution_id,
            source_manifest_id: &self.source_manifest_id,
            native_manifest_digest: &self.native_manifest_digest,
            fresh_identity_digest: &self.fresh_identity_digest,
            target: &self.target,
            resolved_device: &self.resolved_device,
            partition_step_id: self.partition_step_id,
            pv_step_id: self.pv_step_id,
            lv_step_id: self.lv_step_id,
            filesystem_step_id: self.filesystem_step_id,
            partition: &self.partition,
            pv_uuid: &self.pv_uuid,
            lv_uuid: &self.lv_uuid,
            filesystem_type: &self.filesystem_type,
            filesystem_mountpoint: &self.filesystem_mountpoint,
            compile_feature_enabled: self.compile_feature_enabled,
            execution_enabled: self.execution_enabled,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionChainedActivationError {
    #[error("production mutation activation feature is not compiled")]
    FeatureDisabled,
    #[error("execution binding is invalid or does not match the validated manifest")]
    ExecutionBindingMismatch,
    #[error("production chained activation requires exact partition -> PV -> LV -> filesystem mutations")]
    MutationSequenceMismatch,
    #[error("production chained activation dependencies are not strictly ordered")]
    DependencyMismatch,
    #[error("production chained activation contains an unsupported operation profile")]
    UnsupportedProfile,
    #[error("fresh target identity does not match the exact chained pre-mutation state")]
    FreshIdentityMismatch,
    #[error("filesystem identity does not match the authorized chained filesystem mutation")]
    FilesystemIdentityMismatch,
    #[error("chained activation intent serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone)]
struct ChainedProfileSpec {
    partition_step_id: u32,
    pv_step_id: u32,
    lv_step_id: u32,
    filesystem_step_id: u32,
    partition: String,
    start_sector: u64,
    old_size_sectors: u64,
    sector_size_bytes: u64,
    pv_uuid: String,
    expected_pv_size_bytes: u64,
    lv_uuid: String,
    expected_lv_size_bytes: u64,
    filesystem_type: String,
    filesystem_mountpoint: Option<String>,
}

fn exact_chained_profile(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
) -> Result<ChainedProfileSpec, ProductionChainedActivationError> {
    let mutations = mutation_steps(validated);
    if mutations.len() != 4 || execution.mutation_step_ids.len() != 4 {
        return Err(ProductionChainedActivationError::MutationSequenceMismatch);
    }

    let partition = mutations[0];
    let pv = mutations[1];
    let lv = mutations[2];
    let filesystem = mutations[3];
    let exact_ids = [
        partition.plan_step_id,
        pv.plan_step_id,
        lv.plan_step_id,
        filesystem.plan_step_id,
    ];
    if execution.mutation_step_ids.as_slice() != exact_ids {
        return Err(ProductionChainedActivationError::MutationSequenceMismatch);
    }
    if !pv.depends_on.contains(&partition.plan_step_id)
        || !lv.depends_on.contains(&pv.plan_step_id)
        || !filesystem.depends_on.contains(&lv.plan_step_id)
    {
        return Err(ProductionChainedActivationError::DependencyMismatch);
    }

    match (
        &partition.operation,
        &pv.operation,
        &lv.operation,
        &filesystem.operation,
    ) {
        (
            NativeOperationSpec::ExtendPartition {
                partition,
                start_sector,
                old_size_sectors,
                new_size_sectors,
                sector_size_bytes,
            },
            NativeOperationSpec::ResizePhysicalVolume {
                pv_uuid,
                expected_pv_size_bytes,
            },
            NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid,
                expected_lv_size_bytes,
                ..
            },
            NativeOperationSpec::GrowFilesystem {
                fs_type,
                mountpoint,
            },
        ) if *new_size_sectors > *old_size_sectors
            && matches!(*sector_size_bytes, 512 | 4096)
            && matches!(fs_type.as_str(), "ext4" | "xfs")
            && (fs_type == "ext4" || mountpoint.is_some()) =>
        {
            Ok(ChainedProfileSpec {
                partition_step_id: mutations[0].plan_step_id,
                pv_step_id: mutations[1].plan_step_id,
                lv_step_id: mutations[2].plan_step_id,
                filesystem_step_id: mutations[3].plan_step_id,
                partition: partition.clone(),
                start_sector: *start_sector,
                old_size_sectors: *old_size_sectors,
                sector_size_bytes: *sector_size_bytes,
                pv_uuid: pv_uuid.clone(),
                expected_pv_size_bytes: *expected_pv_size_bytes,
                lv_uuid: lv_uuid.clone(),
                expected_lv_size_bytes: *expected_lv_size_bytes,
                filesystem_type: fs_type.clone(),
                filesystem_mountpoint: mountpoint.clone(),
            })
        }
        _ => Err(ProductionChainedActivationError::UnsupportedProfile),
    }
}

fn validate_chained_execution_binding(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
) -> Result<(), ProductionChainedActivationError> {
    if execution.schema_version != 1
        || !execution.integrity_matches().unwrap_or(false)
        || execution.source_manifest_id != validated.manifest().source_manifest_id
        || execution.native_manifest_digest != validated.digest()
    {
        return Err(ProductionChainedActivationError::ExecutionBindingMismatch);
    }
    Ok(())
}

fn validate_chained_identity_binding(
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
    profile: &ChainedProfileSpec,
) -> Result<(), ProductionChainedActivationError> {
    if identity.manifest_digest != execution.fresh_identity_digest
        || identity.route_status != LayerRouteStatus::SupportedProfile
        || identity.target.is_empty()
        || identity.resolved_device.is_empty()
    {
        return Err(ProductionChainedActivationError::FreshIdentityMismatch);
    }

    let partitions = identity
        .partitions
        .iter()
        .filter(|entry| entry.partition == profile.partition)
        .collect::<Vec<_>>();
    if partitions.len() != 1 {
        return Err(ProductionChainedActivationError::FreshIdentityMismatch);
    }
    let partition = partitions[0];
    if partition.start_sector != Some(profile.start_sector)
        || partition.size_sectors != Some(profile.old_size_sectors)
        || partition.sector_size_bytes != Some(profile.sector_size_bytes)
        || partition.disk.is_none()
    {
        return Err(ProductionChainedActivationError::FreshIdentityMismatch);
    }

    let physical_volumes = identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == lsm_planner::LvmIdentityKind::PhysicalVolume
                && entry.uuid.as_deref() == Some(profile.pv_uuid.as_str())
        })
        .collect::<Vec<_>>();
    let logical_volumes = identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == lsm_planner::LvmIdentityKind::LogicalVolume
                && entry.uuid.as_deref() == Some(profile.lv_uuid.as_str())
        })
        .collect::<Vec<_>>();
    let single_pv_vg = identity.lvm.iter().any(|entry| {
        entry.kind == lsm_planner::LvmIdentityKind::VolumeGroup && entry.pv_count == Some(1)
    });
    if physical_volumes.len() != 1
        || logical_volumes.len() != 1
        || !single_pv_vg
        || physical_volumes[0].name != profile.partition
        || physical_volumes[0].size_bytes >= profile.expected_pv_size_bytes
        || logical_volumes[0].size_bytes >= profile.expected_lv_size_bytes
    {
        return Err(ProductionChainedActivationError::FreshIdentityMismatch);
    }

    let filesystem = identity
        .filesystem
        .as_ref()
        .ok_or(ProductionChainedActivationError::FilesystemIdentityMismatch)?;
    if filesystem.device != identity.resolved_device
        || filesystem.fs_type != profile.filesystem_type
        || filesystem.uuid.is_none()
    {
        return Err(ProductionChainedActivationError::FilesystemIdentityMismatch);
    }

    match profile.filesystem_mountpoint.as_deref() {
        Some(expected) => {
            let matches = identity
                .mounts
                .iter()
                .filter(|mount| {
                    mount.target == expected
                        && mount.fs_type.as_deref() == Some(profile.filesystem_type.as_str())
                })
                .count();
            if matches != 1 {
                return Err(ProductionChainedActivationError::FilesystemIdentityMismatch);
            }
        }
        None => {
            if profile.filesystem_type != "ext4" || !identity.mounts.is_empty() {
                return Err(ProductionChainedActivationError::FilesystemIdentityMismatch);
            }
        }
    }

    Ok(())
}

/// Inspect the second production candidate without enabling any new execution
/// path. This profile admits only an already-existing single-PV LVM filesystem
/// whose backing partition has exact adjacent tail capacity and whose frozen
/// mutation order is partition -> PV -> LV -> filesystem.
pub fn inspect_production_chained_activation_readiness(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
) -> ProductionChainedActivationReadiness {
    let mut blockers = Vec::new();

    let execution_ok = validate_chained_execution_binding(validated, execution).is_ok();
    if !execution_ok {
        blockers.push("execution-binding-mismatch".to_owned());
    }

    let profile = exact_chained_profile(validated, execution);
    let topology_eligible = profile.is_ok();
    if !topology_eligible {
        blockers.push("unsupported-partition-pv-production-profile".to_owned());
    }

    let identity_ok = match profile.as_ref() {
        Ok(profile) => validate_chained_identity_binding(execution, identity, profile).is_ok(),
        Err(_) => false,
    };
    if !identity_ok {
        blockers.push("fresh-chained-identity-mismatch".to_owned());
    }

    if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
        blockers.push("production-activation-feature-disabled".to_owned());
    }

    ProductionChainedActivationReadiness {
        schema_version: 1,
        profile: ProductionChainedMutationProfile::SinglePvPartitionTailLvmFilesystem,
        compile_feature_enabled: PRODUCTION_MUTATION_ACTIVATION_COMPILED,
        topology_eligible,
        exact_execution_binding: execution_ok,
        exact_identity_binding: identity_ok,
        mutation_step_ids: execution.mutation_step_ids.clone(),
        blockers,
    }
}

/// Seal the exact non-executing activation contract for partition -> PV -> LV
/// -> filesystem growth. No downstream production execution permit consumes
/// this intent yet; M1B45 therefore expands eligibility evidence only and does
/// not broaden the M1B44 descriptor-execution scope.
pub fn seal_production_chained_mutation_activation_intent(
    validated: &ValidatedNativeManifest,
    execution: &ExecutionStartBinding,
    identity: &TargetIdentityManifest,
) -> Result<ProductionChainedMutationActivationIntent, ProductionChainedActivationError> {
    if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
        return Err(ProductionChainedActivationError::FeatureDisabled);
    }
    validate_chained_execution_binding(validated, execution)?;
    let profile = exact_chained_profile(validated, execution)?;
    validate_chained_identity_binding(execution, identity, &profile)?;

    let mut intent = ProductionChainedMutationActivationIntent {
        schema_version: 1,
        activation_id: String::new(),
        profile: ProductionChainedMutationProfile::SinglePvPartitionTailLvmFilesystem,
        execution_id: execution.execution_id.clone(),
        source_manifest_id: execution.source_manifest_id.clone(),
        native_manifest_digest: execution.native_manifest_digest.clone(),
        fresh_identity_digest: execution.fresh_identity_digest.clone(),
        target: identity.target.clone(),
        resolved_device: identity.resolved_device.clone(),
        partition_step_id: profile.partition_step_id,
        pv_step_id: profile.pv_step_id,
        lv_step_id: profile.lv_step_id,
        filesystem_step_id: profile.filesystem_step_id,
        partition: profile.partition,
        pv_uuid: profile.pv_uuid,
        lv_uuid: profile.lv_uuid,
        filesystem_type: profile.filesystem_type,
        filesystem_mountpoint: profile.filesystem_mountpoint,
        compile_feature_enabled: true,
        execution_enabled: false,
    };
    intent.activation_id = intent
        .expected_activation_id()
        .map_err(|error| ProductionChainedActivationError::Serialization(error.to_string()))?;
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        validate_and_bind_native_manifest, FrozenIntentRole, NativeCompiledManifest,
        NativeCompiledStep, NativeVerificationBarrier,
    };
    use lsm_planner::{
        FilesystemIdentity, LvmIdentity, LvmIdentityKind, MountIdentity,
        PartitionGeometryIdentity, Reversibility,
    };

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn validated(include_partition: bool) -> ValidatedNativeManifest {
        let mut steps = Vec::new();
        let mut barriers = Vec::new();
        let mut next_id = 3;

        if include_partition {
            steps.push(NativeCompiledStep {
                plan_step_id: next_id,
                depends_on: vec![],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ExtendPartition {
                    partition: "/dev/sda1".into(),
                    start_sector: 2048,
                    old_size_sectors: 1024,
                    new_size_sectors: 2048,
                    sector_size_bytes: 512,
                },
            });
            barriers.push(NativeVerificationBarrier {
                after_plan_step_id: next_id,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            });
            next_id += 1;
        }

        let lv_id = next_id;
        let fs_id = next_id + 1;
        steps.push(NativeCompiledStep {
            plan_step_id: lv_id,
            depends_on: if include_partition {
                vec![lv_id - 1]
            } else {
                vec![]
            },
            reversibility: Reversibility::Irreversible,
            role: FrozenIntentRole::MutationCandidate,
            operation: NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid: "lv-uuid".into(),
                additional_extents: 8,
                expected_lv_size_bytes: 2 * 1024 * 1024 * 1024,
            },
        });
        steps.push(NativeCompiledStep {
            plan_step_id: fs_id,
            depends_on: vec![lv_id],
            reversibility: Reversibility::Irreversible,
            role: FrozenIntentRole::MutationCandidate,
            operation: NativeOperationSpec::GrowFilesystem {
                fs_type: "ext4".into(),
                mountpoint: Some("/mnt/data".into()),
            },
        });
        for id in [lv_id, fs_id] {
            barriers.push(NativeVerificationBarrier {
                after_plan_step_id: id,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            });
        }

        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: digest('a'),
            steps,
            verification_barriers: barriers,
        })
        .unwrap()
    }

    fn execution(validated: &ValidatedNativeManifest) -> ExecutionStartBinding {
        let mutations = validated
            .manifest()
            .steps
            .iter()
            .filter(|step| step.role == FrozenIntentRole::MutationCandidate)
            .map(|step| step.plan_step_id)
            .collect::<Vec<_>>();
        let mut execution = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: digest('1'),
            plan_id: digest('2'),
            approval_id: digest('3'),
            source_manifest_id: validated.manifest().source_manifest_id.clone(),
            native_manifest_digest: validated.digest().to_owned(),
            fresh_identity_digest: digest('b'),
            mutation_step_ids: mutations,
            approved_journal_digest: digest('4'),
        };
        execution.execution_id = execution.expected_execution_id().unwrap();
        execution
    }

    fn identity() -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/data".into(),
            manifest_digest: digest('b'),
            resolved_device: "/dev/mapper/vg-data".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![],
            partitions: vec![],
            lvm: vec![
                LvmIdentity {
                    kind: LvmIdentityKind::PhysicalVolume,
                    name: "/dev/sda1".into(),
                    uuid: Some("pv-uuid".into()),
                    size_bytes: 4 * 1024 * 1024 * 1024,
                    free_bytes: None,
                    pe_start_bytes: Some(1024 * 1024),
                    extent_size_bytes: Some(4 * 1024 * 1024),
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: None,
                    layout: None,
                    role: None,
                },
                LvmIdentity {
                    kind: LvmIdentityKind::VolumeGroup,
                    name: "vg".into(),
                    uuid: Some("vg-uuid".into()),
                    size_bytes: 4 * 1024 * 1024 * 1024,
                    free_bytes: Some(2 * 1024 * 1024 * 1024),
                    pe_start_bytes: None,
                    extent_size_bytes: Some(4 * 1024 * 1024),
                    free_extent_count: Some(512),
                    pv_count: Some(1),
                    lv_count: Some(1),
                    attributes: None,
                    layout: None,
                    role: None,
                },
                LvmIdentity {
                    kind: LvmIdentityKind::LogicalVolume,
                    name: "/dev/mapper/vg-data".into(),
                    uuid: Some("lv-uuid".into()),
                    size_bytes: 1024 * 1024 * 1024,
                    free_bytes: None,
                    pe_start_bytes: None,
                    extent_size_bytes: Some(4 * 1024 * 1024),
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: None,
                    layout: None,
                    role: None,
                },
            ],
            filesystem: Some(FilesystemIdentity {
                device: "/dev/mapper/vg-data".into(),
                fs_type: "ext4".into(),
                fs_version: Some("1.0".into()),
                uuid: Some("fs-uuid".into()),
                backing_device_size_bytes: 1024 * 1024 * 1024,
                observed_filesystem_size_bytes: Some(1024 * 1024 * 1024),
            }),
            mounts: vec![MountIdentity {
                source: Some("/dev/mapper/vg-data".into()),
                target: "/mnt/data".into(),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            }],
        }
    }

    #[test]
    fn default_build_reports_activation_feature_disabled() {
        let validated = validated(false);
        let execution = execution(&validated);
        let readiness =
            inspect_production_activation_readiness(&validated, &execution, &identity());

        assert!(readiness.topology_eligible);
        assert!(readiness.exact_execution_binding);
        assert!(readiness.exact_identity_binding);
        if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
            assert!(!readiness.ready());
            assert!(readiness
                .blockers
                .contains(&"production-activation-feature-disabled".to_owned()));
        }
    }

    #[test]
    fn partition_or_pv_growth_is_not_in_the_initial_production_scope() {
        let validated = validated(true);
        let execution = execution(&validated);
        let readiness =
            inspect_production_activation_readiness(&validated, &execution, &identity());

        assert!(!readiness.topology_eligible);
        assert!(readiness
            .blockers
            .contains(&"unsupported-production-profile".to_owned()));
    }

    #[cfg(feature = "production-mutation-activation")]
    #[test]
    fn activation_feature_only_seals_nonexecuting_exact_intent() {
        let validated = validated(false);
        let execution = execution(&validated);
        let intent =
            seal_production_mutation_activation_intent(&validated, &execution, &identity())
                .unwrap();

        assert!(intent.integrity_matches().unwrap());
        assert!(intent.compile_feature_enabled);
        assert!(!intent.execution_enabled);
        assert_eq!(intent.filesystem_type, "ext4");
        assert_eq!(intent.filesystem_mountpoint.as_deref(), Some("/mnt/data"));
    }

    fn chained_validated() -> ValidatedNativeManifest {
        let gib = 1024 * 1024 * 1024_u64;
        let steps = vec![
            NativeCompiledStep {
                plan_step_id: 3,
                depends_on: vec![],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ExtendPartition {
                    partition: "/dev/sda1".into(),
                    start_sector: 2048,
                    old_size_sectors: 8_388_608,
                    new_size_sectors: 12_582_912,
                    sector_size_bytes: 512,
                },
            },
            NativeCompiledStep {
                plan_step_id: 4,
                depends_on: vec![3],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ResizePhysicalVolume {
                    pv_uuid: "pv-uuid".into(),
                    expected_pv_size_bytes: 6 * gib,
                },
            },
            NativeCompiledStep {
                plan_step_id: 5,
                depends_on: vec![4],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ExtendLogicalVolume {
                    lv_uuid: "lv-uuid".into(),
                    additional_extents: 256,
                    expected_lv_size_bytes: 2 * gib,
                },
            },
            NativeCompiledStep {
                plan_step_id: 6,
                depends_on: vec![5],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::GrowFilesystem {
                    fs_type: "ext4".into(),
                    mountpoint: Some("/mnt/data".into()),
                },
            },
        ];
        let verification_barriers = [3_u32, 4, 5, 6]
            .into_iter()
            .map(|after_plan_step_id| NativeVerificationBarrier {
                after_plan_step_id,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            })
            .collect();

        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: digest('a'),
            steps,
            verification_barriers,
        })
        .unwrap()
    }

    fn chained_identity() -> TargetIdentityManifest {
        let mut value = identity();
        value.partitions = vec![PartitionGeometryIdentity {
            partition: "/dev/sda1".into(),
            disk: Some("/dev/sda".into()),
            table_label: Some("gpt".into()),
            table_id: Some("gpt-test".into()),
            sector_size_bytes: Some(512),
            start_sector: Some(2048),
            size_sectors: Some(8_388_608),
            record_uuid: Some("part-uuid".into()),
        }];
        value
    }

    #[test]
    fn chained_partition_pv_profile_is_recognized_but_not_execution_enabled() {
        let validated = chained_validated();
        let execution = execution(&validated);
        let readiness = inspect_production_chained_activation_readiness(
            &validated,
            &execution,
            &chained_identity(),
        );

        assert!(readiness.topology_eligible);
        assert!(readiness.exact_execution_binding);
        assert!(readiness.exact_identity_binding);
        assert_eq!(readiness.mutation_step_ids, vec![3, 4, 5, 6]);
        if !PRODUCTION_MUTATION_ACTIVATION_COMPILED {
            assert!(!readiness.ready());
            assert!(readiness
                .blockers
                .contains(&"production-activation-feature-disabled".to_owned()));
        }
    }

    #[test]
    fn chained_profile_rejects_stale_partition_geometry() {
        let validated = chained_validated();
        let execution = execution(&validated);
        let mut stale = chained_identity();
        stale.partitions[0].start_sector = Some(4096);

        let readiness =
            inspect_production_chained_activation_readiness(&validated, &execution, &stale);
        assert!(readiness.topology_eligible);
        assert!(!readiness.exact_identity_binding);
        assert!(readiness
            .blockers
            .contains(&"fresh-chained-identity-mismatch".to_owned()));
    }

    #[cfg(feature = "production-mutation-activation")]
    #[test]
    fn chained_activation_seals_only_a_nonexecuting_scope_contract() {
        let validated = chained_validated();
        let execution = execution(&validated);
        let intent = seal_production_chained_mutation_activation_intent(
            &validated,
            &execution,
            &chained_identity(),
        )
        .unwrap();

        assert!(intent.integrity_matches().unwrap());
        assert!(intent.compile_feature_enabled);
        assert!(!intent.execution_enabled);
        assert_eq!(intent.partition_step_id, 3);
        assert_eq!(intent.pv_step_id, 4);
        assert_eq!(intent.lv_step_id, 5);
        assert_eq!(intent.filesystem_step_id, 6);
        assert_eq!(intent.partition, "/dev/sda1");
        assert_eq!(intent.pv_uuid, "pv-uuid");
        assert_eq!(intent.lv_uuid, "lv-uuid");
    }
}
