use std::collections::BTreeMap;

use lsm_planner::Reversibility;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    FrozenExecutionIntentManifest, FrozenIntentAction, FrozenIntentRole, FrozenIntentStep,
    VerificationBarrierSpec,
};

/// Typed, non-executable operation classes for the future native executor.
///
/// M1B14 remains metadata only: it does not invoke storage APIs, spawn commands,
/// advance the journal, or enable mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOperationKind {
    RevalidateSnapshot,
    BackupLvmMetadata,
    BackupPartitionTableMetadata,
    ExtendPartition,
    ResizePhysicalVolume,
    ExtendLogicalVolume,
    GrowFilesystem,
    RediscoverAndVerify,
}

pub const NATIVE_OPERATION_ALLOWLIST: &[NativeOperationKind] = &[
    NativeOperationKind::RevalidateSnapshot,
    NativeOperationKind::BackupLvmMetadata,
    NativeOperationKind::BackupPartitionTableMetadata,
    NativeOperationKind::ExtendPartition,
    NativeOperationKind::ResizePhysicalVolume,
    NativeOperationKind::ExtendLogicalVolume,
    NativeOperationKind::GrowFilesystem,
    NativeOperationKind::RediscoverAndVerify,
];

impl NativeOperationKind {
    pub const fn is_mutation_candidate(self) -> bool {
        matches!(
            self,
            Self::ExtendPartition
                | Self::ResizePhysicalVolume
                | Self::ExtendLogicalVolume
                | Self::GrowFilesystem
        )
    }
}

/// Exhaustive semantic classification from the frozen M1B13 intent.
///
/// There is deliberately no fallback arm: adding a new frozen intent action must
/// update this mapping before the native backend can represent it.
pub fn classify_frozen_intent_action(action: &FrozenIntentAction) -> NativeOperationKind {
    match action {
        FrozenIntentAction::RevalidateSnapshot => NativeOperationKind::RevalidateSnapshot,
        FrozenIntentAction::BackupLvmMetadata { .. } => NativeOperationKind::BackupLvmMetadata,
        FrozenIntentAction::BackupPartitionTableMetadata { .. } => {
            NativeOperationKind::BackupPartitionTableMetadata
        }
        FrozenIntentAction::ExtendPartition { .. } => NativeOperationKind::ExtendPartition,
        FrozenIntentAction::ResizePhysicalVolume { .. } => {
            NativeOperationKind::ResizePhysicalVolume
        }
        FrozenIntentAction::ExtendLogicalVolume { .. } => NativeOperationKind::ExtendLogicalVolume,
        FrozenIntentAction::GrowFilesystem { .. } => NativeOperationKind::GrowFilesystem,
        FrozenIntentAction::RediscoverAndVerify => NativeOperationKind::RediscoverAndVerify,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum NativeOperationSpec {
    RevalidateSnapshot,
    BackupLvmMetadata {
        vg_uuid: String,
    },
    BackupPartitionTableMetadata {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    ExtendPartition {
        partition: String,
        start_sector: u64,
        old_size_sectors: u64,
        new_size_sectors: u64,
        sector_size_bytes: u64,
    },
    ResizePhysicalVolume {
        pv_uuid: String,
        expected_pv_size_bytes: u64,
    },
    ExtendLogicalVolume {
        lv_uuid: String,
        additional_extents: u64,
        expected_lv_size_bytes: u64,
    },
    GrowFilesystem {
        fs_type: String,
        mountpoint: String,
    },
    RediscoverAndVerify,
}

/// Builds a non-executable native operation payload.
///
/// M1B14 builds payload support one operation at a time. Revalidation, exact
/// partition-growth geometry, exact LV-growth identity/size, filesystem
/// type/mountpoint, rediscovery/verification, LVM backup identity, and partition
/// table backup identity are representable here. Every current M1B13 frozen
/// action now has an exact non-executable native payload.
pub fn build_native_operation_spec(action: &FrozenIntentAction) -> NativeOperationSpec {
    match action {
        FrozenIntentAction::RevalidateSnapshot => NativeOperationSpec::RevalidateSnapshot,
        FrozenIntentAction::BackupLvmMetadata { vg_uuid } => {
            NativeOperationSpec::BackupLvmMetadata {
                vg_uuid: vg_uuid.clone(),
            }
        }
        FrozenIntentAction::BackupPartitionTableMetadata {
            disk,
            table_label,
            table_id,
        } => NativeOperationSpec::BackupPartitionTableMetadata {
            disk: disk.clone(),
            table_label: table_label.clone(),
            table_id: table_id.clone(),
        },
        FrozenIntentAction::ExtendPartition {
            partition,
            start_sector,
            old_size_sectors,
            new_size_sectors,
            sector_size_bytes,
        } => NativeOperationSpec::ExtendPartition {
            partition: partition.clone(),
            start_sector: *start_sector,
            old_size_sectors: *old_size_sectors,
            new_size_sectors: *new_size_sectors,
            sector_size_bytes: *sector_size_bytes,
        },
        FrozenIntentAction::ResizePhysicalVolume {
            pv_uuid,
            expected_pv_size_bytes,
        } => NativeOperationSpec::ResizePhysicalVolume {
            pv_uuid: pv_uuid.clone(),
            expected_pv_size_bytes: *expected_pv_size_bytes,
        },
        FrozenIntentAction::ExtendLogicalVolume {
            lv_uuid,
            additional_extents,
            expected_lv_size_bytes,
        } => NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid: lv_uuid.clone(),
            additional_extents: *additional_extents,
            expected_lv_size_bytes: *expected_lv_size_bytes,
        },
        FrozenIntentAction::GrowFilesystem {
            fs_type,
            mountpoint,
        } => NativeOperationSpec::GrowFilesystem {
            fs_type: fs_type.clone(),
            mountpoint: mountpoint.clone(),
        },
        FrozenIntentAction::RediscoverAndVerify => NativeOperationSpec::RediscoverAndVerify,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeCompiledStep {
    pub plan_step_id: u32,
    pub depends_on: Vec<u32>,
    pub reversibility: Reversibility,
    pub role: FrozenIntentRole,
    pub operation: NativeOperationSpec,
}

pub fn compile_native_step(step: &FrozenIntentStep) -> NativeCompiledStep {
    NativeCompiledStep {
        plan_step_id: step.plan_step_id,
        depends_on: step.depends_on.clone(),
        reversibility: step.reversibility,
        role: step.role,
        operation: build_native_operation_spec(&step.action),
    }
}

pub fn compile_native_steps(steps: &[FrozenIntentStep]) -> Vec<NativeCompiledStep> {
    steps.iter().map(compile_native_step).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeVerificationBarrier {
    pub after_plan_step_id: u32,
    pub before_next_mutation: bool,
    pub require_fresh_target_identity: bool,
    pub require_fresh_capabilities: bool,
    pub require_expected_state_check: bool,
    pub stop_on_mismatch: bool,
}

pub fn compile_native_verification_barrier(
    barrier: &VerificationBarrierSpec,
) -> NativeVerificationBarrier {
    NativeVerificationBarrier {
        after_plan_step_id: barrier.after_plan_step_id,
        before_next_mutation: barrier.before_next_mutation,
        require_fresh_target_identity: barrier.require_fresh_target_identity,
        require_fresh_capabilities: barrier.require_fresh_capabilities,
        require_expected_state_check: barrier.require_expected_state_check,
        stop_on_mismatch: barrier.stop_on_mismatch,
    }
}

pub fn compile_native_verification_barriers(
    barriers: &[VerificationBarrierSpec],
) -> Vec<NativeVerificationBarrier> {
    barriers
        .iter()
        .map(compile_native_verification_barrier)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeCompiledManifest {
    pub source_manifest_id: String,
    pub steps: Vec<NativeCompiledStep>,
    pub verification_barriers: Vec<NativeVerificationBarrier>,
}

pub fn compile_native_manifest_parts(
    source_manifest_id: &str,
    steps: &[FrozenIntentStep],
    verification_barriers: &[VerificationBarrierSpec],
) -> NativeCompiledManifest {
    NativeCompiledManifest {
        source_manifest_id: source_manifest_id.to_owned(),
        steps: compile_native_steps(steps),
        verification_barriers: compile_native_verification_barriers(verification_barriers),
    }
}

pub fn compile_native_manifest(manifest: &FrozenExecutionIntentManifest) -> NativeCompiledManifest {
    compile_native_manifest_parts(
        manifest.manifest_id(),
        manifest.steps(),
        manifest.verification_barriers(),
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeManifestValidationError {
    #[error("native step ID must be non-zero")]
    ZeroStepId,
    #[error("duplicate native step ID {0}")]
    DuplicateStepId(u32),
    #[error("native step {step_id} depends on unknown step {dependency}")]
    UnknownDependency { step_id: u32, dependency: u32 },
    #[error("native step {0} depends on itself")]
    SelfDependency(u32),
    #[error("native dependency graph contains a cycle")]
    DependencyCycle,
    #[error("native step {0} role does not match its operation")]
    RoleOperationMismatch(u32),
    #[error("native mutation step {after} is not ordered after required lower-layer step {before}")]
    UnsafeLayerOrder { before: u32, after: u32 },
    #[error("mutation step {0} is missing a verification barrier")]
    MissingVerificationBarrier(u32),
    #[error("mutation step {0} has multiple verification barriers")]
    DuplicateVerificationBarrier(u32),
    #[error("verification barrier after step {0} does not reference a mutation step")]
    UnexpectedVerificationBarrier(u32),
    #[error("verification barrier after step {0} is not fail-closed")]
    UnsafeVerificationBarrier(u32),
}

#[derive(Debug, Error)]
pub enum NativeManifestBindingError {
    #[error("native manifest validation failed: {0}")]
    Validation(#[from] NativeManifestValidationError),
    #[error("native manifest digest serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedNativeManifest {
    manifest: NativeCompiledManifest,
    digest: String,
}

impl ValidatedNativeManifest {
    pub fn manifest(&self) -> &NativeCompiledManifest {
        &self.manifest
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn is_mutation_operation(operation: &NativeOperationSpec) -> bool {
    matches!(
        operation,
        NativeOperationSpec::ExtendPartition { .. }
            | NativeOperationSpec::ResizePhysicalVolume { .. }
            | NativeOperationSpec::ExtendLogicalVolume { .. }
            | NativeOperationSpec::GrowFilesystem { .. }
    )
}

fn expected_role(operation: &NativeOperationSpec) -> FrozenIntentRole {
    match operation {
        NativeOperationSpec::RevalidateSnapshot
        | NativeOperationSpec::BackupLvmMetadata { .. }
        | NativeOperationSpec::BackupPartitionTableMetadata { .. } => {
            FrozenIntentRole::PreExecutionEvidence
        }
        NativeOperationSpec::ExtendPartition { .. }
        | NativeOperationSpec::ResizePhysicalVolume { .. }
        | NativeOperationSpec::ExtendLogicalVolume { .. }
        | NativeOperationSpec::GrowFilesystem { .. } => FrozenIntentRole::MutationCandidate,
        NativeOperationSpec::RediscoverAndVerify => FrozenIntentRole::Verification,
    }
}

fn mutation_layer_rank(operation: &NativeOperationSpec) -> Option<u8> {
    match operation {
        NativeOperationSpec::ExtendPartition { .. } => Some(1),
        NativeOperationSpec::ResizePhysicalVolume { .. } => Some(2),
        NativeOperationSpec::ExtendLogicalVolume { .. } => Some(3),
        NativeOperationSpec::GrowFilesystem { .. } => Some(4),
        _ => None,
    }
}

fn validate_native_layer_order(
    steps: &[NativeCompiledStep],
) -> Result<(), NativeManifestValidationError> {
    let by_id = steps
        .iter()
        .map(|step| (step.plan_step_id, step))
        .collect::<BTreeMap<_, _>>();

    fn depends_on(
        current: u32,
        required: u32,
        by_id: &BTreeMap<u32, &NativeCompiledStep>,
    ) -> bool {
        let Some(step) = by_id.get(&current) else {
            return false;
        };
        step.depends_on.iter().any(|dependency| {
            *dependency == required || depends_on(*dependency, required, by_id)
        })
    }

    let mutations = steps
        .iter()
        .filter_map(|step| mutation_layer_rank(&step.operation).map(|rank| (step, rank)))
        .collect::<Vec<_>>();

    for (earlier, earlier_rank) in &mutations {
        for (later, later_rank) in &mutations {
            if earlier_rank < later_rank
                && !depends_on(later.plan_step_id, earlier.plan_step_id, &by_id)
            {
                return Err(NativeManifestValidationError::UnsafeLayerOrder {
                    before: earlier.plan_step_id,
                    after: later.plan_step_id,
                });
            }
        }
    }

    Ok(())
}

pub fn native_manifest_digest(
    manifest: &NativeCompiledManifest,
) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&(
        &manifest.source_manifest_id,
        &manifest.steps,
        &manifest.verification_barriers,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_native_dependency_graph(
    steps: &[NativeCompiledStep],
) -> Result<(), NativeManifestValidationError> {
    let mut by_id = BTreeMap::new();
    for step in steps {
        if step.plan_step_id == 0 {
            return Err(NativeManifestValidationError::ZeroStepId);
        }
        if by_id.insert(step.plan_step_id, step).is_some() {
            return Err(NativeManifestValidationError::DuplicateStepId(
                step.plan_step_id,
            ));
        }
    }

    for step in steps {
        for dependency in &step.depends_on {
            if *dependency == step.plan_step_id {
                return Err(NativeManifestValidationError::SelfDependency(
                    step.plan_step_id,
                ));
            }
            if !by_id.contains_key(dependency) {
                return Err(NativeManifestValidationError::UnknownDependency {
                    step_id: step.plan_step_id,
                    dependency: *dependency,
                });
            }
        }
    }

    fn visit(
        id: u32,
        by_id: &BTreeMap<u32, &NativeCompiledStep>,
        states: &mut BTreeMap<u32, u8>,
    ) -> Result<(), NativeManifestValidationError> {
        match states.get(&id).copied() {
            Some(1) => return Err(NativeManifestValidationError::DependencyCycle),
            Some(2) => return Ok(()),
            _ => {}
        }

        states.insert(id, 1);
        let step = by_id[&id];
        for dependency in &step.depends_on {
            visit(*dependency, by_id, states)?;
        }
        states.insert(id, 2);
        Ok(())
    }

    let mut states = BTreeMap::new();
    for id in by_id.keys().copied() {
        visit(id, &by_id, &mut states)?;
    }

    Ok(())
}

pub fn validate_native_manifest(
    manifest: &NativeCompiledManifest,
) -> Result<(), NativeManifestValidationError> {
    validate_native_dependency_graph(&manifest.steps)?;
    validate_native_layer_order(&manifest.steps)?;

    for step in &manifest.steps {
        if step.role != expected_role(&step.operation) {
            return Err(NativeManifestValidationError::RoleOperationMismatch(
                step.plan_step_id,
            ));
        }
    }

    for barrier in &manifest.verification_barriers {
        let Some(step) = manifest
            .steps
            .iter()
            .find(|step| step.plan_step_id == barrier.after_plan_step_id)
        else {
            return Err(
                NativeManifestValidationError::UnexpectedVerificationBarrier(
                    barrier.after_plan_step_id,
                ),
            );
        };

        if !is_mutation_operation(&step.operation) {
            return Err(
                NativeManifestValidationError::UnexpectedVerificationBarrier(
                    barrier.after_plan_step_id,
                ),
            );
        }

        if !(barrier.before_next_mutation
            && barrier.require_fresh_target_identity
            && barrier.require_fresh_capabilities
            && barrier.require_expected_state_check
            && barrier.stop_on_mismatch)
        {
            return Err(NativeManifestValidationError::UnsafeVerificationBarrier(
                barrier.after_plan_step_id,
            ));
        }
    }

    for step in &manifest.steps {
        if !is_mutation_operation(&step.operation) {
            continue;
        }

        match manifest
            .verification_barriers
            .iter()
            .filter(|barrier| barrier.after_plan_step_id == step.plan_step_id)
            .count()
        {
            0 => {
                return Err(NativeManifestValidationError::MissingVerificationBarrier(
                    step.plan_step_id,
                ));
            }
            1 => {}
            _ => {
                return Err(NativeManifestValidationError::DuplicateVerificationBarrier(
                    step.plan_step_id,
                ));
            }
        }
    }

    Ok(())
}

pub fn validate_and_bind_native_manifest(
    manifest: NativeCompiledManifest,
) -> Result<ValidatedNativeManifest, NativeManifestBindingError> {
    validate_native_manifest(&manifest)?;
    let digest = native_manifest_digest(&manifest)?;
    Ok(ValidatedNativeManifest { manifest, digest })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validated_native_manifest_binds_only_valid_manifest_and_digest() {
        let valid = NativeCompiledManifest {
            source_manifest_id: "validated-native-test".into(),
            steps: vec![NativeCompiledStep {
                plan_step_id: 1,
                depends_on: vec![],
                reversibility: Reversibility::NotApplicable,
                role: FrozenIntentRole::PreExecutionEvidence,
                operation: NativeOperationSpec::RevalidateSnapshot,
            }],
            verification_barriers: vec![],
        };

        let expected_digest = native_manifest_digest(&valid).unwrap();
        let validated = validate_and_bind_native_manifest(valid.clone()).unwrap();

        assert_eq!(validated.manifest(), &valid);
        assert_eq!(validated.digest(), expected_digest);

        let mut invalid = valid;
        invalid.steps[0].role = FrozenIntentRole::MutationCandidate;
        assert!(matches!(
            validate_and_bind_native_manifest(invalid),
            Err(NativeManifestBindingError::Validation(
                NativeManifestValidationError::RoleOperationMismatch(1)
            ))
        ));
    }

    #[test]
    fn native_mutation_layers_require_dependency_order() {
        let mutation_step = |plan_step_id, depends_on, operation| NativeCompiledStep {
            plan_step_id,
            depends_on,
            reversibility: Reversibility::Irreversible,
            role: FrozenIntentRole::MutationCandidate,
            operation,
        };

        let valid = vec![
            mutation_step(
                1,
                vec![],
                NativeOperationSpec::ExtendPartition {
                    partition: "/dev/test1".into(),
                    start_sector: 2048,
                    old_size_sectors: 4096,
                    new_size_sectors: 8192,
                    sector_size_bytes: 512,
                },
            ),
            mutation_step(
                2,
                vec![1],
                NativeOperationSpec::ResizePhysicalVolume {
                    pv_uuid: "pv-test".into(),
                    expected_pv_size_bytes: 8 * 1024 * 1024,
                },
            ),
            mutation_step(
                3,
                vec![2],
                NativeOperationSpec::ExtendLogicalVolume {
                    lv_uuid: "lv-test".into(),
                    additional_extents: 1,
                    expected_lv_size_bytes: 12 * 1024 * 1024,
                },
            ),
            mutation_step(
                4,
                vec![3],
                NativeOperationSpec::GrowFilesystem {
                    fs_type: "ext4".into(),
                    mountpoint: "/".into(),
                },
            ),
        ];

        assert_eq!(validate_native_layer_order(&valid), Ok(()));

        let mut invalid = valid;
        invalid[2].depends_on = vec![1];
        assert_eq!(
            validate_native_layer_order(&invalid),
            Err(NativeManifestValidationError::UnsafeLayerOrder {
                before: 2,
                after: 3,
            })
        );
    }

    fn graph_step(plan_step_id: u32, depends_on: Vec<u32>) -> NativeCompiledStep {
        NativeCompiledStep {
            plan_step_id,
            depends_on,
            reversibility: Reversibility::NotApplicable,
            role: FrozenIntentRole::PreExecutionEvidence,
            operation: NativeOperationSpec::RevalidateSnapshot,
        }
    }

    #[test]
    fn native_manifest_role_operation_validation_fails_closed() {
        let valid = NativeCompiledManifest {
            source_manifest_id: "role-test".into(),
            steps: vec![
                NativeCompiledStep {
                    plan_step_id: 1,
                    depends_on: vec![],
                    reversibility: Reversibility::NotApplicable,
                    role: FrozenIntentRole::PreExecutionEvidence,
                    operation: NativeOperationSpec::RevalidateSnapshot,
                },
                NativeCompiledStep {
                    plan_step_id: 2,
                    depends_on: vec![1],
                    reversibility: Reversibility::NotApplicable,
                    role: FrozenIntentRole::Verification,
                    operation: NativeOperationSpec::RediscoverAndVerify,
                },
            ],
            verification_barriers: vec![],
        };

        assert_eq!(validate_native_manifest(&valid), Ok(()));

        let mut invalid = valid.clone();
        invalid.steps[1].role = FrozenIntentRole::MutationCandidate;
        assert_eq!(
            validate_native_manifest(&invalid),
            Err(NativeManifestValidationError::RoleOperationMismatch(2))
        );
    }

    #[test]
    fn native_manifest_digest_is_deterministic_and_content_sensitive() {
        let manifest = NativeCompiledManifest {
            source_manifest_id: "digest-source".into(),
            steps: vec![NativeCompiledStep {
                plan_step_id: 1,
                depends_on: vec![],
                reversibility: Reversibility::NotApplicable,
                role: FrozenIntentRole::PreExecutionEvidence,
                operation: NativeOperationSpec::RevalidateSnapshot,
            }],
            verification_barriers: vec![],
        };

        let first = native_manifest_digest(&manifest).unwrap();
        let second = native_manifest_digest(&manifest).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);

        let mut changed = manifest.clone();
        changed.source_manifest_id = "digest-source-changed".into();
        assert_ne!(first, native_manifest_digest(&changed).unwrap());
    }

    #[test]
    fn native_manifest_dependency_graph_fails_closed() {
        let manifest = |steps| NativeCompiledManifest {
            source_manifest_id: "dependency-graph-test".into(),
            steps,
            verification_barriers: vec![],
        };

        assert_eq!(
            validate_native_manifest(&manifest(vec![
                graph_step(1, vec![]),
                graph_step(2, vec![1]),
            ])),
            Ok(())
        );
        assert_eq!(
            validate_native_manifest(&manifest(vec![graph_step(0, vec![])])),
            Err(NativeManifestValidationError::ZeroStepId)
        );
        assert_eq!(
            validate_native_manifest(&manifest(vec![
                graph_step(1, vec![]),
                graph_step(1, vec![]),
            ])),
            Err(NativeManifestValidationError::DuplicateStepId(1))
        );
        assert_eq!(
            validate_native_manifest(&manifest(vec![graph_step(2, vec![99])])),
            Err(NativeManifestValidationError::UnknownDependency {
                step_id: 2,
                dependency: 99,
            })
        );
        assert_eq!(
            validate_native_manifest(&manifest(vec![graph_step(3, vec![3])])),
            Err(NativeManifestValidationError::SelfDependency(3))
        );
        assert_eq!(
            validate_native_manifest(&manifest(vec![
                graph_step(4, vec![5]),
                graph_step(5, vec![4]),
            ])),
            Err(NativeManifestValidationError::DependencyCycle)
        );
    }

    #[test]
    fn native_manifest_validation_fails_closed_on_barrier_mismatch() {
        let step = NativeCompiledStep {
            plan_step_id: 31,
            depends_on: vec![],
            reversibility: Reversibility::Irreversible,
            role: FrozenIntentRole::MutationCandidate,
            operation: NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid: "lv-validation-test".into(),
                additional_extents: 3,
                expected_lv_size_bytes: 32 * 1024 * 1024,
            },
        };
        let barrier = NativeVerificationBarrier {
            after_plan_step_id: 31,
            before_next_mutation: true,
            require_fresh_target_identity: true,
            require_fresh_capabilities: true,
            require_expected_state_check: true,
            stop_on_mismatch: true,
        };
        let valid = NativeCompiledManifest {
            source_manifest_id: "manifest-validation-test".into(),
            steps: vec![step],
            verification_barriers: vec![barrier],
        };

        assert_eq!(validate_native_manifest(&valid), Ok(()));

        let mut missing = valid.clone();
        missing.verification_barriers.clear();
        assert_eq!(
            validate_native_manifest(&missing),
            Err(NativeManifestValidationError::MissingVerificationBarrier(
                31
            ))
        );

        let mut duplicate = valid.clone();
        duplicate
            .verification_barriers
            .push(duplicate.verification_barriers[0].clone());
        assert_eq!(
            validate_native_manifest(&duplicate),
            Err(NativeManifestValidationError::DuplicateVerificationBarrier(
                31
            ))
        );

        let mut unexpected = valid.clone();
        unexpected.steps[0].role = FrozenIntentRole::PreExecutionEvidence;
        unexpected.steps[0].operation = NativeOperationSpec::RevalidateSnapshot;
        assert_eq!(
            validate_native_manifest(&unexpected),
            Err(NativeManifestValidationError::UnexpectedVerificationBarrier(31))
        );

        let mut unsafe_barrier = valid.clone();
        unsafe_barrier.verification_barriers[0].stop_on_mismatch = false;
        assert_eq!(
            validate_native_manifest(&unsafe_barrier),
            Err(NativeManifestValidationError::UnsafeVerificationBarrier(31))
        );
    }

    #[test]
    fn native_manifest_compiler_binds_exact_frozen_manifest() {
        let source = FrozenExecutionIntentManifest::test_for_native_compiler(
            vec![FrozenIntentStep {
                plan_step_id: 21,
                depends_on: vec![],
                reversibility: Reversibility::NotApplicable,
                role: FrozenIntentRole::PreExecutionEvidence,
                action: FrozenIntentAction::RevalidateSnapshot,
            }],
            vec![VerificationBarrierSpec {
                after_plan_step_id: 21,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            }],
        )
        .unwrap();

        let compiled = compile_native_manifest(&source);

        assert_eq!(compiled.source_manifest_id, source.manifest_id());
        assert_eq!(compiled.steps.len(), source.steps().len());
        assert_eq!(
            compiled.verification_barriers.len(),
            source.verification_barriers().len()
        );
        assert_eq!(compiled.steps[0].plan_step_id, 21);
        assert_eq!(compiled.verification_barriers[0].after_plan_step_id, 21);
    }

    #[test]
    fn native_manifest_parts_combine_steps_and_barriers_without_reordering() {
        let steps = vec![FrozenIntentStep {
            plan_step_id: 5,
            depends_on: vec![],
            reversibility: Reversibility::NotApplicable,
            role: FrozenIntentRole::PreExecutionEvidence,
            action: FrozenIntentAction::RevalidateSnapshot,
        }];
        let barriers = vec![VerificationBarrierSpec {
            after_plan_step_id: 5,
            before_next_mutation: true,
            require_fresh_target_identity: true,
            require_fresh_capabilities: true,
            require_expected_state_check: true,
            stop_on_mismatch: true,
        }];

        let compiled = compile_native_manifest_parts("intent-test", &steps, &barriers);

        assert_eq!(compiled.source_manifest_id, "intent-test");
        assert_eq!(compiled.steps.len(), 1);
        assert_eq!(compiled.steps[0].plan_step_id, 5);
        assert_eq!(compiled.verification_barriers.len(), 1);
        assert_eq!(compiled.verification_barriers[0].after_plan_step_id, 5);
    }

    #[test]
    fn native_verification_barrier_list_preserves_source_order() {
        let barriers = vec![
            VerificationBarrierSpec {
                after_plan_step_id: 7,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            },
            VerificationBarrierSpec {
                after_plan_step_id: 19,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            },
        ];

        let compiled = compile_native_verification_barriers(&barriers);

        assert_eq!(
            compiled
                .iter()
                .map(|barrier| barrier.after_plan_step_id)
                .collect::<Vec<_>>(),
            vec![7, 19]
        );
        assert!(compiled.iter().all(|barrier| barrier.stop_on_mismatch));
    }

    #[test]
    fn native_verification_barrier_preserves_all_fail_closed_requirements() {
        let barrier = VerificationBarrierSpec {
            after_plan_step_id: 77,
            before_next_mutation: true,
            require_fresh_target_identity: true,
            require_fresh_capabilities: true,
            require_expected_state_check: true,
            stop_on_mismatch: true,
        };

        assert_eq!(
            compile_native_verification_barrier(&barrier),
            NativeVerificationBarrier {
                after_plan_step_id: 77,
                before_next_mutation: true,
                require_fresh_target_identity: true,
                require_fresh_capabilities: true,
                require_expected_state_check: true,
                stop_on_mismatch: true,
            }
        );
    }

    #[test]
    fn native_step_list_compiler_preserves_source_order() {
        let steps = vec![
            FrozenIntentStep {
                plan_step_id: 10,
                depends_on: vec![],
                reversibility: Reversibility::NotApplicable,
                role: FrozenIntentRole::PreExecutionEvidence,
                action: FrozenIntentAction::RevalidateSnapshot,
            },
            FrozenIntentStep {
                plan_step_id: 11,
                depends_on: vec![10],
                reversibility: Reversibility::NotApplicable,
                role: FrozenIntentRole::Verification,
                action: FrozenIntentAction::RediscoverAndVerify,
            },
        ];

        let compiled = compile_native_steps(&steps);

        assert_eq!(
            compiled
                .iter()
                .map(|step| step.plan_step_id)
                .collect::<Vec<_>>(),
            vec![10, 11]
        );
        assert_eq!(compiled[1].depends_on, vec![10]);
        assert_eq!(
            compiled[0].operation,
            NativeOperationSpec::RevalidateSnapshot
        );
        assert_eq!(
            compiled[1].operation,
            NativeOperationSpec::RediscoverAndVerify
        );
    }

    #[test]
    fn native_step_compiler_preserves_frozen_step_semantics() {
        let step = FrozenIntentStep {
            plan_step_id: 42,
            depends_on: vec![3, 9],
            reversibility: Reversibility::Irreversible,
            role: FrozenIntentRole::MutationCandidate,
            action: FrozenIntentAction::ExtendLogicalVolume {
                lv_uuid: "lv-step-test".into(),
                additional_extents: 11,
                expected_lv_size_bytes: 128 * 1024 * 1024,
            },
        };

        assert_eq!(
            compile_native_step(&step),
            NativeCompiledStep {
                plan_step_id: 42,
                depends_on: vec![3, 9],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ExtendLogicalVolume {
                    lv_uuid: "lv-step-test".into(),
                    additional_extents: 11,
                    expected_lv_size_bytes: 128 * 1024 * 1024,
                },
            }
        );
    }

    #[test]
    fn native_operation_allowlist_is_exact() {
        assert_eq!(
            NATIVE_OPERATION_ALLOWLIST,
            &[
                NativeOperationKind::RevalidateSnapshot,
                NativeOperationKind::BackupLvmMetadata,
                NativeOperationKind::BackupPartitionTableMetadata,
                NativeOperationKind::ExtendPartition,
                NativeOperationKind::ResizePhysicalVolume,
                NativeOperationKind::ExtendLogicalVolume,
                NativeOperationKind::GrowFilesystem,
                NativeOperationKind::RediscoverAndVerify,
            ]
        );
    }

    #[test]
    fn only_growth_operations_are_mutation_candidates() {
        for operation in NATIVE_OPERATION_ALLOWLIST {
            let expected = matches!(
                operation,
                NativeOperationKind::ExtendPartition
                    | NativeOperationKind::ResizePhysicalVolume
                    | NativeOperationKind::ExtendLogicalVolume
                    | NativeOperationKind::GrowFilesystem
            );
            assert_eq!(operation.is_mutation_candidate(), expected);
        }
    }

    #[test]
    fn native_partition_backup_spec_preserves_exact_table_identity() {
        let action = FrozenIntentAction::BackupPartitionTableMetadata {
            disk: "/dev/test".into(),
            table_label: "gpt".into(),
            table_id: Some("A1B2-C3D4".into()),
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::BackupPartitionTableMetadata {
                disk: "/dev/test".into(),
                table_label: "gpt".into(),
                table_id: Some("A1B2-C3D4".into()),
            }
        );
    }

    #[test]
    fn native_lvm_backup_spec_preserves_exact_vg_identity() {
        let action = FrozenIntentAction::BackupLvmMetadata {
            vg_uuid: "vg-uuid-test".into(),
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::BackupLvmMetadata {
                vg_uuid: "vg-uuid-test".into(),
            }
        );
    }

    #[test]
    fn native_partition_spec_preserves_exact_geometry() {
        let action = FrozenIntentAction::ExtendPartition {
            partition: "/dev/test1".into(),
            start_sector: 2048,
            old_size_sectors: 4096,
            new_size_sectors: 8192,
            sector_size_bytes: 4096,
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::ExtendPartition {
                partition: "/dev/test1".into(),
                start_sector: 2048,
                old_size_sectors: 4096,
                new_size_sectors: 8192,
                sector_size_bytes: 4096,
            }
        );
    }

    #[test]
    fn native_pv_resize_spec_preserves_exact_identity_and_growth() {
        let action = FrozenIntentAction::ResizePhysicalVolume {
            pv_uuid: "pv-test".into(),
            expected_pv_size_bytes: 12 * 1024 * 1024 * 1024,
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::ResizePhysicalVolume {
                pv_uuid: "pv-test".into(),
                expected_pv_size_bytes: 12 * 1024 * 1024 * 1024,
            }
        );
    }

    #[test]
    fn native_lv_spec_preserves_exact_identity_and_growth() {
        let action = FrozenIntentAction::ExtendLogicalVolume {
            lv_uuid: "lv-test".into(),
            additional_extents: 17,
            expected_lv_size_bytes: 64 * 1024 * 1024,
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid: "lv-test".into(),
                additional_extents: 17,
                expected_lv_size_bytes: 64 * 1024 * 1024,
            }
        );
    }

    #[test]
    fn native_filesystem_spec_preserves_exact_type_and_mountpoint() {
        let action = FrozenIntentAction::GrowFilesystem {
            fs_type: "xfs".into(),
            mountpoint: "/srv/data".into(),
        };

        assert_eq!(
            build_native_operation_spec(&action),
            NativeOperationSpec::GrowFilesystem {
                fs_type: "xfs".into(),
                mountpoint: "/srv/data".into(),
            }
        );
    }

    #[test]
    fn native_rediscover_spec_is_exact_verification_marker() {
        assert_eq!(
            build_native_operation_spec(&FrozenIntentAction::RediscoverAndVerify),
            NativeOperationSpec::RediscoverAndVerify
        );
    }

    #[test]
    fn frozen_intent_actions_map_to_exact_native_kinds() {
        let cases = [
            (
                FrozenIntentAction::RevalidateSnapshot,
                NativeOperationKind::RevalidateSnapshot,
            ),
            (
                FrozenIntentAction::BackupLvmMetadata {
                    vg_uuid: "vg-test".into(),
                },
                NativeOperationKind::BackupLvmMetadata,
            ),
            (
                FrozenIntentAction::BackupPartitionTableMetadata {
                    disk: "/dev/test".into(),
                    table_label: "gpt".into(),
                    table_id: None,
                },
                NativeOperationKind::BackupPartitionTableMetadata,
            ),
            (
                FrozenIntentAction::ExtendPartition {
                    partition: "/dev/test1".into(),
                    start_sector: 2048,
                    old_size_sectors: 4096,
                    new_size_sectors: 8192,
                    sector_size_bytes: 512,
                },
                NativeOperationKind::ExtendPartition,
            ),
            (
                FrozenIntentAction::ResizePhysicalVolume {
                    pv_uuid: "pv-test".into(),
                    expected_pv_size_bytes: 12 * 1024 * 1024 * 1024,
                },
                NativeOperationKind::ResizePhysicalVolume,
            ),
            (
                FrozenIntentAction::ExtendLogicalVolume {
                    lv_uuid: "lv-test".into(),
                    additional_extents: 4,
                    expected_lv_size_bytes: 16 * 1024 * 1024,
                },
                NativeOperationKind::ExtendLogicalVolume,
            ),
            (
                FrozenIntentAction::GrowFilesystem {
                    fs_type: "ext4".into(),
                    mountpoint: "/mnt/test".into(),
                },
                NativeOperationKind::GrowFilesystem,
            ),
            (
                FrozenIntentAction::RediscoverAndVerify,
                NativeOperationKind::RediscoverAndVerify,
            ),
        ];

        for (action, expected) in cases {
            assert_eq!(classify_frozen_intent_action(&action), expected);
        }
    }
}
