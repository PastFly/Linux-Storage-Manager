use lsm_planner::Reversibility;
use serde::Serialize;

use crate::{FrozenIntentAction, FrozenIntentRole, FrozenIntentStep};

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
    ExtendLogicalVolume,
    GrowFilesystem,
    RediscoverAndVerify,
}

pub const NATIVE_OPERATION_ALLOWLIST: &[NativeOperationKind] = &[
    NativeOperationKind::RevalidateSnapshot,
    NativeOperationKind::BackupLvmMetadata,
    NativeOperationKind::BackupPartitionTableMetadata,
    NativeOperationKind::ExtendPartition,
    NativeOperationKind::ExtendLogicalVolume,
    NativeOperationKind::GrowFilesystem,
    NativeOperationKind::RediscoverAndVerify,
];

impl NativeOperationKind {
    pub const fn is_mutation_candidate(self) -> bool {
        matches!(
            self,
            Self::ExtendPartition | Self::ExtendLogicalVolume | Self::GrowFilesystem
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

#[cfg(test)]
mod tests {
    use super::*;

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
            compiled.iter().map(|step| step.plan_step_id).collect::<Vec<_>>(),
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
