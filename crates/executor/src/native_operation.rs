use serde::Serialize;
use thiserror::Error;

use crate::FrozenIntentAction;

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
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NativeOperationSpecError {
    #[error("native operation payload is not yet supported for {0:?}")]
    Unsupported(NativeOperationKind),
}

/// Builds a non-executable native operation payload.
///
/// M1B14 builds payload support one operation at a time. Revalidation, exact
/// partition-growth geometry, exact LV-growth identity/size, and filesystem
/// type/mountpoint are representable here; every other current frozen action
/// remains rejected until its contract is added in a separate increment.
pub fn build_native_operation_spec(
    action: &FrozenIntentAction,
) -> Result<NativeOperationSpec, NativeOperationSpecError> {
    let kind = classify_frozen_intent_action(action);
    match action {
        FrozenIntentAction::RevalidateSnapshot => Ok(NativeOperationSpec::RevalidateSnapshot),
        FrozenIntentAction::ExtendPartition {
            partition,
            start_sector,
            old_size_sectors,
            new_size_sectors,
            sector_size_bytes,
        } => Ok(NativeOperationSpec::ExtendPartition {
            partition: partition.clone(),
            start_sector: *start_sector,
            old_size_sectors: *old_size_sectors,
            new_size_sectors: *new_size_sectors,
            sector_size_bytes: *sector_size_bytes,
        }),
        FrozenIntentAction::ExtendLogicalVolume {
            lv_uuid,
            additional_extents,
            expected_lv_size_bytes,
        } => Ok(NativeOperationSpec::ExtendLogicalVolume {
            lv_uuid: lv_uuid.clone(),
            additional_extents: *additional_extents,
            expected_lv_size_bytes: *expected_lv_size_bytes,
        }),
        FrozenIntentAction::GrowFilesystem {
            fs_type,
            mountpoint,
        } => Ok(NativeOperationSpec::GrowFilesystem {
            fs_type: fs_type.clone(),
            mountpoint: mountpoint.clone(),
        }),
        FrozenIntentAction::BackupLvmMetadata { .. }
        | FrozenIntentAction::BackupPartitionTableMetadata { .. }
        | FrozenIntentAction::RediscoverAndVerify => {
            Err(NativeOperationSpecError::Unsupported(kind))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn native_spec_keeps_unimplemented_actions_fail_closed() {
        assert_eq!(
            build_native_operation_spec(&FrozenIntentAction::RevalidateSnapshot).unwrap(),
            NativeOperationSpec::RevalidateSnapshot
        );

        let unsupported = FrozenIntentAction::RediscoverAndVerify;
        assert_eq!(
            build_native_operation_spec(&unsupported),
            Err(NativeOperationSpecError::Unsupported(
                NativeOperationKind::RediscoverAndVerify
            ))
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
            build_native_operation_spec(&action).unwrap(),
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
            build_native_operation_spec(&action).unwrap(),
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
            build_native_operation_spec(&action).unwrap(),
            NativeOperationSpec::GrowFilesystem {
                fs_type: "xfs".into(),
                mountpoint: "/srv/data".into(),
            }
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
