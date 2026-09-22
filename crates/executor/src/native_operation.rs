use serde::Serialize;

/// Typed, non-executable operation classes for the future native executor.
///
/// M1B14.1 is metadata only: it does not invoke storage APIs, spawn commands,
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
}
