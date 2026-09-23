use lsm_planner::{
    ExecutionStartBinding, JournalPhase, LayerRouteStatus, LvmIdentityKind, TargetIdentityManifest,
};
use thiserror::Error;

use crate::{
    LockedExecutionSession, LockedSessionError, NativeOperationSpec, ValidatedNativeManifest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisposableVerifiedBoundary {
    execution_id: String,
    completed_step_id: u32,
    next_step_id: u32,
    fresh_identity_digest: String,
}

impl DisposableVerifiedBoundary {
    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn completed_step_id(&self) -> u32 {
        self.completed_step_id
    }

    pub fn next_step_id(&self) -> u32 {
        self.next_step_id
    }

    pub fn fresh_identity_digest(&self) -> &str {
        &self.fresh_identity_digest
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisposableBoundaryVerificationError {
    #[error("durable session is not at the post-mutation verification boundary")]
    DurableVerificationStateRequired,
    #[error("durable execution binding is missing or invalid")]
    ExecutionBindingInvalid,
    #[error("validated native manifest does not match the durable execution binding")]
    ManifestBindingMismatch,
    #[error("completed mutation step is not in the durable ordered mutation sequence")]
    CompletedStepNotAuthorized,
    #[error("completed mutation step has no following mutation step")]
    NoNextMutationStep,
    #[error("first disposable verification boundary only supports logical-volume growth")]
    UnsupportedCompletedMutation,
    #[error("fresh target route is not a supported profile")]
    UnsupportedFreshRoute,
    #[error("logical volume UUID did not resolve to exactly one fresh identity")]
    LogicalVolumeIdentityNotUnique,
    #[error("fresh logical volume size does not equal the exact expected post-mutation size")]
    LogicalVolumeSizeMismatch,
    #[error("fresh filesystem backing size does not equal the verified logical volume size")]
    FilesystemBackingSizeMismatch,
    #[error("durable verification continuation could not be persisted")]
    PersistenceFailed,
}

fn verify_boundary_state(
    execution: &ExecutionStartBinding,
    validated: &ValidatedNativeManifest,
    fresh_identity: &TargetIdentityManifest,
    completed_step_id: u32,
) -> Result<(u32, String), DisposableBoundaryVerificationError> {
    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(DisposableBoundaryVerificationError::ExecutionBindingInvalid);
    }
    if execution.source_manifest_id != validated.manifest().source_manifest_id
        || execution.native_manifest_digest != validated.digest()
    {
        return Err(DisposableBoundaryVerificationError::ManifestBindingMismatch);
    }

    let Some(position) = execution
        .mutation_step_ids
        .iter()
        .position(|step_id| *step_id == completed_step_id)
    else {
        return Err(DisposableBoundaryVerificationError::CompletedStepNotAuthorized);
    };
    let next_step_id = execution
        .mutation_step_ids
        .get(position + 1)
        .copied()
        .ok_or(DisposableBoundaryVerificationError::NoNextMutationStep)?;

    let step = validated
        .manifest()
        .steps
        .iter()
        .find(|step| step.plan_step_id == completed_step_id)
        .ok_or(DisposableBoundaryVerificationError::CompletedStepNotAuthorized)?;

    let NativeOperationSpec::ExtendLogicalVolume {
        lv_uuid,
        expected_lv_size_bytes,
        ..
    } = &step.operation
    else {
        return Err(DisposableBoundaryVerificationError::UnsupportedCompletedMutation);
    };

    if fresh_identity.route_status != LayerRouteStatus::SupportedProfile {
        return Err(DisposableBoundaryVerificationError::UnsupportedFreshRoute);
    }

    let matches = fresh_identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == LvmIdentityKind::LogicalVolume
                && entry.uuid.as_deref() == Some(lv_uuid.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableBoundaryVerificationError::LogicalVolumeIdentityNotUnique);
    }
    if matches[0].size_bytes != *expected_lv_size_bytes {
        return Err(DisposableBoundaryVerificationError::LogicalVolumeSizeMismatch);
    }

    let filesystem = fresh_identity
        .filesystem
        .as_ref()
        .ok_or(DisposableBoundaryVerificationError::FilesystemBackingSizeMismatch)?;
    if filesystem.backing_device_size_bytes != *expected_lv_size_bytes {
        return Err(DisposableBoundaryVerificationError::FilesystemBackingSizeMismatch);
    }

    Ok((next_step_id, fresh_identity.manifest_digest.clone()))
}

/// Verify the completed destructive layer against a fresh target identity and durably
/// reopen execution only for the next ordered mutation boundary.
pub fn verify_and_continue_disposable_boundary(
    session: &mut LockedExecutionSession<'_>,
    validated: &ValidatedNativeManifest,
    fresh_identity: &TargetIdentityManifest,
    completed_step_id: u32,
) -> Result<DisposableVerifiedBoundary, DisposableBoundaryVerificationError> {
    session
        .require_current_durable_journal()
        .map_err(|_| DisposableBoundaryVerificationError::DurableVerificationStateRequired)?;
    if session.journal().phase != JournalPhase::Verifying
        || !session.journal().mutation_may_have_started
    {
        return Err(DisposableBoundaryVerificationError::DurableVerificationStateRequired);
    }
    let execution = session
        .journal()
        .execution
        .as_ref()
        .cloned()
        .ok_or(DisposableBoundaryVerificationError::ExecutionBindingInvalid)?;

    let (next_step_id, fresh_identity_digest) =
        verify_boundary_state(&execution, validated, fresh_identity, completed_step_id)?;

    session
        .persist_verification_passed_continue(completed_step_id, next_step_id)
        .map_err(|_| DisposableBoundaryVerificationError::PersistenceFailed)?;

    Ok(DisposableVerifiedBoundary {
        execution_id: execution.execution_id,
        completed_step_id,
        next_step_id,
        fresh_identity_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::NodeKind;
    use lsm_planner::{
        FilesystemIdentity, LvmIdentity, MountIdentity, Reversibility,
    };

    use crate::{
        validate_and_bind_native_manifest, FrozenIntentRole, NativeCompiledManifest,
        NativeCompiledStep, NativeVerificationBarrier,
    };

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn barrier(after_plan_step_id: u32) -> NativeVerificationBarrier {
        NativeVerificationBarrier {
            after_plan_step_id,
            before_next_mutation: true,
            require_fresh_target_identity: true,
            require_fresh_capabilities: true,
            require_expected_state_check: true,
            stop_on_mismatch: true,
        }
    }

    fn validated() -> ValidatedNativeManifest {
        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: digest('a'),
            steps: vec![
                NativeCompiledStep {
                    plan_step_id: 3,
                    depends_on: vec![],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::ExtendLogicalVolume {
                        lv_uuid: "lv-1".into(),
                        additional_extents: 4,
                        expected_lv_size_bytes: 9 * 1024 * 1024 * 1024,
                    },
                },
                NativeCompiledStep {
                    plan_step_id: 4,
                    depends_on: vec![3],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::GrowFilesystem {
                        fs_type: "ext4".into(),
                        mountpoint: "/mnt/test".into(),
                    },
                },
            ],
            verification_barriers: vec![barrier(3), barrier(4)],
        })
        .unwrap()
    }

    fn execution(validated: &ValidatedNativeManifest) -> ExecutionStartBinding {
        let mut binding = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: digest('2'),
            plan_id: digest('3'),
            approval_id: digest('4'),
            source_manifest_id: validated.manifest().source_manifest_id.clone(),
            native_manifest_digest: validated.digest().to_owned(),
            fresh_identity_digest: digest('5'),
            mutation_step_ids: vec![3, 4],
            approved_journal_digest: digest('6'),
        };
        binding.execution_id = binding.expected_execution_id().unwrap();
        binding
    }

    fn fresh_identity(size_bytes: u64) -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/test".into(),
            manifest_digest: digest('b'),
            resolved_device: "/dev/mapper/vg0-root".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![lsm_planner::DeviceIdentity {
                kind: NodeKind::Loop,
                path: "/dev/loop7".into(),
                kernel_name: Some("loop7".into()),
                parent_kernel_name: None,
                size_bytes: 16 * 1024 * 1024 * 1024,
                start_512_sector: None,
                logical_sector_bytes: Some(512),
                uuid: None,
                partition_uuid: None,
                model: None,
                serial: None,
                filesystem_type: None,
            }],
            partitions: vec![],
            lvm: vec![LvmIdentity {
                kind: LvmIdentityKind::LogicalVolume,
                name: "/dev/vg0/root".into(),
                uuid: Some("lv-1".into()),
                size_bytes,
                free_bytes: None,
                extent_size_bytes: None,
                free_extent_count: None,
                pv_count: None,
                lv_count: None,
                attributes: Some("-wi-ao----".into()),
                layout: Some("linear".into()),
                role: Some("public".into()),
            }],
            filesystem: Some(FilesystemIdentity {
                device: "/dev/mapper/vg0-root".into(),
                fs_type: "ext4".into(),
                fs_version: Some("1.0".into()),
                uuid: Some("fs-1".into()),
                backing_device_size_bytes: size_bytes,
                observed_filesystem_size_bytes: Some(8 * 1024 * 1024 * 1024),
            }),
            mounts: vec![MountIdentity {
                target: "/mnt/test".into(),
                source: Some("/dev/mapper/vg0-root".into()),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            }],
        }
    }

    #[test]
    fn exact_post_lv_state_authorizes_only_the_next_step() {
        let validated = validated();
        let execution = execution(&validated);
        let expected = 9 * 1024 * 1024 * 1024;

        let (next, fresh_digest) =
            verify_boundary_state(&execution, &validated, &fresh_identity(expected), 3).unwrap();

        assert_eq!(next, 4);
        assert_eq!(fresh_digest, digest('b'));
    }

    #[test]
    fn wrong_post_lv_size_fails_closed() {
        let validated = validated();
        let execution = execution(&validated);

        assert_eq!(
            verify_boundary_state(
                &execution,
                &validated,
                &fresh_identity(8 * 1024 * 1024 * 1024),
                3,
            ),
            Err(DisposableBoundaryVerificationError::LogicalVolumeSizeMismatch)
        );
    }
}
