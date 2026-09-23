use lsm_planner::{
    build_execution_start_binding, ExecutionStartBinding, ExecutionStartBindingError,
    OperationJournal,
};
use thiserror::Error;

use crate::{DisposableCommandPlan, LockedExecutionSession, LockedSessionError};

#[derive(Debug, Error)]
pub enum DisposableExecutionStartError {
    #[error("disposable command plan contains no mutation commands")]
    EmptyCommandPlan,
    #[error("could not bind exact disposable execution start: {0}")]
    Binding(#[from] ExecutionStartBindingError),
    #[error("could not persist disposable execution start: {0}")]
    Session(#[from] LockedSessionError),
}

fn build_binding(
    journal: &OperationJournal,
    plan: &DisposableCommandPlan,
) -> Result<ExecutionStartBinding, DisposableExecutionStartError> {
    let mutation_step_ids = plan
        .commands()
        .iter()
        .map(|command| command.plan_step_id())
        .collect::<Vec<_>>();
    if mutation_step_ids.is_empty() {
        return Err(DisposableExecutionStartError::EmptyCommandPlan);
    }

    Ok(build_execution_start_binding(
        journal,
        plan.source_manifest_id(),
        plan.native_manifest_digest(),
        plan.fresh_identity_digest(),
        &mutation_step_ids,
    )?)
}

/// Atomically bind and persist the exact disposable command plan before mutation.
///
/// On success the locked session is durably in `Executing`, with
/// `mutation_may_have_started=true`. The returned binding must then be supplied when
/// minting a per-step disposable execution permit.
pub fn persist_disposable_execution_start(
    session: &mut LockedExecutionSession<'_>,
    plan: &DisposableCommandPlan,
) -> Result<ExecutionStartBinding, DisposableExecutionStartError> {
    let binding = build_binding(session.journal(), plan)?;
    session.persist_execution_started(&binding)?;
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::NodeKind;
    use lsm_planner::{
        ExactApprovalBinding, FilesystemIdentity, JournalPhase, LayerRouteStatus, LvmIdentity,
        LvmIdentityKind, MountIdentity, Reversibility, TargetIdentityManifest,
    };

    use crate::{
        compile_disposable_lvm_growth_commands, validate_and_bind_native_manifest,
        FrozenIntentRole, NativeCompiledManifest, NativeCompiledStep, NativeOperationSpec,
        NativeVerificationBarrier,
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

    fn command_plan() -> DisposableCommandPlan {
        let source_manifest_id = digest('a');
        let validated = validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id,
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
        .unwrap();

        let identity = TargetIdentityManifest {
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
                size_bytes: 8 * 1024 * 1024 * 1024,
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
                backing_device_size_bytes: 8 * 1024 * 1024 * 1024,
                observed_filesystem_size_bytes: Some(8 * 1024 * 1024 * 1024),
            }),
            mounts: vec![MountIdentity {
                target: "/mnt/test".into(),
                source: Some("/dev/mapper/vg0-root".into()),
                fs_type: Some("ext4".into()),
                options: vec!["rw".into()],
            }],
        };

        compile_disposable_lvm_growth_commands(&validated, &identity).unwrap()
    }

    fn approved_journal(plan: &DisposableCommandPlan) -> OperationJournal {
        let approval = ExactApprovalBinding {
            schema_version: 1,
            approval_id: digest('c'),
            plan_id: digest('d'),
            evidence_bundle_id: digest('e'),
            target_manifest_digest: plan.fresh_identity_digest().to_owned(),
            locked_session_id: digest('f'),
            preconditions_journal_digest: digest('1'),
        };
        OperationJournal {
            schema_version: 1,
            journal_id: digest('2'),
            plan_id: approval.plan_id.clone(),
            target: "/mnt/test".into(),
            baseline_manifest_digest: plan.fresh_identity_digest().to_owned(),
            phase: JournalPhase::Approved,
            mutation_may_have_started: false,
            approval: Some(approval),
            execution: None,
            verified_boundary: None,
            events: vec![],
        }
    }

    #[test]
    fn binding_uses_exact_ordered_command_step_ids() {
        let plan = command_plan();
        let binding = build_binding(&approved_journal(&plan), &plan).unwrap();

        assert_eq!(binding.source_manifest_id, plan.source_manifest_id());
        assert_eq!(
            binding.native_manifest_digest,
            plan.native_manifest_digest()
        );
        assert_eq!(binding.fresh_identity_digest, plan.fresh_identity_digest());
        assert_eq!(binding.mutation_step_ids, vec![3, 4]);
        assert!(binding.integrity_matches().unwrap());
    }
}
