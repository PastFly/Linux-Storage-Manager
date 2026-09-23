use lsm_planner::{ExecutionStartBinding, LvmIdentityKind, TargetIdentityManifest};
use thiserror::Error;

use crate::disposable_argv::compile_verified_disposable_next_command;
use crate::{
    revalidate_disposable_loop_ownership, DisposableArgvError, DisposableCommandPlan,
    DisposableCommandSpec, DisposableLoopAssociation, DisposableLoopOwnershipProof,
    DisposableOwnershipError, DisposableVerifiedBoundary, ValidatedNativeManifest,
};

#[derive(Debug)]
pub struct DisposableExecutionPermit {
    source_manifest_id: String,
    native_manifest_digest: String,
    fresh_identity_digest: String,
    execution_id: String,
    loop_device: String,
    command: DisposableCommandSpec,
    #[cfg(feature = "disposable-executor")]
    ownership: DisposableLoopOwnershipProof,
}

impl DisposableExecutionPermit {
    pub fn source_manifest_id(&self) -> &str {
        &self.source_manifest_id
    }

    pub fn native_manifest_digest(&self) -> &str {
        &self.native_manifest_digest
    }

    pub fn fresh_identity_digest(&self) -> &str {
        &self.fresh_identity_digest
    }

    pub fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub fn loop_device(&self) -> &str {
        &self.loop_device
    }

    pub fn command(&self) -> &DisposableCommandSpec {
        &self.command
    }

    #[cfg(feature = "disposable-executor")]
    pub(crate) fn ownership(&self) -> &DisposableLoopOwnershipProof {
        &self.ownership
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisposablePermitError {
    #[error("disposable command plan is not bound to the supplied fresh identity")]
    FreshIdentityBindingMismatch,
    #[error("verified loop association does not match the ownership proof")]
    AssociationOwnershipMismatch,
    #[error("fresh target identity is not rooted exclusively in the owned loop device")]
    TargetNotOwnedByLoop,
    #[error("durable execution binding does not match the disposable command plan")]
    ExecutionBindingMismatch,
    #[error("durable execution binding integrity check failed")]
    ExecutionBindingIntegrityMismatch,
    #[error("disposable plan step {0} is not the next authorized mutation boundary")]
    ExecutionStepNotNext(u32),
    #[error("verified disposable boundary does not match the durable execution continuation")]
    VerifiedBoundaryMismatch,
    #[error("verified disposable continuation command is invalid: {0}")]
    VerifiedCommand(#[from] DisposableArgvError),
    #[error("requested disposable plan step {0} did not resolve to exactly one command")]
    CommandStepNotUnique(u32),
    #[error("disposable ownership proof is no longer valid: {0}")]
    Ownership(#[from] DisposableOwnershipError),
}

fn belongs_to_loop(path: &str, loop_path: &str) -> bool {
    if path == loop_path {
        return true;
    }
    path.strip_prefix(loop_path)
        .and_then(|suffix| suffix.strip_prefix('p'))
        .is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn verify_target_owned_by_loop(
    identity: &TargetIdentityManifest,
    loop_device: &str,
) -> Result<(), DisposablePermitError> {
    let chain_has_loop = identity
        .devices
        .iter()
        .any(|device| device.path == loop_device);
    let foreign_loop = identity
        .devices
        .iter()
        .filter(|device| device.path.starts_with("/dev/loop"))
        .any(|device| !belongs_to_loop(&device.path, loop_device));
    let pvs = identity
        .lvm
        .iter()
        .filter(|entry| entry.kind == LvmIdentityKind::PhysicalVolume)
        .collect::<Vec<_>>();

    if !chain_has_loop
        || foreign_loop
        || pvs.len() != 1
        || !belongs_to_loop(&pvs[0].name, loop_device)
    {
        return Err(DisposablePermitError::TargetNotOwnedByLoop);
    }
    Ok(())
}

/// Bind one exact compiled command to current disposable ownership and fresh identity.
///
/// The returned permit is intentionally non-cloneable. Future execution consumes it,
/// forcing ownership/identity proof to be rebuilt before the next destructive layer.
pub fn bind_disposable_execution_permit(
    plan: &DisposableCommandPlan,
    fresh_identity: &TargetIdentityManifest,
    ownership: &DisposableLoopOwnershipProof,
    association: &DisposableLoopAssociation,
    execution: &ExecutionStartBinding,
    plan_step_id: u32,
) -> Result<DisposableExecutionPermit, DisposablePermitError> {
    revalidate_disposable_loop_ownership(ownership)?;

    if plan.fresh_identity_digest() != fresh_identity.manifest_digest {
        return Err(DisposablePermitError::FreshIdentityBindingMismatch);
    }

    if association.loop_device() != ownership.loop_device()
        || association.backing_file() != ownership.backing_file()
    {
        return Err(DisposablePermitError::AssociationOwnershipMismatch);
    }

    verify_target_owned_by_loop(fresh_identity, ownership.loop_device())?;

    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(DisposablePermitError::ExecutionBindingIntegrityMismatch);
    }
    if execution.source_manifest_id != plan.source_manifest_id()
        || execution.native_manifest_digest != plan.native_manifest_digest()
        || execution.fresh_identity_digest != plan.fresh_identity_digest()
    {
        return Err(DisposablePermitError::ExecutionBindingMismatch);
    }
    if execution.mutation_step_ids.first().copied() != Some(plan_step_id) {
        return Err(DisposablePermitError::ExecutionStepNotNext(plan_step_id));
    }

    let commands = plan
        .commands()
        .iter()
        .filter(|command| command.plan_step_id() == plan_step_id)
        .collect::<Vec<_>>();
    if commands.len() != 1 {
        return Err(DisposablePermitError::CommandStepNotUnique(plan_step_id));
    }

    Ok(DisposableExecutionPermit {
        source_manifest_id: plan.source_manifest_id().to_owned(),
        native_manifest_digest: plan.native_manifest_digest().to_owned(),
        fresh_identity_digest: plan.fresh_identity_digest().to_owned(),
        execution_id: execution.execution_id.clone(),
        loop_device: ownership.loop_device().to_owned(),
        command: commands[0].clone(),
        #[cfg(feature = "disposable-executor")]
        ownership: ownership.clone(),
    })
}

/// Bind the next destructive layer only from a consumed, freshly verified boundary.
///
/// Unlike the first-step binder, this intentionally does not compare the durable
/// execution's original `fresh_identity_digest`: that digest describes the state
/// before the first mutation. The consumed boundary is the only authority for the
/// post-mutation identity and exact next ordered step.
pub fn bind_verified_disposable_execution_permit(
    validated: &ValidatedNativeManifest,
    fresh_identity: &TargetIdentityManifest,
    ownership: &DisposableLoopOwnershipProof,
    association: &DisposableLoopAssociation,
    execution: &ExecutionStartBinding,
    boundary: DisposableVerifiedBoundary,
) -> Result<DisposableExecutionPermit, DisposablePermitError> {
    revalidate_disposable_loop_ownership(ownership)?;

    if association.loop_device() != ownership.loop_device()
        || association.backing_file() != ownership.backing_file()
    {
        return Err(DisposablePermitError::AssociationOwnershipMismatch);
    }

    verify_target_owned_by_loop(fresh_identity, ownership.loop_device())?;

    if execution.schema_version != 1 || !execution.integrity_matches().unwrap_or(false) {
        return Err(DisposablePermitError::ExecutionBindingIntegrityMismatch);
    }
    if execution.source_manifest_id != validated.manifest().source_manifest_id
        || execution.native_manifest_digest != validated.digest()
    {
        return Err(DisposablePermitError::ExecutionBindingMismatch);
    }

    let ordered_pair = execution.mutation_step_ids.windows(2).any(|pair| {
        pair[0] == boundary.completed_step_id() && pair[1] == boundary.next_step_id()
    });
    if boundary.execution_id() != execution.execution_id
        || boundary.fresh_identity_digest() != fresh_identity.manifest_digest
        || !ordered_pair
    {
        return Err(DisposablePermitError::VerifiedBoundaryMismatch);
    }

    let next_step_id = boundary.next_step_id();
    let plan =
        compile_verified_disposable_next_command(validated, fresh_identity, next_step_id)?;
    let commands = plan.commands();
    if commands.len() != 1 || commands[0].plan_step_id() != next_step_id {
        return Err(DisposablePermitError::CommandStepNotUnique(next_step_id));
    }

    Ok(DisposableExecutionPermit {
        source_manifest_id: plan.source_manifest_id().to_owned(),
        native_manifest_digest: plan.native_manifest_digest().to_owned(),
        fresh_identity_digest: plan.fresh_identity_digest().to_owned(),
        execution_id: execution.execution_id.clone(),
        loop_device: ownership.loop_device().to_owned(),
        command: commands[0].clone(),
        #[cfg(feature = "disposable-executor")]
        ownership: ownership.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use lsm_planner::{
        FilesystemIdentity, LayerRouteStatus, LvmIdentity, MountIdentity, Reversibility,
    };

    use crate::{
        capture_disposable_loop_ownership, compile_disposable_lvm_growth_commands,
        validate_and_bind_native_manifest, verify_disposable_loop_association_row,
        FrozenIntentRole, NativeCompiledManifest, NativeCompiledStep, NativeOperationSpec,
        NativeVerificationBarrier, ValidatedNativeManifest,
    };

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn root() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("lsm-disposable-permit-{}-{id}", std::process::id()))
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
            source_manifest_id: "source-intent".into(),
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

    fn identity(loop_device: &str) -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: "/mnt/test".into(),
            manifest_digest: "fresh-id".into(),
            resolved_device: "/dev/mapper/vg0-root".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![lsm_planner::DeviceIdentity {
                kind: lsm_core::NodeKind::Loop,
                path: loop_device.into(),
                kernel_name: Some(loop_device.trim_start_matches("/dev/").into()),
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
            lvm: vec![
                LvmIdentity {
                    kind: LvmIdentityKind::PhysicalVolume,
                    name: format!("{loop_device}p1"),
                    uuid: Some("pv-1".into()),
                    size_bytes: 16 * 1024 * 1024 * 1024,
                    free_bytes: Some(8 * 1024 * 1024 * 1024),
                    extent_size_bytes: None,
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: Some("a--".into()),
                    layout: None,
                    role: None,
                },
                LvmIdentity {
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
                },
            ],
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
        }
    }

    fn setup() -> (
        PathBuf,
        DisposableLoopOwnershipProof,
        DisposableLoopAssociation,
        DisposableCommandPlan,
        TargetIdentityManifest,
    ) {
        let root = root();
        fs::create_dir_all(&root).unwrap();
        let image = root.join("owned.img");
        File::create(&image).unwrap();
        let ownership = capture_disposable_loop_ownership("/dev/loop7", &image, &root).unwrap();
        let association = verify_disposable_loop_association_row(
            "/dev/loop7",
            &image,
            &format!("/dev/loop7 {}", image.display()),
        )
        .unwrap();
        let identity = identity("/dev/loop7");
        let mut command_identity = identity.clone();
        command_identity.manifest_digest = "fresh-id".into();
        let plan = compile_disposable_lvm_growth_commands(&validated(), &command_identity).unwrap();
        (root, ownership, association, plan, identity)
    }

    fn execution(plan: &DisposableCommandPlan) -> ExecutionStartBinding {
        let mut binding = ExecutionStartBinding {
            schema_version: 1,
            execution_id: String::new(),
            journal_id: "journal".into(),
            plan_id: "plan".into(),
            approval_id: "approval".into(),
            source_manifest_id: plan.source_manifest_id().to_owned(),
            native_manifest_digest: plan.native_manifest_digest().to_owned(),
            fresh_identity_digest: plan.fresh_identity_digest().to_owned(),
            mutation_step_ids: vec![3, 4],
            approved_journal_digest: "approved-journal".into(),
        };
        binding.execution_id = binding.expected_execution_id().unwrap();
        binding
    }

    #[test]
    fn binds_one_exact_command_to_owned_loop_and_fresh_identity() {
        let (root, ownership, association, plan, identity) = setup();

        let execution = execution(&plan);
        let permit = bind_disposable_execution_permit(
            &plan,
            &identity,
            &ownership,
            &association,
            &execution,
            3,
        )
        .unwrap();

        assert_eq!(permit.execution_id(), execution.execution_id);
        assert_eq!(permit.loop_device(), "/dev/loop7");
        assert_eq!(permit.command().plan_step_id(), 3);
        assert_eq!(
            permit.native_manifest_digest(),
            plan.native_manifest_digest()
        );
        fs::remove_dir_all(root).unwrap();
    }


    #[test]
    fn verified_boundary_mints_only_fresh_filesystem_permit() {
        let (root, ownership, association, plan, mut identity) = setup();
        let execution = execution(&plan);

        identity.manifest_digest = "post-lv-id".into();
        identity.lvm[1].size_bytes = 9 * 1024 * 1024 * 1024;
        let filesystem = identity.filesystem.as_mut().unwrap();
        filesystem.backing_device_size_bytes = 9 * 1024 * 1024 * 1024;
        filesystem.observed_filesystem_size_bytes = Some(8 * 1024 * 1024 * 1024);

        let boundary = DisposableVerifiedBoundary::new(
            execution.execution_id.clone(),
            3,
            4,
            identity.manifest_digest.clone(),
        );
        let permit = bind_verified_disposable_execution_permit(
            &validated(),
            &identity,
            &ownership,
            &association,
            &execution,
            boundary,
        )
        .unwrap();

        assert_eq!(permit.execution_id(), execution.execution_id);
        assert_eq!(permit.fresh_identity_digest(), "post-lv-id");
        assert_eq!(permit.command().plan_step_id(), 4);
        assert_eq!(
            permit.command().args(),
            ["/dev/mapper/vg0-root"]
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_or_reordered_verified_boundary_fails_closed() {
        let (root, ownership, association, plan, mut identity) = setup();
        let execution = execution(&plan);

        identity.manifest_digest = "post-lv-id".into();
        identity.lvm[1].size_bytes = 9 * 1024 * 1024 * 1024;
        let filesystem = identity.filesystem.as_mut().unwrap();
        filesystem.backing_device_size_bytes = 9 * 1024 * 1024 * 1024;
        filesystem.observed_filesystem_size_bytes = Some(8 * 1024 * 1024 * 1024);

        let stale = DisposableVerifiedBoundary::new(
            execution.execution_id.clone(),
            3,
            4,
            "stale-post-lv-id".into(),
        );
        assert!(matches!(
            bind_verified_disposable_execution_permit(
                &validated(),
                &identity,
                &ownership,
                &association,
                &execution,
                stale,
            ),
            Err(DisposablePermitError::VerifiedBoundaryMismatch)
        ));

        let reordered = DisposableVerifiedBoundary::new(
            execution.execution_id.clone(),
            4,
            3,
            identity.manifest_digest.clone(),
        );
        assert!(matches!(
            bind_verified_disposable_execution_permit(
                &validated(),
                &identity,
                &ownership,
                &association,
                &execution,
                reordered,
            ),
            Err(DisposablePermitError::VerifiedBoundaryMismatch)
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn association_or_identity_mismatch_fails_closed() {
        let (root, ownership, _association, plan, mut identity) = setup();
        let other = verify_disposable_loop_association_row(
            "/dev/loop8",
            ownership.backing_file(),
            &format!("/dev/loop8 {}", ownership.backing_file().display()),
        )
        .unwrap();

        assert!(matches!(
            bind_disposable_execution_permit(
                &plan,
                &identity,
                &ownership,
                &other,
                &execution(&plan),
                3,
            ),
            Err(DisposablePermitError::AssociationOwnershipMismatch)
        ));

        identity.manifest_digest = "different".into();
        let association = verify_disposable_loop_association_row(
            "/dev/loop7",
            ownership.backing_file(),
            &format!("/dev/loop7 {}", ownership.backing_file().display()),
        )
        .unwrap();
        assert!(matches!(
            bind_disposable_execution_permit(
                &plan,
                &identity,
                &ownership,
                &association,
                &execution(&plan),
                3,
            ),
            Err(DisposablePermitError::FreshIdentityBindingMismatch)
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_execution_binding_or_step_fails_closed() {
        let (root, ownership, association, plan, identity) = setup();
        let mut binding = execution(&plan);
        binding.native_manifest_digest = "different".into();
        binding.execution_id = binding.expected_execution_id().unwrap();

        assert!(matches!(
            bind_disposable_execution_permit(
                &plan,
                &identity,
                &ownership,
                &association,
                &binding,
                3,
            ),
            Err(DisposablePermitError::ExecutionBindingMismatch)
        ));

        let binding = execution(&plan);
        assert!(matches!(
            bind_disposable_execution_permit(
                &plan,
                &identity,
                &ownership,
                &association,
                &binding,
                99,
            ),
            Err(DisposablePermitError::ExecutionStepNotNext(99))
        ));
        assert!(matches!(
            bind_disposable_execution_permit(
                &plan,
                &identity,
                &ownership,
                &association,
                &binding,
                4,
            ),
            Err(DisposablePermitError::ExecutionStepNotNext(4))
        ));

        fs::remove_dir_all(root).unwrap();
    }
}
