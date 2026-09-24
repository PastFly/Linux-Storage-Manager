use lsm_planner::{LvmIdentityKind, TargetIdentityManifest};
use serde::Serialize;
use thiserror::Error;

use crate::{FrozenIntentRole, NativeOperationKind, NativeOperationSpec, ValidatedNativeManifest};

/// Narrow executable program allowlist for the first disposable-only profile.
///
/// This module compiles argv only. It never spawns a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisposableProgram {
    Pvresize,
    Lvextend,
    Resize2fs,
    XfsGrowfs,
}

impl DisposableProgram {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pvresize => "pvresize",
            Self::Lvextend => "lvextend",
            Self::Resize2fs => "resize2fs",
            Self::XfsGrowfs => "xfs_growfs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisposableCommandSpec {
    plan_step_id: u32,
    program: DisposableProgram,
    args: Vec<String>,
}

impl DisposableCommandSpec {
    pub fn plan_step_id(&self) -> u32 {
        self.plan_step_id
    }

    pub fn program(&self) -> DisposableProgram {
        self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisposableCommandPlan {
    source_manifest_id: String,
    native_manifest_digest: String,
    fresh_identity_digest: String,
    commands: Vec<DisposableCommandSpec>,
}

impl DisposableCommandPlan {
    pub fn source_manifest_id(&self) -> &str {
        &self.source_manifest_id
    }

    pub fn native_manifest_digest(&self) -> &str {
        &self.native_manifest_digest
    }

    pub fn fresh_identity_digest(&self) -> &str {
        &self.fresh_identity_digest
    }

    pub fn commands(&self) -> &[DisposableCommandSpec] {
        &self.commands
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisposableArgvError {
    #[error("first disposable profile does not execute native mutation {0:?}")]
    UnsupportedMutation(NativeOperationKind),
    #[error("disposable profile requires LV -> filesystem or PV -> LV -> filesystem growth")]
    UnsupportedMutationProfile,
    #[error("physical volume UUID {0} did not resolve to exactly one fresh identity")]
    PhysicalVolumeIdentityNotUnique(String),
    #[error("physical volume path is not a safe absolute /dev path")]
    UnsafePhysicalVolumePath,
    #[error("physical volume growth values are not valid against fresh identity")]
    PhysicalVolumeGrowthMismatch,
    #[error("fresh block-device identity does not prove the requested PV capacity")]
    PhysicalVolumeBackingNotProven,
    #[error("logical volume UUID {0} did not resolve to exactly one fresh identity")]
    LogicalVolumeIdentityNotUnique(String),
    #[error("logical volume path is not a safe absolute /dev path")]
    UnsafeLogicalVolumePath,
    #[error("logical volume growth values are not valid against fresh identity")]
    LogicalVolumeGrowthMismatch,
    #[error("fresh filesystem identity is absent")]
    FilesystemIdentityMissing,
    #[error("fresh filesystem identity does not match frozen growth intent")]
    FilesystemIdentityMismatch,
    #[error("fresh filesystem geometry does not prove remaining growth capacity")]
    FilesystemGrowthNotProven,
    #[error("fresh filesystem mount identity is not unique")]
    FilesystemMountNotUnique,
    #[error("filesystem device path is not a safe absolute /dev path")]
    UnsafeFilesystemDevicePath,
    #[error("filesystem mountpoint is not a safe absolute path")]
    UnsafeFilesystemMountpoint,
    #[error("filesystem {0} is not supported by the first disposable profile")]
    UnsupportedFilesystem(String),
}

fn safe_absolute_path(value: &str) -> bool {
    value.starts_with('/') && !value.chars().any(char::is_control)
}

fn safe_device_path(value: &str) -> bool {
    value.starts_with("/dev/") && !value.chars().any(char::is_control)
}

fn compile_pvresize(
    plan_step_id: u32,
    pv_uuid: &str,
    expected_pv_size_bytes: u64,
    identity: &TargetIdentityManifest,
) -> Result<DisposableCommandSpec, DisposableArgvError> {
    let matches = identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == LvmIdentityKind::PhysicalVolume && entry.uuid.as_deref() == Some(pv_uuid)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableArgvError::PhysicalVolumeIdentityNotUnique(
            pv_uuid.to_owned(),
        ));
    }

    let pv = matches[0];
    if expected_pv_size_bytes == 0 || expected_pv_size_bytes <= pv.size_bytes {
        return Err(DisposableArgvError::PhysicalVolumeGrowthMismatch);
    }
    if !safe_device_path(&pv.name) {
        return Err(DisposableArgvError::UnsafePhysicalVolumePath);
    }

    let backing_matches = identity
        .devices
        .iter()
        .filter(|device| device.path == pv.name)
        .collect::<Vec<_>>();
    if backing_matches.len() != 1 || backing_matches[0].size_bytes < expected_pv_size_bytes {
        return Err(DisposableArgvError::PhysicalVolumeBackingNotProven);
    }

    Ok(DisposableCommandSpec {
        plan_step_id,
        program: DisposableProgram::Pvresize,
        args: vec![
            "--setphysicalvolumesize".to_owned(),
            format!("{expected_pv_size_bytes}B"),
            "--yes".to_owned(),
            "--".to_owned(),
            pv.name.clone(),
        ],
    })
}

fn compile_lvextend(
    plan_step_id: u32,
    lv_uuid: &str,
    additional_extents: u64,
    expected_lv_size_bytes: u64,
    identity: &TargetIdentityManifest,
) -> Result<DisposableCommandSpec, DisposableArgvError> {
    let matches = identity
        .lvm
        .iter()
        .filter(|entry| {
            entry.kind == LvmIdentityKind::LogicalVolume && entry.uuid.as_deref() == Some(lv_uuid)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DisposableArgvError::LogicalVolumeIdentityNotUnique(
            lv_uuid.to_owned(),
        ));
    }

    let lv = matches[0];
    if additional_extents == 0
        || expected_lv_size_bytes == 0
        || expected_lv_size_bytes <= lv.size_bytes
    {
        return Err(DisposableArgvError::LogicalVolumeGrowthMismatch);
    }
    if !safe_device_path(&lv.name) {
        return Err(DisposableArgvError::UnsafeLogicalVolumePath);
    }

    Ok(DisposableCommandSpec {
        plan_step_id,
        program: DisposableProgram::Lvextend,
        args: vec![
            "--extents".to_owned(),
            format!("+{additional_extents}"),
            "--".to_owned(),
            lv.name.clone(),
        ],
    })
}

fn compile_filesystem_grow(
    plan_step_id: u32,
    fs_type: &str,
    mountpoint: &str,
    identity: &TargetIdentityManifest,
) -> Result<DisposableCommandSpec, DisposableArgvError> {
    let filesystem = identity
        .filesystem
        .as_ref()
        .ok_or(DisposableArgvError::FilesystemIdentityMissing)?;

    if filesystem.fs_type != fs_type
        || filesystem.device != identity.resolved_device
        || !safe_device_path(&filesystem.device)
    {
        if !safe_device_path(&filesystem.device) {
            return Err(DisposableArgvError::UnsafeFilesystemDevicePath);
        }
        return Err(DisposableArgvError::FilesystemIdentityMismatch);
    }
    if !safe_absolute_path(mountpoint) {
        return Err(DisposableArgvError::UnsafeFilesystemMountpoint);
    }

    let mount_matches = identity
        .mounts
        .iter()
        .filter(|mount| mount.target == mountpoint && mount.fs_type.as_deref() == Some(fs_type))
        .count();
    if mount_matches != 1 {
        return Err(DisposableArgvError::FilesystemMountNotUnique);
    }

    match fs_type {
        "ext4" => Ok(DisposableCommandSpec {
            plan_step_id,
            program: DisposableProgram::Resize2fs,
            args: vec![filesystem.device.clone()],
        }),
        "xfs" => Ok(DisposableCommandSpec {
            plan_step_id,
            program: DisposableProgram::XfsGrowfs,
            args: vec!["-d".to_owned(), mountpoint.to_owned()],
        }),
        other => Err(DisposableArgvError::UnsupportedFilesystem(other.to_owned())),
    }
}

/// Compile the first disposable-only mutation profile into exact non-shell argv.
///
/// Accepted mutation sequences:
/// `ExtendLogicalVolume -> GrowFilesystem` or
/// `ResizePhysicalVolume -> ExtendLogicalVolume -> GrowFilesystem`.
///
/// Partition mutation remains deliberately rejected until separately enabled.
pub fn compile_disposable_lvm_growth_commands(
    validated: &ValidatedNativeManifest,
    fresh_identity: &TargetIdentityManifest,
) -> Result<DisposableCommandPlan, DisposableArgvError> {
    let manifest = validated.manifest();
    let mut commands = Vec::new();
    let mut mutation_kinds = Vec::new();

    for step in &manifest.steps {
        if step.role != FrozenIntentRole::MutationCandidate {
            continue;
        }

        match &step.operation {
            NativeOperationSpec::ExtendPartition { .. } => {
                return Err(DisposableArgvError::UnsupportedMutation(
                    NativeOperationKind::ExtendPartition,
                ));
            }
            NativeOperationSpec::ResizePhysicalVolume {
                pv_uuid,
                expected_pv_size_bytes,
            } => {
                mutation_kinds.push(NativeOperationKind::ResizePhysicalVolume);
                commands.push(compile_pvresize(
                    step.plan_step_id,
                    pv_uuid,
                    *expected_pv_size_bytes,
                    fresh_identity,
                )?);
            }
            NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid,
                additional_extents,
                expected_lv_size_bytes,
            } => {
                mutation_kinds.push(NativeOperationKind::ExtendLogicalVolume);
                commands.push(compile_lvextend(
                    step.plan_step_id,
                    lv_uuid,
                    *additional_extents,
                    *expected_lv_size_bytes,
                    fresh_identity,
                )?);
            }
            NativeOperationSpec::GrowFilesystem {
                fs_type,
                mountpoint,
            } => {
                mutation_kinds.push(NativeOperationKind::GrowFilesystem);
                commands.push(compile_filesystem_grow(
                    step.plan_step_id,
                    fs_type,
                    mountpoint,
                    fresh_identity,
                )?);
            }
            _ => {
                return Err(DisposableArgvError::UnsupportedMutationProfile);
            }
        }
    }

    let lv_filesystem = [
        NativeOperationKind::ExtendLogicalVolume,
        NativeOperationKind::GrowFilesystem,
    ];
    let pv_lv_filesystem = [
        NativeOperationKind::ResizePhysicalVolume,
        NativeOperationKind::ExtendLogicalVolume,
        NativeOperationKind::GrowFilesystem,
    ];
    if mutation_kinds != lv_filesystem && mutation_kinds != pv_lv_filesystem {
        return Err(DisposableArgvError::UnsupportedMutationProfile);
    }

    Ok(DisposableCommandPlan {
        source_manifest_id: manifest.source_manifest_id.clone(),
        native_manifest_digest: validated.digest().to_owned(),
        fresh_identity_digest: fresh_identity.manifest_digest.clone(),
        commands,
    })
}

/// Compile only the verified next destructive boundary against the freshly rediscovered identity.
///
/// This deliberately cannot recompile or re-authorize the already-completed LV mutation.
/// The only accepted continuation for the first disposable profile is the filesystem-growth
/// step that directly depends on the verified LV-growth step.
pub(crate) fn compile_verified_disposable_next_command(
    validated: &ValidatedNativeManifest,
    fresh_identity: &TargetIdentityManifest,
    plan_step_id: u32,
) -> Result<DisposableCommandPlan, DisposableArgvError> {
    let manifest = validated.manifest();
    let mutation_steps = manifest
        .steps
        .iter()
        .filter(|step| step.role == FrozenIntentRole::MutationCandidate)
        .collect::<Vec<_>>();

    if !matches!(mutation_steps.len(), 2 | 3) {
        return Err(DisposableArgvError::UnsupportedMutationProfile);
    }
    let Some(position) = mutation_steps
        .iter()
        .position(|step| step.plan_step_id == plan_step_id)
    else {
        return Err(DisposableArgvError::UnsupportedMutationProfile);
    };
    if position == 0 {
        return Err(DisposableArgvError::UnsupportedMutationProfile);
    }

    let previous = mutation_steps[position - 1];
    let current = mutation_steps[position];
    if !current.depends_on.contains(&previous.plan_step_id) {
        return Err(DisposableArgvError::UnsupportedMutationProfile);
    }

    let command = match (&previous.operation, &current.operation) {
        (
            NativeOperationSpec::ResizePhysicalVolume { .. },
            NativeOperationSpec::ExtendLogicalVolume {
                lv_uuid,
                additional_extents,
                expected_lv_size_bytes,
            },
        ) => compile_lvextend(
            current.plan_step_id,
            lv_uuid,
            *additional_extents,
            *expected_lv_size_bytes,
            fresh_identity,
        )?,
        (
            NativeOperationSpec::ExtendLogicalVolume { .. },
            NativeOperationSpec::GrowFilesystem {
                fs_type,
                mountpoint,
            },
        ) => {
            let filesystem = fresh_identity
                .filesystem
                .as_ref()
                .ok_or(DisposableArgvError::FilesystemIdentityMissing)?;
            let observed = filesystem
                .observed_filesystem_size_bytes
                .ok_or(DisposableArgvError::FilesystemGrowthNotProven)?;
            if observed == 0 || filesystem.backing_device_size_bytes <= observed {
                return Err(DisposableArgvError::FilesystemGrowthNotProven);
            }
            compile_filesystem_grow(current.plan_step_id, fs_type, mountpoint, fresh_identity)?
        }
        _ => return Err(DisposableArgvError::UnsupportedMutationProfile),
    };

    Ok(DisposableCommandPlan {
        source_manifest_id: manifest.source_manifest_id.clone(),
        native_manifest_digest: validated.digest().to_owned(),
        fresh_identity_digest: fresh_identity.manifest_digest.clone(),
        commands: vec![command],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_planner::{
        FilesystemIdentity, LayerRouteStatus, LvmIdentity, MountIdentity, Reversibility,
    };

    use crate::{
        validate_and_bind_native_manifest, FrozenIntentRole, NativeCompiledManifest,
        NativeCompiledStep, NativeOperationSpec, NativeVerificationBarrier,
    };

    fn identity(fs_type: &str, mountpoint: &str) -> TargetIdentityManifest {
        TargetIdentityManifest {
            schema_version: 1,
            target: mountpoint.to_owned(),
            manifest_digest: "identity-test".into(),
            resolved_device: "/dev/mapper/vg0-root".into(),
            route_status: LayerRouteStatus::SupportedProfile,
            route_issue_codes: vec![],
            devices: vec![],
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
                fs_type: fs_type.to_owned(),
                fs_version: Some("test".into()),
                uuid: Some("fs-1".into()),
                backing_device_size_bytes: 8 * 1024 * 1024 * 1024,
                observed_filesystem_size_bytes: Some(8 * 1024 * 1024 * 1024),
            }),
            mounts: vec![MountIdentity {
                target: mountpoint.to_owned(),
                source: Some("/dev/mapper/vg0-root".into()),
                fs_type: Some(fs_type.to_owned()),
                options: vec!["rw".into()],
            }],
        }
    }

    fn pv_identity(fs_type: &str, mountpoint: &str) -> TargetIdentityManifest {
        let mut identity = identity(fs_type, mountpoint);
        identity.devices.push(lsm_planner::DeviceIdentity {
            kind: lsm_core::NodeKind::Partition,
            path: "/dev/loop7p1".into(),
            kernel_name: Some("loop7p1".into()),
            parent_kernel_name: Some("loop7".into()),
            size_bytes: 12 * 1024 * 1024 * 1024,
            start_512_sector: Some(2048),
            logical_sector_bytes: Some(512),
            uuid: None,
            partition_uuid: Some("part-1".into()),
            model: None,
            serial: None,
            filesystem_type: Some("LVM2_member".into()),
        });
        identity.lvm.insert(
            0,
            LvmIdentity {
                kind: LvmIdentityKind::PhysicalVolume,
                name: "/dev/loop7p1".into(),
                uuid: Some("pv-1".into()),
                size_bytes: 10 * 1024 * 1024 * 1024,
                free_bytes: Some(2 * 1024 * 1024 * 1024),
                extent_size_bytes: None,
                free_extent_count: None,
                pv_count: None,
                lv_count: None,
                attributes: Some("a--".into()),
                layout: None,
                role: None,
            },
        );
        identity
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

    fn validated_manifest(fs_type: &str, mountpoint: &str) -> ValidatedNativeManifest {
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
                        fs_type: fs_type.to_owned(),
                        mountpoint: mountpoint.to_owned(),
                    },
                },
            ],
            verification_barriers: vec![barrier(3), barrier(4)],
        })
        .unwrap()
    }

    fn validated_pv_manifest() -> ValidatedNativeManifest {
        validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: "source-pv-intent".into(),
            steps: vec![
                NativeCompiledStep {
                    plan_step_id: 3,
                    depends_on: vec![],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::ResizePhysicalVolume {
                        pv_uuid: "pv-1".into(),
                        expected_pv_size_bytes: 11 * 1024 * 1024 * 1024,
                    },
                },
                NativeCompiledStep {
                    plan_step_id: 4,
                    depends_on: vec![3],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::ExtendLogicalVolume {
                        lv_uuid: "lv-1".into(),
                        additional_extents: 4,
                        expected_lv_size_bytes: 9 * 1024 * 1024 * 1024,
                    },
                },
                NativeCompiledStep {
                    plan_step_id: 5,
                    depends_on: vec![4],
                    reversibility: Reversibility::Irreversible,
                    role: FrozenIntentRole::MutationCandidate,
                    operation: NativeOperationSpec::GrowFilesystem {
                        fs_type: "ext4".into(),
                        mountpoint: "/".into(),
                    },
                },
            ],
            verification_barriers: vec![barrier(3), barrier(4), barrier(5)],
        })
        .unwrap()
    }

    #[test]
    fn ext4_profile_compiles_exact_non_shell_argv() {
        let validated = validated_manifest("ext4", "/");
        let plan =
            compile_disposable_lvm_growth_commands(&validated, &identity("ext4", "/")).unwrap();

        assert_eq!(plan.native_manifest_digest(), validated.digest());
        assert_eq!(plan.fresh_identity_digest(), "identity-test");
        assert_eq!(
            plan.commands(),
            vec![
                DisposableCommandSpec {
                    plan_step_id: 3,
                    program: DisposableProgram::Lvextend,
                    args: vec![
                        "--extents".into(),
                        "+4".into(),
                        "--".into(),
                        "/dev/vg0/root".into(),
                    ],
                },
                DisposableCommandSpec {
                    plan_step_id: 4,
                    program: DisposableProgram::Resize2fs,
                    args: vec!["/dev/mapper/vg0-root".into()],
                },
            ]
        );
    }

    #[test]
    fn pv_lv_filesystem_profile_compiles_exact_pvresize_argv() {
        let validated = validated_pv_manifest();
        let plan =
            compile_disposable_lvm_growth_commands(&validated, &pv_identity("ext4", "/")).unwrap();

        assert_eq!(plan.commands().len(), 3);
        assert_eq!(plan.commands()[0].program(), DisposableProgram::Pvresize);
        assert_eq!(
            plan.commands()[0].args(),
            [
                "--setphysicalvolumesize",
                "11811160064B",
                "--yes",
                "--",
                "/dev/loop7p1"
            ]
        );
        assert_eq!(plan.commands()[1].program(), DisposableProgram::Lvextend);
        assert_eq!(plan.commands()[2].program(), DisposableProgram::Resize2fs);
    }

    #[test]
    fn verified_post_pv_identity_compiles_only_lv_command() {
        let validated = validated_pv_manifest();
        let mut fresh = pv_identity("ext4", "/");
        fresh.manifest_digest = "post-pv-identity".into();
        fresh.lvm[0].size_bytes = 11 * 1024 * 1024 * 1024;

        let plan = compile_verified_disposable_next_command(&validated, &fresh, 4).unwrap();

        assert_eq!(plan.commands().len(), 1);
        assert_eq!(plan.commands()[0].plan_step_id(), 4);
        assert_eq!(plan.commands()[0].program(), DisposableProgram::Lvextend);
        assert_eq!(
            plan.commands()[0].args(),
            ["--extents", "+4", "--", "/dev/vg0/root"]
        );
    }

    #[test]
    fn pv_growth_requires_exact_uuid_and_proven_backing_capacity() {
        let validated = validated_pv_manifest();
        let mut fresh = pv_identity("ext4", "/");
        fresh.lvm[0].uuid = Some("other-pv".into());
        assert_eq!(
            compile_disposable_lvm_growth_commands(&validated, &fresh),
            Err(DisposableArgvError::PhysicalVolumeIdentityNotUnique(
                "pv-1".into()
            ))
        );

        let mut fresh = pv_identity("ext4", "/");
        fresh.devices.last_mut().unwrap().size_bytes = 10 * 1024 * 1024 * 1024;
        assert_eq!(
            compile_disposable_lvm_growth_commands(&validated, &fresh),
            Err(DisposableArgvError::PhysicalVolumeBackingNotProven)
        );
    }

    #[test]
    fn xfs_profile_compiles_exact_mountpoint_argv() {
        let validated = validated_manifest("xfs", "/srv/data");
        let plan =
            compile_disposable_lvm_growth_commands(&validated, &identity("xfs", "/srv/data"))
                .unwrap();

        assert_eq!(plan.commands()[1].program(), DisposableProgram::XfsGrowfs);
        assert_eq!(plan.commands()[1].args(), ["-d", "/srv/data"]);
    }

    #[test]
    fn verified_post_lv_identity_compiles_only_filesystem_command() {
        let validated = validated_manifest("ext4", "/");
        let mut fresh = identity("ext4", "/");
        fresh.manifest_digest = "post-lv-identity".into();
        fresh.lvm[0].size_bytes = 9 * 1024 * 1024 * 1024;
        let filesystem = fresh.filesystem.as_mut().unwrap();
        filesystem.backing_device_size_bytes = 9 * 1024 * 1024 * 1024;
        filesystem.observed_filesystem_size_bytes = Some(8 * 1024 * 1024 * 1024);

        let plan = compile_verified_disposable_next_command(&validated, &fresh, 4).unwrap();

        assert_eq!(plan.fresh_identity_digest(), "post-lv-identity");
        assert_eq!(plan.commands().len(), 1);
        assert_eq!(plan.commands()[0].plan_step_id(), 4);
        assert_eq!(plan.commands()[0].program(), DisposableProgram::Resize2fs);
        assert_eq!(plan.commands()[0].args(), ["/dev/mapper/vg0-root"]);
    }

    #[test]
    fn verified_continuation_rejects_wrong_step_or_missing_growth_room() {
        let validated = validated_manifest("xfs", "/srv/data");
        let mut fresh = identity("xfs", "/srv/data");
        fresh.manifest_digest = "post-lv-identity".into();
        fresh.lvm[0].size_bytes = 9 * 1024 * 1024 * 1024;
        let filesystem = fresh.filesystem.as_mut().unwrap();
        filesystem.backing_device_size_bytes = 9 * 1024 * 1024 * 1024;
        filesystem.observed_filesystem_size_bytes = Some(8 * 1024 * 1024 * 1024);

        assert_eq!(
            compile_verified_disposable_next_command(&validated, &fresh, 3),
            Err(DisposableArgvError::UnsupportedMutationProfile)
        );

        fresh
            .filesystem
            .as_mut()
            .unwrap()
            .observed_filesystem_size_bytes = Some(9 * 1024 * 1024 * 1024);
        assert_eq!(
            compile_verified_disposable_next_command(&validated, &fresh, 4),
            Err(DisposableArgvError::FilesystemGrowthNotProven)
        );
    }

    #[test]
    fn partition_mutation_remains_rejected() {
        let validated = validate_and_bind_native_manifest(NativeCompiledManifest {
            source_manifest_id: "unsupported-mutation".into(),
            steps: vec![NativeCompiledStep {
                plan_step_id: 1,
                depends_on: vec![],
                reversibility: Reversibility::Irreversible,
                role: FrozenIntentRole::MutationCandidate,
                operation: NativeOperationSpec::ExtendPartition {
                    partition: "/dev/loop0p1".into(),
                    start_sector: 2048,
                    old_size_sectors: 4096,
                    new_size_sectors: 8192,
                    sector_size_bytes: 512,
                },
            }],
            verification_barriers: vec![barrier(1)],
        })
        .unwrap();

        assert_eq!(
            compile_disposable_lvm_growth_commands(&validated, &identity("ext4", "/")),
            Err(DisposableArgvError::UnsupportedMutation(
                NativeOperationKind::ExtendPartition
            ))
        );
    }

    #[test]
    fn stale_or_ambiguous_lv_identity_fails_closed() {
        let validated = validated_manifest("ext4", "/");
        let mut fresh = identity("ext4", "/");
        fresh.lvm[0].uuid = Some("different-lv".into());

        assert_eq!(
            compile_disposable_lvm_growth_commands(&validated, &fresh),
            Err(DisposableArgvError::LogicalVolumeIdentityNotUnique(
                "lv-1".into()
            ))
        );
    }

    #[test]
    fn filesystem_identity_mismatch_fails_closed() {
        let validated = validated_manifest("ext4", "/");
        let mut fresh = identity("ext4", "/");
        fresh.filesystem.as_mut().unwrap().device = "/dev/mapper/other".into();

        assert_eq!(
            compile_disposable_lvm_growth_commands(&validated, &fresh),
            Err(DisposableArgvError::FilesystemIdentityMismatch)
        );
    }
}
