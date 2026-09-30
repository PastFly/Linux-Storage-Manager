use std::fs::File;

use lsm_planner::CreatePartitionTablePolicy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_launch::inspect_elf;
use crate::{
    ElfExecutionIdentity, PinnedProductionCreateTools, PrivilegedLaunchSpecError,
    PrivilegedProgram, ProductionCreateActivationIntent, ProductionCreateExecutionPermit,
    ProductionCreateRuntimePreflightReceipt, ProductionCreateToolLeaseError, TrustedToolIdentity,
};

pub const PRODUCTION_CREATE_RUNTIME_LAUNCH_COMPILED: bool =
    cfg!(feature = "production-create-runtime-launch");

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";
const GPT_LINUX_FILESYSTEM_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
const DOS_LINUX_FILESYSTEM_TYPE: &str = "83";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub executable: TrustedToolIdentity,
    pub elf: ElfExecutionIdentity,
    pub stdin_len: u64,
    pub stdin_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateRuntimeLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub preflight_receipt_id: String,
    pub create_intent_id: String,
    pub disk: String,
    pub partition_device: String,
    pub partition_table: CreatePartitionTablePolicy,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub sfdisk_script: String,
    pub sfdisk: ProductionCreateLaunchStage,
    pub partx: ProductionCreateLaunchStage,
    pub mkfs: ProductionCreateLaunchStage,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub descriptor_exec_api: String,
    pub require_partition_rediscovery_before_mkfs: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct LaunchDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    preflight_receipt_id: &'a str,
    create_intent_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    partition_table: CreatePartitionTablePolicy,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    sfdisk_script: &'a str,
    sfdisk: &'a ProductionCreateLaunchStage,
    partx: &'a ProductionCreateLaunchStage,
    mkfs: &'a ProductionCreateLaunchStage,
    fixed_path: &'a str,
    fixed_locale: &'a str,
    descriptor_exec_api: &'a str,
    require_partition_rediscovery_before_mkfs: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionCreateRuntimeLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let payload = LaunchDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            execution_permit_id: &self.execution_permit_id,
            preflight_receipt_id: &self.preflight_receipt_id,
            create_intent_id: &self.create_intent_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            partition_table: self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            sfdisk_script: &self.sfdisk_script,
            sfdisk: &self.sfdisk,
            partx: &self.partx,
            mkfs: &self.mkfs,
            fixed_path: &self.fixed_path,
            fixed_locale: &self.fixed_locale,
            descriptor_exec_api: &self.descriptor_exec_api,
            require_partition_rediscovery_before_mkfs: self
                .require_partition_rediscovery_before_mkfs,
            mutation_enabled: self.mutation_enabled,
            process_spawned: self.process_spawned,
            partition_table_changed: self.partition_table_changed,
            filesystem_formatted: self.filesystem_formatted,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateRuntimeLaunchError {
    #[error("production create runtime launch feature is not compiled")]
    FeatureDisabled,
    #[error("create authorization/preflight integrity is invalid")]
    AuthorizationInvalid,
    #[error("create launch scope does not exactly match activation/permit/preflight")]
    BindingMismatch,
    #[error("pinned create tool lease is invalid: {0}")]
    ToolLease(#[from] ProductionCreateToolLeaseError),
    #[error("create launch tool identities do not match required programs")]
    ProgramMismatch,
    #[error("create launch argument or payload contains an embedded NUL byte")]
    EmbeddedNul,
    #[error("create partition device path could not be derived safely")]
    PartitionPathInvalid,
    #[error("create launch executable is not a supported native ELF: {0}")]
    Executable(#[from] PrivilegedLaunchSpecError),
    #[error("create launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_text(value: &str) -> Result<(), ProductionCreateRuntimeLaunchError> {
    if value.as_bytes().contains(&0) {
        return Err(ProductionCreateRuntimeLaunchError::EmbeddedNul);
    }
    Ok(())
}

fn partition_device(disk: &str) -> Result<String, ProductionCreateRuntimeLaunchError> {
    if !disk.starts_with("/dev/")
        || disk.as_bytes().contains(&0)
        || disk.len() <= "/dev/".len()
        || disk.ends_with('/')
    {
        return Err(ProductionCreateRuntimeLaunchError::PartitionPathInvalid);
    }
    let suffix = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        "p1"
    } else {
        "1"
    };
    Ok(format!("{disk}{suffix}"))
}

fn sfdisk_script(
    policy: CreatePartitionTablePolicy,
    start: u64,
    count: u64,
) -> Result<String, ProductionCreateRuntimeLaunchError> {
    if start == 0 || count == 0 {
        return Err(ProductionCreateRuntimeLaunchError::BindingMismatch);
    }
    let (label, partition_type) = match policy {
        CreatePartitionTablePolicy::Gpt => ("gpt", GPT_LINUX_FILESYSTEM_TYPE),
        CreatePartitionTablePolicy::Dos => ("dos", DOS_LINUX_FILESYSTEM_TYPE),
    };
    Ok(format!(
        "label: {label}\nunit: sectors\n\nstart={start}, size={count}, type={partition_type}\n"
    ))
}

fn stage(
    program: PrivilegedProgram,
    argv: Vec<String>,
    identity: &TrustedToolIdentity,
    file: &File,
    stdin_payload: Option<&str>,
) -> Result<ProductionCreateLaunchStage, ProductionCreateRuntimeLaunchError> {
    if identity.program != program {
        return Err(ProductionCreateRuntimeLaunchError::ProgramMismatch);
    }
    for arg in &argv {
        validate_text(arg)?;
    }
    let (stdin_len, stdin_sha256) = match stdin_payload {
        Some(payload) => {
            validate_text(payload)?;
            (
                payload.len() as u64,
                Some(format!("{:x}", Sha256::digest(payload.as_bytes()))),
            )
        }
        None => (0, None),
    };
    Ok(ProductionCreateLaunchStage {
        program,
        argv,
        executable: identity.clone(),
        elf: inspect_elf(file)?,
        stdin_len,
        stdin_sha256,
    })
}

fn validate_bindings(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
) -> Result<(), ProductionCreateRuntimeLaunchError> {
    if activation.schema_version != 1
        || permit.schema_version != 1
        || preflight.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !permit.integrity_matches().unwrap_or(false)
        || !preflight.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !permit.compile_feature_enabled
        || !preflight.runtime_ready
        || activation.execution_enabled
        || permit.mutation_enabled
        || permit.process_spawned
        || preflight.mutation_enabled
        || preflight.process_spawned
        || activation.partition_table_changed
        || activation.filesystem_formatted
        || permit.partition_table_changed
        || permit.filesystem_formatted
        || preflight.partition_table_changed
        || preflight.filesystem_formatted
    {
        return Err(ProductionCreateRuntimeLaunchError::AuthorizationInvalid);
    }

    if permit.activation_id != activation.activation_id
        || preflight.activation_id != activation.activation_id
        || preflight.execution_permit_id != permit.permit_id
        || permit.create_intent_id != activation.create_intent_id
        || preflight.create_intent_id != activation.create_intent_id
        || permit.create_plan_id != activation.create_plan_id
        || permit.source_id != activation.source_id
        || permit.disk != activation.disk
        || preflight.disk != activation.disk
        || permit.disk_size_bytes != activation.disk_size_bytes
        || preflight.disk_size_bytes != activation.disk_size_bytes
        || permit.logical_sector_bytes != activation.logical_sector_bytes
        || preflight.logical_sector_bytes != activation.logical_sector_bytes
        || permit.partition_table != activation.partition_table
        || preflight.partition_table != activation.partition_table
        || permit.partition_start_sector != activation.partition_start_sector
        || preflight.partition_start_sector != activation.partition_start_sector
        || permit.partition_sector_count != activation.partition_sector_count
        || preflight.partition_sector_count != activation.partition_sector_count
        || permit.partition_size_bytes != activation.partition_size_bytes
        || preflight.partition_size_bytes != activation.partition_size_bytes
        || permit.filesystem != activation.filesystem
        || preflight.filesystem != activation.filesystem
    {
        return Err(ProductionCreateRuntimeLaunchError::BindingMismatch);
    }
    Ok(())
}

fn expected_mkfs_program(
    filesystem: &str,
) -> Result<PrivilegedProgram, ProductionCreateRuntimeLaunchError> {
    match filesystem {
        "ext4" => Ok(PrivilegedProgram::MkfsExt4),
        "xfs" => Ok(PrivilegedProgram::MkfsXfs),
        _ => Err(ProductionCreateRuntimeLaunchError::BindingMismatch),
    }
}

fn exact_stage_inputs(
    activation: &ProductionCreateActivationIntent,
) -> Result<(String, String, Vec<String>, Vec<String>, Vec<String>), ProductionCreateRuntimeLaunchError>
{
    let partition = partition_device(&activation.disk)?;
    let script = sfdisk_script(
        activation.partition_table,
        activation.partition_start_sector,
        activation.partition_sector_count,
    )?;
    let sfdisk_argv = vec![
        "sfdisk".into(),
        "--lock=yes".into(),
        "--no-reread".into(),
        "--no-tell-kernel".into(),
        activation.disk.clone(),
    ];
    let partx_argv = vec![
        "partx".into(),
        "--add".into(),
        "--nr".into(),
        "1".into(),
        activation.disk.clone(),
    ];
    let mkfs_argv = match activation.filesystem.as_str() {
        "ext4" => vec!["mkfs.ext4".into(), "-F".into(), partition.clone()],
        "xfs" => vec!["mkfs.xfs".into(), "-f".into(), partition.clone()],
        _ => return Err(ProductionCreateRuntimeLaunchError::BindingMismatch),
    };
    Ok((partition, script, sfdisk_argv, partx_argv, mkfs_argv))
}

/// Freeze the exact descriptor-based create launch contract.
///
/// This is deliberately non-spawning. It binds one exact blank-disk
/// partition-table write, one exact kernel partition-map add, and one exact
/// mkfs invocation. A later durable executor must rediscover and prove the new
/// partition geometry after sfdisk/partx and before mkfs is allowed to run.
pub fn build_production_create_runtime_launch_spec(
    activation: &ProductionCreateActivationIntent,
    permit: &ProductionCreateExecutionPermit,
    preflight: &ProductionCreateRuntimePreflightReceipt,
    tools: &PinnedProductionCreateTools,
) -> Result<ProductionCreateRuntimeLaunchSpec, ProductionCreateRuntimeLaunchError> {
    if !PRODUCTION_CREATE_RUNTIME_LAUNCH_COMPILED {
        return Err(ProductionCreateRuntimeLaunchError::FeatureDisabled);
    }
    validate_bindings(activation, permit, preflight)?;
    tools.revalidate(preflight)?;

    let (partition, script, sfdisk_argv, partx_argv, mkfs_argv) =
        exact_stage_inputs(activation)?;
    let mkfs_program = expected_mkfs_program(&activation.filesystem)?;

    let sfdisk = stage(
        PrivilegedProgram::Sfdisk,
        sfdisk_argv,
        &preflight.sfdisk,
        tools.sfdisk_file(),
        Some(&script),
    )?;
    let partx = stage(
        PrivilegedProgram::Partx,
        partx_argv,
        &preflight.partx,
        tools.partx_file(),
        None,
    )?;
    let mkfs = stage(
        mkfs_program,
        mkfs_argv,
        &preflight.mkfs,
        tools.mkfs_file(),
        None,
    )?;

    let mut launch = ProductionCreateRuntimeLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        create_intent_id: activation.create_intent_id.clone(),
        disk: activation.disk.clone(),
        partition_device: partition,
        partition_table: activation.partition_table,
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        sfdisk_script: script,
        sfdisk,
        partx,
        mkfs,
        fixed_path: FIXED_PATH.into(),
        fixed_locale: FIXED_LOCALE.into(),
        descriptor_exec_api: "fexecve".into(),
        require_partition_rediscovery_before_mkfs: true,
        mutation_enabled: false,
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation(policy: CreatePartitionTablePolicy, filesystem: &str) -> ProductionCreateActivationIntent {
        let mut value = ProductionCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: crate::ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: "space-".to_owned() + &"c".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            partition_table: policy,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: filesystem.into(),
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    #[test]
    fn gpt_ext4_inputs_are_exact_and_shell_free() {
        let value = activation(CreatePartitionTablePolicy::Gpt, "ext4");
        let (partition, script, sfdisk, partx, mkfs) = exact_stage_inputs(&value).unwrap();
        assert_eq!(partition, "/dev/loop7p1");
        assert_eq!(
            script,
            "label: gpt\nunit: sectors\n\nstart=2048, size=262144, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n"
        );
        assert_eq!(
            sfdisk,
            ["sfdisk", "--lock=yes", "--no-reread", "--no-tell-kernel", "/dev/loop7"]
        );
        assert_eq!(partx, ["partx", "--add", "--nr", "1", "/dev/loop7"]);
        assert_eq!(mkfs, ["mkfs.ext4", "-F", "/dev/loop7p1"]);
    }

    #[test]
    fn dos_xfs_inputs_use_exact_linux_partition_type() {
        let value = activation(CreatePartitionTablePolicy::Dos, "xfs");
        let (_, script, _, _, mkfs) = exact_stage_inputs(&value).unwrap();
        assert_eq!(
            script,
            "label: dos\nunit: sectors\n\nstart=2048, size=262144, type=83\n"
        );
        assert_eq!(mkfs, ["mkfs.xfs", "-f", "/dev/loop7p1"]);
    }

    #[test]
    fn ordinary_scsi_style_disk_uses_non_p_partition_suffix() {
        assert_eq!(partition_device("/dev/sda").unwrap(), "/dev/sda1");
    }

    #[test]
    fn launch_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_RUNTIME_LAUNCH_COMPILED,
            cfg!(feature = "production-create-runtime-launch")
        );
    }
}
