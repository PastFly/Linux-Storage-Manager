use std::fs::File;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_launch::inspect_elf;
use crate::{
    ElfExecutionIdentity, PinnedProductionSwapRuntimeTools, PrivilegedLaunchSpecError,
    PrivilegedProgram, ProductionSwapReplacementActivationIntent,
    ProductionSwapReplacementExecutionPermit, ProductionSwapRuntimePreflightReceipt,
    ProductionSwapRuntimeToolLeaseError, TrustedToolIdentity,
};

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";

pub const PRODUCTION_SWAP_RUNTIME_LAUNCH_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-runtime-launch");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapfileCreationContract {
    pub path: String,
    pub size_bytes: u64,
    pub mode: u32,
    pub create_new: bool,
    pub no_follow: bool,
    pub fully_allocate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapRuntimeLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub executable: TrustedToolIdentity,
    pub elf: ElfExecutionIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapRuntimeLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub activation_id: String,
    pub execution_permit_id: String,
    pub preflight_receipt_id: String,
    pub swap_replacement_intent_id: String,
    pub swapfile: ProductionSwapfileCreationContract,
    pub mkswap: ProductionSwapRuntimeLaunchStage,
    pub swapon: ProductionSwapRuntimeLaunchStage,
    pub swapoff: ProductionSwapRuntimeLaunchStage,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub descriptor_exec_api: String,
    pub require_dual_active_verification_before_swapoff: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
    pub swapfile_created: bool,
}

#[derive(Serialize)]
struct LaunchDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    execution_permit_id: &'a str,
    preflight_receipt_id: &'a str,
    swap_replacement_intent_id: &'a str,
    swapfile: &'a ProductionSwapfileCreationContract,
    mkswap: &'a ProductionSwapRuntimeLaunchStage,
    swapon: &'a ProductionSwapRuntimeLaunchStage,
    swapoff: &'a ProductionSwapRuntimeLaunchStage,
    fixed_path: &'a str,
    fixed_locale: &'a str,
    descriptor_exec_api: &'a str,
    require_dual_active_verification_before_swapoff: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    swapfile_created: bool,
}

impl ProductionSwapRuntimeLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    pub(crate) fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let payload = LaunchDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            execution_permit_id: &self.execution_permit_id,
            preflight_receipt_id: &self.preflight_receipt_id,
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            swapfile: &self.swapfile,
            mkswap: &self.mkswap,
            swapon: &self.swapon,
            swapoff: &self.swapoff,
            fixed_path: &self.fixed_path,
            fixed_locale: &self.fixed_locale,
            descriptor_exec_api: &self.descriptor_exec_api,
            require_dual_active_verification_before_swapoff: self
                .require_dual_active_verification_before_swapoff,
            mutation_enabled: self.mutation_enabled,
            process_spawned: self.process_spawned,
            swapfile_created: self.swapfile_created,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapRuntimeLaunchError {
    #[error("production swap runtime launch feature is not compiled")]
    FeatureDisabled,
    #[error("swap runtime authorization or preflight integrity is invalid")]
    AuthorizationInvalid,
    #[error("swap runtime launch scope does not match activation/permit/preflight")]
    BindingMismatch,
    #[error("pinned swap runtime tool lease is invalid: {0}")]
    ToolLease(#[from] ProductionSwapRuntimeToolLeaseError),
    #[error("swap runtime launch stage is bound to the wrong program")]
    ProgramMismatch,
    #[error("swap runtime launch argument contains an embedded NUL byte")]
    EmbeddedNul,
    #[error("swap runtime executable descriptor is not a supported native ELF: {0}")]
    Executable(#[from] PrivilegedLaunchSpecError),
    #[error("swap runtime launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_text(value: &str) -> Result<(), ProductionSwapRuntimeLaunchError> {
    if value.as_bytes().contains(&0) {
        return Err(ProductionSwapRuntimeLaunchError::EmbeddedNul);
    }
    Ok(())
}

fn stage(
    program: PrivilegedProgram,
    args: Vec<String>,
    identity: &TrustedToolIdentity,
    file: &File,
) -> Result<ProductionSwapRuntimeLaunchStage, ProductionSwapRuntimeLaunchError> {
    if identity.program != program {
        return Err(ProductionSwapRuntimeLaunchError::ProgramMismatch);
    }
    for arg in &args {
        validate_text(arg)?;
    }
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.as_str().to_owned());
    argv.extend(args);

    Ok(ProductionSwapRuntimeLaunchStage {
        program,
        argv,
        executable: identity.clone(),
        elf: inspect_elf(file)?,
    })
}

fn validate_bindings(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
) -> Result<(), ProductionSwapRuntimeLaunchError> {
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
    {
        return Err(ProductionSwapRuntimeLaunchError::AuthorizationInvalid);
    }

    if permit.activation_id != activation.activation_id
        || preflight.activation_id != activation.activation_id
        || preflight.execution_permit_id != permit.permit_id
        || permit.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || preflight.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || permit.target != activation.target
        || preflight.target != activation.target
        || permit.retiring_swap_device != activation.retiring_swap_device
        || preflight.retiring_swap_device != activation.retiring_swap_device
        || permit.retiring_swap_bytes != activation.retiring_swap_bytes
        || preflight.retiring_swap_bytes != activation.retiring_swap_bytes
        || permit.retiring_swap_priority != activation.retiring_swap_priority
        || preflight.retiring_swap_priority != activation.retiring_swap_priority
        || permit.swapfile_path != activation.swapfile_path
        || preflight.swapfile_path != activation.swapfile_path
        || permit.swapfile_mode != activation.swapfile_mode
        || preflight.destination_mount != activation.destination_mount
        || preflight.destination_available_bytes < activation.retiring_swap_bytes
    {
        return Err(ProductionSwapRuntimeLaunchError::BindingMismatch);
    }
    Ok(())
}

fn exact_stage_args(
    preflight: &ProductionSwapRuntimePreflightReceipt,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    (
        vec!["--force".into(), preflight.swapfile_path.clone()],
        vec![
            "--priority".into(),
            preflight.retiring_swap_priority.to_string(),
            preflight.swapfile_path.clone(),
        ],
        vec![preflight.retiring_swap_device.clone()],
    )
}

/// Freeze the exact future descriptor-based swap runtime launch sequence.
///
/// This revalidates the already-open M1B61 descriptors immediately before
/// launch-spec construction and then binds the exact mkswap -> swapon ->
/// dual-active verification -> swapoff ordering. It does not create the
/// swapfile and does not spawn any process.
pub fn build_production_swap_runtime_launch_spec(
    activation: &ProductionSwapReplacementActivationIntent,
    permit: &ProductionSwapReplacementExecutionPermit,
    preflight: &ProductionSwapRuntimePreflightReceipt,
    tools: &PinnedProductionSwapRuntimeTools,
) -> Result<ProductionSwapRuntimeLaunchSpec, ProductionSwapRuntimeLaunchError> {
    if !PRODUCTION_SWAP_RUNTIME_LAUNCH_COMPILED {
        return Err(ProductionSwapRuntimeLaunchError::FeatureDisabled);
    }
    validate_bindings(activation, permit, preflight)?;
    tools.revalidate(preflight)?;

    let (mkswap_args, swapon_args, swapoff_args) = exact_stage_args(preflight);
    let mkswap = stage(
        PrivilegedProgram::Mkswap,
        mkswap_args,
        &preflight.mkswap,
        tools.mkswap_file(),
    )?;
    let swapon = stage(
        PrivilegedProgram::Swapon,
        swapon_args,
        &preflight.swapon,
        tools.swapon_file(),
    )?;
    let swapoff = stage(
        PrivilegedProgram::Swapoff,
        swapoff_args,
        &preflight.swapoff,
        tools.swapoff_file(),
    )?;

    let mut launch = ProductionSwapRuntimeLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        activation_id: activation.activation_id.clone(),
        execution_permit_id: permit.permit_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        swapfile: ProductionSwapfileCreationContract {
            path: activation.swapfile_path.clone(),
            size_bytes: activation.retiring_swap_bytes,
            mode: activation.swapfile_mode,
            create_new: true,
            no_follow: true,
            fully_allocate: true,
        },
        mkswap,
        swapon,
        swapoff,
        fixed_path: FIXED_PATH.to_owned(),
        fixed_locale: FIXED_LOCALE.to_owned(),
        descriptor_exec_api: "fexecve".to_owned(),
        require_dual_active_verification_before_swapoff: true,
        mutation_enabled: false,
        process_spawned: false,
        swapfile_created: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_runtime_argv_freezes_replacement_before_old_swapoff() {
        let preflight = ProductionSwapRuntimePreflightReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            activation_id: "a".repeat(64),
            execution_permit_id: "b".repeat(64),
            consent_receipt_id: "c".repeat(64),
            swap_replacement_intent_id: "d".repeat(64),
            target: "/data".into(),
            retiring_swap_device: "/dev/loop7p5".into(),
            retiring_swap_bytes: 64 * 1024 * 1024,
            retiring_swap_priority: 7,
            destination_mount: "/data".into(),
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            destination_available_bytes: 128 * 1024 * 1024,
            mkswap: dummy_identity(PrivilegedProgram::Mkswap),
            swapon: dummy_identity(PrivilegedProgram::Swapon),
            swapoff: dummy_identity(PrivilegedProgram::Swapoff),
            runtime_ready: true,
            mutation_enabled: false,
            process_spawned: false,
        };
        let (mkswap, swapon, swapoff) = exact_stage_args(&preflight);
        assert_eq!(mkswap, vec!["--force", "/data/.linux-storage-manager.swap"]);
        assert_eq!(
            swapon,
            vec!["--priority", "7", "/data/.linux-storage-manager.swap"]
        );
        assert_eq!(swapoff, vec!["/dev/loop7p5"]);
    }

    fn dummy_identity(program: PrivilegedProgram) -> TrustedToolIdentity {
        TrustedToolIdentity {
            program,
            requested_path: format!("/usr/sbin/{}", program.as_str()),
            canonical_path: format!("/usr/sbin/{}", program.as_str()),
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o755,
            size_bytes: 4096,
            sha256: "e".repeat(64),
        }
    }

    #[test]
    fn launch_text_rejects_embedded_nul() {
        assert!(matches!(
            validate_text("safe\0unsafe"),
            Err(ProductionSwapRuntimeLaunchError::EmbeddedNul)
        ));
    }

    #[test]
    fn default_build_keeps_swap_runtime_launch_disabled() {
        assert_eq!(
            PRODUCTION_SWAP_RUNTIME_LAUNCH_COMPILED,
            cfg!(feature = "production-swap-replacement-runtime-launch")
        );
    }
}
