use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PinnedPrivilegedTools, PinnedToolReceipt, PrivilegedCommandSpec, PrivilegedProgram};

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ElfDataEncoding {
    LittleEndian,
    BigEndian,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfExecutionIdentity {
    pub class: ElfClass,
    pub data_encoding: ElfDataEncoding,
    pub version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DescriptorLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub executable: PinnedToolReceipt,
    pub elf: ElfExecutionIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedDescriptorLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub pin_id: String,
    pub authorization_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub primary: DescriptorLaunchStage,
    pub kernel_refresh: Option<DescriptorLaunchStage>,
    pub stdin_len: u64,
    pub stdin_sha256: Option<String>,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub descriptor_exec_api: String,
    pub process_spawned: bool,
}

impl PrivilegedDescriptorLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.pin_id,
            &self.authorization_id,
            self.plan_step_id,
            &self.command_digest,
            &self.primary,
            &self.kernel_refresh,
            self.stdin_len,
            &self.stdin_sha256,
            &self.fixed_path,
            &self.fixed_locale,
            &self.descriptor_exec_api,
            self.process_spawned,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedLaunchSpecError {
    #[error("pinned executable receipt integrity check failed")]
    PinIntegrityMismatch,
    #[error("pinned executable receipt does not match the exact command")]
    PinCommandMismatch,
    #[error("pinned executable file descriptor is no longer open")]
    PinnedDescriptorClosed,
    #[error("kernel-refresh descriptor presence does not match the exact command")]
    KernelRefreshPresenceMismatch,
    #[error("pinned executable is not a supported native ELF image")]
    UnsupportedExecutableFormat,
    #[error("launch argument contains an embedded NUL byte")]
    EmbeddedNul,
    #[error("descriptor launch validation I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("descriptor launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn inspect_elf(file: &File) -> Result<ElfExecutionIdentity, PrivilegedLaunchSpecError> {
    let mut ident = [0_u8; 16];
    let read = file.read_at(&mut ident, 0)?;
    if read != ident.len() || ident[0..4] != [0x7f, b'E', b'L', b'F'] || ident[6] != 1 {
        return Err(PrivilegedLaunchSpecError::UnsupportedExecutableFormat);
    }

    let class = match ident[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err(PrivilegedLaunchSpecError::UnsupportedExecutableFormat),
    };
    let data_encoding = match ident[5] {
        1 => ElfDataEncoding::LittleEndian,
        2 => ElfDataEncoding::BigEndian,
        _ => return Err(PrivilegedLaunchSpecError::UnsupportedExecutableFormat),
    };

    Ok(ElfExecutionIdentity {
        class,
        data_encoding,
        version: ident[6],
    })
}

fn validate_text(value: &str) -> Result<(), PrivilegedLaunchSpecError> {
    if value.as_bytes().contains(&0) {
        return Err(PrivilegedLaunchSpecError::EmbeddedNul);
    }
    Ok(())
}

fn stage(
    program: PrivilegedProgram,
    args: &[String],
    receipt: &PinnedToolReceipt,
    file: &File,
) -> Result<DescriptorLaunchStage, PrivilegedLaunchSpecError> {
    if receipt.program != program || file.metadata().is_err() {
        return Err(PrivilegedLaunchSpecError::PinnedDescriptorClosed);
    }

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.as_str().to_owned());
    for arg in args {
        validate_text(arg)?;
        argv.push(arg.clone());
    }

    Ok(DescriptorLaunchStage {
        program,
        argv,
        executable: receipt.clone(),
        elf: inspect_elf(file)?,
    })
}

/// Freeze the exact future descriptor-based process launch without creating a
/// process. The launch contract accepts native ELF tools only, which permits
/// a later fexecve/execveat-style implementation to keep the pinned
/// close-on-exec file descriptor model without script-interpreter leakage.
///
/// Environment inheritance is forbidden: only the fixed PATH and C locale are
/// represented. The command stdin payload is bound by length and SHA-256.
pub fn build_privileged_descriptor_launch_spec(
    pinned: &PinnedPrivilegedTools,
    command: &PrivilegedCommandSpec,
) -> Result<PrivilegedDescriptorLaunchSpec, PrivilegedLaunchSpecError> {
    if !pinned.integrity_matches()? {
        return Err(PrivilegedLaunchSpecError::PinIntegrityMismatch);
    }

    let command_digest = command
        .digest()
        .map_err(|_| PrivilegedLaunchSpecError::PinCommandMismatch)?;
    if pinned.plan_step_id != command.plan_step_id || pinned.command_digest != command_digest {
        return Err(PrivilegedLaunchSpecError::PinCommandMismatch);
    }
    if !pinned.primary_is_open() || !pinned.kernel_refresh_is_open() {
        return Err(PrivilegedLaunchSpecError::PinnedDescriptorClosed);
    }

    let primary = stage(
        command.program,
        &command.args,
        &pinned.primary,
        pinned.primary_file(),
    )?;

    let kernel_refresh = match (
        &command.kernel_refresh,
        &pinned.kernel_refresh,
        pinned.kernel_refresh_file(),
    ) {
        (Some(refresh), Some(receipt), Some(file)) => {
            Some(stage(refresh.program, &refresh.args, receipt, file)?)
        }
        (None, None, None) => None,
        _ => return Err(PrivilegedLaunchSpecError::KernelRefreshPresenceMismatch),
    };

    let (stdin_len, stdin_sha256) = match command.stdin_payload.as_deref() {
        Some(payload) => {
            validate_text(payload)?;
            (
                payload.len() as u64,
                Some(format!("{:x}", Sha256::digest(payload.as_bytes()))),
            )
        }
        None => (0, None),
    };

    let mut launch = PrivilegedDescriptorLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        pin_id: pinned.pin_id.clone(),
        authorization_id: pinned.authorization_id.clone(),
        plan_step_id: command.plan_step_id,
        command_digest,
        primary,
        kernel_refresh,
        stdin_len,
        stdin_sha256,
        fixed_path: FIXED_PATH.to_owned(),
        fixed_locale: FIXED_LOCALE.to_owned(),
        descriptor_exec_api: "fexecve".to_owned(),
        process_spawned: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn current_test_binary_is_recognized_as_native_elf() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let elf = inspect_elf(&file).unwrap();
        assert_eq!(elf.version, 1);
        assert!(matches!(elf.class, ElfClass::Elf32 | ElfClass::Elf64));
    }

    #[test]
    fn script_is_rejected_from_descriptor_launch_contract() {
        let path = std::env::temp_dir().join(format!("lsm-launch-script-{}", std::process::id()));
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        let file = File::open(&path).unwrap();

        assert!(matches!(
            inspect_elf(&file),
            Err(PrivilegedLaunchSpecError::UnsupportedExecutableFormat)
        ));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn embedded_nul_is_rejected_before_future_exec() {
        assert!(matches!(
            validate_text("safe\0unsafe"),
            Err(PrivilegedLaunchSpecError::EmbeddedNul)
        ));
    }
}
