use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DescriptorExecOutcome, PrivilegedDescriptorLaunchSpec, PrivilegedDescriptorSequenceOutcome,
    PrivilegedLaunchPermit,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedRuntimeDisposition {
    RediscoveryRequired,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedProcessReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub execution_id: String,
    pub permit_id: String,
    pub launch_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub primary_exit_code: i32,
    pub primary_stdout_sha256: String,
    pub primary_stderr_sha256: String,
    pub primary_stdout_truncated: bool,
    pub primary_stderr_truncated: bool,
    pub kernel_refresh_exit_code: Option<i32>,
    pub kernel_refresh_stdout_sha256: Option<String>,
    pub kernel_refresh_stderr_sha256: Option<String>,
    pub kernel_refresh_stdout_truncated: Option<bool>,
    pub kernel_refresh_stderr_truncated: Option<bool>,
    pub mutation_may_have_started: bool,
    pub disposition: PrivilegedRuntimeDisposition,
}

#[derive(Serialize)]
struct ProcessReceiptDigestPayload<'a> {
    schema_version: u32,
    execution_id: &'a str,
    permit_id: &'a str,
    launch_id: &'a str,
    plan_step_id: u32,
    command_digest: &'a str,
    primary_exit_code: i32,
    primary_stdout_sha256: &'a str,
    primary_stderr_sha256: &'a str,
    primary_stdout_truncated: bool,
    primary_stderr_truncated: bool,
    kernel_refresh_exit_code: Option<i32>,
    kernel_refresh_stdout_sha256: &'a Option<String>,
    kernel_refresh_stderr_sha256: &'a Option<String>,
    kernel_refresh_stdout_truncated: Option<bool>,
    kernel_refresh_stderr_truncated: Option<bool>,
    mutation_may_have_started: bool,
    disposition: PrivilegedRuntimeDisposition,
}

impl PrivilegedProcessReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    pub(crate) fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = ProcessReceiptDigestPayload {
            schema_version: self.schema_version,
            execution_id: &self.execution_id,
            permit_id: &self.permit_id,
            launch_id: &self.launch_id,
            plan_step_id: self.plan_step_id,
            command_digest: &self.command_digest,
            primary_exit_code: self.primary_exit_code,
            primary_stdout_sha256: &self.primary_stdout_sha256,
            primary_stderr_sha256: &self.primary_stderr_sha256,
            primary_stdout_truncated: self.primary_stdout_truncated,
            primary_stderr_truncated: self.primary_stderr_truncated,
            kernel_refresh_exit_code: self.kernel_refresh_exit_code,
            kernel_refresh_stdout_sha256: &self.kernel_refresh_stdout_sha256,
            kernel_refresh_stderr_sha256: &self.kernel_refresh_stderr_sha256,
            kernel_refresh_stdout_truncated: self.kernel_refresh_stdout_truncated,
            kernel_refresh_stderr_truncated: self.kernel_refresh_stderr_truncated,
            mutation_may_have_started: self.mutation_may_have_started,
            disposition: self.disposition,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedProcessReceiptError {
    #[error("launch permit integrity check failed")]
    PermitIntegrityMismatch,
    #[error("descriptor launch specification integrity check failed")]
    LaunchIntegrityMismatch,
    #[error("launch permit does not match the descriptor launch")]
    BindingMismatch,
    #[error("kernel-refresh outcome presence does not match the launch contract")]
    KernelRefreshOutcomeMismatch,
    #[error("process-receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct RefreshReceiptFields {
    exit_code: Option<i32>,
    stdout_sha256: Option<String>,
    stderr_sha256: Option<String>,
    stdout_truncated: Option<bool>,
    stderr_truncated: Option<bool>,
}

fn refresh_fields(outcome: Option<&DescriptorExecOutcome>) -> RefreshReceiptFields {
    match outcome {
        Some(outcome) => RefreshReceiptFields {
            exit_code: Some(outcome.exit_code),
            stdout_sha256: Some(digest(&outcome.stdout)),
            stderr_sha256: Some(digest(&outcome.stderr)),
            stdout_truncated: Some(outcome.stdout_truncated),
            stderr_truncated: Some(outcome.stderr_truncated),
        },
        None => RefreshReceiptFields {
            exit_code: None,
            stdout_sha256: None,
            stderr_sha256: None,
            stdout_truncated: None,
            stderr_truncated: None,
        },
    }
}

/// Convert one spawned descriptor sequence into a tamper-evident runtime
/// receipt. A zero child exit is never treated as storage completion: it only
/// advances the conceptual state to RediscoveryRequired. Any failed primary,
/// failed refresh, or missing expected refresh is RecoveryRequired because the
/// durable journal already conservatively records that mutation may have
/// started.
///
/// This function does not change the durable journal.
pub fn classify_privileged_process_outcome(
    permit: &PrivilegedLaunchPermit,
    launch: &PrivilegedDescriptorLaunchSpec,
    outcome: &PrivilegedDescriptorSequenceOutcome,
) -> Result<PrivilegedProcessReceipt, PrivilegedProcessReceiptError> {
    if !permit.integrity_matches()? {
        return Err(PrivilegedProcessReceiptError::PermitIntegrityMismatch);
    }
    if !launch.integrity_matches()? {
        return Err(PrivilegedProcessReceiptError::LaunchIntegrityMismatch);
    }
    if permit.launch_id != launch.launch_id
        || permit.authorization_id != launch.authorization_id
        || permit.plan_step_id != launch.plan_step_id
        || permit.command_digest != launch.command_digest
    {
        return Err(PrivilegedProcessReceiptError::BindingMismatch);
    }

    let refresh_expected = launch.kernel_refresh.is_some();
    let refresh_present = outcome.kernel_refresh.is_some();
    if !refresh_expected && refresh_present {
        return Err(PrivilegedProcessReceiptError::KernelRefreshOutcomeMismatch);
    }

    let disposition = if outcome.primary.exit_code != 0 {
        PrivilegedRuntimeDisposition::RecoveryRequired
    } else if refresh_expected {
        match outcome.kernel_refresh.as_ref() {
            Some(refresh) if refresh.exit_code == 0 => {
                PrivilegedRuntimeDisposition::RediscoveryRequired
            }
            _ => PrivilegedRuntimeDisposition::RecoveryRequired,
        }
    } else {
        PrivilegedRuntimeDisposition::RediscoveryRequired
    };

    let refresh = refresh_fields(outcome.kernel_refresh.as_ref());

    let mut receipt = PrivilegedProcessReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        execution_id: permit.execution_id.clone(),
        permit_id: permit.permit_id.clone(),
        launch_id: launch.launch_id.clone(),
        plan_step_id: launch.plan_step_id,
        command_digest: launch.command_digest.clone(),
        primary_exit_code: outcome.primary.exit_code,
        primary_stdout_sha256: digest(&outcome.primary.stdout),
        primary_stderr_sha256: digest(&outcome.primary.stderr),
        primary_stdout_truncated: outcome.primary.stdout_truncated,
        primary_stderr_truncated: outcome.primary.stderr_truncated,
        kernel_refresh_exit_code: refresh.exit_code,
        kernel_refresh_stdout_sha256: refresh.stdout_sha256,
        kernel_refresh_stderr_sha256: refresh.stderr_sha256,
        kernel_refresh_stdout_truncated: refresh.stdout_truncated,
        kernel_refresh_stderr_truncated: refresh.stderr_truncated,
        mutation_may_have_started: true,
        disposition,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DescriptorLaunchStage, ElfClass, ElfDataEncoding, ElfExecutionIdentity, PinnedToolReceipt,
        PrivilegedProgram,
    };

    fn digest_text(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn outcome(exit_code: i32) -> DescriptorExecOutcome {
        DescriptorExecOutcome {
            exit_code,
            stdout: b"stdout".to_vec(),
            stderr: b"stderr".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn launch(refresh: bool) -> PrivilegedDescriptorLaunchSpec {
        let executable = PinnedToolReceipt {
            program: PrivilegedProgram::Lvextend,
            canonical_path: "/usr/sbin/lvextend".into(),
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: digest_text('a'),
        };
        let stage = DescriptorLaunchStage {
            program: PrivilegedProgram::Lvextend,
            argv: vec!["lvextend".into(), "--version".into()],
            executable: executable.clone(),
            elf: ElfExecutionIdentity {
                class: ElfClass::Elf64,
                data_encoding: ElfDataEncoding::LittleEndian,
                version: 1,
            },
        };
        let refresh_stage = refresh.then_some(DescriptorLaunchStage {
            program: PrivilegedProgram::Partx,
            argv: vec!["partx".into(), "--update".into()],
            executable: PinnedToolReceipt {
                program: PrivilegedProgram::Partx,
                ..executable
            },
            elf: ElfExecutionIdentity {
                class: ElfClass::Elf64,
                data_encoding: ElfDataEncoding::LittleEndian,
                version: 1,
            },
        });
        let mut value = PrivilegedDescriptorLaunchSpec {
            schema_version: 1,
            launch_id: String::new(),
            pin_id: digest_text('b'),
            authorization_id: digest_text('c'),
            plan_step_id: 7,
            command_digest: digest_text('d'),
            primary: stage,
            kernel_refresh: refresh_stage,
            stdin_len: 0,
            stdin_sha256: None,
            fixed_path: "/usr/sbin:/usr/bin:/sbin:/bin".into(),
            fixed_locale: "C".into(),
            descriptor_exec_api: "fexecve".into(),
            process_spawned: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.pin_id,
            &value.authorization_id,
            value.plan_step_id,
            &value.command_digest,
            &value.primary,
            &value.kernel_refresh,
            value.stdin_len,
            &value.stdin_sha256,
            &value.fixed_path,
            &value.fixed_locale,
            &value.descriptor_exec_api,
            value.process_spawned,
        ))
        .unwrap();
        value.launch_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn permit(launch: &PrivilegedDescriptorLaunchSpec) -> PrivilegedLaunchPermit {
        let mut value = PrivilegedLaunchPermit {
            schema_version: 1,
            permit_id: String::new(),
            execution_id: digest_text('e'),
            execution_start_receipt_id: digest_text('f'),
            authorization_id: launch.authorization_id.clone(),
            launch_id: launch.launch_id.clone(),
            plan_step_id: launch.plan_step_id,
            command_digest: launch.command_digest.clone(),
            mutation_enabled: false,
            process_spawned: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.execution_id,
            &value.execution_start_receipt_id,
            &value.authorization_id,
            &value.launch_id,
            value.plan_step_id,
            &value.command_digest,
            value.mutation_enabled,
            value.process_spawned,
        ))
        .unwrap();
        value.permit_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    #[test]
    fn successful_primary_requires_rediscovery_not_completion() {
        let launch = launch(false);
        let permit = permit(&launch);
        let sequence = PrivilegedDescriptorSequenceOutcome {
            primary: outcome(0),
            kernel_refresh: None,
        };
        let receipt = classify_privileged_process_outcome(&permit, &launch, &sequence).unwrap();
        assert_eq!(
            receipt.disposition,
            PrivilegedRuntimeDisposition::RediscoveryRequired
        );
        assert!(receipt.mutation_may_have_started);
        assert!(receipt.integrity_matches().unwrap());
    }

    #[test]
    fn failed_primary_requires_recovery() {
        let launch = launch(false);
        let permit = permit(&launch);
        let sequence = PrivilegedDescriptorSequenceOutcome {
            primary: outcome(5),
            kernel_refresh: None,
        };
        let receipt = classify_privileged_process_outcome(&permit, &launch, &sequence).unwrap();
        assert_eq!(
            receipt.disposition,
            PrivilegedRuntimeDisposition::RecoveryRequired
        );
    }

    #[test]
    fn missing_expected_refresh_requires_recovery() {
        let launch = launch(true);
        let permit = permit(&launch);
        let sequence = PrivilegedDescriptorSequenceOutcome {
            primary: outcome(0),
            kernel_refresh: None,
        };
        let receipt = classify_privileged_process_outcome(&permit, &launch, &sequence).unwrap();
        assert_eq!(
            receipt.disposition,
            PrivilegedRuntimeDisposition::RecoveryRequired
        );
    }

    #[test]
    fn successful_expected_refresh_requires_rediscovery() {
        let launch = launch(true);
        let permit = permit(&launch);
        let sequence = PrivilegedDescriptorSequenceOutcome {
            primary: outcome(0),
            kernel_refresh: Some(outcome(0)),
        };
        let receipt = classify_privileged_process_outcome(&permit, &launch, &sequence).unwrap();
        assert_eq!(
            receipt.disposition,
            PrivilegedRuntimeDisposition::RediscoveryRequired
        );
    }
}
