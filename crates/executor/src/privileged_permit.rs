use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PrivilegedContinuationStartReceipt, PrivilegedDescriptorLaunchSpec,
    PrivilegedExecutionStartReceipt, PrivilegedSpawnAuthorization, MUTATION_ENABLED,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedLaunchPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub execution_id: String,
    pub execution_start_receipt_id: String,
    pub authorization_id: String,
    pub launch_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
}

impl PrivilegedLaunchPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.execution_start_receipt_id,
            &self.authorization_id,
            &self.launch_id,
            self.plan_step_id,
            &self.command_digest,
            self.mutation_enabled,
            self.process_spawned,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedLaunchPermitError {
    #[error("production mutation unexpectedly enabled while sealing launch permit")]
    MutationEnabled,
    #[error("execution-start receipt integrity check failed")]
    ExecutionStartIntegrityMismatch,
    #[error("continuation-start receipt integrity check failed")]
    ContinuationStartIntegrityMismatch,
    #[error("spawn authorization integrity check failed")]
    AuthorizationIntegrityMismatch,
    #[error("descriptor launch specification integrity check failed")]
    LaunchIntegrityMismatch,
    #[error("descriptor launch specification already reports a spawned process")]
    AlreadySpawned,
    #[error("launch chain identifiers do not match")]
    BindingMismatch,
    #[error("launch-permit serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Seal the exact pre-spawn authorization chain into one tamper-evident permit.
///
/// This is still a non-executing gate. It binds the durable execution-start
/// receipt, post-journal spawn authorization and descriptor launch contract
/// into one exact first-step permit. No process is created here.
pub fn seal_privileged_launch_permit(
    start: &PrivilegedExecutionStartReceipt,
    authorization: &PrivilegedSpawnAuthorization,
    launch: &PrivilegedDescriptorLaunchSpec,
) -> Result<PrivilegedLaunchPermit, PrivilegedLaunchPermitError> {
    if MUTATION_ENABLED {
        return Err(PrivilegedLaunchPermitError::MutationEnabled);
    }
    if !start.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::ExecutionStartIntegrityMismatch);
    }
    if !authorization.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::AuthorizationIntegrityMismatch);
    }
    if !launch.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::LaunchIntegrityMismatch);
    }
    if launch.process_spawned {
        return Err(PrivilegedLaunchPermitError::AlreadySpawned);
    }

    if start.execution_id != authorization.execution_id
        || start.receipt_id != authorization.execution_start_receipt_id
        || start.first_plan_step_id != authorization.plan_step_id
        || authorization.authorization_id != launch.authorization_id
        || authorization.plan_step_id != launch.plan_step_id
        || authorization.command_digest != launch.command_digest
    {
        return Err(PrivilegedLaunchPermitError::BindingMismatch);
    }

    let mut permit = PrivilegedLaunchPermit {
        schema_version: 1,
        permit_id: String::new(),
        execution_id: start.execution_id.clone(),
        execution_start_receipt_id: start.receipt_id.clone(),
        authorization_id: authorization.authorization_id.clone(),
        launch_id: launch.launch_id.clone(),
        plan_step_id: launch.plan_step_id,
        command_digest: launch.command_digest.clone(),
        mutation_enabled: false,
        process_spawned: false,
    };
    permit.permit_id = permit.expected_permit_id()?;
    Ok(permit)
}

/// Seal the same descriptor launch chain for a later step that was bound to a
/// durable verified continuation boundary.
pub fn seal_privileged_continuation_launch_permit(
    start: &PrivilegedContinuationStartReceipt,
    authorization: &PrivilegedSpawnAuthorization,
    launch: &PrivilegedDescriptorLaunchSpec,
) -> Result<PrivilegedLaunchPermit, PrivilegedLaunchPermitError> {
    if MUTATION_ENABLED {
        return Err(PrivilegedLaunchPermitError::MutationEnabled);
    }
    if !start.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::ContinuationStartIntegrityMismatch);
    }
    if !authorization.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::AuthorizationIntegrityMismatch);
    }
    if !launch.integrity_matches()? {
        return Err(PrivilegedLaunchPermitError::LaunchIntegrityMismatch);
    }
    if launch.process_spawned {
        return Err(PrivilegedLaunchPermitError::AlreadySpawned);
    }

    if start.execution_id != authorization.execution_id
        || start.receipt_id != authorization.execution_start_receipt_id
        || start.plan_step_id != authorization.plan_step_id
        || authorization.authorization_id != launch.authorization_id
        || authorization.plan_step_id != launch.plan_step_id
        || authorization.command_digest != launch.command_digest
    {
        return Err(PrivilegedLaunchPermitError::BindingMismatch);
    }

    let mut permit = PrivilegedLaunchPermit {
        schema_version: 1,
        permit_id: String::new(),
        execution_id: start.execution_id.clone(),
        execution_start_receipt_id: start.receipt_id.clone(),
        authorization_id: authorization.authorization_id.clone(),
        launch_id: launch.launch_id.clone(),
        plan_step_id: launch.plan_step_id,
        command_digest: launch.command_digest.clone(),
        mutation_enabled: false,
        process_spawned: false,
    };
    permit.permit_id = permit.expected_permit_id()?;
    Ok(permit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DescriptorLaunchStage, ElfClass, ElfDataEncoding, ElfExecutionIdentity, PinnedToolReceipt,
        PrivilegedProgram,
    };

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn start() -> PrivilegedExecutionStartReceipt {
        let mut value = PrivilegedExecutionStartReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: digest('1'),
            prepared_id: digest('2'),
            journal_id: digest('3'),
            first_plan_step_id: 7,
            executing_journal_digest: digest('4'),
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.execution_id,
            &value.prepared_id,
            &value.journal_id,
            value.first_plan_step_id,
            &value.executing_journal_digest,
        ))
        .unwrap();
        value.receipt_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn authorization(start: &PrivilegedExecutionStartReceipt) -> PrivilegedSpawnAuthorization {
        let mut value = PrivilegedSpawnAuthorization {
            schema_version: 1,
            authorization_id: String::new(),
            execution_id: start.execution_id.clone(),
            prepared_id: start.prepared_id.clone(),
            execution_start_receipt_id: start.receipt_id.clone(),
            plan_step_id: start.first_plan_step_id,
            command_digest: digest('5'),
            tool_resolution_digest: digest('6'),
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.execution_id,
            &value.prepared_id,
            &value.execution_start_receipt_id,
            value.plan_step_id,
            &value.command_digest,
            &value.tool_resolution_digest,
        ))
        .unwrap();
        value.authorization_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn launch(authorization: &PrivilegedSpawnAuthorization) -> PrivilegedDescriptorLaunchSpec {
        let receipt = PinnedToolReceipt {
            program: PrivilegedProgram::Lvextend,
            canonical_path: "/usr/sbin/lvextend".into(),
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: digest('7'),
        };
        let stage = DescriptorLaunchStage {
            program: PrivilegedProgram::Lvextend,
            argv: vec![
                "lvextend".into(),
                "--extents".into(),
                "+8".into(),
                "--".into(),
                "/dev/vg/data".into(),
            ],
            executable: receipt,
            elf: ElfExecutionIdentity {
                class: ElfClass::Elf64,
                data_encoding: ElfDataEncoding::LittleEndian,
                version: 1,
            },
        };
        let mut value = PrivilegedDescriptorLaunchSpec {
            schema_version: 1,
            launch_id: String::new(),
            pin_id: digest('8'),
            authorization_id: authorization.authorization_id.clone(),
            plan_step_id: authorization.plan_step_id,
            command_digest: authorization.command_digest.clone(),
            primary: stage,
            kernel_refresh: None,
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

    #[test]
    fn seals_exact_launch_chain_without_spawning() {
        let start = start();
        let authorization = authorization(&start);
        let launch = launch(&authorization);

        let permit = seal_privileged_launch_permit(&start, &authorization, &launch).unwrap();
        assert!(permit.integrity_matches().unwrap());
        assert!(!permit.mutation_enabled);
        assert!(!permit.process_spawned);
        assert_eq!(permit.plan_step_id, 7);
    }


    fn continuation_start(
        authorization: &PrivilegedSpawnAuthorization,
    ) -> PrivilegedContinuationStartReceipt {
        let mut value = PrivilegedContinuationStartReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: authorization.execution_id.clone(),
            verified_boundary_id: digest('a'),
            prepared_id: authorization.prepared_id.clone(),
            journal_id: digest('b'),
            plan_step_id: authorization.plan_step_id,
            live_identity_digest: digest('c'),
            executing_journal_digest: digest('d'),
        };
        value.receipt_id = value.expected_receipt_id().unwrap();
        value
    }

    #[test]
    fn seals_exact_continuation_launch_chain_without_spawning() {
        let initial = start();
        let mut authorization = authorization(&initial);
        let continuation = continuation_start(&authorization);
        authorization.execution_start_receipt_id = continuation.receipt_id.clone();
        authorization.authorization_id = authorization.expected_authorization_id().unwrap();
        let launch = launch(&authorization);

        let permit =
            seal_privileged_continuation_launch_permit(&continuation, &authorization, &launch)
                .unwrap();
        assert!(permit.integrity_matches().unwrap());
        assert_eq!(permit.execution_start_receipt_id, continuation.receipt_id);
        assert_eq!(permit.plan_step_id, continuation.plan_step_id);
    }

    #[test]
    fn rejects_launch_bound_to_another_authorization() {
        let start = start();
        let authorization = authorization(&start);
        let mut launch = launch(&authorization);
        launch.authorization_id = digest('f');

        assert!(matches!(
            seal_privileged_launch_permit(&start, &authorization, &launch),
            Err(PrivilegedLaunchPermitError::LaunchIntegrityMismatch)
        ));
    }
}
