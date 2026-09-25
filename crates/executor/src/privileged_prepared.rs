use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use lsm_planner::TargetIdentityManifest;

use crate::{
    validate_privileged_helper_live_identity, validate_privileged_helper_request,
    PrivilegedCommandSpec, PrivilegedHelperProtocolError, PrivilegedHelperRequest,
    PrivilegedToolResolution, TrustedToolError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedPrivilegedInvocation {
    pub schema_version: u32,
    pub prepared_id: String,
    pub request_id: String,
    pub execution_id: String,
    pub plan_step_id: u32,
    pub live_identity_digest: String,
    pub command_digest: String,
    pub tool_resolution_digest: String,
}

impl PreparedPrivilegedInvocation {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.prepared_id == self.expected_prepared_id()?)
    }

    fn expected_prepared_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.request_id,
            &self.execution_id,
            self.plan_step_id,
            &self.live_identity_digest,
            &self.command_digest,
            &self.tool_resolution_digest,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PreparedInvocationError {
    #[error("privileged-helper protocol validation failed: {0}")]
    Protocol(#[from] PrivilegedHelperProtocolError),
    #[error("compiled command does not match the authorized request step")]
    CommandStepMismatch,
    #[error("tool resolution is not bound to the exact compiled command")]
    ToolCommandDigestMismatch,
    #[error("primary trusted executable does not match the compiled program")]
    PrimaryProgramMismatch,
    #[error("kernel-refresh trusted executable does not match the compiled refresh program")]
    KernelRefreshProgramMismatch,
    #[error("unexpected kernel-refresh tool resolution")]
    KernelRefreshPresenceMismatch,
    #[error("prepared invocation serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("trusted tool provenance validation failed: {0}")]
    Tools(#[from] TrustedToolError),
}

pub fn prepare_privileged_invocation(
    request: &PrivilegedHelperRequest,
    live_identity: &TargetIdentityManifest,
    command: &PrivilegedCommandSpec,
    tools: &PrivilegedToolResolution,
) -> Result<PreparedPrivilegedInvocation, PreparedInvocationError> {
    validate_privileged_helper_request(request)?;
    validate_privileged_helper_live_identity(request, live_identity)?;

    if command.plan_step_id != request.plan_step_id {
        return Err(PreparedInvocationError::CommandStepMismatch);
    }

    let command_digest = command.digest().map_err(|error| {
        PreparedInvocationError::Tools(TrustedToolError::CommandDigest(error.to_string()))
    })?;
    if tools.command_digest != command_digest {
        return Err(PreparedInvocationError::ToolCommandDigestMismatch);
    }
    if tools.primary.program != command.program {
        return Err(PreparedInvocationError::PrimaryProgramMismatch);
    }

    match (&command.kernel_refresh, &tools.kernel_refresh) {
        (Some(refresh), Some(identity)) if refresh.program == identity.program => {}
        (Some(_), Some(_)) => {
            return Err(PreparedInvocationError::KernelRefreshProgramMismatch);
        }
        (None, None) => {}
        _ => return Err(PreparedInvocationError::KernelRefreshPresenceMismatch),
    }

    let tool_resolution_digest = tools.digest()?;
    let mut prepared = PreparedPrivilegedInvocation {
        schema_version: 1,
        prepared_id: String::new(),
        request_id: request.request_id.clone(),
        execution_id: request.execution_id.clone(),
        plan_step_id: request.plan_step_id,
        live_identity_digest: live_identity.manifest_digest.clone(),
        command_digest,
        tool_resolution_digest,
    };
    prepared.prepared_id = prepared.expected_prepared_id()?;
    Ok(prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrivilegedKernelRefreshSpec, PrivilegedProgram, TrustedToolIdentity};

    fn tool(program: PrivilegedProgram, seed: u64) -> TrustedToolIdentity {
        TrustedToolIdentity {
            program,
            requested_path: format!("/usr/sbin/{}", program.as_str()),
            canonical_path: format!("/usr/sbin/{}", program.as_str()),
            device_id: 1,
            inode: seed,
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: format!("{seed:064x}"),
        }
    }

    #[test]
    fn rejects_tool_resolution_for_a_different_command() {
        let command = PrivilegedCommandSpec {
            plan_step_id: 3,
            program: PrivilegedProgram::Lvextend,
            args: vec![
                "--extents".into(),
                "+8".into(),
                "--".into(),
                "/dev/vg/data".into(),
            ],
            stdin_payload: None,
            kernel_refresh: None,
        };
        let tools = PrivilegedToolResolution {
            command_digest: "0".repeat(64),
            primary: tool(PrivilegedProgram::Lvextend, 1),
            kernel_refresh: None,
        };

        let digest = command.digest().unwrap();
        assert_ne!(tools.command_digest, digest);
    }

    #[test]
    fn prepared_invocation_digest_is_stable_and_tamper_evident() {
        let mut prepared = PreparedPrivilegedInvocation {
            schema_version: 1,
            prepared_id: String::new(),
            request_id: "a".repeat(64),
            execution_id: "b".repeat(64),
            plan_step_id: 3,
            live_identity_digest: "c".repeat(64),
            command_digest: "d".repeat(64),
            tool_resolution_digest: "e".repeat(64),
        };
        prepared.prepared_id = prepared.expected_prepared_id().unwrap();
        assert!(prepared.integrity_matches().unwrap());

        prepared.command_digest = "f".repeat(64);
        assert!(!prepared.integrity_matches().unwrap());
    }

    #[test]
    fn refresh_presence_must_be_exact() {
        let command = PrivilegedCommandSpec {
            plan_step_id: 1,
            program: PrivilegedProgram::Sfdisk,
            args: vec!["-N".into(), "1".into(), "/dev/sda".into()],
            stdin_payload: Some("start=2048, size=4096\n".into()),
            kernel_refresh: Some(PrivilegedKernelRefreshSpec {
                program: PrivilegedProgram::Partx,
                args: vec![
                    "--update".into(),
                    "--nr".into(),
                    "1".into(),
                    "/dev/sda".into(),
                ],
            }),
        };
        let tools = PrivilegedToolResolution {
            command_digest: command.digest().unwrap(),
            primary: tool(PrivilegedProgram::Sfdisk, 1),
            kernel_refresh: None,
        };
        assert!(matches!(
            (&command.kernel_refresh, &tools.kernel_refresh),
            (Some(_), None)
        ));
    }
}
