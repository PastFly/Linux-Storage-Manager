use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    resolve_privileged_command_tools, PreparedPrivilegedInvocation, PrivilegedCommandSpec,
    PrivilegedExecutionStartReceipt, PrivilegedToolResolution, TrustedToolError,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrivilegedSpawnAuthorization {
    pub schema_version: u32,
    pub authorization_id: String,
    pub execution_id: String,
    pub prepared_id: String,
    pub execution_start_receipt_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub tool_resolution_digest: String,
}

impl PrivilegedSpawnAuthorization {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.authorization_id == self.expected_authorization_id()?)
    }

    fn expected_authorization_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_id,
            &self.prepared_id,
            &self.execution_start_receipt_id,
            self.plan_step_id,
            &self.command_digest,
            &self.tool_resolution_digest,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum PrivilegedSpawnAuthorizationError {
    #[error("execution-start receipt integrity check failed")]
    ExecutionStartIntegrityMismatch,
    #[error("prepared invocation integrity check failed")]
    PreparedIntegrityMismatch,
    #[error("execution-start receipt does not match the prepared invocation")]
    StartPreparedMismatch,
    #[error("compiled command does not match the prepared invocation")]
    CommandMismatch,
    #[error("trusted executable provenance changed after invocation preparation")]
    ToolProvenanceDrift,
    #[error("trusted tool provenance validation failed: {0}")]
    Tools(#[from] TrustedToolError),
    #[error("spawn-authorization serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn authorize_with_resolution(
    start: &PrivilegedExecutionStartReceipt,
    prepared: &PreparedPrivilegedInvocation,
    command: &PrivilegedCommandSpec,
    fresh_tools: &PrivilegedToolResolution,
) -> Result<PrivilegedSpawnAuthorization, PrivilegedSpawnAuthorizationError> {
    if !start.integrity_matches()? {
        return Err(PrivilegedSpawnAuthorizationError::ExecutionStartIntegrityMismatch);
    }
    if !prepared.integrity_matches()? {
        return Err(PrivilegedSpawnAuthorizationError::PreparedIntegrityMismatch);
    }
    if start.execution_id != prepared.execution_id
        || start.prepared_id != prepared.prepared_id
        || start.first_plan_step_id != prepared.plan_step_id
    {
        return Err(PrivilegedSpawnAuthorizationError::StartPreparedMismatch);
    }

    let command_digest = command
        .digest()
        .map_err(|error| TrustedToolError::CommandDigest(error.to_string()))?;
    if command.plan_step_id != prepared.plan_step_id || command_digest != prepared.command_digest {
        return Err(PrivilegedSpawnAuthorizationError::CommandMismatch);
    }

    if fresh_tools.command_digest != command_digest
        || fresh_tools.digest()? != prepared.tool_resolution_digest
    {
        return Err(PrivilegedSpawnAuthorizationError::ToolProvenanceDrift);
    }

    let mut authorization = PrivilegedSpawnAuthorization {
        schema_version: 1,
        authorization_id: String::new(),
        execution_id: prepared.execution_id.clone(),
        prepared_id: prepared.prepared_id.clone(),
        execution_start_receipt_id: start.receipt_id.clone(),
        plan_step_id: prepared.plan_step_id,
        command_digest,
        tool_resolution_digest: prepared.tool_resolution_digest.clone(),
    };
    authorization.authorization_id = authorization.expected_authorization_id()?;
    Ok(authorization)
}

/// Re-resolve and re-hash the trusted storage executables immediately before a
/// future process spawn. A successful authorization proves that the exact
/// command and tool provenance prepared before Executing still match after
/// the durable execution-start transition.
///
/// This gate intentionally does not spawn the command.
pub fn authorize_privileged_spawn(
    start: &PrivilegedExecutionStartReceipt,
    prepared: &PreparedPrivilegedInvocation,
    command: &PrivilegedCommandSpec,
) -> Result<PrivilegedSpawnAuthorization, PrivilegedSpawnAuthorizationError> {
    let fresh_tools = resolve_privileged_command_tools(command)?;
    authorize_with_resolution(start, prepared, command, &fresh_tools)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrivilegedProgram, TrustedToolIdentity};

    fn tool(seed: u64) -> TrustedToolIdentity {
        TrustedToolIdentity {
            program: PrivilegedProgram::Lvextend,
            requested_path: "/usr/sbin/lvextend".into(),
            canonical_path: "/usr/sbin/lvextend".into(),
            device_id: 1,
            inode: seed,
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: format!("{seed:064x}"),
        }
    }

    fn command() -> PrivilegedCommandSpec {
        PrivilegedCommandSpec {
            plan_step_id: 7,
            program: PrivilegedProgram::Lvextend,
            args: vec![
                "--extents".into(),
                "+8".into(),
                "--".into(),
                "/dev/vg/data".into(),
            ],
            stdin_payload: None,
            kernel_refresh: None,
        }
    }

    fn prepared(
        command: &PrivilegedCommandSpec,
        tools: &PrivilegedToolResolution,
    ) -> PreparedPrivilegedInvocation {
        let mut prepared = PreparedPrivilegedInvocation {
            schema_version: 1,
            prepared_id: String::new(),
            request_id: "a".repeat(64),
            execution_id: "b".repeat(64),
            plan_step_id: command.plan_step_id,
            live_identity_digest: "c".repeat(64),
            command_digest: command.digest().unwrap(),
            tool_resolution_digest: tools.digest().unwrap(),
        };
        let bytes = serde_json::to_vec(&(
            prepared.schema_version,
            &prepared.request_id,
            &prepared.execution_id,
            prepared.plan_step_id,
            &prepared.live_identity_digest,
            &prepared.command_digest,
            &prepared.tool_resolution_digest,
        ))
        .unwrap();
        prepared.prepared_id = format!("{:x}", Sha256::digest(bytes));
        prepared
    }

    fn start(prepared: &PreparedPrivilegedInvocation) -> PrivilegedExecutionStartReceipt {
        let mut start = PrivilegedExecutionStartReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            execution_id: prepared.execution_id.clone(),
            prepared_id: prepared.prepared_id.clone(),
            journal_id: "d".repeat(64),
            first_plan_step_id: prepared.plan_step_id,
            executing_journal_digest: "e".repeat(64),
        };
        let bytes = serde_json::to_vec(&(
            start.schema_version,
            &start.execution_id,
            &start.prepared_id,
            &start.journal_id,
            start.first_plan_step_id,
            &start.executing_journal_digest,
        ))
        .unwrap();
        start.receipt_id = format!("{:x}", Sha256::digest(bytes));
        start
    }

    #[test]
    fn exact_prepared_tools_authorize_without_spawning() {
        let command = command();
        let tools = PrivilegedToolResolution {
            command_digest: command.digest().unwrap(),
            primary: tool(1),
            kernel_refresh: None,
        };
        let prepared = prepared(&command, &tools);
        let start = start(&prepared);

        let authorization =
            authorize_with_resolution(&start, &prepared, &command, &tools).unwrap();
        assert!(authorization.integrity_matches().unwrap());
        assert_eq!(authorization.plan_step_id, 7);
        assert_eq!(authorization.command_digest, prepared.command_digest);
    }

    #[test]
    fn executable_provenance_drift_fails_closed() {
        let command = command();
        let original = PrivilegedToolResolution {
            command_digest: command.digest().unwrap(),
            primary: tool(1),
            kernel_refresh: None,
        };
        let prepared = prepared(&command, &original);
        let start = start(&prepared);
        let changed = PrivilegedToolResolution {
            command_digest: command.digest().unwrap(),
            primary: tool(2),
            kernel_refresh: None,
        };

        assert!(matches!(
            authorize_with_resolution(&start, &prepared, &command, &changed),
            Err(PrivilegedSpawnAuthorizationError::ToolProvenanceDrift)
        ));
    }

    #[test]
    fn command_drift_fails_closed() {
        let command = command();
        let tools = PrivilegedToolResolution {
            command_digest: command.digest().unwrap(),
            primary: tool(1),
            kernel_refresh: None,
        };
        let prepared = prepared(&command, &tools);
        let start = start(&prepared);
        let mut changed = command.clone();
        changed.args[1] = "+9".into();

        assert!(matches!(
            authorize_with_resolution(&start, &prepared, &changed, &tools),
            Err(PrivilegedSpawnAuthorizationError::CommandMismatch)
        ));
    }
}
