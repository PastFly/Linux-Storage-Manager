use std::io::{self, Read};
use std::process::ExitCode;

use lsm_discovery::discover_snapshot;
use lsm_executor::{
    decode_privileged_helper_request, validate_privileged_helper_live_identity,
    MAX_PRIVILEGED_HELPER_REQUEST_BYTES, MUTATION_ENABLED,
};
use lsm_planner::capture_target_identity;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ValidationResponse<'a> {
    status: &'static str,
    request_id: &'a str,
    execution_id: &'a str,
    plan_step_id: u32,
    live_identity_digest: &'a str,
    mutation_enabled: bool,
    execution_started: bool,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if MUTATION_ENABLED {
        return Err("production mutation must remain disabled at the protocol boundary".into());
    }

    let stdin = io::stdin();
    let mut limited = stdin
        .lock()
        .take((MAX_PRIVILEGED_HELPER_REQUEST_BYTES + 1) as u64);
    let mut input = Vec::new();
    limited.read_to_end(&mut input)?;

    let request = decode_privileged_helper_request(&input)?;
    let snapshot = discover_snapshot()?;
    let live_identity = capture_target_identity(&snapshot, &request.target)?;
    validate_privileged_helper_live_identity(&request, &live_identity)?;

    let response = ValidationResponse {
        status: "identity_revalidated",
        request_id: &request.request_id,
        execution_id: &request.execution_id,
        plan_step_id: request.plan_step_id,
        live_identity_digest: &live_identity.manifest_digest,
        mutation_enabled: false,
        execution_started: false,
    };

    serde_json::to_writer(io::stdout().lock(), &response)?;
    println!();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("privileged-helper protocol rejected request: {error}");
            ExitCode::from(2)
        }
    }
}
