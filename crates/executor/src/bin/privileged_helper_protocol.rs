use std::io::{self, Read};
use std::process::ExitCode;

use lsm_executor::{
    decode_privileged_helper_request, MAX_PRIVILEGED_HELPER_REQUEST_BYTES, MUTATION_ENABLED,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ValidationResponse<'a> {
    status: &'static str,
    request_id: &'a str,
    execution_id: &'a str,
    plan_step_id: u32,
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
    let response = ValidationResponse {
        status: "validated",
        request_id: &request.request_id,
        execution_id: &request.execution_id,
        plan_step_id: request.plan_step_id,
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
