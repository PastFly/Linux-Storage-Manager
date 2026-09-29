use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use lsm_executor::{
    capture_disposable_loop_ownership, execute_disposable_swap_replacement,
    verify_disposable_loop_association_row, DisposableSwapActivationOptions,
    DisposableSwapExecutionStage, DisposableSwapToolPaths,
};

#[derive(Debug)]
struct Args {
    target: PathBuf,
    loop_device: String,
    backing_file: PathBuf,
    owned_root: PathBuf,
    association_row: String,
    old_swap_device: String,
    mkswap: PathBuf,
    swapon: PathBuf,
    swapoff: PathBuf,
    inject_failure_before_old_swapoff: bool,
}

fn required_value(
    iter: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut target = None;
    let mut loop_device = None;
    let mut backing_file = None;
    let mut owned_root = None;
    let mut association_row = None;
    let mut old_swap_device = None;
    let mut mkswap = None;
    let mut swapon = None;
    let mut swapoff = None;
    let mut allow = false;
    let mut inject_failure_before_old_swapoff = false;

    let mut iter = env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--allow-disposable-swap-execution" => allow = true,
            "--inject-failure-before-old-swapoff" => {
                inject_failure_before_old_swapoff = true;
            }
            "--target" => target = Some(PathBuf::from(required_value(&mut iter, &flag)?)),
            "--loop-device" => loop_device = Some(required_value(&mut iter, &flag)?),
            "--backing-file" => {
                backing_file = Some(PathBuf::from(required_value(&mut iter, &flag)?))
            }
            "--owned-root" => owned_root = Some(PathBuf::from(required_value(&mut iter, &flag)?)),
            "--association-row" => association_row = Some(required_value(&mut iter, &flag)?),
            "--old-swap-device" => old_swap_device = Some(required_value(&mut iter, &flag)?),
            "--mkswap" => mkswap = Some(PathBuf::from(required_value(&mut iter, &flag)?)),
            "--swapon" => swapon = Some(PathBuf::from(required_value(&mut iter, &flag)?)),
            "--swapoff" => swapoff = Some(PathBuf::from(required_value(&mut iter, &flag)?)),
            _ => return Err(format!("unknown argument: {flag}").into()),
        }
    }

    if !allow {
        return Err("explicit --allow-disposable-swap-execution is required".into());
    }

    Ok(Args {
        target: target.ok_or("--target is required")?,
        loop_device: loop_device.ok_or("--loop-device is required")?,
        backing_file: backing_file.ok_or("--backing-file is required")?,
        owned_root: owned_root.ok_or("--owned-root is required")?,
        association_row: association_row.ok_or("--association-row is required")?,
        old_swap_device: old_swap_device.ok_or("--old-swap-device is required")?,
        mkswap: mkswap.ok_or("--mkswap is required")?,
        swapon: swapon.ok_or("--swapon is required")?,
        swapoff: swapoff.ok_or("--swapoff is required")?,
        inject_failure_before_old_swapoff,
    })
}

fn run() -> Result<(lsm_executor::DisposableSwapExecutionReceipt, ExitCode), Box<dyn Error>> {
    let args = parse_args()?;
    let ownership =
        capture_disposable_loop_ownership(&args.loop_device, &args.backing_file, &args.owned_root)?;
    let association = verify_disposable_loop_association_row(
        &args.loop_device,
        &args.backing_file,
        &args.association_row,
    )?;
    let swapfile_path = args.target.join(".linux-storage-manager.swap");
    let tools = DisposableSwapToolPaths::new(args.mkswap, args.swapon, args.swapoff);
    let receipt = execute_disposable_swap_replacement(
        &ownership,
        &association,
        &args.target,
        &args.old_swap_device,
        &swapfile_path,
        &tools,
        DisposableSwapActivationOptions {
            inject_failure_before_old_swapoff: args.inject_failure_before_old_swapoff,
        },
    )?;
    let code = if receipt.stage == DisposableSwapExecutionStage::ReplacementActiveOldPreserved
        && receipt.injected_failure_before_old_swapoff
    {
        ExitCode::from(20)
    } else {
        ExitCode::SUCCESS
    };
    Ok((receipt, code))
}

fn main() -> ExitCode {
    match run() {
        Ok((receipt, code)) => {
            match serde_json::to_string(&receipt) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("DISPOSABLE_SWAP_E2E_FAILED: could not serialize receipt: {error}");
                    return ExitCode::FAILURE;
                }
            }
            code
        }
        Err(error) => {
            eprintln!("DISPOSABLE_SWAP_E2E_FAILED: {error}");
            ExitCode::FAILURE
        }
    }
}
