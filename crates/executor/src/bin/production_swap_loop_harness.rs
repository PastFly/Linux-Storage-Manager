use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use lsm_core::{FstabEntry, HibernationResumeEvidence};
use lsm_discovery::{
    discover_capabilities, discover_filesystem_space, discover_hibernation_resume_evidence,
    discover_path_occupancy, discover_snapshot, discover_swaps,
};
use lsm_executor::{
    build_production_swap_partition_removal_launch_spec,
    build_production_swap_runtime_launch_spec, capture_disposable_loop_ownership,
    execute_production_swap_partition_removal, execute_production_swap_runtime_replacement,
    inspect_production_swap_replacement_activation_readiness,
    pin_production_swap_partition_removal_tools, pin_production_swap_replacement_consent_at,
    pin_production_swap_runtime_tools, prepare_production_swap_partition_removal,
    prepare_production_swap_runtime_preflight_from_evidence,
    seal_production_swap_replacement_activation_intent,
    seal_production_swap_replacement_execution_permit,
    update_production_swap_persistent_config_at_path, verify_disposable_loop_association_row,
    HostStorageLock, ProductionSwapReplacementConsentDocument,
    ProductionSwapRuntimeJournalStore, ProductionSwapRuntimePhase,
    PRODUCTION_SWAP_REPLACEMENT_CONSENT_PHRASE,
};
use lsm_planner::{
    analyze_swap_migration_safety, analyze_swapfile_destination, build_swap_replacement_intent,
};
use serde::Serialize;

#[derive(Debug)]
struct Args {
    target: String,
    loop_device: String,
    backing_file: PathBuf,
    owned_root: PathBuf,
    association_row: String,
    old_swap_device: String,
}

#[derive(Debug, Serialize)]
struct SuccessReceipt {
    schema_version: u32,
    profile: &'static str,
    journal_id: String,
    final_phase: ProductionSwapRuntimePhase,
    old_swap_device: String,
    swapfile_path: String,
    old_swap_active: bool,
    replacement_swap_active_before_cleanup: bool,
    logical_swap_removed: bool,
    extended_container_removed: bool,
    persistent_config_updated: bool,
    partition_table_changed: bool,
    production_chain_completed: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut allow = false;
    let mut target = None;
    let mut loop_device = None;
    let mut backing_file = None;
    let mut owned_root = None;
    let mut association_row = None;
    let mut old_swap_device = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-production-swap-loop-e2e" => allow = true,
            "--target" => target = args.next(),
            "--loop-device" => loop_device = args.next(),
            "--backing-file" => backing_file = args.next().map(PathBuf::from),
            "--owned-root" => owned_root = args.next().map(PathBuf::from),
            "--association-row" => association_row = args.next(),
            "--old-swap-device" => old_swap_device = args.next(),
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    if !allow {
        return Err("explicit --allow-production-swap-loop-e2e is required".into());
    }

    Ok(Args {
        target: target.ok_or("missing --target")?,
        loop_device: loop_device.ok_or("missing --loop-device")?,
        backing_file: backing_file.ok_or("missing --backing-file")?,
        owned_root: owned_root.ok_or("missing --owned-root")?,
        association_row: association_row.ok_or("missing --association-row")?,
        old_swap_device: old_swap_device.ok_or("missing --old-swap-device")?,
    })
}

fn require_direct_child(root: &Path, path: &Path, label: &str) -> Result<(), String> {
    if path.parent() != Some(root) {
        return Err(format!("{label} must be a direct child of the owned root"));
    }
    Ok(())
}

fn write_secure(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != bytes.len() as u64
    {
        return Err("secure fixture file identity mismatch".into());
    }
    Ok(())
}

fn synthetic_fstab(old_swap_device: &str, priority: i32) -> String {
    format!(
        "# Linux Storage Manager owned production-swap E2E fixture\n{old_swap_device}\tnone\tswap\tsw,pri={priority}\t0\t0\n"
    )
}

fn run() -> Result<SuccessReceipt, Box<dyn Error>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("production swap loop harness requires root".into());
    }
    let args = parse_args().map_err(std::io::Error::other)?;
    let owned_root = args.owned_root.canonicalize()?;
    let backing_file = args.backing_file.canonicalize()?;
    if backing_file.parent() != Some(owned_root.as_path()) {
        return Err("backing file is outside owned root".into());
    }
    if args.old_swap_device != format!("{}p5", args.loop_device) {
        return Err("old swap must be the owned loop logical partition p5".into());
    }

    let _ownership =
        capture_disposable_loop_ownership(&args.loop_device, &backing_file, &owned_root)?;
    let _association = verify_disposable_loop_association_row(
        &args.loop_device,
        &backing_file,
        &args.association_row,
    )?;

    let target_path = PathBuf::from(&args.target).canonicalize()?;
    if target_path.parent() != Some(owned_root.as_path()) {
        return Err("target mount is outside the owned root".into());
    }
    let sentinel_path = target_path.join("readonly-sentinel");
    let sentinel_before = fs::read(&sentinel_path)?;

    let journal_root = owned_root.join("production-swap-runtime");
    let fstab_path = owned_root.join("production-swap.fstab");
    let consent_path = owned_root.join("production-swap-consent.json");
    let lock_path = owned_root.join("production-swap.lock");
    for (path, label) in [
        (&journal_root, "journal root"),
        (&fstab_path, "fstab fixture"),
        (&consent_path, "consent fixture"),
        (&lock_path, "lock fixture"),
    ] {
        require_direct_child(&owned_root, path, label).map_err(std::io::Error::other)?;
    }

    let mut snapshot = discover_snapshot()?;
    let old_swap = snapshot
        .swaps
        .iter()
        .find(|entry| entry.name == args.old_swap_device)
        .cloned()
        .ok_or("old swap is not active")?;
    if old_swap.kind != "partition" {
        return Err("old swap fixture is not a partition".into());
    }

    snapshot.fstab = vec![FstabEntry {
        source: args.old_swap_device.clone(),
        target: "none".into(),
        fs_type: "swap".into(),
        options: vec!["sw".into(), format!("pri={}", old_swap.priority)],
        dump: 0,
        pass: 0,
    }];

    let resume = discover_hibernation_resume_evidence()?;
    if resume.configured() {
        return Err("CI host has hibernation/resume configured; refusing production swap E2E".into());
    }

    let safety = analyze_swap_migration_safety(&snapshot, &resume, &args.target);
    if !safety.clear_for_planning() {
        return Err(format!("swap migration safety blocked: {:?}", safety.blockers).into());
    }

    let capabilities = discover_capabilities();
    let space = discover_filesystem_space(&args.target)?;
    let readiness =
        analyze_swapfile_destination(&snapshot, &capabilities, &safety, &space, &args.target);
    if !readiness.ready_for_planning() {
        return Err(format!("swapfile destination blocked: {:?}", readiness.blockers).into());
    }

    let path_state = discover_path_occupancy(&readiness.swapfile_path)?;
    let intent = build_swap_replacement_intent(&snapshot, &safety, &readiness, &path_state)?;
    if !intent.ready() || !intent.integrity_matches()? {
        return Err(format!("swap replacement intent blocked: {:?}", intent.blockers).into());
    }

    let activation_readiness = inspect_production_swap_replacement_activation_readiness(&intent);
    if !activation_readiness.ready() {
        return Err(format!(
            "production swap activation blocked: {:?}",
            activation_readiness.blockers
        )
        .into());
    }
    let activation = seal_production_swap_replacement_activation_intent(&intent)?;

    let fstab = synthetic_fstab(&args.old_swap_device, old_swap.priority);
    write_secure(&fstab_path, fstab.as_bytes())?;

    let consent_document = ProductionSwapReplacementConsentDocument {
        schema_version: 1,
        activation_id: activation.activation_id.clone(),
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        target: activation.target.clone(),
        retiring_swap_device: activation.retiring_swap_device.clone(),
        swapfile_path: activation.swapfile_path.clone(),
        consent_phrase: PRODUCTION_SWAP_REPLACEMENT_CONSENT_PHRASE.into(),
    };
    let consent_bytes = serde_json::to_vec(&consent_document)?;
    write_secure(&consent_path, &consent_bytes)?;

    let consent = pin_production_swap_replacement_consent_at(&activation, &consent_path)?;
    let permit =
        seal_production_swap_replacement_execution_permit(&activation, consent.receipt())?;

    let preflight = prepare_production_swap_runtime_preflight_from_evidence(
        &activation,
        &permit,
        &consent,
        &snapshot,
        &HibernationResumeEvidence::default(),
        &space,
        &path_state,
    )?;
    let runtime_tools = pin_production_swap_runtime_tools(&preflight)?;
    let runtime_launch =
        build_production_swap_runtime_launch_spec(&activation, &permit, &preflight, &runtime_tools)?;

    let store = ProductionSwapRuntimeJournalStore::at(&journal_root);
    let mut journal = lsm_executor::persist_new_production_swap_runtime_journal(
        &store,
        &activation,
        &permit,
        &preflight,
        &runtime_launch,
    )?;
    let host_lock = HostStorageLock::try_acquire_at(&lock_path)?;

    let runtime = execute_production_swap_runtime_replacement(
        &host_lock,
        &activation,
        &permit,
        &preflight,
        &runtime_launch,
        &consent,
        &runtime_tools,
        &store,
        &mut journal,
    )?;
    if runtime.old_swap_active
        || !runtime.replacement_swap_active
        || runtime.priority != old_swap.priority
    {
        return Err("runtime replacement did not reach exact old-swap-off state".into());
    }

    let persistent = update_production_swap_persistent_config_at_path(
        &host_lock,
        &activation,
        &runtime,
        &consent,
        &store,
        &mut journal,
        &fstab_path,
    )?;

    let removal_preflight = prepare_production_swap_partition_removal(
        &host_lock,
        &activation,
        &runtime,
        &persistent,
        &consent,
        &store,
        &journal,
    )?;
    let removal_tools = pin_production_swap_partition_removal_tools(&removal_preflight)?;
    let removal_launch =
        build_production_swap_partition_removal_launch_spec(&removal_preflight, &removal_tools)?;
    let removal = execute_production_swap_partition_removal(
        &host_lock,
        &activation,
        &runtime,
        &persistent,
        &consent,
        &removal_preflight,
        &removal_tools,
        &removal_launch,
        &store,
        &mut journal,
    )?;

    if !removal.completed || journal.phase != ProductionSwapRuntimePhase::Completed {
        return Err("production swap runtime journal did not reach Completed".into());
    }
    let persisted = store.load(&journal.journal_id)?;
    if persisted != journal {
        return Err("persisted production swap journal differs from in-memory completion".into());
    }

    let after = discover_snapshot()?;
    let table = after
        .partition_tables
        .iter()
        .find(|table| table.device == args.loop_device)
        .ok_or("owned loop partition table disappeared")?;
    let logical_swap_removed = !table
        .partitions
        .iter()
        .any(|record| record.node == args.old_swap_device);
    let extended_device = format!("{}p2", args.loop_device);
    let extended_container_removed = !table
        .partitions
        .iter()
        .any(|record| record.node == extended_device);
    if !logical_swap_removed || !extended_container_removed {
        return Err("retired swap/extended partitions remain after production removal".into());
    }

    let swaps = discover_swaps()?;
    let old_swap_active = swaps
        .iter()
        .any(|entry| entry.name == args.old_swap_device);
    let replacement = swaps
        .iter()
        .find(|entry| entry.name == activation.swapfile_path)
        .cloned();
    if old_swap_active
        || replacement
            .as_ref()
            .is_none_or(|entry| entry.priority != old_swap.priority)
    {
        return Err("final active swap state does not match production completion".into());
    }
    if fs::read(&sentinel_path)? != sentinel_before {
        return Err("filesystem sentinel changed during production swap E2E".into());
    }

    let receipt = SuccessReceipt {
        schema_version: 1,
        profile: "tail_swap_partition_to_ext4_swapfile",
        journal_id: journal.journal_id.clone(),
        final_phase: journal.phase,
        old_swap_device: args.old_swap_device.clone(),
        swapfile_path: activation.swapfile_path.clone(),
        old_swap_active,
        replacement_swap_active_before_cleanup: replacement.is_some(),
        logical_swap_removed,
        extended_container_removed,
        persistent_config_updated: persistent.persistent_config_updated,
        partition_table_changed: removal.partition_table_changed,
        production_chain_completed: removal.completed,
    };

    // Harness-only cleanup after all production completion evidence is captured.
    let status = std::process::Command::new("swapoff")
        .arg(&activation.swapfile_path)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .status()?;
    if !status.success() {
        return Err("could not deactivate replacement swapfile after completed E2E".into());
    }
    if discover_swaps()?
        .iter()
        .any(|entry| entry.name == activation.swapfile_path)
    {
        return Err("replacement swapfile remained active after E2E cleanup".into());
    }
    fs::remove_file(&activation.swapfile_path)?;

    Ok(receipt)
}

fn main() {
    match run() {
        Ok(receipt) => {
            println!("{}", serde_json::to_string(&receipt).unwrap());
        }
        Err(error) => {
            eprintln!("PRODUCTION_SWAP_LOOP_E2E_FAILED: {error}");
            std::process::exit(1);
        }
    }
}
