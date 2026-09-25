use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use lsm_discovery::{discover_capabilities, discover_snapshot};
use lsm_executor::{
    approve_exact_plan, bind_disposable_execution_permit,
    bind_verified_disposable_execution_permit, build_metadata_backup_manifest,
    build_pre_mutation_evidence, build_pre_mutation_evidence_with_filesystem_health,
    capture_disposable_loop_ownership, capture_metadata_backups_at_disposable_root,
    compile_disposable_lvm_growth_commands, compile_native_manifest, execute_disposable_command,
    execute_explicit_filesystem_health_check, freeze_execution_intent,
    persist_disposable_execution_start, revalidate_metadata_backup_receipt_at_disposable_root,
    verify_and_complete_disposable_execution, verify_and_continue_disposable_boundary,
    verify_disposable_loop_association_row, verify_preconditions, DisposableProgram,
    DisposableToolPaths, DurableJournalStore, LockedExecutionSession, LockedRevalidationStatus,
    NativeOperationSpec, PreMutationEvidenceStatus,
};
use lsm_planner::{
    build_frozen_execution_handoff, capture_target_identity, plan_extend, ExtendRequest,
    FilesystemDecisionState, Growth, JournalPhase, PlanStatus,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
struct HarnessError(String);

type HarnessResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct Args {
    target: String,
    loop_device: String,
    backing_file: PathBuf,
    owned_root: PathBuf,
    association_row: String,
    journal_root: PathBuf,
    backup_root: PathBuf,
    growth_bytes: u64,
    sfdisk: PathBuf,
    partx: PathBuf,
    pvresize: PathBuf,
    lvextend: PathBuf,
    resize2fs: PathBuf,
    xfs_growfs: PathBuf,
    xfs_scrub: PathBuf,
    e2fsck: Option<PathBuf>,
    udevadm: PathBuf,
    inject_failure_after_resize2fs: bool,
}

fn boxed(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(HarnessError(message.into()))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("DISPOSABLE_EXECUTOR_FAILED: {error}");
        std::process::exit(1);
    }
}

fn run() -> HarnessResult<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(boxed("disposable loop harness requires root"));
    }
    let args = parse_args()?;
    let owned_root = args.owned_root.canonicalize()?;
    require_direct_child(&owned_root, &args.journal_root, "journal root")?;
    require_direct_child(&owned_root, &args.backup_root, "backup root")?;

    let backing_file = args.backing_file.canonicalize()?;
    let ownership =
        capture_disposable_loop_ownership(&args.loop_device, &backing_file, &owned_root)?;
    let association = verify_disposable_loop_association_row(
        &args.loop_device,
        &backing_file,
        &args.association_row,
    )?;

    settle_udev(&args.udevadm)?;
    let snapshot = discover_snapshot()?;
    let capabilities = discover_capabilities();
    let plan = plan_extend(
        &snapshot,
        &capabilities,
        ExtendRequest {
            target: args.target.clone(),
            growth: Growth::ByBytes(args.growth_bytes),
        },
    )?;
    if plan.status() != PlanStatus::Preview {
        return Err(boxed(
            "live disposable fixture did not produce a preview-ready plan",
        ));
    }
    let handoff = build_frozen_execution_handoff(&snapshot, &capabilities, &plan)?;

    let store = DurableJournalStore::at(&args.journal_root);
    let mut session = LockedExecutionSession::begin_durable(&handoff, &store)?;

    let fresh_snapshot = discover_snapshot()?;
    let fresh_capabilities = discover_capabilities();
    let revalidation = session.revalidate(&fresh_snapshot, &fresh_capabilities)?;
    if revalidation.status != LockedRevalidationStatus::Revalidated {
        return Err(boxed(format!(
            "locked revalidation blocked: {}",
            revalidation.blockers.join("; ")
        )));
    }

    let backup_manifest = build_metadata_backup_manifest(&handoff)?;
    let backup_receipt =
        capture_metadata_backups_at_disposable_root(&session, &backup_manifest, &args.backup_root)?;
    let backup_revalidation = revalidate_metadata_backup_receipt_at_disposable_root(
        &backup_manifest,
        &backup_receipt,
        &args.backup_root,
    )?;
    if !backup_revalidation.matches() {
        return Err(boxed(format!(
            "backup revalidation blocked: {}",
            backup_revalidation.blockers().join("; ")
        )));
    }

    let mut evidence = build_pre_mutation_evidence(
        &session,
        &fresh_snapshot,
        &fresh_capabilities,
        &backup_revalidation,
    )?;
    if evidence.status() == PreMutationEvidenceStatus::FutureChecksRequired {
        let health_tool = match evidence.filesystem_decision().state {
            FilesystemDecisionState::ReadOnlyHealthCheckRequired => Some(args.xfs_scrub.as_path()),
            FilesystemDecisionState::OfflineHealthCheckRequired => args.e2fsck.as_deref(),
            _ => None,
        };
        if let Some(health_tool) = health_tool {
            let health_receipt = execute_explicit_filesystem_health_check(
                &session,
                &fresh_snapshot,
                &fresh_capabilities,
                health_tool,
            )?;
            evidence = build_pre_mutation_evidence_with_filesystem_health(
                &session,
                &fresh_snapshot,
                &fresh_capabilities,
                &backup_revalidation,
                &health_receipt,
            )?;
        }
    }
    if evidence.status() != PreMutationEvidenceStatus::EvidenceComplete {
        let mut details = evidence.blockers().to_vec();
        details.extend(evidence.future_gates().iter().cloned());
        return Err(boxed(format!(
            "pre-mutation evidence incomplete: {}",
            details.join("; ")
        )));
    }
    let verification = verify_preconditions(&mut session, &evidence)?;
    let approved_plan_id = verification.plan_id().to_owned();
    let approved_evidence_id = verification.bundle_id().to_owned();
    let approved_target_digest = verification.target_manifest_digest().to_owned();
    let approval = approve_exact_plan(
        &mut session,
        &verification,
        &approved_plan_id,
        &approved_evidence_id,
        &approved_target_digest,
    )?;

    let intent = freeze_execution_intent(&session, &approval)?;
    let validated =
        lsm_executor::validate_and_bind_native_manifest(compile_native_manifest(&intent))?;

    let executable_snapshot = discover_snapshot()?;
    let executable_capabilities = discover_capabilities();
    if !handoff.matches_capabilities(&executable_capabilities)? {
        return Err(boxed(
            "capability inventory changed immediately before disposable execution",
        ));
    }
    let initial_identity = capture_target_identity(&executable_snapshot, &args.target)?;
    if initial_identity.manifest_digest != handoff.target_identity().manifest_digest {
        return Err(boxed(
            "fresh executable identity diverged from the locked handoff",
        ));
    }
    let command_plan = compile_disposable_lvm_growth_commands(&validated, &initial_identity)?;
    let commands = command_plan.commands();
    let supported_sequence = match commands {
        [lv, filesystem] => {
            lv.program() == DisposableProgram::Lvextend
                && matches!(
                    filesystem.program(),
                    DisposableProgram::Resize2fs | DisposableProgram::XfsGrowfs
                )
        }
        [pv, lv, filesystem] => {
            pv.program() == DisposableProgram::Pvresize
                && lv.program() == DisposableProgram::Lvextend
                && matches!(
                    filesystem.program(),
                    DisposableProgram::Resize2fs | DisposableProgram::XfsGrowfs
                )
        }
        [partition, pv, lv, filesystem] => {
            partition.program() == DisposableProgram::Sfdisk
                && pv.program() == DisposableProgram::Pvresize
                && lv.program() == DisposableProgram::Lvextend
                && matches!(
                    filesystem.program(),
                    DisposableProgram::Resize2fs | DisposableProgram::XfsGrowfs
                )
        }
        _ => false,
    };
    if !supported_sequence {
        return Err(boxed(
            "compiled mutation sequence is not an approved disposable LVM growth profile",
        ));
    }

    let execution = persist_disposable_execution_start(&mut session, &command_plan)?;
    let tools = DisposableToolPaths::new(
        args.sfdisk.clone(),
        args.partx.clone(),
        args.pvresize.clone(),
        args.lvextend.clone(),
        args.resize2fs.clone(),
        args.xfs_growfs.clone(),
    );
    let first_step = commands[0].plan_step_id();
    let final_step = commands.last().unwrap().plan_step_id();

    let mutation_result: HarnessResult<(String, String)> = (|| {
        let mut current_identity = initial_identity.clone();
        let mut permit = bind_disposable_execution_permit(
            &command_plan,
            &current_identity,
            &ownership,
            &association,
            &execution,
            first_step,
        )?;

        for (index, expected_command) in commands.iter().enumerate() {
            let outcome = execute_disposable_command(permit, &session, &tools)?;
            if outcome.plan_step_id != expected_command.plan_step_id()
                || outcome.program != expected_command.program()
            {
                return Err(boxed("executor returned a mutation outcome out of order"));
            }
            if args.inject_failure_after_resize2fs
                && outcome.program == DisposableProgram::Resize2fs
            {
                return Err(boxed(
                    "injected failure after resize2fs before terminal verification",
                ));
            }

            let final_mutation = index + 1 == commands.len();
            let fresh_identity = if outcome.program == DisposableProgram::Lvextend {
                refresh_udev(&args.udevadm, &current_identity.resolved_device)?;
                let expected_lv_size = validated
                    .manifest()
                    .steps
                    .iter()
                    .find(|step| step.plan_step_id == outcome.plan_step_id)
                    .and_then(|step| match &step.operation {
                        NativeOperationSpec::ExtendLogicalVolume {
                            expected_lv_size_bytes,
                            ..
                        } => Some(*expected_lv_size_bytes),
                        _ => None,
                    })
                    .ok_or_else(|| boxed("executed LV step lost its exact expected size"))?;

                let mut converged = None;
                for attempt in 0..20 {
                    let snapshot = discover_snapshot()?;
                    let identity = capture_target_identity(&snapshot, &args.target)?;
                    let backing_size = identity
                        .filesystem
                        .as_ref()
                        .ok_or_else(|| boxed("fresh LV target lost filesystem identity"))?
                        .backing_device_size_bytes;
                    if backing_size == expected_lv_size {
                        converged = Some(identity);
                        break;
                    }
                    if backing_size > expected_lv_size {
                        return Err(boxed(format!(
                            "fresh LV backing size exceeded approved size: expected={expected_lv_size} actual={backing_size}"
                        )));
                    }
                    if attempt < 19 {
                        thread::sleep(Duration::from_millis(50));
                        refresh_udev(&args.udevadm, &current_identity.resolved_device)?;
                    }
                }
                converged.ok_or_else(|| {
                    boxed(format!(
                        "fresh LV backing size did not converge to approved size {expected_lv_size}"
                    ))
                })?
            } else if matches!(
                outcome.program,
                DisposableProgram::Resize2fs | DisposableProgram::XfsGrowfs
            ) {
                settle_udev(&args.udevadm)?;
                let expected_backing_size = current_identity
                    .filesystem
                    .as_ref()
                    .ok_or_else(|| boxed("pre-filesystem boundary lost filesystem identity"))?
                    .backing_device_size_bytes;
                let mut converged = None;
                for attempt in 0..20 {
                    let snapshot = discover_snapshot()?;
                    let identity = capture_target_identity(&snapshot, &args.target)?;
                    let Some(filesystem) = identity.filesystem.as_ref() else {
                        if attempt < 19 {
                            thread::sleep(Duration::from_millis(50));
                            refresh_udev(&args.udevadm, &current_identity.resolved_device)?;
                            continue;
                        }
                        return Err(boxed(
                            "terminal filesystem identity did not reappear after bounded rediscovery",
                        ));
                    };
                    let backing_size = filesystem.backing_device_size_bytes;
                    if backing_size == expected_backing_size {
                        converged = Some(identity);
                        break;
                    }
                    if backing_size > expected_backing_size {
                        return Err(boxed(format!(
                            "terminal filesystem backing size exceeded verified LV size: expected={expected_backing_size} actual={backing_size}"
                        )));
                    }
                    if attempt < 19 {
                        thread::sleep(Duration::from_millis(50));
                        refresh_udev(&args.udevadm, &current_identity.resolved_device)?;
                    }
                }
                converged.ok_or_else(|| {
                    boxed(format!(
                        "terminal filesystem backing size did not converge to verified LV size {expected_backing_size}"
                    ))
                })?
            } else {
                settle_udev(&args.udevadm)?;
                let snapshot = discover_snapshot()?;
                capture_target_identity(&snapshot, &args.target)?
            };
            session.persist_verification_started()?;
            let fresh_capabilities = discover_capabilities();

            if final_mutation {
                let completion = verify_and_complete_disposable_execution(
                    &mut session,
                    &validated,
                    &current_identity,
                    &fresh_identity,
                    &fresh_capabilities,
                    outcome.plan_step_id,
                )?;
                return Ok((
                    completion.execution_id().to_owned(),
                    completion.fresh_identity_digest().to_owned(),
                ));
            }

            let boundary = verify_and_continue_disposable_boundary(
                &mut session,
                &validated,
                &fresh_identity,
                &fresh_capabilities,
                outcome.plan_step_id,
            )?;
            current_identity = fresh_identity;
            permit = bind_verified_disposable_execution_permit(
                &validated,
                &current_identity,
                &ownership,
                &association,
                &execution,
                boundary,
            )?;
        }

        Err(boxed(
            "disposable mutation sequence ended without terminal verification",
        ))
    })();

    let (execution_id, final_identity_digest) = match mutation_result {
        Ok(value) => value,
        Err(error) => {
            let _ =
                session.persist_interrupted("disposable loop harness failed after execution start");
            return Err(error);
        }
    };

    if session.journal().phase != JournalPhase::Completed {
        return Err(boxed("successful executor run did not end in Completed"));
    }
    let persisted = store.load(&session.journal().journal_id)?;
    if persisted != *session.journal() {
        return Err(boxed(
            "completed durable journal does not match live session state",
        ));
    }
    let final_binding = persisted
        .verified_boundary
        .as_ref()
        .ok_or_else(|| boxed("completed journal is missing verified boundary"))?;
    if final_binding.final_step_id != Some(final_step)
        || final_binding.final_identity_digest.as_deref() != Some(final_identity_digest.as_str())
    {
        return Err(boxed(
            "completed journal is missing exact terminal verification identity",
        ));
    }

    let journal_id = persisted.journal_id.clone();
    drop(session);
    remove_owned_directory(&args.backup_root, &owned_root)?;
    remove_owned_directory(&args.journal_root, &owned_root)?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "completed",
            "execution_id": execution_id,
            "journal_id": journal_id,
            "first_step_id": first_step,
            "final_step_id": final_step,
            "final_identity_digest": final_identity_digest,
            "mutation_enabled": lsm_executor::MUTATION_ENABLED,
        }))?
    );
    Ok(())
}

fn parse_args() -> HarnessResult<Args> {
    let mut values = std::collections::BTreeMap::<String, String>::new();
    let mut allowed = false;
    let mut inject_failure_after_resize2fs = false;
    let mut iter = env::args().skip(1);
    while let Some(key) = iter.next() {
        if key == "--allow-disposable-loop-execution" {
            if allowed {
                return Err(boxed("duplicate disposable execution acknowledgement"));
            }
            allowed = true;
            continue;
        }
        if key == "--inject-failure-after-resize2fs" {
            if inject_failure_after_resize2fs {
                return Err(boxed("duplicate resize2fs failure injection"));
            }
            inject_failure_after_resize2fs = true;
            continue;
        }
        if !key.starts_with("--") {
            return Err(boxed(format!("unexpected argument: {key}")));
        }
        let value = iter
            .next()
            .ok_or_else(|| boxed(format!("missing value for {key}")))?;
        if values.insert(key.clone(), value).is_some() {
            return Err(boxed(format!("duplicate argument: {key}")));
        }
    }
    if !allowed {
        return Err(boxed(
            "explicit --allow-disposable-loop-execution is required",
        ));
    }

    let e2fsck = values.remove("--e2fsck").map(PathBuf::from);
    let mut take = |key: &str| -> HarnessResult<String> {
        values
            .remove(key)
            .ok_or_else(|| boxed(format!("missing required argument: {key}")))
    };
    let target = take("--target")?;
    let loop_device = take("--loop-device")?;
    let backing_file = PathBuf::from(take("--backing-file")?);
    let owned_root = PathBuf::from(take("--owned-root")?);
    let association_row = take("--association-row")?;
    let journal_root = PathBuf::from(take("--journal-root")?);
    let backup_root = PathBuf::from(take("--backup-root")?);
    let growth_bytes = take("--growth-bytes")?
        .parse::<u64>()
        .map_err(|_| boxed("--growth-bytes must be a positive integer"))?;
    if growth_bytes == 0 {
        return Err(boxed("--growth-bytes must be nonzero"));
    }
    let sfdisk = PathBuf::from(take("--sfdisk")?);
    let partx = PathBuf::from(take("--partx")?);
    let pvresize = PathBuf::from(take("--pvresize")?);
    let lvextend = PathBuf::from(take("--lvextend")?);
    let resize2fs = PathBuf::from(take("--resize2fs")?);
    let xfs_growfs = PathBuf::from(take("--xfs-growfs")?);
    let xfs_scrub = PathBuf::from(take("--xfs-scrub")?);
    let udevadm = PathBuf::from(take("--udevadm")?);
    if !values.is_empty() {
        return Err(boxed(format!(
            "unknown arguments: {}",
            values.keys().cloned().collect::<Vec<_>>().join(", ")
        )));
    }

    Ok(Args {
        target,
        loop_device,
        backing_file,
        owned_root,
        association_row,
        journal_root,
        backup_root,
        growth_bytes,
        sfdisk,
        partx,
        pvresize,
        lvextend,
        resize2fs,
        xfs_growfs,
        xfs_scrub,
        e2fsck,
        udevadm,
        inject_failure_after_resize2fs,
    })
}

fn require_direct_child(root: &Path, path: &Path, label: &str) -> HarnessResult<()> {
    if !path.is_absolute() {
        return Err(boxed(format!("{label} must be absolute")));
    }
    let parent = path
        .parent()
        .ok_or_else(|| boxed(format!("{label} has no parent")))?
        .canonicalize()?;
    if parent != root {
        return Err(boxed(format!(
            "{label} must be a direct child of the owned root"
        )));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(boxed(format!("{label} already exists"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

fn validate_udevadm(path: &Path) -> HarnessResult<()> {
    if !path.is_absolute() || path.file_name().and_then(|name| name.to_str()) != Some("udevadm") {
        return Err(boxed("udevadm path is not exact"));
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(boxed("udevadm path is not a file"));
    }
    Ok(())
}

fn settle_udev(udevadm: &Path) -> HarnessResult<()> {
    validate_udevadm(udevadm)?;
    let status = Command::new(udevadm)
        .args(["settle", "--timeout=30"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if !status.success() {
        return Err(boxed(format!("udevadm settle failed with {status}")));
    }
    Ok(())
}

fn refresh_udev(udevadm: &Path, device: &str) -> HarnessResult<()> {
    validate_udevadm(udevadm)?;
    let canonical = Path::new(device).canonicalize()?;
    let sysname = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| boxed("resolved device has no UTF-8 sysname"))?;
    if sysname.is_empty()
        || !sysname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+!-".contains(&byte))
    {
        return Err(boxed("resolved device has unsafe sysname"));
    }
    let status = Command::new(udevadm)
        .args([
            "trigger",
            "--action=change",
            &format!("--sysname-match={sysname}"),
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if !status.success() {
        return Err(boxed(format!("udevadm trigger failed with {status}")));
    }
    settle_udev(udevadm)
}

fn remove_owned_directory(path: &Path, root: &Path) -> HarnessResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| boxed("owned cleanup path has no parent"))?
        .canonicalize()?;
    if parent != root {
        return Err(boxed("refusing cleanup outside owned root"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(boxed("owned cleanup path is not an exact directory"));
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(boxed(format!(
                "unexpected non-file in owned cleanup directory: {}",
                entry_path.display()
            )));
        }
        fs::remove_file(entry_path)?;
    }
    fs::remove_dir(path)?;
    Ok(())
}
