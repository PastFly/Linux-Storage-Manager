use std::env;
use std::error::Error;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use lsm_discovery::{discover_capabilities, discover_snapshot};
use lsm_executor::{
    approve_exact_plan, build_metadata_backup_manifest, build_pre_mutation_evidence,
    build_pre_mutation_evidence_with_filesystem_health, capture_disposable_loop_ownership,
    capture_metadata_backups_at_disposable_root, compile_native_manifest,
    execute_explicit_filesystem_health_check, execute_verify_and_persist_production_chained_step,
    execute_verify_and_persist_production_step, freeze_execution_intent,
    inspect_production_activation_readiness, inspect_production_chained_activation_readiness,
    pin_default_production_chained_mutation_consent, pin_default_production_mutation_consent,
    prepare_continuation_production_chained_mutation_step,
    prepare_continuation_production_mutation_step, prepare_first_production_chained_mutation_step,
    prepare_first_production_mutation_step, revalidate_metadata_backup_receipt_at_disposable_root,
    seal_production_chained_mutation_activation_intent, seal_production_mutation_activation_intent,
    verify_disposable_loop_association_row, verify_preconditions, DurableJournalStore,
    FrozenIntentRole, LockedExecutionSession, LockedRevalidationStatus, PreMutationEvidenceStatus,
    PrivilegedDurableDisposition, ProductionMutationConsentDocument,
    PRODUCTION_MUTATION_CONSENT_PATH, PRODUCTION_MUTATION_CONSENT_PHRASE,
};
use lsm_planner::{
    build_execution_start_binding, build_frozen_execution_handoff, capture_target_identity,
    plan_extend, ExtendRequest, FilesystemDecisionState, Growth, JournalPhase, PlanStatus,
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
    xfs_scrub: PathBuf,
    e2fsck: Option<PathBuf>,
}

#[derive(Debug)]
struct ProductionProfileOutcome {
    profile: &'static str,
    first_step_id: u32,
    final_step_id: u32,
    final_identity_digest: String,
}

#[derive(Debug)]
struct ConsentGuard {
    path: PathBuf,
    device_id: u64,
    inode: u64,
    parent: PathBuf,
    parent_created: bool,
}

impl Drop for ConsentGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.dev() == self.device_id
            && metadata.ino() == self.inode
            && metadata.uid() == 0
            && metadata.mode() & 0o777 == 0o600
            && metadata.nlink() == 1
        {
            let _ = fs::remove_file(&self.path);
        }
        if self.parent_created {
            let _ = fs::remove_dir(&self.parent);
        }
    }
}

fn boxed(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(HarnessError(message.into()))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PRODUCTION_LOOP_E2E_FAILED: {error}");
        std::process::exit(1);
    }
}

fn run() -> HarnessResult<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(boxed("production loop harness requires root"));
    }

    let args = parse_args()?;
    let owned_root = args.owned_root.canonicalize()?;
    require_direct_child(&owned_root, &args.journal_root, "journal root")?;
    require_direct_child(&owned_root, &args.backup_root, "backup root")?;

    let backing_file = args.backing_file.canonicalize()?;
    let _ownership =
        capture_disposable_loop_ownership(&args.loop_device, &backing_file, &owned_root)?;
    let _association = verify_disposable_loop_association_row(
        &args.loop_device,
        &backing_file,
        &args.association_row,
    )?;

    let sentinel_path = Path::new(&args.target).join("readonly-sentinel");
    let sentinel_before = fs::read(&sentinel_path).map_err(|error| {
        boxed(format!(
            "production fixture sentinel is unavailable: {error}"
        ))
    })?;

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
            "production loop fixture did not produce a preview-ready plan",
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
            "locked production revalidation blocked: {}",
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
            "production backup revalidation blocked: {}",
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
            "production pre-mutation evidence incomplete: {}",
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
            "capability inventory changed immediately before production execution",
        ));
    }
    let initial_identity = capture_target_identity(&executable_snapshot, &args.target)?;
    if initial_identity.manifest_digest != handoff.target_identity().manifest_digest {
        return Err(boxed(
            "fresh production identity diverged from the locked handoff",
        ));
    }

    let mutation_step_ids = validated
        .manifest()
        .steps
        .iter()
        .filter(|step| step.role == FrozenIntentRole::MutationCandidate)
        .map(|step| step.plan_step_id)
        .collect::<Vec<_>>();
    if !matches!(mutation_step_ids.len(), 2 | 4) {
        return Err(boxed(
            "production loop E2E requires an exact two-step LV -> filesystem or four-step partition -> PV -> LV -> filesystem profile",
        ));
    }

    let execution = build_execution_start_binding(
        session.journal(),
        &validated.manifest().source_manifest_id,
        validated.digest(),
        &initial_identity.manifest_digest,
        &mutation_step_ids,
    )?;

    let profile_outcome = match mutation_step_ids.len() {
        2 => execute_narrow_production_profile(
            &mut session,
            &validated,
            &execution,
            &initial_identity,
        )?,
        4 => execute_chained_production_profile(
            &mut session,
            &validated,
            &execution,
            &initial_identity,
        )?,
        _ => unreachable!("mutation step count was validated above"),
    };

    if session.journal().phase != JournalPhase::Completed {
        return Err(boxed(
            "successful production loop E2E did not end in Completed",
        ));
    }

    let persisted = store.load(&session.journal().journal_id)?;
    if persisted != *session.journal() {
        return Err(boxed(
            "completed production journal does not match live session state",
        ));
    }
    if fs::read(&sentinel_path)? != sentinel_before {
        return Err(boxed(
            "filesystem sentinel changed across production loop execution",
        ));
    }

    let execution_id = execution.execution_id.clone();
    let journal_id = persisted.journal_id.clone();

    drop(session);

    remove_owned_directory(&args.backup_root, &owned_root)?;
    remove_owned_directory(&args.journal_root, &owned_root)?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "completed",
            "profile": profile_outcome.profile,
            "execution_id": execution_id,
            "journal_id": journal_id,
            "first_step_id": profile_outcome.first_step_id,
            "final_step_id": profile_outcome.final_step_id,
            "final_identity_digest": profile_outcome.final_identity_digest,
            "sentinel_preserved": true
        }))?
    );
    Ok(())
}

fn execute_narrow_production_profile(
    session: &mut LockedExecutionSession<'_>,
    validated: &lsm_executor::ValidatedNativeManifest,
    execution: &lsm_planner::ExecutionStartBinding,
    initial_identity: &lsm_planner::TargetIdentityManifest,
) -> HarnessResult<ProductionProfileOutcome> {
    let readiness = inspect_production_activation_readiness(validated, execution, initial_identity);
    if !readiness.ready() {
        return Err(boxed(format!(
            "production activation is not ready: {}",
            readiness.blockers.join("; ")
        )));
    }
    let activation =
        seal_production_mutation_activation_intent(validated, execution, initial_identity)?;

    let consent_guard = create_exact_runtime_consent(&activation)?;
    let consent_lease = pin_default_production_mutation_consent(&activation)?;
    let consent_receipt = consent_lease.receipt().clone();

    let first = prepare_first_production_mutation_step(
        session,
        validated,
        execution,
        initial_identity,
        &activation,
        &consent_receipt,
    )?;
    let first_result = execute_verify_and_persist_production_step(
        session,
        first.descriptor_chain(&activation, &consent_lease),
        initial_identity,
    )?;

    match first_result.durable_disposition {
        PrivilegedDurableDisposition::Continue { next_step_id }
            if next_step_id == activation.filesystem_step_id => {}
        ref other => {
            return Err(boxed(format!(
                "first production step did not authorize the exact filesystem continuation: {other:?}"
            )));
        }
    }

    let second = prepare_continuation_production_mutation_step(
        session,
        validated,
        &first_result.fresh_identity,
        &activation,
        &consent_receipt,
    )?;
    let second_result = execute_verify_and_persist_production_step(
        session,
        second.descriptor_chain(&activation, &consent_lease),
        &first_result.fresh_identity,
    )?;

    if second_result.durable_disposition != PrivilegedDurableDisposition::Complete {
        return Err(boxed(format!(
            "terminal production step did not complete durable execution: {:?}",
            second_result.durable_disposition
        )));
    }

    let outcome = ProductionProfileOutcome {
        profile: "production_lv_filesystem",
        first_step_id: activation.lv_step_id,
        final_step_id: activation.filesystem_step_id,
        final_identity_digest: second_result.fresh_identity_digest.clone(),
    };

    drop(second);
    drop(first);
    drop(consent_lease);
    drop(consent_guard);
    Ok(outcome)
}

fn require_next_step(
    disposition: &PrivilegedDurableDisposition,
    expected_step_id: u32,
    label: &str,
) -> HarnessResult<()> {
    match disposition {
        PrivilegedDurableDisposition::Continue { next_step_id }
            if *next_step_id == expected_step_id =>
        {
            Ok(())
        }
        other => Err(boxed(format!(
            "{label} did not authorize exact next chained step {expected_step_id}: {other:?}"
        ))),
    }
}

fn execute_chained_production_profile(
    session: &mut LockedExecutionSession<'_>,
    validated: &lsm_executor::ValidatedNativeManifest,
    execution: &lsm_planner::ExecutionStartBinding,
    initial_identity: &lsm_planner::TargetIdentityManifest,
) -> HarnessResult<ProductionProfileOutcome> {
    let readiness =
        inspect_production_chained_activation_readiness(validated, execution, initial_identity);
    if !readiness.ready() {
        return Err(boxed(format!(
            "chained production activation is not ready: {}",
            readiness.blockers.join("; ")
        )));
    }
    let activation =
        seal_production_chained_mutation_activation_intent(validated, execution, initial_identity)?;

    let consent_guard = create_exact_runtime_chained_consent(&activation)?;
    let consent_lease = pin_default_production_chained_mutation_consent(&activation)?;
    let consent_receipt = consent_lease.receipt().clone();

    let partition = prepare_first_production_chained_mutation_step(
        session,
        validated,
        execution,
        initial_identity,
        &activation,
        &consent_receipt,
    )?;
    let partition_result = execute_verify_and_persist_production_chained_step(
        session,
        partition.descriptor_chain(&activation, &consent_lease),
        initial_identity,
    )?;
    require_next_step(
        &partition_result.durable_disposition,
        activation.pv_step_id,
        "partition mutation",
    )?;
    drop(partition);

    let pv = prepare_continuation_production_chained_mutation_step(
        session,
        validated,
        &partition_result.fresh_identity,
        &activation,
        &consent_receipt,
    )?;
    let pv_result = execute_verify_and_persist_production_chained_step(
        session,
        pv.descriptor_chain(&activation, &consent_lease),
        &partition_result.fresh_identity,
    )?;
    require_next_step(
        &pv_result.durable_disposition,
        activation.lv_step_id,
        "PV mutation",
    )?;
    drop(pv);

    let lv = prepare_continuation_production_chained_mutation_step(
        session,
        validated,
        &pv_result.fresh_identity,
        &activation,
        &consent_receipt,
    )?;
    let lv_result = execute_verify_and_persist_production_chained_step(
        session,
        lv.descriptor_chain(&activation, &consent_lease),
        &pv_result.fresh_identity,
    )?;
    require_next_step(
        &lv_result.durable_disposition,
        activation.filesystem_step_id,
        "LV mutation",
    )?;
    drop(lv);

    let filesystem = prepare_continuation_production_chained_mutation_step(
        session,
        validated,
        &lv_result.fresh_identity,
        &activation,
        &consent_receipt,
    )?;
    let filesystem_result = execute_verify_and_persist_production_chained_step(
        session,
        filesystem.descriptor_chain(&activation, &consent_lease),
        &lv_result.fresh_identity,
    )?;
    if filesystem_result.durable_disposition != PrivilegedDurableDisposition::Complete {
        return Err(boxed(format!(
            "terminal chained filesystem mutation did not complete execution: {:?}",
            filesystem_result.durable_disposition
        )));
    }

    let outcome = ProductionProfileOutcome {
        profile: "production_partition_pv_lv_filesystem",
        first_step_id: activation.partition_step_id,
        final_step_id: activation.filesystem_step_id,
        final_identity_digest: filesystem_result.fresh_identity_digest.clone(),
    };

    drop(filesystem);
    drop(consent_lease);
    drop(consent_guard);
    Ok(outcome)
}

fn create_exact_runtime_consent(
    activation: &lsm_executor::ProductionMutationActivationIntent,
) -> HarnessResult<ConsentGuard> {
    create_exact_runtime_consent_document(
        &activation.activation_id,
        &activation.execution_id,
        &activation.target,
        &activation.resolved_device,
    )
}

fn create_exact_runtime_chained_consent(
    activation: &lsm_executor::ProductionChainedMutationActivationIntent,
) -> HarnessResult<ConsentGuard> {
    create_exact_runtime_consent_document(
        &activation.activation_id,
        &activation.execution_id,
        &activation.target,
        &activation.resolved_device,
    )
}

fn create_exact_runtime_consent_document(
    activation_id: &str,
    execution_id: &str,
    target: &str,
    resolved_device: &str,
) -> HarnessResult<ConsentGuard> {
    let path = PathBuf::from(PRODUCTION_MUTATION_CONSENT_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| boxed("production consent path has no parent"))?
        .to_path_buf();

    let parent_created = match fs::symlink_metadata(&parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(boxed(
                    "existing production consent parent is not root-owned and secure",
                ));
            }
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o755);
            builder.create(&parent)?;
            true
        }
        Err(error) => return Err(Box::new(error)),
    };

    if fs::symlink_metadata(&path).is_ok() {
        return Err(boxed(
            "refusing to replace an existing production mutation consent file",
        ));
    }

    let document = ProductionMutationConsentDocument {
        schema_version: 1,
        activation_id: activation_id.to_owned(),
        execution_id: execution_id.to_owned(),
        target: target.to_owned(),
        resolved_device: resolved_device.to_owned(),
        consent_phrase: PRODUCTION_MUTATION_CONSENT_PHRASE.into(),
    };
    let bytes = serde_json::to_vec(&document)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);

    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        let _ = fs::remove_file(&path);
        if parent_created {
            let _ = fs::remove_dir(&parent);
        }
        return Err(boxed(
            "created production consent file failed exact ownership/mode checks",
        ));
    }

    Ok(ConsentGuard {
        path,
        device_id: metadata.dev(),
        inode: metadata.ino(),
        parent,
        parent_created,
    })
}

fn parse_args() -> HarnessResult<Args> {
    let mut values = std::collections::BTreeMap::<String, String>::new();
    let mut allowed = false;
    let mut iter = env::args().skip(1);
    while let Some(key) = iter.next() {
        if key == "--allow-production-loop-execution" {
            if allowed {
                return Err(boxed("duplicate production execution acknowledgement"));
            }
            allowed = true;
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
            "explicit --allow-production-loop-execution is required",
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
    let xfs_scrub = PathBuf::from(take("--xfs-scrub")?);

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
        xfs_scrub,
        e2fsck,
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
