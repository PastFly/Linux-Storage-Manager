use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use lsm_executor::{
    approve_operator_plan, build_metadata_backup_manifest_for_session, build_pre_mutation_evidence,
    build_pre_mutation_evidence_with_filesystem_health, capture_metadata_backups,
    compile_native_manifest, execute_explicit_filesystem_health_check,
    execute_verify_and_persist_production_step, freeze_execution_intent,
    inspect_production_activation_readiness, operator_confirmation_phrase,
    prepare_continuation_production_mutation_step, prepare_first_production_mutation_step,
    record_and_pin_operator_production_mutation_consent, resolve_trusted_privileged_tool,
    revalidate_metadata_backup_receipt, seal_production_mutation_activation_intent,
    validate_and_bind_native_manifest, verify_preconditions, DurableJournalStore, FrozenIntentRole,
    LockedExecutionSession, LockedRevalidationStatus, PreMutationEvidenceStatus,
    PrivilegedDurableDisposition, PrivilegedProgram,
};
use lsm_planner::{
    build_execution_start_binding, build_frozen_execution_handoff, capture_target_identity,
    plan_extend, ExtendRequest, FilesystemDecisionState, Growth, JournalPhase, Operation,
    PlanStatus,
};

pub fn apply(target: String, growth: Growth) -> Result<()> {
    if !lsm_executor::effective_user_is_root() {
        bail!("apply extend requires root privileges");
    }
    // A controlling terminal is mandatory; never read approval from a pipe.
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("apply extend requires an interactive controlling terminal")?;
    let snapshot = lsm_executor::discover_snapshot_trusted()?;
    let capabilities = lsm_executor::discover_capabilities_trusted();
    // The general preview's MaxFree may include future partition/PV growth.
    // This operator command is intentionally limited to existing VG extents.
    let growth = if matches!(growth, Growth::MaxFree) {
        let probe = plan_extend(
            &snapshot,
            &capabilities,
            ExtendRequest {
                target: target.clone(),
                growth: Growth::ByBytes(1),
            },
        )?;
        let size = probe
            .size_change()
            .context("no verified existing VG free extents")?;
        let available = size
            .rounded_growth_bytes
            .checked_add(size.remaining_vg_free_bytes)
            .context("VG free capacity overflow")?;
        Growth::ByBytes(available)
    } else {
        growth
    };
    let plan = plan_extend(
        &snapshot,
        &capabilities,
        ExtendRequest {
            target: target.clone(),
            growth,
        },
    )?;
    if plan.status() != PlanStatus::Preview {
        bail!("plan is not ready for execution:\n{}", plan.render_text());
    }
    let mutations = plan
        .steps()
        .iter()
        .filter_map(|step| match &step.operation {
            Operation::ExtendPartition { .. }
            | Operation::ResizePhysicalVolume { .. }
            | Operation::ExtendLogicalVolume { .. }
            | Operation::GrowFilesystem { .. } => Some(&step.operation),
            _ => None,
        })
        .collect::<Vec<_>>();
    match mutations.as_slice() {
        [Operation::ExtendLogicalVolume { .. }, Operation::GrowFilesystem {
            fs_type,
            mountpoint,
        }] if fs_type == "ext4" || (fs_type == "xfs" && mountpoint.is_some()) => {}
        _ => bail!("only an existing LV followed by ext4 or mounted XFS growth is supported"),
    }
    let handoff = build_frozen_execution_handoff(&snapshot, &capabilities, &plan)?;
    let store = DurableJournalStore::default();
    let mut session = LockedExecutionSession::begin_durable(&handoff, &store)?;
    let result = run_locked(&mut session, &mut tty, &store, &target, &plan);
    if let Err(error) = &result {
        if !matches!(
            session.journal().phase,
            JournalPhase::Completed | JournalPhase::Aborted | JournalPhase::RecoveryRequired
        ) {
            if let Err(journal_error) =
                session.persist_interrupted("operator apply did not complete")
            {
                return Err(anyhow::anyhow!(
                    "{error:#}; could not persist interruption: {journal_error}"
                ));
            }
        }
    }
    result
}

fn run_locked(
    session: &mut LockedExecutionSession<'_>,
    tty: &mut std::fs::File,
    store: &DurableJournalStore,
    target: &str,
    plan: &lsm_planner::PlanPreview,
) -> Result<()> {
    let snapshot = lsm_executor::discover_snapshot_trusted()?;
    let capabilities = lsm_executor::discover_capabilities_trusted();
    let revalidation = session.revalidate(&snapshot, &capabilities)?;
    if revalidation.status != LockedRevalidationStatus::Revalidated {
        bail!(
            "locked revalidation blocked: {}",
            revalidation.blockers.join("; ")
        );
    }
    let backup_manifest = build_metadata_backup_manifest_for_session(session)?;
    let backup = capture_metadata_backups(session, &backup_manifest)?;
    let backup_check = revalidate_metadata_backup_receipt(&backup_manifest, &backup)?;
    if !backup_check.matches() {
        bail!(
            "metadata backup verification blocked: {}",
            backup_check.blockers().join("; ")
        );
    }
    let mut evidence =
        build_pre_mutation_evidence(session, &snapshot, &capabilities, &backup_check)?;
    if evidence.status() == PreMutationEvidenceStatus::FutureChecksRequired {
        let program = match evidence.filesystem_decision().state {
            FilesystemDecisionState::ReadOnlyHealthCheckRequired => {
                Some(PrivilegedProgram::XfsScrub)
            }
            FilesystemDecisionState::OfflineHealthCheckRequired => Some(PrivilegedProgram::E2fsck),
            _ => None,
        };
        if let Some(program) = program {
            let tool = resolve_trusted_privileged_tool(program)?;
            let health = execute_explicit_filesystem_health_check(
                session,
                &snapshot,
                &capabilities,
                Path::new(&tool.canonical_path),
            )?;
            evidence = build_pre_mutation_evidence_with_filesystem_health(
                session,
                &snapshot,
                &capabilities,
                &backup_check,
                &health,
            )?;
        }
    }
    if evidence.status() != PreMutationEvidenceStatus::EvidenceComplete {
        let mut details = evidence.blockers().to_vec();
        details.extend(evidence.future_gates().iter().cloned());
        bail!("pre-mutation evidence incomplete: {}", details.join("; "));
    }
    let verification = verify_preconditions(session, &evidence)?;
    let phrase = operator_confirmation_phrase(&verification);
    let size = plan.size_change().context("LV size evidence is missing")?;
    writeln!(
        tty,
        "CONFIRM STORAGE MODIFICATION: this will change the logical volume and filesystem.\nTarget: {:?}\nDevice: {:?}\nLV size: {} -> {} bytes\nGrowth: {} bytes\nVG free afterwards: {} bytes\nPlan: {}",
        plan.target(), size.device, size.current_lv_size_bytes, size.expected_lv_size_bytes,
        size.rounded_growth_bytes, size.remaining_vg_free_bytes, plan.plan_id(),
    )?;
    for step in plan.steps() {
        writeln!(tty, "{}. {:?}", step.id, step.operation)?;
    }
    writeln!(
        tty,
        "Evidence: {}\nType exactly to proceed: {}",
        verification.bundle_id(),
        phrase
    )?;
    tty.flush()?;
    let mut input = String::new();
    let mut reader = BufReader::new(tty.try_clone()?.take(256));
    reader.read_line(&mut input)?;
    if !input.ends_with('\n') {
        bail!("confirmation was incomplete or too long");
    }
    if input.ends_with('\n') {
        input.pop();
        if input.ends_with('\r') {
            input.pop();
        }
    }
    let approval = approve_operator_plan(session, &verification, &input)?;
    let current_backup = revalidate_metadata_backup_receipt(&backup_manifest, &backup)?;
    if !current_backup.matches() {
        bail!(
            "metadata backup changed while awaiting confirmation: {}",
            current_backup.blockers().join("; ")
        );
    }
    let intent = freeze_execution_intent(session, &approval)?;
    let validated = validate_and_bind_native_manifest(compile_native_manifest(&intent))?;
    let executable_snapshot = lsm_executor::discover_snapshot_trusted()?;
    let executable_capabilities = lsm_executor::discover_capabilities_trusted();
    if !session
        .handoff()
        .matches_capabilities(&executable_capabilities)?
    {
        bail!("capabilities changed before execution");
    }
    let identity = capture_target_identity(&executable_snapshot, target)?;
    if identity.manifest_digest != session.handoff().target_identity().manifest_digest {
        bail!("target identity changed before execution");
    }
    let steps = validated
        .manifest()
        .steps
        .iter()
        .filter(|step| step.role == FrozenIntentRole::MutationCandidate)
        .map(|step| step.plan_step_id)
        .collect::<Vec<_>>();
    if steps.len() != 2 {
        bail!("expected exactly two mutation steps");
    }
    let execution = build_execution_start_binding(
        session.journal(),
        &validated.manifest().source_manifest_id,
        validated.digest(),
        &identity.manifest_digest,
        &steps,
    )?;
    let readiness = inspect_production_activation_readiness(&validated, &execution, &identity);
    if !readiness.ready() {
        bail!(
            "production activation blocked: {}",
            readiness.blockers.join("; ")
        );
    }
    let activation = seal_production_mutation_activation_intent(&validated, &execution, &identity)?;
    let lease = record_and_pin_operator_production_mutation_consent(
        session,
        &approval,
        &execution,
        &activation,
    )?;
    let receipt = lease.receipt().clone();
    let first = prepare_first_production_mutation_step(
        session,
        &validated,
        &execution,
        &identity,
        &activation,
        &receipt,
    )?;
    let current_backup = revalidate_metadata_backup_receipt(&backup_manifest, &backup)?;
    if !current_backup.matches() {
        bail!(
            "metadata backup changed before execution: {}",
            current_backup.blockers().join("; ")
        );
    }
    let outcome = execute_verify_and_persist_production_step(
        session,
        first.descriptor_chain(&activation, &lease),
        &identity,
    )?;
    if outcome.durable_disposition
        != (PrivilegedDurableDisposition::Continue {
            next_step_id: activation.filesystem_step_id,
        })
    {
        bail!(
            "LV step did not authorize filesystem continuation: {:?}",
            outcome.durable_disposition
        );
    }
    let next = prepare_continuation_production_mutation_step(
        session,
        &validated,
        &outcome.fresh_identity,
        &activation,
        &receipt,
    )?;
    let final_outcome = execute_verify_and_persist_production_step(
        session,
        next.descriptor_chain(&activation, &lease),
        &outcome.fresh_identity,
    )?;
    if final_outcome.durable_disposition != PrivilegedDurableDisposition::Complete
        || session.journal().phase != JournalPhase::Completed
    {
        bail!(
            "filesystem step did not complete: {:?}",
            final_outcome.durable_disposition
        );
    }
    if store.load(&session.journal().journal_id)? != *session.journal() {
        bail!("completed journal changed");
    }
    println!("Completed. Journal: {}", session.journal().journal_id);
    Ok(())
}
