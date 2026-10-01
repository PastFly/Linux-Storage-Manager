use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use lsm_core::{BlockDevice, HostSnapshot};
use lsm_discovery::discover_snapshot;
use lsm_executor::{
    build_production_create_mount_runtime_launch_spec, build_production_create_runtime_launch_spec,
    capture_disposable_loop_ownership, execute_production_create_filesystem_crossing,
    execute_production_create_mount_crossing, execute_production_create_partition_crossing,
    inspect_production_create_activation_readiness,
    persist_new_production_create_mount_runtime_journal,
    persist_new_production_create_persistent_config_journal,
    persist_new_production_create_runtime_journal, pin_default_production_create_consent,
    pin_production_create_mount_tool, pin_production_create_tools,
    prepare_production_create_mount_runtime_preflight, prepare_production_create_runtime_preflight,
    revalidate_production_create_persistent_config_receipt,
    seal_production_create_activation_intent, seal_production_create_execution_permit,
    seal_production_create_mount_activation_intent, update_production_create_persistent_config,
    verify_disposable_loop_association_row, HostStorageLock, ProductionCreateConsentDocument,
    ProductionCreateMountRuntimeJournalStore, ProductionCreateMountRuntimePhase,
    ProductionCreatePersistentConfigJournal, ProductionCreatePersistentConfigJournalStore,
    ProductionCreatePersistentConfigPhase, ProductionCreateRuntimeJournalStore,
    ProductionCreateRuntimePhase, PRODUCTION_CREATE_CONSENT_PATH, PRODUCTION_CREATE_CONSENT_PHRASE,
};
use lsm_planner::{
    freeze_blank_disk_filesystem_create_intent, list_provisioning_opportunities, plan_create,
    CreatePartitionTablePolicy, CreatePurpose, CreateRequest, Growth, PlanStatus,
    ProvisioningSpaceKind,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("{0}")]
struct HarnessError(String);

type HarnessResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Execute,
    VerifyRestart,
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    loop_device: String,
    backing_file: PathBuf,
    owned_root: PathBuf,
    association_row: String,
    mountpoint: PathBuf,
    filesystem: String,
    partition_table: CreatePartitionTablePolicy,
    create_journal_root: PathBuf,
    mount_journal_root: PathBuf,
    persistent_journal_root: PathBuf,
    lock_path: PathBuf,
    create_journal_id: Option<String>,
    mount_journal_id: Option<String>,
    persistent_journal_id: Option<String>,
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

fn require_direct_child(root: &Path, path: &Path, label: &str) -> HarnessResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| boxed(format!("{label} has no parent")))?;
    if parent != root || path.file_name().is_none() {
        return Err(boxed(format!(
            "{label} must be a direct child of owned root"
        )));
    }
    Ok(())
}

fn parse_args() -> HarnessResult<Args> {
    let mut values = BTreeMap::<String, String>::new();
    let mut allow = false;
    let mut mode = None;
    let mut iter = env::args().skip(1);
    while let Some(key) = iter.next() {
        match key.as_str() {
            "--allow-production-create-loop-execution" => allow = true,
            "--mode" => {
                let value = iter
                    .next()
                    .ok_or_else(|| boxed("--mode requires a value"))?;
                mode = Some(match value.as_str() {
                    "execute" => Mode::Execute,
                    "verify-restart" => Mode::VerifyRestart,
                    _ => return Err(boxed("--mode must be execute or verify-restart")),
                });
            }
            "--loop-device"
            | "--backing-file"
            | "--owned-root"
            | "--association-row"
            | "--mountpoint"
            | "--filesystem"
            | "--partition-table"
            | "--create-journal-root"
            | "--mount-journal-root"
            | "--persistent-journal-root"
            | "--lock-path"
            | "--create-journal-id"
            | "--mount-journal-id"
            | "--persistent-journal-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| boxed(format!("{key} requires a value")))?;
                if values.insert(key.clone(), value).is_some() {
                    return Err(boxed(format!("duplicate argument: {key}")));
                }
            }
            _ => return Err(boxed(format!("unknown argument: {key}"))),
        }
    }
    if !allow {
        return Err(boxed(
            "explicit --allow-production-create-loop-execution is required",
        ));
    }

    let take = |key: &str| -> HarnessResult<String> {
        values
            .get(key)
            .cloned()
            .ok_or_else(|| boxed(format!("{key} is required")))
    };
    let mode = mode.ok_or_else(|| boxed("--mode is required"))?;
    let filesystem = take("--filesystem")?;
    if !matches!(filesystem.as_str(), "ext4" | "xfs") {
        return Err(boxed("--filesystem must be ext4 or xfs"));
    }
    let partition_table_value = take("--partition-table")?;
    let partition_table = match partition_table_value.as_str() {
        "gpt" => CreatePartitionTablePolicy::Gpt,
        "dos" => CreatePartitionTablePolicy::Dos,
        _ => return Err(boxed("--partition-table must be gpt or dos")),
    };
    let create_journal_id = values.get("--create-journal-id").cloned();
    let mount_journal_id = values.get("--mount-journal-id").cloned();
    let persistent_journal_id = values.get("--persistent-journal-id").cloned();
    if mode == Mode::VerifyRestart
        && (create_journal_id.is_none()
            || mount_journal_id.is_none()
            || persistent_journal_id.is_none())
    {
        return Err(boxed(
            "verify-restart requires --create-journal-id, --mount-journal-id and --persistent-journal-id",
        ));
    }

    Ok(Args {
        mode,
        loop_device: take("--loop-device")?,
        backing_file: PathBuf::from(take("--backing-file")?),
        owned_root: PathBuf::from(take("--owned-root")?),
        association_row: take("--association-row")?,
        mountpoint: PathBuf::from(take("--mountpoint")?),
        filesystem,
        partition_table,
        create_journal_root: PathBuf::from(take("--create-journal-root")?),
        mount_journal_root: PathBuf::from(take("--mount-journal-root")?),
        persistent_journal_root: PathBuf::from(take("--persistent-journal-root")?),
        lock_path: PathBuf::from(take("--lock-path")?),
        create_journal_id,
        mount_journal_id,
        persistent_journal_id,
    })
}

fn partition_table_name(policy: CreatePartitionTablePolicy) -> &'static str {
    match policy {
        CreatePartitionTablePolicy::Gpt => "gpt",
        CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn create_exact_create_consent(
    activation: &lsm_executor::ProductionCreateActivationIntent,
) -> HarnessResult<ConsentGuard> {
    let path = PathBuf::from(PRODUCTION_CREATE_CONSENT_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| boxed("production create consent path has no parent"))?
        .to_path_buf();

    let parent_created = match fs::symlink_metadata(&parent) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                return Err(boxed(
                    "existing production create consent parent is not root-owned and secure",
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
            "refusing to replace an existing production create consent file",
        ));
    }

    let document = ProductionCreateConsentDocument {
        schema_version: 1,
        activation_id: activation.activation_id.clone(),
        create_intent_id: activation.create_intent_id.clone(),
        disk: activation.disk.clone(),
        filesystem: activation.filesystem.clone(),
        consent_phrase: PRODUCTION_CREATE_CONSENT_PHRASE.into(),
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
            "created production create consent failed ownership/mode checks",
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

fn flatten<'a>(devices: &'a [BlockDevice], output: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        output.push(device);
        flatten(&device.children, output);
    }
}

fn source_matches(source: Option<&str>, partition: &str, uuid: &str) -> bool {
    let uuid_source = format!("UUID={uuid}");
    source
        .is_some_and(|value| value == partition || value.eq_ignore_ascii_case(uuid_source.as_str()))
}

fn verify_live_mount(
    snapshot: &HostSnapshot,
    journal: &lsm_executor::ProductionCreateMountRuntimeJournal,
    persistent: Option<&ProductionCreatePersistentConfigJournal>,
) -> HarnessResult<()> {
    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let partitions = nodes
        .iter()
        .copied()
        .filter(|node| node.path.as_deref() == Some(journal.partition_device.as_str()))
        .collect::<Vec<_>>();
    if partitions.len() != 1 {
        return Err(boxed("restart verification lost exact partition identity"));
    }
    let partition = partitions[0];
    if partition
        .uuid
        .as_deref()
        .is_none_or(|value| !value.eq_ignore_ascii_case(&journal.filesystem_uuid))
        || partition
            .filesystem
            .as_ref()
            .is_none_or(|filesystem| filesystem.fs_type != journal.filesystem)
        || partition.mountpoints.len() != 1
        || partition.mountpoints[0] != journal.mountpoint
    {
        return Err(boxed(
            "restart verification filesystem/UUID/mountpoint binding changed",
        ));
    }

    let mounts = snapshot
        .mounts
        .iter()
        .filter(|entry| entry.target == journal.mountpoint)
        .collect::<Vec<_>>();
    if mounts.len() != 1 {
        return Err(boxed(
            "restart verification did not find exactly one target mount",
        ));
    }
    let mounted = mounts[0];
    if !source_matches(
        mounted.source.as_deref(),
        &journal.partition_device,
        &journal.filesystem_uuid,
    ) || mounted.fs_type.as_deref() != Some(journal.filesystem.as_str())
        || !mounted.options.iter().any(|option| option == "rw")
        || mounted.options.iter().any(|option| option == "ro")
    {
        return Err(boxed("restart verification live mount identity changed"));
    }
    if snapshot.mounts.iter().any(|entry| {
        entry.target != journal.mountpoint
            && source_matches(
                entry.source.as_deref(),
                &journal.partition_device,
                &journal.filesystem_uuid,
            )
    }) {
        return Err(boxed(
            "restart verification found the created filesystem mounted elsewhere",
        ));
    }

    let uuid_source = format!("UUID={}", journal.filesystem_uuid);
    if snapshot.swaps.iter().any(|entry| {
        entry.name == journal.partition_device || entry.name.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(boxed(
            "restart verification found the created filesystem active as swap",
        ));
    }

    match persistent {
        None => {
            if snapshot.fstab.iter().any(|entry| {
                entry.target == journal.mountpoint
                    || entry.source == journal.partition_device
                    || entry.source.eq_ignore_ascii_case(&uuid_source)
            }) {
                return Err(boxed(
                    "restart verification found an unexpected persistent mount binding",
                ));
            }
        }
        Some(persistent) => {
            if persistent.phase != ProductionCreatePersistentConfigPhase::Completed
                || !persistent.integrity_matches().unwrap_or(false)
                || persistent.mount_runtime_journal_id != journal.journal_id
                || persistent.mount_activation_id != journal.mount_activation_id
                || persistent.disk != journal.disk
                || persistent.partition_device != journal.partition_device
                || persistent.filesystem != journal.filesystem
                || !persistent
                    .filesystem_uuid
                    .eq_ignore_ascii_case(&journal.filesystem_uuid)
                || persistent.mountpoint != journal.mountpoint
                || !persistent.fstab_source.eq_ignore_ascii_case(&uuid_source)
            {
                return Err(boxed(
                    "restart verification persistent journal does not match the live mount",
                ));
            }

            let is_exact = |entry: &&lsm_core::FstabEntry| {
                entry.source.eq_ignore_ascii_case(&persistent.fstab_source)
                    && entry.target == persistent.mountpoint
                    && entry.fs_type == persistent.filesystem
                    && entry.options == persistent.fstab_options
                    && entry.dump == persistent.fstab_dump
                    && entry.pass == persistent.fstab_pass
            };
            let exact_count = snapshot.fstab.iter().filter(is_exact).count();
            if exact_count != 1
                || snapshot.fstab.iter().any(|entry| {
                    let conflict = entry.target == persistent.mountpoint
                        || entry.source == persistent.partition_device
                        || entry.source.eq_ignore_ascii_case(&persistent.fstab_source);
                    conflict && !is_exact(&entry)
                })
            {
                return Err(boxed(
                    "restart verification did not find exactly one sealed persistent mount binding",
                ));
            }
        }
    }
    Ok(())
}

fn execute(args: &Args) -> HarnessResult<()> {
    let fstab_before = fs::read("/etc/fstab")?;
    let snapshot = discover_snapshot()?;
    let opportunities = list_provisioning_opportunities(&snapshot);
    let matches = opportunities
        .iter()
        .filter(|opportunity| {
            opportunity.kind == ProvisioningSpaceKind::BlankDisk
                && opportunity.disk.as_deref() == Some(args.loop_device.as_str())
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(boxed(format!(
            "expected exactly one usable blank-disk opportunity for {} but found {}",
            args.loop_device,
            matches.len()
        )));
    }

    let plan = plan_create(
        &snapshot,
        CreateRequest {
            source_id: matches[0].id.clone(),
            size: Growth::MaxFree,
            purpose: CreatePurpose::Filesystem,
            filesystem: Some(args.filesystem.clone()),
            mountpoint: None,
            partition_table: Some(args.partition_table),
        },
    )?;
    if plan.status() != PlanStatus::Preview || plan.executable() || !plan.blockers().is_empty() {
        return Err(boxed(format!(
            "blank-disk create plan is not preview-ready: {:?}",
            plan.blockers()
        )));
    }

    let intent = freeze_blank_disk_filesystem_create_intent(&snapshot, &plan)?;
    let readiness = inspect_production_create_activation_readiness(&intent);
    if !readiness.ready() {
        return Err(boxed(format!(
            "production create activation is not ready: {}",
            readiness.blockers.join("; ")
        )));
    }
    let activation = seal_production_create_activation_intent(&intent)?;
    if activation.disk != args.loop_device
        || activation.filesystem != args.filesystem
        || activation.partition_table != args.partition_table
    {
        return Err(boxed(
            "sealed create activation escaped the exact owned loop profile",
        ));
    }

    let _consent_guard = create_exact_create_consent(&activation)?;
    let consent = pin_default_production_create_consent(&activation)?;
    let permit = seal_production_create_execution_permit(&activation, &consent)?;
    let preflight = prepare_production_create_runtime_preflight(&activation, &permit, &consent)?;
    let tools = pin_production_create_tools(&preflight)?;
    let launch =
        build_production_create_runtime_launch_spec(&activation, &permit, &preflight, &tools)?;

    let create_store = ProductionCreateRuntimeJournalStore::at(&args.create_journal_root);
    let mut create_journal = persist_new_production_create_runtime_journal(
        &create_store,
        &activation,
        &permit,
        &preflight,
        &launch,
    )?;
    let host_lock = HostStorageLock::try_acquire_at(&args.lock_path)?;
    let partition_receipt = execute_production_create_partition_crossing(
        &host_lock,
        &activation,
        &permit,
        &preflight,
        &launch,
        &consent,
        &tools,
        &create_store,
        &mut create_journal,
    )?;
    let filesystem_receipt = execute_production_create_filesystem_crossing(
        &host_lock,
        &activation,
        &permit,
        &preflight,
        &launch,
        &partition_receipt,
        &consent,
        &tools,
        &create_store,
        &mut create_journal,
    )?;
    if create_journal.phase != ProductionCreateRuntimePhase::Completed
        || !filesystem_receipt.journal_completed
    {
        return Err(boxed(
            "create journal did not reach Completed after filesystem proof",
        ));
    }

    let mountpoint = args
        .mountpoint
        .to_str()
        .ok_or_else(|| boxed("mountpoint is not valid UTF-8"))?;
    let fresh = discover_snapshot()?;
    let mount_activation = seal_production_create_mount_activation_intent(
        &activation,
        &filesystem_receipt,
        &create_journal,
        &fresh,
        mountpoint,
        true,
    )?;
    let mount_preflight =
        prepare_production_create_mount_runtime_preflight(&activation, &mount_activation)?;
    let mount_tool = pin_production_create_mount_tool(&mount_preflight)?;
    let mount_launch = build_production_create_mount_runtime_launch_spec(
        &mount_activation,
        &mount_preflight,
        &mount_tool,
    )?;
    let mount_store = ProductionCreateMountRuntimeJournalStore::at(&args.mount_journal_root);
    let mut mount_journal = persist_new_production_create_mount_runtime_journal(
        &mount_store,
        &mount_activation,
        &mount_preflight,
        &mount_launch,
    )?;
    let mount_receipt = execute_production_create_mount_crossing(
        &host_lock,
        &activation,
        &mount_activation,
        &mount_preflight,
        &mount_launch,
        &mount_tool,
        &mount_store,
        &mut mount_journal,
    )?;
    if mount_journal.phase != ProductionCreateMountRuntimePhase::Completed
        || !mount_receipt.mounted_verified
        || mount_receipt.fstab_changed
    {
        return Err(boxed(
            "mount crossing did not finish with exact verified live state",
        ));
    }

    let fstab_after_mount = fs::read("/etc/fstab")?;
    if fstab_after_mount != fstab_before {
        return Err(boxed("M2A14b live mount unexpectedly changed /etc/fstab"));
    }
    let live = discover_snapshot()?;
    verify_live_mount(&live, &mount_journal, None)?;

    let persistent_store =
        ProductionCreatePersistentConfigJournalStore::at(&args.persistent_journal_root);
    let mut persistent_journal = persist_new_production_create_persistent_config_journal(
        &persistent_store,
        &activation,
        &mount_activation,
        &mount_receipt,
        &mount_journal,
    )?;
    let persistent_receipt = update_production_create_persistent_config(
        &host_lock,
        &activation,
        &mount_activation,
        &mount_receipt,
        &mount_store,
        &mount_journal,
        &persistent_store,
        &mut persistent_journal,
    )?;
    revalidate_production_create_persistent_config_receipt(&mount_activation, &persistent_receipt)?;
    if persistent_journal.phase != ProductionCreatePersistentConfigPhase::Completed
        || !persistent_receipt.persistent_config_updated
        || persistent_receipt.before_sha256 == persistent_receipt.after_sha256
    {
        return Err(boxed(
            "persistent-config crossing did not finish with an exact durable update",
        ));
    }

    let persisted_live = discover_snapshot()?;
    verify_live_mount(&persisted_live, &mount_journal, Some(&persistent_journal))?;

    let reloaded_create = ProductionCreateRuntimeJournalStore::at(&args.create_journal_root)
        .load(&create_journal.journal_id)?;
    let reloaded_mount = ProductionCreateMountRuntimeJournalStore::at(&args.mount_journal_root)
        .load(&mount_journal.journal_id)?;
    let reloaded_persistent =
        ProductionCreatePersistentConfigJournalStore::at(&args.persistent_journal_root)
            .load(&persistent_journal.journal_id)?;
    if reloaded_create != create_journal
        || reloaded_mount != mount_journal
        || reloaded_persistent != persistent_journal
    {
        return Err(boxed(
            "durable journal reload changed completed Create state",
        ));
    }

    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "persistent-mount-awaiting-restart-verification",
            "loop_device": args.loop_device,
            "partition_device": mount_journal.partition_device,
            "partition_table": partition_table_name(args.partition_table),
            "filesystem": mount_journal.filesystem,
            "filesystem_uuid": mount_journal.filesystem_uuid,
            "mountpoint": mount_journal.mountpoint,
            "create_journal_id": create_journal.journal_id,
            "mount_journal_id": mount_journal.journal_id,
            "persistent_journal_id": persistent_journal.journal_id,
            "persistent_receipt_id": persistent_receipt.receipt_id,
            "create_journal_completed": true,
            "mount_journal_completed": true,
            "persistent_journal_completed": true,
            "fstab_persisted": true,
            "mounted_verified": true
        }))?
    );
    Ok(())
}

fn verify_restart(args: &Args) -> HarnessResult<()> {
    let create_journal_id = args
        .create_journal_id
        .as_deref()
        .ok_or_else(|| boxed("missing create journal ID"))?;
    let mount_journal_id = args
        .mount_journal_id
        .as_deref()
        .ok_or_else(|| boxed("missing mount journal ID"))?;
    let persistent_journal_id = args
        .persistent_journal_id
        .as_deref()
        .ok_or_else(|| boxed("missing persistent journal ID"))?;
    let create_journal = ProductionCreateRuntimeJournalStore::at(&args.create_journal_root)
        .load(create_journal_id)?;
    let mount_journal = ProductionCreateMountRuntimeJournalStore::at(&args.mount_journal_root)
        .load(mount_journal_id)?;
    let persistent_journal =
        ProductionCreatePersistentConfigJournalStore::at(&args.persistent_journal_root)
            .load(persistent_journal_id)?;

    let mountpoint = args
        .mountpoint
        .to_str()
        .ok_or_else(|| boxed("mountpoint is not valid UTF-8"))?;
    if create_journal.phase != ProductionCreateRuntimePhase::Completed
        || mount_journal.phase != ProductionCreateMountRuntimePhase::Completed
        || create_journal.disk != args.loop_device
        || create_journal.partition_table != partition_table_name(args.partition_table)
        || create_journal.filesystem != args.filesystem
        || mount_journal.disk != args.loop_device
        || mount_journal.filesystem != args.filesystem
        || mount_journal.create_journal_id != create_journal.journal_id
        || mount_journal.partition_device != format!("{}p1", args.loop_device)
        || mount_journal.mountpoint != mountpoint
        || !mount_journal.mutation_may_have_started
        || !mount_journal.mount_may_have_changed
        || mount_journal.fstab_may_have_changed
        || persistent_journal.phase != ProductionCreatePersistentConfigPhase::Completed
        || persistent_journal.mount_runtime_journal_id != mount_journal.journal_id
        || persistent_journal.create_activation_id != create_journal.activation_id
        || persistent_journal.disk != args.loop_device
        || persistent_journal.partition_device != mount_journal.partition_device
        || persistent_journal.mountpoint != mountpoint
        || !persistent_journal.mutation_may_have_started
        || !persistent_journal.persistent_config_may_have_changed
    {
        return Err(boxed(
            "restart journal chain does not match the exact completed owned loop mount",
        ));
    }

    let snapshot = discover_snapshot()?;
    verify_live_mount(&snapshot, &mount_journal, Some(&persistent_journal))?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "status": "persistent-restart-recovery-verified",
            "loop_device": args.loop_device,
            "partition_device": mount_journal.partition_device,
            "partition_table": partition_table_name(args.partition_table),
            "filesystem": mount_journal.filesystem,
            "filesystem_uuid": mount_journal.filesystem_uuid,
            "mountpoint": mount_journal.mountpoint,
            "create_journal_id": create_journal.journal_id,
            "mount_journal_id": mount_journal.journal_id,
            "persistent_journal_id": persistent_journal.journal_id,
            "live_mount_verified": true,
            "persistent_config_verified": true,
            "safe_to_restore_fstab_and_unmount_owned_fixture": true
        }))?
    );
    Ok(())
}

fn run() -> HarnessResult<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(boxed("production create loop harness requires root"));
    }
    let args = parse_args()?;
    let owned_root = args.owned_root.canonicalize()?;
    let backing_file = args.backing_file.canonicalize()?;
    require_direct_child(
        &owned_root,
        &args.create_journal_root,
        "create journal root",
    )?;
    require_direct_child(&owned_root, &args.mount_journal_root, "mount journal root")?;
    require_direct_child(
        &owned_root,
        &args.persistent_journal_root,
        "persistent journal root",
    )?;
    require_direct_child(&owned_root, &args.lock_path, "host lock path")?;

    let _ownership =
        capture_disposable_loop_ownership(&args.loop_device, &backing_file, &owned_root)?;
    let _association = verify_disposable_loop_association_row(
        &args.loop_device,
        &backing_file,
        &args.association_row,
    )?;

    match args.mode {
        Mode::Execute => execute(&args),
        Mode::VerifyRestart => verify_restart(&args),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("PRODUCTION_CREATE_LOOP_E2E_FAILED: {error}");
        std::process::exit(1);
    }
}
