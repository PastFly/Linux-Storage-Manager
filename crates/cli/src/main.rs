use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use lsm_core::BlockDevice;
use lsm_discovery::{
    analyze_extendability, discover_capabilities, discover_fstab, discover_lvm, discover_mounts,
    discover_partition_tables, discover_snapshot, discover_storage, discover_swaps,
};
use lsm_planner::{
    analyze_layer_route, decide_filesystem_growth, list_extend_targets,
    list_provisioning_opportunities, parse_growth_size, plan_create, plan_extend,
    CreatePartitionTablePolicy, CreatePurpose, CreateRequest, ExtendRequest,
    FilesystemDecisionState, Growth, PlanStatus,
};
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "storagemgr",
    version,
    about = "Safety-first Linux storage administration"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the normalized storage hierarchy.
    Tree,
    /// Emit the normalized storage graph as JSON.
    Json,
    /// Emit the complete read-only host storage snapshot as JSON.
    Snapshot,
    /// Show detected host storage-tool capabilities.
    Capabilities,
    /// Emit authoritative partition-table data from read-only sfdisk JSON.
    PartitionTables,
    /// Emit the current mount table as normalized JSON.
    Mounts,
    /// Emit /etc/fstab as normalized JSON without changing it.
    Fstab,
    /// Emit active swap areas as normalized JSON.
    Swap,
    /// Emit LVM PV/VG/LV inventory as normalized JSON.
    Lvm,
    /// Run read-only topology and cross-source consistency diagnostics.
    Diagnose,
    /// Explain whether a mount point or block device can be grown with currently known capacity.
    Explain {
        /// Mount point (for example / or /var) or block-device path.
        target: String,
    },
    /// Create a read-only preview; never executes the described operations.
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },
    /// Open the full-screen read-only terminal UI.
    Tui,
}

#[derive(Debug, Subcommand)]
enum PlanCommand {
    /// Preview growing a selected filesystem target.
    Extend {
        /// Exact mountpoint or block-device/LV path.
        target: String,
        /// Additional capacity, e.g. 8GiB; rounded to the storage layer's allocation unit.
        #[arg(long, conflicts_with = "max", required_unless_present = "max")]
        by: Option<String>,
        /// Freeze the request to the maximum currently verified growth path.
        #[arg(long)]
        max: bool,
        /// Emit structured JSON instead of the human-readable preview.
        #[arg(long)]
        json: bool,
    },
    /// List filesystem targets that can be selected for growth planning.
    Targets {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain the discovered storage-layer route for a selected target.
    Route {
        /// Exact mountpoint or block-device/LV path.
        target: String,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain the filesystem execution decision for a selected growth target.
    Filesystem {
        /// Exact mountpoint or block-device/LV path.
        target: String,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// List discovered free-space sources for future create/provision workflows.
    CreateSpaces {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Preview creating a filesystem volume or swap from a discovered free-space source.
    Create {
        /// Stable source ID or unique 16+ character prefix reported by `plan create-spaces`.
        source_id: String,
        /// Requested capacity, e.g. 8GiB; rounded to sectors or LVM extents.
        #[arg(long, conflicts_with = "max", required_unless_present = "max")]
        by: Option<String>,
        /// Use the maximum currently verified capacity of the selected source.
        #[arg(long)]
        max: bool,
        /// Intended use of the new block volume.
        #[arg(long, value_enum)]
        purpose: CreatePurposeArg,
        /// Filesystem type for filesystem purpose: ext4 or xfs.
        #[arg(long)]
        fs: Option<String>,
        /// Optional future mountpoint for filesystem purpose.
        #[arg(long)]
        mount: Option<String>,
        /// Partition-table policy for a blank-disk source.
        #[arg(long, value_enum)]
        partition_table: Option<CreatePartitionTableArg>,
        /// Emit structured JSON instead of the human-readable preview.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CreatePurposeArg {
    Filesystem,
    Swap,
}

impl From<CreatePurposeArg> for CreatePurpose {
    fn from(value: CreatePurposeArg) -> Self {
        match value {
            CreatePurposeArg::Filesystem => CreatePurpose::Filesystem,
            CreatePurposeArg::Swap => CreatePurpose::Swap,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CreatePartitionTableArg {
    Gpt,
    Dos,
}

impl From<CreatePartitionTableArg> for CreatePartitionTablePolicy {
    fn from(value: CreatePartitionTableArg) -> Self {
        match value {
            CreatePartitionTableArg::Gpt => CreatePartitionTablePolicy::Gpt,
            CreatePartitionTableArg::Dos => CreatePartitionTablePolicy::Dos,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Capabilities) => print_capabilities()?,
        Some(Command::Json) => {
            println!("{}", serde_json::to_string_pretty(&discover_storage()?)?);
        }
        Some(Command::Snapshot) => {
            println!("{}", serde_json::to_string_pretty(&discover_snapshot()?)?);
        }
        Some(Command::PartitionTables) => {
            let graph = discover_storage()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&discover_partition_tables(&graph)?)?
            );
        }
        Some(Command::Mounts) => {
            println!("{}", serde_json::to_string_pretty(&discover_mounts()?)?);
        }
        Some(Command::Fstab) => {
            println!("{}", serde_json::to_string_pretty(&discover_fstab()?)?);
        }
        Some(Command::Swap) => {
            println!("{}", serde_json::to_string_pretty(&discover_swaps()?)?);
        }
        Some(Command::Lvm) => {
            println!("{}", serde_json::to_string_pretty(&discover_lvm()?)?);
        }
        Some(Command::Diagnose) => {
            let snapshot = discover_snapshot()?;
            println!("{}", serde_json::to_string_pretty(&snapshot.diagnostics)?);
        }
        Some(Command::Explain { target }) => {
            let snapshot = discover_snapshot()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&analyze_extendability(&snapshot, &target)?)?
            );
        }
        Some(Command::Plan {
            command:
                PlanCommand::Extend {
                    target,
                    by,
                    max,
                    json,
                },
        }) => {
            let growth = match (by, max) {
                (Some(value), false) => Growth::ByBytes(parse_growth_size(&value)?),
                (None, true) => Growth::MaxFree,
                _ => anyhow::bail!("select exactly one of --by or --max"),
            };
            let snapshot = discover_snapshot()?;
            let capabilities = discover_capabilities();
            let plan = plan_extend(&snapshot, &capabilities, ExtendRequest { target, growth })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print!("{}", plan.render_text());
            }
            return Ok(if plan.status() == PlanStatus::Blocked {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            });
        }
        Some(Command::Plan {
            command: PlanCommand::Targets { json },
        }) => {
            let snapshot = discover_snapshot()?;
            let capabilities = discover_capabilities();
            let targets = list_extend_targets(&snapshot, &capabilities);
            if json {
                println!("{}", serde_json::to_string_pretty(&targets)?);
            } else if targets.is_empty() {
                println!("No filesystem targets discovered.");
            } else {
                for target in targets {
                    println!(
                        "{:<18} {:<28} fs={:<10} status={:?} verified={} layout={} blockers={}  {}",
                        target.target,
                        target.device,
                        target.filesystem,
                        target.availability,
                        target
                            .verified_growth_bytes
                            .map(|bytes| bytes.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        target
                            .layout_growth_bytes
                            .map(|bytes| bytes.to_string())
                            .unwrap_or_else(|| "-".to_owned()),
                        if target.blockers.is_empty() {
                            "-".to_owned()
                        } else {
                            target
                                .blockers
                                .iter()
                                .map(|blocker| format!("{}={}", blocker.code, blocker.message))
                                .collect::<Vec<_>>()
                                .join("; ")
                        },
                        target.reason
                    );
                }
            }
        }
        Some(Command::Plan {
            command: PlanCommand::Route { target, json },
        }) => {
            let snapshot = discover_snapshot()?;
            let route = analyze_layer_route(&snapshot, &target);
            if json {
                println!("{}", serde_json::to_string_pretty(&route)?);
            } else {
                println!("Target: {}", route.target);
                println!(
                    "Resolved device: {}",
                    route.resolved_device.as_deref().unwrap_or("-")
                );
                println!("Status: {:?}", route.status);
                if !route.layers.is_empty() {
                    println!("Layers:");
                    for (index, layer) in route.layers.iter().enumerate() {
                        println!(
                            "  {}. {:?}  identity={}  device={}  size={}",
                            index + 1,
                            layer.kind,
                            layer.identity,
                            layer.device.as_deref().unwrap_or("-"),
                            layer
                                .size_bytes
                                .map(|bytes| bytes.to_string())
                                .unwrap_or_else(|| "-".to_owned())
                        );
                    }
                }
                for issue in &route.issues {
                    println!("{:?} [{}]: {}", issue.kind, issue.code, issue.message);
                }
            }
            return Ok(if route.status == lsm_planner::LayerRouteStatus::Blocked {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            });
        }
        Some(Command::Plan {
            command: PlanCommand::Filesystem { target, json },
        }) => {
            let snapshot = discover_snapshot()?;
            let capabilities = discover_capabilities();
            let decision = decide_filesystem_growth(&snapshot, &capabilities, &target);
            if json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                println!("Target: {}", decision.target);
                println!("Device: {}", decision.device.as_deref().unwrap_or("-"));
                println!("Filesystem: {}", decision.fs_type.as_deref().unwrap_or("-"));
                println!("State: {:?}", decision.state);
                if let Some(check) = &decision.read_only_check {
                    println!("Read-only check: {} {}", check.tool, check.args.join(" "));
                    println!("Automatic refresh: {}", check.run_automatically_on_refresh);
                }
                for reason in &decision.reasons {
                    println!("Reason: {reason}");
                }
                for action in &decision.required_actions {
                    println!("Required: {action}");
                }
            }
            return Ok(
                if matches!(
                    decision.state,
                    FilesystemDecisionState::Blocked | FilesystemDecisionState::AdapterRequired
                ) {
                    ExitCode::from(2)
                } else {
                    ExitCode::SUCCESS
                },
            );
        }
        Some(Command::Plan {
            command: PlanCommand::CreateSpaces { json },
        }) => {
            let snapshot = discover_snapshot()?;
            let spaces = list_provisioning_opportunities(&snapshot);
            if json {
                println!("{}", serde_json::to_string_pretty(&spaces)?);
            } else if spaces.is_empty() {
                println!("No verified free-space sources discovered.");
            } else {
                for space in spaces {
                    println!(
                        "{:<14} {:<16} {:<28} available={} advisory_only={} blockers={}",
                        &space.id[..space.id.len().min(16)],
                        format!("{:?}", space.kind),
                        space.source,
                        space.available_bytes,
                        space.advisory_only,
                        if space.blockers.is_empty() {
                            "-".to_owned()
                        } else {
                            space.blockers.join("; ")
                        }
                    );
                }
            }
        }
        Some(Command::Plan {
            command:
                PlanCommand::Create {
                    source_id,
                    by,
                    max,
                    purpose,
                    fs,
                    mount,
                    partition_table,
                    json,
                },
        }) => {
            let size = match (by, max) {
                (Some(value), false) => Growth::ByBytes(parse_growth_size(&value)?),
                (None, true) => Growth::MaxFree,
                _ => anyhow::bail!("select exactly one of --by or --max"),
            };
            let purpose = CreatePurpose::from(purpose);
            if purpose == CreatePurpose::Filesystem && fs.is_none() {
                anyhow::bail!("--fs ext4|xfs is required for --purpose filesystem");
            }
            if purpose == CreatePurpose::Swap && (fs.is_some() || mount.is_some()) {
                anyhow::bail!("--purpose swap does not accept --fs or --mount");
            }
            let snapshot = discover_snapshot()?;
            let plan = plan_create(
                &snapshot,
                CreateRequest {
                    source_id,
                    size,
                    purpose,
                    filesystem: fs,
                    mountpoint: mount,
                    partition_table: partition_table.map(CreatePartitionTablePolicy::from),
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print!("{}", plan.render_text());
            }
            return Ok(if plan.status() == PlanStatus::Blocked {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            });
        }
        Some(Command::Tree) => {
            let graph = discover_storage()?;
            for device in &graph.block_devices {
                print_device(device, 0);
            }
        }
        Some(Command::Tui) | None => {
            let snapshot = discover_snapshot()?;
            let capabilities = discover_capabilities();
            lsm_tui::run(snapshot, capabilities)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_capabilities() -> Result<()> {
    for tool in discover_capabilities().tools {
        println!(
            "{:<12} {}",
            tool.name,
            if tool.available {
                "available"
            } else {
                "missing"
            }
        );
    }
    Ok(())
}

fn print_device(device: &BlockDevice, depth: usize) {
    let indent = "  ".repeat(depth);
    let path = device.path.as_deref().unwrap_or(&device.name);
    let fs = device
        .filesystem
        .as_ref()
        .map(|filesystem| filesystem.fs_type.as_str())
        .unwrap_or("-");
    let mounts = if device.mountpoints.is_empty() {
        "-".to_owned()
    } else {
        device.mountpoints.join(",")
    };
    println!(
        "{indent}{path}  kind={:?} size={} fs={fs} mount={mounts}",
        device.kind, device.size_bytes
    );
    for child in &device.children {
        print_device(child, depth + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_requires_one_size_mode_and_rejects_apply() {
        assert!(Cli::try_parse_from(["storagemgr", "plan", "extend", "/", "--by", "8GiB"]).is_ok());
        assert!(
            Cli::try_parse_from(["storagemgr", "plan", "extend", "/", "--max", "--json"]).is_ok()
        );
        assert!(Cli::try_parse_from(["storagemgr", "plan", "extend", "/"]).is_err());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "extend",
            "/",
            "--max",
            "--by",
            "8GiB"
        ])
        .is_err());
        assert!(
            Cli::try_parse_from(["storagemgr", "plan", "extend", "/", "--max", "--apply"]).is_err()
        );
        assert!(Cli::try_parse_from(["storagemgr", "plan", "targets"]).is_ok());
        assert!(Cli::try_parse_from(["storagemgr", "plan", "targets", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["storagemgr", "plan", "route", "/"]).is_ok());
        assert!(Cli::try_parse_from(["storagemgr", "plan", "filesystem", "/"]).is_ok());
        assert!(
            Cli::try_parse_from(["storagemgr", "plan", "filesystem", "/dev/sda1", "--json"])
                .is_ok()
        );
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "route",
            "/dev/mapper/vg0-root",
            "--json"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["storagemgr", "plan", "create-spaces"]).is_ok());
        assert!(Cli::try_parse_from(["storagemgr", "plan", "create-spaces", "--json"]).is_ok());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "space-test",
            "--by",
            "8GiB",
            "--purpose",
            "filesystem",
            "--fs",
            "ext4",
            "--mount",
            "/data"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "blank-source",
            "--max",
            "--purpose",
            "filesystem",
            "--fs",
            "xfs",
            "--partition-table",
            "gpt"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "blank-source",
            "--max",
            "--purpose",
            "swap",
            "--partition-table",
            "dos"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "blank-source",
            "--max",
            "--purpose",
            "swap",
            "--partition-table",
            "mbr"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "space-test",
            "--max",
            "--purpose",
            "swap",
            "--json"
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "storagemgr",
            "plan",
            "create",
            "space-test",
            "--purpose",
            "filesystem",
            "--fs",
            "ext4"
        ])
        .is_err());
    }
}
