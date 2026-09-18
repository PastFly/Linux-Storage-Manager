use anyhow::Result;
use clap::{Parser, Subcommand};
use lsm_core::BlockDevice;
use lsm_discovery::{
    analyze_extendability, discover_capabilities, discover_fstab, discover_lvm, discover_mounts,
    discover_partition_tables, discover_snapshot, discover_storage, discover_swaps,
};
use lsm_planner::{parse_growth_size, plan_extend, ExtendRequest, Growth, PlanStatus};
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
    /// Preview growing a mounted linear LV using only existing VG free extents.
    Extend {
        /// Exact mountpoint or LV path.
        target: String,
        /// Additional capacity, e.g. 8GiB; rounded up to whole extents.
        #[arg(long, conflicts_with = "max", required_unless_present = "max")]
        by: Option<String>,
        /// Freeze the request to all currently reported free VG extents.
        #[arg(long)]
        max: bool,
        /// Emit structured JSON instead of the human-readable preview.
        #[arg(long)]
        json: bool,
    },
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
        Some(Command::Tree) => {
            let graph = discover_storage()?;
            for device in &graph.block_devices {
                print_device(device, 0);
            }
        }
        Some(Command::Tui) | None => {
            let snapshot = discover_snapshot()?;
            let capabilities = discover_capabilities();
            lsm_tui::run(&snapshot, &capabilities)?;
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
    }
}
