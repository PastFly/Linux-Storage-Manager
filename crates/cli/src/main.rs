use anyhow::Result;
use clap::{Parser, Subcommand};
use lsm_core::BlockDevice;
use lsm_discovery::{
    diagnose_storage, discover_capabilities, discover_fstab, discover_lvm, discover_mounts,
    discover_storage, discover_swaps,
};

#[derive(Debug, Parser)]
#[command(name = "storagemgr", version, about = "Safety-first Linux storage administration")]
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
    /// Show detected host storage-tool capabilities.
    Capabilities,
    /// Emit the current mount table as normalized JSON.
    Mounts,
    /// Emit /etc/fstab as normalized JSON without changing it.
    Fstab,
    /// Emit active swap areas as normalized JSON.
    Swap,
    /// Emit LVM PV/VG/LV inventory as normalized JSON.
    Lvm,
    /// Run read-only topology consistency diagnostics.
    Diagnose,
    /// Open the full-screen read-only terminal UI.
    Tui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Capabilities) => print_capabilities(),
        Some(Command::Json) => {
            let graph = discover_storage()?;
            println!("{}", serde_json::to_string_pretty(&graph)?);
            Ok(())
        }
        Some(Command::Mounts) => {
            println!("{}", serde_json::to_string_pretty(&discover_mounts()?)?);
            Ok(())
        }
        Some(Command::Fstab) => {
            println!("{}", serde_json::to_string_pretty(&discover_fstab()?)?);
            Ok(())
        }
        Some(Command::Swap) => {
            println!("{}", serde_json::to_string_pretty(&discover_swaps()?)?);
            Ok(())
        }
        Some(Command::Lvm) => {
            println!("{}", serde_json::to_string_pretty(&discover_lvm()?)?);
            Ok(())
        }
        Some(Command::Diagnose) => {
            let graph = discover_storage()?;
            println!("{}", serde_json::to_string_pretty(&diagnose_storage(&graph))?);
            Ok(())
        }
        Some(Command::Tree) => {
            let graph = discover_storage()?;
            for device in &graph.block_devices {
                print_device(device, 0);
            }
            Ok(())
        }
        Some(Command::Tui) | None => {
            let graph = discover_storage()?;
            let capabilities = discover_capabilities();
            lsm_tui::run(&graph, &capabilities)
        }
    }
}

fn print_capabilities() -> Result<()> {
    for tool in discover_capabilities().tools {
        println!(
            "{:<12} {}",
            tool.name,
            if tool.available { "available" } else { "missing" }
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
