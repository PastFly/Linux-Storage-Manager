use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path};
use std::process::{ExitStatus, Output};

use lsm_discovery::DiscoveryCommandRunner;

use crate::{BackupCaptureError, PrivilegedProgram, TrustedToolError};

/// An allowlisted read-only discovery runner for privileged operation.
pub struct TrustedDiscoveryRunner;

pub fn discover_snapshot_trusted(
) -> Result<lsm_core::HostSnapshot, lsm_discovery::SnapshotDiscoveryError> {
    lsm_discovery::discover_snapshot_with_runner(&TrustedDiscoveryRunner)
}

pub fn discover_capabilities_trusted() -> lsm_core::HostCapabilities {
    lsm_discovery::discover_capabilities_with_runner(&TrustedDiscoveryRunner)
}

fn program(name: &str) -> Option<PrivilegedProgram> {
    use PrivilegedProgram::*;
    Some(match name {
        "lsblk" => Lsblk,
        "findmnt" => Findmnt,
        "blkid" => Blkid,
        "sfdisk" => Sfdisk,
        "partprobe" => Partprobe,
        "udevadm" => Udevadm,
        "pvs" => Pvs,
        "vgs" => Vgs,
        "lvs" => Lvs,
        "pvresize" => Pvresize,
        "pvcreate" => Pvcreate,
        "vgcfgbackup" => Vgcfgbackup,
        "vgcreate" => Vgcreate,
        "vgextend" => Vgextend,
        "lvextend" => Lvextend,
        "lvcreate" => Lvcreate,
        "swapon" => Swapon,
        "swapoff" => Swapoff,
        "mkswap" => Mkswap,
        "mount" => Mount,
        "umount" => Umount,
        "resize2fs" => Resize2fs,
        "e2fsck" => E2fsck,
        "tune2fs" => Tune2fs,
        "xfs_growfs" => XfsGrowfs,
        // xfs_info is a shell script on Ubuntu; use its read-only compiled
        // geometry provider so both the executable and its arguments are pinned.
        "xfs_info" => XfsSpaceman,
        "xfs_scrub" => XfsScrub,
        "xfs_repair" => XfsRepair,
        "mkfs.ext4" => MkfsExt4,
        "mkfs.xfs" => MkfsXfs,
        "cryptsetup" => Cryptsetup,
        "mdadm" => Mdadm,
        "btrfs" => Btrfs,
        "multipath" => Multipath,
        "zpool" => Zpool,
        "zfs" => Zfs,
        _ => return None,
    })
}

fn safe_absolute_path(value: &str, device: bool) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && (!device || path.starts_with("/dev"))
        && !value.chars().any(char::is_control)
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn allowed(program: &str, args: &[&str]) -> bool {
    const COLUMNS: &str = "NAME,KNAME,PATH,TYPE,SIZE,START,LOG-SEC,FSTYPE,FSVER,MOUNTPOINTS,PKNAME,MODEL,SERIAL,UUID,PARTUUID,PTTYPE";
    match (program, args) {
        ("lsblk", ["--json", "--bytes", "--output", COLUMNS]) => true,
        ("findmnt", ["--json", "--bytes", "--output", "SOURCE,TARGET,FSTYPE,OPTIONS"]) => true,
        ("sfdisk", ["--json", path]) => safe_absolute_path(path, true),
        ("tune2fs", ["-l", path]) => safe_absolute_path(path, true),
        ("xfs_info", [path]) => safe_absolute_path(path, false),
        ("xfs_growfs", ["-n", path]) => safe_absolute_path(path, false),
        (name @ ("pvs" | "vgs" | "lvs"), ["--reportformat", "json", "--units", "b", "--nosuffix", "--options", columns]) => {
            match name {
                "pvs" => *columns == "pv_name,pv_uuid,vg_name,pv_size,pv_free,pe_start",
                "vgs" => *columns == "vg_name,vg_uuid,vg_size,vg_free,pv_count,lv_count,vg_extent_size,vg_free_count,vg_missing_pv_count,vg_attr",
                "lvs" => *columns == "lv_name,lv_path,lv_uuid,vg_name,lv_size,lv_attr,lv_layout,lv_role",
                _ => false,
            }
        }
        _ => false,
    }
}

impl DiscoveryCommandRunner for TrustedDiscoveryRunner {
    fn output(&self, name: &str, args: &[&str]) -> io::Result<Output> {
        if !allowed(name, args) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "discovery command is outside the read-only allowlist",
            ));
        }
        let program = program(name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "unsupported discovery utility")
        })?;
        let mut pinned_args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        if name == "xfs_info" {
            pinned_args.splice(0..0, ["-c".to_owned(), "info".to_owned()]);
        }
        let result = crate::backup_capture::run_trusted_read_only_tool(program, pinned_args)
            .map_err(|error| {
                let kind = if matches!(
                    error,
                    BackupCaptureError::TrustedTool(TrustedToolError::NotFound(_))
                ) {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                };
                io::Error::new(kind, error.to_string())
            })?;
        if result.stdout_truncated || result.stderr_truncated {
            return Err(io::Error::other(
                "trusted discovery output exceeded the capture limit",
            ));
        }
        Ok(Output {
            status: ExitStatus::from_raw(result.exit_code << 8),
            stdout: result.stdout,
            stderr: result.stderr,
        })
    }

    fn available(&self, name: &str) -> bool {
        program(name).is_some_and(|program| crate::resolve_trusted_privileged_tool(program).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_commands_and_arguments_outside_read_only_allowlist() {
        for (name, args) in [
            ("sfdisk", vec!["--delete", "/dev/sda"]),
            ("lsblk", vec!["--raw"]),
            ("sfdisk", vec!["--json", "/dev/../etc/passwd"]),
            ("xfs_growfs", vec!["/mnt/data"]),
            ("sh", vec!["-c", "id"]),
        ] {
            let error = TrustedDiscoveryRunner.output(name, &args).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{name}");
        }
    }
}
