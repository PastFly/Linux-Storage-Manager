use std::io::ErrorKind;
use std::process::{Command, Output};

use lsm_core::{BlockDevice, FilesystemPreflightEvidence, FilesystemProbeState, StorageGraph};

pub fn discover_filesystem_preflight(storage: &StorageGraph) -> Vec<FilesystemPreflightEvidence> {
    let mut evidence = Vec::new();
    for device in flatten(&storage.block_devices) {
        let Some(filesystem) = device.filesystem.as_ref() else {
            continue;
        };
        match filesystem.fs_type.as_str() {
            "ext4" => evidence.push(probe_ext4(device)),
            "xfs" => evidence.push(probe_xfs(device)),
            _ => {}
        }
    }
    evidence
}

fn probe_ext4(device: &BlockDevice) -> FilesystemPreflightEvidence {
    let device_name = device.path.clone().unwrap_or_else(|| device.name.clone());
    let mountpoint = first_real_mountpoint(device);
    let Some(path) = device.path.as_deref() else {
        return evidence(
            device_name,
            mountpoint,
            "ext4",
            device.filesystem.as_ref().and_then(|fs| fs.version.clone()),
            FilesystemProbeState::Partial,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            Some(
                "ext4 block-device path is unavailable; tune2fs metadata probe was not run".into(),
            ),
        );
    };

    match Command::new("tune2fs").args(["-l", path]).output() {
        Ok(output) if output.status.success() => {
            let parsed = parse_tune2fs_list(&String::from_utf8_lossy(&output.stdout));
            evidence(
                device_name,
                mountpoint,
                "ext4",
                device.filesystem.as_ref().and_then(|fs| fs.version.clone()),
                FilesystemProbeState::Verified,
                parsed.filesystem_state,
                parsed.revision,
                parsed.features,
                parsed.block_size_bytes,
                parsed.block_count,
                parsed.size_bytes(),
                None,
                Some(
                    "read-only ext4 superblock metadata collected; a dedicated health check is still required before execution"
                        .into(),
                ),
            )
        }
        Ok(output) => evidence(
            device_name,
            mountpoint,
            "ext4",
            device.filesystem.as_ref().and_then(|fs| fs.version.clone()),
            FilesystemProbeState::Failed,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            Some(command_failure("tune2fs -l", &output)),
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => evidence(
            device_name,
            mountpoint,
            "ext4",
            device.filesystem.as_ref().and_then(|fs| fs.version.clone()),
            FilesystemProbeState::Unavailable,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            Some("tune2fs is unavailable; ext4 superblock metadata was not probed".into()),
        ),
        Err(error) => evidence(
            device_name,
            mountpoint,
            "ext4",
            device.filesystem.as_ref().and_then(|fs| fs.version.clone()),
            FilesystemProbeState::Failed,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            Some(format!("tune2fs -l could not be executed: {error}")),
        ),
    }
}

fn probe_xfs(device: &BlockDevice) -> FilesystemPreflightEvidence {
    let device_name = device.path.clone().unwrap_or_else(|| device.name.clone());
    let fs_version = device.filesystem.as_ref().and_then(|fs| fs.version.clone());
    let Some(mountpoint) = first_real_mountpoint(device) else {
        return evidence(
            device_name,
            None,
            "xfs",
            fs_version,
            FilesystemProbeState::Partial,
            None,
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            Some(
                "XFS is not mounted; xfs_growfs requires a mounted filesystem, so dry-run growth validation was not attempted"
                    .into(),
            ),
        );
    };

    let info = Command::new("xfs_info").arg(&mountpoint).output();
    let grow = Command::new("xfs_growfs")
        .args(["-n", mountpoint.as_str()])
        .output();

    let mut features = Vec::new();
    let mut block_size_bytes = None;
    let mut block_count = None;
    let mut size_bytes = None;
    let mut details = Vec::new();
    let info_ok = match info {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            features = parse_xfs_info_features(&text);
            let geometry = parse_xfs_info_geometry(&text);
            block_size_bytes = geometry.block_size_bytes;
            block_count = geometry.block_count;
            size_bytes = geometry.size_bytes();
            true
        }
        Ok(output) => {
            details.push(command_failure("xfs_info", &output));
            false
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            details.push("xfs_info is unavailable".into());
            false
        }
        Err(error) => {
            details.push(format!("xfs_info could not be executed: {error}"));
            false
        }
    };

    let grow_check_passed = match grow {
        Ok(output) if output.status.success() => Some(true),
        Ok(output) => {
            details.push(command_failure("xfs_growfs -n", &output));
            Some(false)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            details.push("xfs_growfs is unavailable".into());
            None
        }
        Err(error) => {
            details.push(format!("xfs_growfs -n could not be executed: {error}"));
            Some(false)
        }
    };

    let state = if info_ok && grow_check_passed == Some(true) {
        FilesystemProbeState::Verified
    } else if info_ok || grow_check_passed == Some(true) {
        FilesystemProbeState::Partial
    } else if grow_check_passed.is_none()
        && details.iter().all(|detail| detail.contains("unavailable"))
    {
        FilesystemProbeState::Unavailable
    } else {
        FilesystemProbeState::Failed
    };

    if state == FilesystemProbeState::Verified {
        details.push(
            "xfs_info succeeded and xfs_growfs -n completed without modifying the filesystem"
                .into(),
        );
    }

    evidence(
        device_name,
        Some(mountpoint),
        "xfs",
        fs_version,
        state,
        None,
        None,
        features,
        block_size_bytes,
        block_count,
        size_bytes,
        grow_check_passed,
        (!details.is_empty()).then(|| details.join("; ")),
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence(
    device: String,
    mountpoint: Option<String>,
    fs_type: &str,
    fs_version: Option<String>,
    state: FilesystemProbeState,
    filesystem_state: Option<String>,
    revision: Option<String>,
    features: Vec<String>,
    block_size_bytes: Option<u64>,
    block_count: Option<u64>,
    size_bytes: Option<u64>,
    grow_check_passed: Option<bool>,
    detail: Option<String>,
) -> FilesystemPreflightEvidence {
    FilesystemPreflightEvidence {
        device,
        mountpoint,
        fs_type: fs_type.to_owned(),
        fs_version,
        state,
        filesystem_state,
        revision,
        features,
        block_size_bytes,
        block_count,
        size_bytes,
        grow_check_passed,
        detail,
    }
}

fn first_real_mountpoint(device: &BlockDevice) -> Option<String> {
    device
        .mountpoints
        .iter()
        .find(|mountpoint| mountpoint.as_str() != "[SWAP]")
        .cloned()
}

fn command_failure(command: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("{command} failed with status {}", output.status)
    } else {
        format!("{command} failed with status {}: {stderr}", output.status)
    }
}

fn flatten(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    let mut nodes = Vec::new();
    for device in devices {
        nodes.push(device);
        nodes.extend(flatten(&device.children));
    }
    nodes
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Ext4Superblock {
    filesystem_state: Option<String>,
    revision: Option<String>,
    features: Vec<String>,
    block_size_bytes: Option<u64>,
    block_count: Option<u64>,
}

impl Ext4Superblock {
    fn size_bytes(&self) -> Option<u64> {
        self.block_size_bytes?.checked_mul(self.block_count?)
    }
}

fn parse_tune2fs_list(input: &str) -> Ext4Superblock {
    let mut parsed = Ext4Superblock::default();
    for line in input.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Filesystem state" => parsed.filesystem_state = nonempty(value),
            "Filesystem revision #" => parsed.revision = nonempty(value),
            "Filesystem features" => {
                parsed.features = value.split_whitespace().map(str::to_owned).collect();
            }
            "Block size" => parsed.block_size_bytes = value.parse::<u64>().ok(),
            "Block count" => parsed.block_count = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    parsed
}

fn parse_xfs_info_features(input: &str) -> Vec<String> {
    const FEATURE_KEYS: &[&str] = &[
        "crc",
        "finobt",
        "sparse",
        "rmapbt",
        "reflink",
        "bigtime",
        "inobtcount",
        "nrext64",
        "exchange",
        "metadir",
        "ftype",
        "ascii-ci",
    ];

    let mut features = Vec::new();
    for raw in input.split_whitespace() {
        let token = raw.trim_matches(',');
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        if FEATURE_KEYS.contains(&key) {
            let normalized = format!("{key}={}", value.trim_matches(','));
            if !features.contains(&normalized) {
                features.push(normalized);
            }
        }
    }
    features.sort();
    features
}

#[derive(Debug, Default, PartialEq, Eq)]
struct XfsGeometry {
    block_size_bytes: Option<u64>,
    block_count: Option<u64>,
}

impl XfsGeometry {
    fn size_bytes(&self) -> Option<u64> {
        self.block_size_bytes?.checked_mul(self.block_count?)
    }
}

fn parse_xfs_info_geometry(input: &str) -> XfsGeometry {
    let mut geometry = XfsGeometry::default();
    let Some(line) = input
        .lines()
        .find(|line| line.trim_start().starts_with("data"))
    else {
        return geometry;
    };

    for raw in line.split_whitespace() {
        let token = raw.trim_matches(',');
        if let Some(value) = token.strip_prefix("bsize=") {
            geometry.block_size_bytes = value.trim_matches(',').parse::<u64>().ok();
        } else if let Some(value) = token.strip_prefix("blocks=") {
            geometry.block_count = value.trim_matches(',').parse::<u64>().ok();
        }
    }
    geometry
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ext4_superblock_state_revision_and_features() {
        let parsed = parse_tune2fs_list(
            "Filesystem UUID:          deadbeef\n\
             Filesystem revision #:    1 (dynamic)\n\
             Filesystem features:      has_journal ext_attr resize_inode extent 64bit metadata_csum\n\
             Block count:              262144\n\
             Block size:               4096\n\
             Filesystem state:         clean\n",
        );

        assert_eq!(parsed.filesystem_state.as_deref(), Some("clean"));
        assert_eq!(parsed.revision.as_deref(), Some("1 (dynamic)"));
        assert_eq!(parsed.block_count, Some(262144));
        assert_eq!(parsed.block_size_bytes, Some(4096));
        assert_eq!(parsed.size_bytes(), Some(1_073_741_824));
        assert_eq!(
            parsed.features,
            vec![
                "has_journal",
                "ext_attr",
                "resize_inode",
                "extent",
                "64bit",
                "metadata_csum"
            ]
        );
    }

    #[test]
    fn parses_known_xfs_feature_flags_without_geometry_noise() {
        let features = parse_xfs_info_features(
            "meta-data=/dev/vda1 isize=512 agcount=4, agsize=65536 blks\n\
             = sectsz=512 attr=2, projid32bit=1\n\
             = crc=1 finobt=1, sparse=1, rmapbt=0 reflink=1\n\
             data = bsize=4096 blocks=262144, imaxpct=25\n\
             naming =version 2 bsize=4096 ascii-ci=0, ftype=1\n\
             log =internal bsize=4096 blocks=16384, version=2\n\
             = bigtime=1 inobtcount=1 nrext64=0 exchange=0 metadir=0\n",
        );
        let geometry = parse_xfs_info_geometry(
            "meta-data=/dev/vda1 isize=512 agcount=4, agsize=65536 blks\n\
             = sectsz=512 attr=2, projid32bit=1\n\
             = crc=1 finobt=1, sparse=1, rmapbt=0 reflink=1\n\
             data = bsize=4096 blocks=262144, imaxpct=25\n\
             naming =version 2 bsize=4096 ascii-ci=0, ftype=1\n\
             log =internal bsize=4096 blocks=16384, version=2\n\
             = bigtime=1 inobtcount=1 nrext64=0 exchange=0 metadir=0\n",
        );
        assert_eq!(geometry.block_count, Some(262144));
        assert_eq!(geometry.block_size_bytes, Some(4096));
        assert_eq!(geometry.size_bytes(), Some(1_073_741_824));

        assert_eq!(
            features,
            vec![
                "ascii-ci=0",
                "bigtime=1",
                "crc=1",
                "exchange=0",
                "finobt=1",
                "ftype=1",
                "inobtcount=1",
                "metadir=0",
                "nrext64=0",
                "reflink=1",
                "rmapbt=0",
                "sparse=1"
            ]
        );
    }
}
