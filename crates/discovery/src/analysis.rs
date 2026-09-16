use lsm_core::{
    BlockDevice, ExtendAnalysis, ExtendabilityStatus, HostSnapshot, LvmLogicalVolume, NodeKind,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtendAnalysisError {
    #[error("storage target `{0}` was not found in the discovered topology")]
    TargetNotFound(String),
}

pub fn analyze_extendability(
    snapshot: &HostSnapshot,
    target: &str,
) -> Result<ExtendAnalysis, ExtendAnalysisError> {
    let device = find_target_device(snapshot, target)
        .ok_or_else(|| ExtendAnalysisError::TargetNotFound(target.to_owned()))?;

    let device_name = device
        .path
        .clone()
        .unwrap_or_else(|| device.name.clone());
    let filesystem = device
        .filesystem
        .as_ref()
        .map(|filesystem| filesystem.fs_type.clone());

    let Some(fs_type) = filesystem.as_deref() else {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: None,
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::Unknown,
            reasons: vec!["no filesystem type was discovered for the target device".to_owned()],
            steps: Vec::new(),
        });
    };

    if !matches!(fs_type, "ext4" | "xfs") {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::UnsupportedFilesystem,
            reasons: vec![format!(
                "filesystem `{fs_type}` is not in the first supported grow set (ext4, XFS)"
            )],
            steps: Vec::new(),
        });
    }

    if device.kind != NodeKind::Lvm {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::NeedsGeometry,
            reasons: vec![
                "target is not an LVM logical volume; safe partition-tail analysis requires partition geometry that M0 does not yet collect"
                    .to_owned(),
            ],
            steps: vec![
                "collect partition start/end geometry and parent-disk sector size".to_owned(),
                "verify that adjacent free space exists after the target partition".to_owned(),
                format!("grow the {fs_type} filesystem only after the block device is safely enlarged"),
            ],
        });
    }

    let Some(lvm) = snapshot.lvm.as_ref() else {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::Unknown,
            reasons: vec![
                "the target is an LVM device, but the LVM inventory collector is unavailable or failed"
                    .to_owned(),
            ],
            steps: Vec::new(),
        });
    };

    let Some(lv) = lvm
        .logical_volumes
        .iter()
        .find(|lv| logical_volume_matches_device(lv, device))
    else {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::Unknown,
            reasons: vec![
                "lsblk identifies the target as LVM, but no matching logical volume was found in the LVM inventory"
                    .to_owned(),
            ],
            steps: Vec::new(),
        });
    };

    let Some(vg) = lvm.volume_groups.iter().find(|vg| vg.name == lv.vg_name) else {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: None,
            status: ExtendabilityStatus::Unknown,
            reasons: vec![format!(
                "logical volume `{}/{}` references volume group `{}`, but that VG is absent from the inventory",
                lv.vg_name, lv.name, lv.vg_name
            )],
            steps: Vec::new(),
        });
    };

    if vg.free_bytes == 0 {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: Some(0),
            status: ExtendabilityStatus::NeedsUnderlyingCapacity,
            reasons: vec![format!(
                "volume group `{}` currently has no free extents",
                vg.name
            )],
            steps: vec![
                "find or create additional capacity below the volume group".to_owned(),
                "increase an existing LVM physical volume or add another physical volume"
                    .to_owned(),
                format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
                format!("grow the {fs_type} filesystem"),
            ],
        });
    }

    if fs_type == "xfs" && device.mountpoints.is_empty() {
        return Ok(ExtendAnalysis {
            target: target.to_owned(),
            device: Some(device_name),
            filesystem: Some(fs_type.to_owned()),
            current_size_bytes: Some(device.size_bytes),
            immediate_growth_bytes: Some(vg.free_bytes),
            status: ExtendabilityStatus::RequiresMount,
            reasons: vec![
                "XFS has immediate LVM capacity available, but XFS growth is performed on a mounted filesystem"
                    .to_owned(),
            ],
            steps: vec![
                format!(
                    "use up to {} bytes of free extents from volume group `{}`",
                    vg.free_bytes, vg.name
                ),
                format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
                "mount the XFS filesystem at its intended mount point".to_owned(),
                "grow the mounted XFS filesystem".to_owned(),
            ],
        });
    }

    Ok(ExtendAnalysis {
        target: target.to_owned(),
        device: Some(device_name),
        filesystem: Some(fs_type.to_owned()),
        current_size_bytes: Some(device.size_bytes),
        immediate_growth_bytes: Some(vg.free_bytes),
        status: ExtendabilityStatus::Ready,
        reasons: vec![format!(
            "volume group `{}` has {} bytes of free extents available without changing the underlying partition layout",
            vg.name, vg.free_bytes
        )],
        steps: vec![
            format!(
                "use up to {} bytes of free extents from volume group `{}`",
                vg.free_bytes, vg.name
            ),
            format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
            format!("grow the {fs_type} filesystem"),
            "re-discover storage and verify the resulting size".to_owned(),
        ],
    })
}

fn find_target_device<'a>(snapshot: &'a HostSnapshot, target: &str) -> Option<&'a BlockDevice> {
    if target.starts_with("/dev/") {
        return find_by_alias(&snapshot.storage.block_devices, target);
    }

    if let Some(device) = find_by_mountpoint(&snapshot.storage.block_devices, target) {
        return Some(device);
    }

    snapshot
        .mounts
        .iter()
        .find(|mount| mount.target == target)
        .and_then(|mount| mount.source.as_deref())
        .and_then(|source| resolve_source(snapshot, source))
}

fn resolve_source<'a>(snapshot: &'a HostSnapshot, source: &str) -> Option<&'a BlockDevice> {
    if let Some(device) = find_by_alias(&snapshot.storage.block_devices, source) {
        return Some(device);
    }

    snapshot.lvm.as_ref().and_then(|lvm| {
        lvm.logical_volumes
            .iter()
            .find(|lv| logical_volume_aliases(lv).iter().any(|alias| alias == source))
            .and_then(|lv| {
                logical_volume_aliases(lv)
                    .iter()
                    .find_map(|alias| find_by_alias(&snapshot.storage.block_devices, alias))
            })
    })
}

fn find_by_mountpoint<'a>(devices: &'a [BlockDevice], target: &str) -> Option<&'a BlockDevice> {
    for device in devices {
        if device.mountpoints.iter().any(|mountpoint| mountpoint == target) {
            return Some(device);
        }
        if let Some(found) = find_by_mountpoint(&device.children, target) {
            return Some(found);
        }
    }
    None
}

fn find_by_alias<'a>(devices: &'a [BlockDevice], alias: &str) -> Option<&'a BlockDevice> {
    for device in devices {
        let direct_match = device.path.as_deref() == Some(alias)
            || device
                .kernel_name
                .as_deref()
                .map(|name| format!("/dev/{name}") == alias)
                .unwrap_or(false)
            || format!("/dev/{}", device.name) == alias;

        if direct_match {
            return Some(device);
        }
        if let Some(found) = find_by_alias(&device.children, alias) {
            return Some(found);
        }
    }
    None
}

fn logical_volume_matches_device(lv: &LvmLogicalVolume, device: &BlockDevice) -> bool {
    logical_volume_aliases(lv).iter().any(|alias| {
        device.path.as_deref() == Some(alias.as_str())
            || format!("/dev/{}", device.name) == *alias
    })
}

fn logical_volume_aliases(lv: &LvmLogicalVolume) -> Vec<String> {
    let mut aliases = Vec::new();
    if let Some(path) = &lv.path {
        aliases.push(path.clone());
    }
    aliases.push(format!(
        "/dev/mapper/{}-{}",
        dm_escape(&lv.vg_name),
        dm_escape(&lv.name)
    ));
    aliases
}

fn dm_escape(value: &str) -> String {
    value.replace('-', "--")
}
