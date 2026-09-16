use lsm_core::{
    BlockDevice, ExtendAnalysis, ExtendabilityStatus, HostSnapshot, LvmLogicalVolume, NodeKind,
};
use thiserror::Error;

const LSBLK_START_SECTOR_BYTES: u64 = 512;
const GPT_TAIL_RESERVED_SECTORS: u64 = 34;

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
        return Ok(base_analysis(
            target,
            device_name,
            None,
            device.size_bytes,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec!["no filesystem type was discovered for the target device".to_owned()],
            Vec::new(),
        ));
    };

    if !matches!(fs_type, "ext4" | "xfs") {
        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::UnsupportedFilesystem,
            None,
            None,
            vec![format!(
                "filesystem `{fs_type}` is not in the first supported grow set (ext4, XFS)"
            )],
            Vec::new(),
        ));
    }

    match device.kind {
        NodeKind::Lvm => analyze_lvm_target(snapshot, target, device, fs_type),
        NodeKind::Partition => Ok(analyze_partition_target(snapshot, target, device, fs_type)),
        _ => Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsGeometry,
            None,
            None,
            vec![
                "the target is not a directly supported LVM or partition growth topology"
                    .to_owned(),
            ],
            vec![
                "inspect the lower block-device layers before planning growth".to_owned(),
                format!("grow the {fs_type} filesystem only after its block device is enlarged"),
            ],
        )),
    }
}

fn analyze_lvm_target(
    snapshot: &HostSnapshot,
    target: &str,
    device: &BlockDevice,
    fs_type: &str,
) -> Result<ExtendAnalysis, ExtendAnalysisError> {
    let device_name = device
        .path
        .clone()
        .unwrap_or_else(|| device.name.clone());

    let Some(lvm) = snapshot.lvm.as_ref() else {
        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec![
                "the target is an LVM device, but the LVM inventory collector is unavailable or failed"
                    .to_owned(),
            ],
            Vec::new(),
        ));
    };

    let Some(lv) = lvm
        .logical_volumes
        .iter()
        .find(|lv| logical_volume_matches_device(lv, device))
    else {
        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec![
                "lsblk identifies the target as LVM, but no matching logical volume was found in the LVM inventory"
                    .to_owned(),
            ],
            Vec::new(),
        ));
    };

    let Some(vg) = lvm.volume_groups.iter().find(|vg| vg.name == lv.vg_name) else {
        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec![format!(
                "logical volume `{}/{}` references volume group `{}`, but that VG is absent from the inventory",
                lv.vg_name, lv.name, lv.vg_name
            )],
            Vec::new(),
        ));
    };

    if vg.free_bytes > 0 {
        let status = if fs_type == "xfs" && device.mountpoints.is_empty() {
            ExtendabilityStatus::RequiresMount
        } else {
            ExtendabilityStatus::Ready
        };

        let mut reasons = vec![format!(
            "volume group `{}` has {} bytes of free extents available without changing the underlying partition layout",
            vg.name, vg.free_bytes
        )];
        let mut steps = vec![
            format!(
                "use up to {} bytes of free extents from volume group `{}`",
                vg.free_bytes, vg.name
            ),
            format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
        ];

        if status == ExtendabilityStatus::RequiresMount {
            reasons.push(
                "XFS growth is performed on a mounted filesystem, but this device is not currently mounted"
                    .to_owned(),
            );
            steps.push("mount the XFS filesystem at its intended mount point".to_owned());
        }
        steps.push(format!("grow the {fs_type} filesystem"));
        steps.push("re-discover storage and verify the resulting size".to_owned());

        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            status,
            Some(vg.free_bytes),
            None,
            reasons,
            steps,
        ));
    }

    let capacity = analyze_vg_underlying_capacity(snapshot, &vg.name);

    if capacity.bytes > 0 {
        let mut steps = vec![
            format!(
                "grow the LVM PV partition(s) with detected adjacent capacity (conservative upper bound: {} bytes)",
                capacity.bytes
            ),
            "resize the affected LVM physical volume(s)".to_owned(),
            format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
        ];
        if fs_type == "xfs" && device.mountpoints.is_empty() {
            steps.push("mount the XFS filesystem at its intended mount point".to_owned());
        }
        steps.push(format!("grow the {fs_type} filesystem"));
        steps.push("re-discover storage and verify every layer".to_owned());

        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsUnderlyingResize,
            Some(0),
            Some(capacity.bytes),
            vec![format!(
                "volume group `{}` has no free extents, but {} bytes of adjacent partition capacity were detected below its PVs",
                vg.name, capacity.bytes
            )],
            steps,
        ));
    }

    if !capacity.complete {
        return Ok(base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsGeometry,
            Some(0),
            None,
            vec![format!(
                "volume group `{}` has no free extents and the lower-layer geometry could not be fully resolved",
                vg.name
            )],
            vec![
                "complete lower-layer partition geometry discovery".to_owned(),
                "verify whether an LVM PV partition has adjacent free space".to_owned(),
            ],
        ));
    }

    Ok(base_analysis(
        target,
        device_name,
        Some(fs_type.to_owned()),
        device.size_bytes,
        ExtendabilityStatus::NeedsUnderlyingCapacity,
        Some(0),
        Some(0),
        vec![format!(
            "volume group `{}` has no free extents and no adjacent partition capacity was detected below its PVs",
            vg.name
        )],
        vec![
            "increase the virtual/physical disk size or attach another disk".to_owned(),
            "make the new capacity available to the volume group".to_owned(),
            format!("extend logical volume `{}/{}`", lv.vg_name, lv.name),
            format!("grow the {fs_type} filesystem"),
        ],
    ))
}

fn analyze_partition_target(
    snapshot: &HostSnapshot,
    target: &str,
    device: &BlockDevice,
    fs_type: &str,
) -> ExtendAnalysis {
    let device_name = device
        .path
        .clone()
        .unwrap_or_else(|| device.name.clone());

    match adjacent_free_after_partition(&snapshot.storage.block_devices, device) {
        Some(bytes) if bytes > 0 => base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsUnderlyingResize,
            None,
            Some(bytes),
            vec![format!(
                "{} bytes of adjacent capacity were detected after the target partition",
                bytes
            )],
            vec![
                "grow the partition into verified adjacent free space".to_owned(),
                format!("grow the {fs_type} filesystem"),
                "re-discover storage and verify the resulting size".to_owned(),
            ],
        ),
        Some(_) => base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsUnderlyingCapacity,
            None,
            Some(0),
            vec!["no adjacent free space was detected after the target partition".to_owned()],
            vec!["increase the underlying disk or rearrange storage outside the M0 scope".to_owned()],
        ),
        None => base_analysis(
            target,
            device_name,
            Some(fs_type.to_owned()),
            device.size_bytes,
            ExtendabilityStatus::NeedsGeometry,
            None,
            None,
            vec![
                "partition start or parent geometry is incomplete, so adjacent capacity cannot be calculated safely"
                    .to_owned(),
            ],
            vec!["complete lower-layer partition geometry discovery".to_owned()],
        ),
    }
}

struct UnderlyingCapacity {
    bytes: u64,
    complete: bool,
}

fn analyze_vg_underlying_capacity(snapshot: &HostSnapshot, vg_name: &str) -> UnderlyingCapacity {
    let Some(lvm) = snapshot.lvm.as_ref() else {
        return UnderlyingCapacity {
            bytes: 0,
            complete: false,
        };
    };

    let pvs: Vec<_> = lvm
        .physical_volumes
        .iter()
        .filter(|pv| pv.vg_name.as_deref() == Some(vg_name))
        .collect();

    if pvs.is_empty() {
        return UnderlyingCapacity {
            bytes: 0,
            complete: false,
        };
    }

    let mut bytes = 0_u64;
    let mut complete = true;

    for pv in pvs {
        let Some(device) = find_by_alias(&snapshot.storage.block_devices, &pv.name) else {
            complete = false;
            continue;
        };

        if device.kind != NodeKind::Partition {
            complete = false;
            continue;
        }

        match adjacent_free_after_partition(&snapshot.storage.block_devices, device) {
            Some(free) => bytes = bytes.saturating_add(free),
            None => complete = false,
        }
    }

    UnderlyingCapacity { bytes, complete }
}

fn adjacent_free_after_partition(devices: &[BlockDevice], target: &BlockDevice) -> Option<u64> {
    for parent in devices {
        if parent.kind == NodeKind::Disk && is_direct_child(parent, target) {
            return adjacent_free_in_disk(parent, target);
        }

        if let Some(value) = adjacent_free_after_partition(&parent.children, target) {
            return Some(value);
        }
    }
    None
}

fn is_direct_child(parent: &BlockDevice, target: &BlockDevice) -> bool {
    parent
        .children
        .iter()
        .any(|child| same_device(child, target))
}

fn adjacent_free_in_disk(disk: &BlockDevice, target: &BlockDevice) -> Option<u64> {
    let target_start_sector = target.start_512_sector?;
    let target_start_bytes = target_start_sector.checked_mul(LSBLK_START_SECTOR_BYTES)?;
    let target_end_bytes = target_start_bytes.checked_add(target.size_bytes)?;

    let next_partition_start = disk
        .children
        .iter()
        .filter(|child| child.kind == NodeKind::Partition && !same_device(child, target))
        .filter_map(|child| {
            child
                .start_512_sector
                .and_then(|start| start.checked_mul(LSBLK_START_SECTOR_BYTES))
        })
        .filter(|start| *start >= target_end_bytes)
        .min();

    let usable_disk_end = if next_partition_start.is_some() {
        disk.size_bytes
    } else if disk.partition_table.as_deref() == Some("gpt") {
        let logical_sector_bytes = disk.logical_sector_bytes.or(target.logical_sector_bytes)?;
        disk.size_bytes.saturating_sub(
            GPT_TAIL_RESERVED_SECTORS.saturating_mul(logical_sector_bytes),
        )
    } else {
        disk.size_bytes
    };

    let limit = next_partition_start.unwrap_or(usable_disk_end).min(usable_disk_end);
    Some(limit.saturating_sub(target_end_bytes))
}

fn same_device(left: &BlockDevice, right: &BlockDevice) -> bool {
    match (left.path.as_deref(), right.path.as_deref()) {
        (Some(left), Some(right)) => left == right,
        _ => left.kernel_name == right.kernel_name && left.name == right.name,
    }
}

fn base_analysis(
    target: &str,
    device: String,
    filesystem: Option<String>,
    current_size_bytes: u64,
    status: ExtendabilityStatus,
    immediate_growth_bytes: Option<u64>,
    potential_underlying_growth_bytes: Option<u64>,
    reasons: Vec<String>,
    steps: Vec<String>,
) -> ExtendAnalysis {
    ExtendAnalysis {
        target: target.to_owned(),
        device: Some(device),
        filesystem,
        current_size_bytes: Some(current_size_bytes),
        immediate_growth_bytes,
        potential_underlying_growth_bytes,
        status,
        reasons,
        steps,
    }
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
