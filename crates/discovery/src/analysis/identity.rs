//! Pure snapshot resolution. Paths are evidence, not proof of live device identity.
//! Duplicate tree occurrences are refused until the model has canonical graph identities.

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, LvmLogicalVolume, NodeKind};

#[derive(Debug)]
pub(super) enum ResolutionFailure {
    NotFound,
    Refused(&'static str),
}

use ResolutionFailure::{NotFound, Refused};

pub(super) fn unique<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let value = items.next()?;
    if items.next().is_some() {
        None
    } else {
        Some(value)
    }
}

fn complete(snapshot: &HostSnapshot, component: &str) -> Result<(), ResolutionFailure> {
    let status = unique(
        snapshot
            .collectors
            .iter()
            .filter(|c| c.component == component),
    )
    .ok_or(Refused(
        "required collector evidence is absent or duplicated",
    ))?;
    if status.state != CollectorState::Complete {
        return Err(Refused("required collector did not complete successfully"));
    }
    Ok(())
}

pub(super) fn resolve_target<'a>(
    snapshot: &'a HostSnapshot,
    target: &str,
) -> Result<&'a BlockDevice, ResolutionFailure> {
    if !target.starts_with('/') || target == "/dev/" || target.chars().any(char::is_control) {
        return Err(Refused(
            "target must be an absolute path without control characters",
        ));
    }
    complete(snapshot, "lsblk")?;
    let device = if target.starts_with("/dev/") {
        resolve_source(snapshot, target)?
    } else {
        complete(snapshot, "mounts")?;
        let mut rows = snapshot.mounts.iter().filter(|m| m.target == target);
        let row = match rows.next() {
            Some(row) if rows.next().is_none() => row,
            Some(_) => return Err(Refused("mountpoint has multiple active mount records")),
            None => {
                if nodes(&snapshot.storage.block_devices)
                    .iter()
                    .any(|d| d.mountpoints.iter().any(|point| point == target))
                {
                    return Err(Refused(
                        "lsblk mountpoint has no matching active mount record",
                    ));
                }
                return Err(NotFound);
            }
        };
        let source = row
            .source
            .as_deref()
            .ok_or(Refused("mount source is absent"))?;
        resolve_source(snapshot, source).map_err(|_| {
            Refused("mount source cannot be resolved uniquely from snapshot evidence")
        })?
    };
    confirm_mounts(snapshot, device)?;
    Ok(device)
}

pub(super) fn resolve_source<'a>(
    snapshot: &'a HostSnapshot,
    source: &str,
) -> Result<&'a BlockDevice, ResolutionFailure> {
    if !source.starts_with("/dev/")
        || source == "/dev/"
        || source.chars().any(char::is_control)
        || source.contains('[')
        || source.contains(']')
    {
        return Err(Refused(
            "unsupported or invalid device source; no path rewriting is performed",
        ));
    }
    let matching_lvs: Vec<_> = snapshot
        .lvm
        .as_ref()
        .into_iter()
        .flat_map(|lvm| &lvm.logical_volumes)
        .filter(|lv| lv_alias(lv, source))
        .collect();
    if matching_lvs.len() > 1 {
        return Err(Refused(
            "device alias matches multiple logical-volume records",
        ));
    }
    let via_lvm = matching_lvs.first().copied();
    if via_lvm.is_some() {
        complete(snapshot, "lvm")?;
    }

    // Enumerate nodes once, so direct and LVM aliases for the SAME occurrence are
    // not counted twice. Distinct occurrences, even identical copies, are ambiguous.
    let all = nodes(&snapshot.storage.block_devices);
    let mut candidates = all.iter().copied().filter(|d| {
        node_alias(d, source) || via_lvm.is_some_and(|lv| logical_volume_matches_device(lv, d))
    });
    let device = candidates.next().ok_or(NotFound)?;
    if candidates.next().is_some() {
        return Err(Refused(
            "device source matches multiple block-device occurrences",
        ));
    }
    if let Some(kernel_name) = device.kernel_name.as_deref() {
        if kernel_name.is_empty()
            || all
                .iter()
                .filter(|d| d.kernel_name.as_deref() == Some(kernel_name))
                .count()
                != 1
        {
            return Err(Refused(
                "kernel device identity is empty or duplicated in the snapshot",
            ));
        }
    }
    if via_lvm.is_some() && device.kind != NodeKind::Lvm {
        return Err(Refused(
            "LVM alias conflicts with the reported block-device kind",
        ));
    }
    if device.kind == NodeKind::Lvm {
        complete(snapshot, "lvm")?;
        let lvm = snapshot
            .lvm
            .as_ref()
            .ok_or(Refused("LVM inventory is absent"))?;
        let lv = unique(
            lvm.logical_volumes
                .iter()
                .filter(|lv| logical_volume_matches_device(lv, device)),
        )
        .ok_or(Refused(
            "LVM device has missing or duplicated logical-volume identity evidence",
        ))?;
        if via_lvm.is_some_and(|other| !std::ptr::eq(lv, other)) {
            return Err(Refused(
                "direct and LVM aliases disagree on logical-volume identity",
            ));
        }
    }
    Ok(device)
}

fn confirm_mounts(snapshot: &HostSnapshot, device: &BlockDevice) -> Result<(), ResolutionFailure> {
    // An empty mount table is meaningful only after successful discovery.
    complete(snapshot, "mounts")?;
    let all = nodes(&snapshot.storage.block_devices);
    for target in &device.mountpoints {
        let mount = unique(snapshot.mounts.iter().filter(|m| m.target == *target)).ok_or(
            Refused("device mountpoint has missing or duplicated active mount evidence"),
        )?;
        let owner = unique(
            all.iter()
                .copied()
                .filter(|d| d.mountpoints.iter().any(|p| p == target)),
        )
        .ok_or(Refused(
            "mountpoint is claimed by multiple block-device occurrences",
        ))?;
        let source = mount
            .source
            .as_deref()
            .ok_or(Refused("mount source is absent"))?;
        let resolved = resolve_source(snapshot, source)
            .map_err(|_| Refused("active mount source is unresolved or ambiguous"))?;
        if !std::ptr::eq(owner, device) || !std::ptr::eq(resolved, device) {
            return Err(Refused(
                "lsblk and active mount sources disagree on the target device",
            ));
        }
        if mount.fs_type.as_deref() != device.filesystem.as_ref().map(|fs| fs.fs_type.as_str()) {
            return Err(Refused("lsblk and active mount filesystem types disagree"));
        }
        if !mount.options.iter().any(|o| o == "rw")
            || mount
                .options
                .iter()
                .any(|o| matches!(o.as_str(), "ro" | "bind" | "rbind"))
        {
            return Err(Refused(
                "read-write non-bind mount evidence is required for growth advice",
            ));
        }
    }
    // Check the reverse direction too: findmnt-only claims must not appear unmounted.
    for mount in &snapshot.mounts {
        let Some(source) = mount.source.as_deref() else {
            continue;
        };
        if let Ok(resolved) = resolve_source(snapshot, source) {
            if std::ptr::eq(resolved, device) && !device.mountpoints.contains(&mount.target) {
                return Err(Refused(
                    "active mount is absent from the target's lsblk mountpoints",
                ));
            }
        }
    }
    Ok(())
}

fn node_alias(device: &BlockDevice, alias: &str) -> bool {
    device.path.as_deref() == Some(alias)
        || device.kernel_name.as_deref().is_some_and(|name| {
            !name.is_empty() && !name.contains('/') && format!("/dev/{name}") == alias
        })
}

fn lv_alias(lv: &LvmLogicalVolume, alias: &str) -> bool {
    lv.path.as_deref() == Some(alias)
        || format!("/dev/{}/{}", lv.vg_name, lv.name) == alias
        || format!(
            "/dev/mapper/{}-{}",
            lv.vg_name.replace('-', "--"),
            lv.name.replace('-', "--")
        ) == alias
}

pub(super) fn logical_volume_matches_device(lv: &LvmLogicalVolume, device: &BlockDevice) -> bool {
    device
        .path
        .as_deref()
        .is_some_and(|path| lv_alias(lv, path))
}

fn nodes(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    let mut result = Vec::new();
    for device in devices {
        result.push(device);
        result.extend(nodes(&device.children));
    }
    result
}
