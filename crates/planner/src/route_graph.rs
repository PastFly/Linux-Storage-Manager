use lsm_core::{BlockDevice, HostSnapshot, LvmLogicalVolume, NodeKind};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLayerKind {
    Disk,
    Partition,
    LoopDevice,
    Encryption,
    Raid,
    LvmPhysicalVolume,
    LvmVolumeGroup,
    LvmLogicalVolume,
    Filesystem,
    Mount,
    Zram,
    Rom,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIssueKind {
    AdapterRequired,
    Blocker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerRouteStatus {
    SupportedProfile,
    AdapterRequired,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteLayer {
    pub kind: RouteLayerKind,
    pub identity: String,
    pub device: Option<String>,
    pub size_bytes: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteIssue {
    pub kind: RouteIssueKind,
    pub code: String,
    pub message: String,
    pub device: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayerRoute {
    pub target: String,
    pub resolved_device: Option<String>,
    pub mountpoint: Option<String>,
    pub status: LayerRouteStatus,
    pub layers: Vec<RouteLayer>,
    pub issues: Vec<RouteIssue>,
}

pub fn analyze_layer_route(snapshot: &HostSnapshot, target: &str) -> LayerRoute {
    let mut route = LayerRoute {
        target: target.to_owned(),
        resolved_device: None,
        mountpoint: None,
        status: LayerRouteStatus::Blocked,
        layers: Vec::new(),
        issues: Vec::new(),
    };

    if target.is_empty() || target.chars().any(char::is_control) {
        route.issues.push(blocker(
            "invalid-target",
            "target must be a nonempty device path or exact mountpoint",
            None,
        ));
        return route;
    }

    let source = if target.starts_with("/dev/") {
        target.to_owned()
    } else {
        let matches: Vec<_> = snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == target)
            .collect();
        match matches.as_slice() {
            [mount] => {
                route.mountpoint = Some(mount.target.clone());
                let Some(source) = mount.source.clone() else {
                    route.issues.push(blocker(
                        "route-mount-source-missing",
                        "the selected mount has no block-device source",
                        None,
                    ));
                    return route;
                };
                source
            }
            [] => {
                route.issues.push(blocker(
                    "route-target-not-found",
                    "no exact mountpoint or device target could be resolved",
                    None,
                ));
                return route;
            }
            _ => {
                route.issues.push(blocker(
                    "route-target-ambiguous",
                    "more than one mount entry matches the selected target",
                    None,
                ));
                return route;
            }
        }
    };

    let nodes = flatten(&snapshot.storage.block_devices);
    let mut candidates: Vec<&BlockDevice> = nodes
        .iter()
        .copied()
        .filter(|device| node_alias(device, &source))
        .collect();

    if let Some(lvm) = snapshot.lvm.as_ref() {
        for lv in lvm
            .logical_volumes
            .iter()
            .filter(|lv| lv_alias(lv, &source))
        {
            for device in nodes.iter().copied().filter(|device| lv_device(lv, device)) {
                if !candidates
                    .iter()
                    .any(|candidate| std::ptr::eq(*candidate, device))
                {
                    candidates.push(device);
                }
            }
        }
    }

    let device = match candidates.as_slice() {
        [device] => *device,
        [] => {
            route.issues.push(blocker(
                "route-device-not-found",
                "the selected target source does not resolve to one block-device node",
                Some(source),
            ));
            return route;
        }
        _ => {
            route.issues.push(blocker(
                "route-device-ambiguous",
                "the selected target source resolves to multiple block-device nodes",
                Some(source),
            ));
            return route;
        }
    };

    route.resolved_device = Some(device_path(device));
    if route.mountpoint.is_none() {
        let mounts: Vec<_> = snapshot
            .mounts
            .iter()
            .filter(|mount| {
                mount.source.as_deref().is_some_and(|mount_source| {
                    node_alias(device, mount_source)
                        || snapshot.lvm.as_ref().is_some_and(|lvm| {
                            lvm.logical_volumes
                                .iter()
                                .any(|lv| lv_device(lv, device) && lv_alias(lv, mount_source))
                        })
                })
            })
            .collect();
        if let [mount] = mounts.as_slice() {
            route.mountpoint = Some(mount.target.clone());
        } else if mounts.len() > 1 {
            route.issues.push(blocker(
                "route-mount-ambiguous",
                "the resolved device is mounted at multiple active targets",
                Some(device_path(device)),
            ));
        }
    }

    let Some(path) = find_path(&snapshot.storage.block_devices, device) else {
        route.issues.push(blocker(
            "route-parent-chain-missing",
            "the resolved device is not reachable from a storage-graph root",
            Some(device_path(device)),
        ));
        return route;
    };

    for node in path {
        append_block_layer(snapshot, node, &mut route);
    }

    if let Some(filesystem) = device.filesystem.as_ref() {
        if !matches!(filesystem.fs_type.as_str(), "LVM2_member" | "swap") {
            route.layers.push(RouteLayer {
                kind: RouteLayerKind::Filesystem,
                identity: filesystem.fs_type.clone(),
                device: Some(device_path(device)),
                size_bytes: Some(device.size_bytes),
                detail: filesystem
                    .version
                    .as_ref()
                    .map(|version| format!("version={version}")),
            });
            match filesystem.fs_type.as_str() {
                "ext4" | "xfs" => {}
                "btrfs" => route.issues.push(adapter(
                    "btrfs-adapter-required",
                    "Btrfs requires a filesystem-aware growth/provisioning adapter",
                    Some(device_path(device)),
                )),
                "zfs" | "zfs_member" => route.issues.push(adapter(
                    "zfs-adapter-required",
                    "ZFS must be handled through pool/dataset semantics, not generic block resize",
                    Some(device_path(device)),
                )),
                other => route.issues.push(adapter(
                    "filesystem-adapter-required",
                    format!("filesystem {other} has no proven mutation adapter"),
                    Some(device_path(device)),
                )),
            }
        }
    }

    if let Some(mountpoint) = route.mountpoint.clone() {
        route.layers.push(RouteLayer {
            kind: RouteLayerKind::Mount,
            identity: mountpoint,
            device: Some(device_path(device)),
            size_bytes: None,
            detail: None,
        });
    }

    route.status = if route
        .issues
        .iter()
        .any(|issue| issue.kind == RouteIssueKind::Blocker)
    {
        LayerRouteStatus::Blocked
    } else if route
        .issues
        .iter()
        .any(|issue| issue.kind == RouteIssueKind::AdapterRequired)
    {
        LayerRouteStatus::AdapterRequired
    } else {
        LayerRouteStatus::SupportedProfile
    };
    route
}

fn append_block_layer(snapshot: &HostSnapshot, device: &BlockDevice, route: &mut LayerRoute) {
    let path = device_path(device);
    match device.kind {
        NodeKind::Disk => route.layers.push(block_layer(RouteLayerKind::Disk, device)),
        NodeKind::Partition => route
            .layers
            .push(block_layer(RouteLayerKind::Partition, device)),
        NodeKind::Loop => route
            .layers
            .push(block_layer(RouteLayerKind::LoopDevice, device)),
        NodeKind::Crypt => {
            route
                .layers
                .push(block_layer(RouteLayerKind::Encryption, device));
            route.issues.push(adapter(
                "luks-adapter-required",
                "encrypted/device-mapper storage requires an explicit crypt-layer adapter",
                Some(path.clone()),
            ));
        }
        NodeKind::Raid => {
            route.layers.push(block_layer(RouteLayerKind::Raid, device));
            route.issues.push(adapter(
                "raid-adapter-required",
                "RAID capacity propagation requires an explicit array/member adapter",
                Some(path.clone()),
            ));
        }
        NodeKind::Lvm => append_lvm_lv(snapshot, device, route),
        NodeKind::Zram => {
            route.layers.push(block_layer(RouteLayerKind::Zram, device));
            route.issues.push(blocker(
                "zram-not-grow-target",
                "zram is runtime compressed memory storage, not a persistent grow target",
                Some(path.clone()),
            ));
        }
        NodeKind::Rom => {
            route.layers.push(block_layer(RouteLayerKind::Rom, device));
            route.issues.push(blocker(
                "rom-not-grow-target",
                "read-only media is not a grow target",
                Some(path.clone()),
            ));
        }
        NodeKind::Unknown => {
            route
                .layers
                .push(block_layer(RouteLayerKind::Unknown, device));
            route.issues.push(blocker(
                "unknown-layer",
                "unknown block-device layer prevents a proven mutation order",
                Some(path.clone()),
            ));
        }
    }

    if device
        .filesystem
        .as_ref()
        .is_some_and(|filesystem| filesystem.fs_type == "LVM2_member")
    {
        append_lvm_pv_and_vg(snapshot, device, route);
    }
}

fn append_lvm_pv_and_vg(snapshot: &HostSnapshot, device: &BlockDevice, route: &mut LayerRoute) {
    let Some(lvm) = snapshot.lvm.as_ref() else {
        route.issues.push(blocker(
            "lvm-inventory-missing",
            "LVM2 member is present but LVM inventory is unavailable",
            Some(device_path(device)),
        ));
        return;
    };

    let matches: Vec<_> = lvm
        .physical_volumes
        .iter()
        .filter(|pv| node_alias(device, &pv.name))
        .collect();
    let pv = match matches.as_slice() {
        [pv] => *pv,
        [] => {
            route.issues.push(blocker(
                "lvm-pv-not-resolved",
                "LVM2 member does not resolve to one discovered physical volume",
                Some(device_path(device)),
            ));
            return;
        }
        _ => {
            route.issues.push(blocker(
                "lvm-pv-ambiguous",
                "LVM2 member resolves to multiple physical-volume records",
                Some(device_path(device)),
            ));
            return;
        }
    };

    route.layers.push(RouteLayer {
        kind: RouteLayerKind::LvmPhysicalVolume,
        identity: pv.uuid.clone().unwrap_or_else(|| pv.name.clone()),
        device: Some(pv.name.clone()),
        size_bytes: Some(pv.size_bytes),
        detail: pv.vg_name.as_ref().map(|vg_name| format!("vg={vg_name}")),
    });

    let Some(vg_name) = pv.vg_name.as_deref() else {
        return;
    };
    let groups: Vec<_> = lvm
        .volume_groups
        .iter()
        .filter(|vg| vg.name == vg_name)
        .collect();
    match groups.as_slice() {
        [vg] => {
            route.layers.push(RouteLayer {
                kind: RouteLayerKind::LvmVolumeGroup,
                identity: vg.uuid.clone().unwrap_or_else(|| vg.name.clone()),
                device: None,
                size_bytes: Some(vg.size_bytes),
                detail: Some(format!(
                    "name={} pv_count={} lv_count={}",
                    vg.name, vg.pv_count, vg.lv_count
                )),
            });
            if vg.missing_pv_count.unwrap_or(0) > 0 {
                route.issues.push(blocker(
                    "lvm-vg-partial",
                    "volume group reports one or more missing physical volumes",
                    Some(vg.name.clone()),
                ));
            }
            if vg.pv_count > 1 {
                route.issues.push(adapter(
                    "lvm-multi-pv-adapter-required",
                    "multi-PV allocation impact requires a dedicated route adapter",
                    Some(vg.name.clone()),
                ));
            }
            if vg.attributes.as_deref() != Some("wz--n-") {
                route.issues.push(adapter(
                    "lvm-vg-profile-adapter-required",
                    "volume group is outside the proven writable/resizable local profile",
                    Some(vg.name.clone()),
                ));
            }
        }
        [] => route.issues.push(blocker(
            "lvm-vg-not-resolved",
            "physical volume names a volume group that is absent from inventory",
            Some(vg_name.to_owned()),
        )),
        _ => route.issues.push(blocker(
            "lvm-vg-ambiguous",
            "volume-group identity is ambiguous",
            Some(vg_name.to_owned()),
        )),
    }
}

fn append_lvm_lv(snapshot: &HostSnapshot, device: &BlockDevice, route: &mut LayerRoute) {
    let Some(lvm) = snapshot.lvm.as_ref() else {
        route
            .layers
            .push(block_layer(RouteLayerKind::LvmLogicalVolume, device));
        route.issues.push(blocker(
            "lvm-inventory-missing",
            "LVM logical-volume node is present but LVM inventory is unavailable",
            Some(device_path(device)),
        ));
        return;
    };

    let matches: Vec<_> = lvm
        .logical_volumes
        .iter()
        .filter(|lv| lv_device(lv, device))
        .collect();
    let lv = match matches.as_slice() {
        [lv] => *lv,
        [] => {
            route
                .layers
                .push(block_layer(RouteLayerKind::LvmLogicalVolume, device));
            route.issues.push(blocker(
                "lvm-lv-not-resolved",
                "LVM device does not resolve to one logical-volume record",
                Some(device_path(device)),
            ));
            return;
        }
        _ => {
            route
                .layers
                .push(block_layer(RouteLayerKind::LvmLogicalVolume, device));
            route.issues.push(blocker(
                "lvm-lv-ambiguous",
                "LVM device resolves to multiple logical-volume records",
                Some(device_path(device)),
            ));
            return;
        }
    };

    route.layers.push(RouteLayer {
        kind: RouteLayerKind::LvmLogicalVolume,
        identity: lv.uuid.clone().unwrap_or_else(|| lv.name.clone()),
        device: Some(
            lv.path
                .clone()
                .unwrap_or_else(|| format!("/dev/{}/{}", lv.vg_name, lv.name)),
        ),
        size_bytes: Some(lv.size_bytes),
        detail: Some(format!(
            "vg={} layout={} role={}",
            lv.vg_name,
            lv.layout.as_deref().unwrap_or("unknown"),
            lv.role.as_deref().unwrap_or("unknown")
        )),
    });

    if lv.layout.as_deref() != Some("linear")
        || lv.role.as_deref() != Some("public")
        || lv.attributes.as_deref() != Some("-wi-ao----")
    {
        route.issues.push(adapter(
            "lvm-layout-adapter-required",
            "nonstandard, inactive or otherwise unsupported LVM logical-volume profiles require a dedicated adapter",
            Some(device_path(device)),
        ));
    }
}

fn block_layer(kind: RouteLayerKind, device: &BlockDevice) -> RouteLayer {
    RouteLayer {
        kind,
        identity: device
            .uuid
            .clone()
            .or_else(|| device.partition_uuid.clone())
            .unwrap_or_else(|| device_path(device)),
        device: Some(device_path(device)),
        size_bytes: Some(device.size_bytes),
        detail: device.model.clone(),
    }
}

fn find_path<'a>(
    devices: &'a [BlockDevice],
    target: &'a BlockDevice,
) -> Option<Vec<&'a BlockDevice>> {
    for device in devices {
        if std::ptr::eq(device, target) {
            return Some(vec![device]);
        }
        if let Some(mut child_path) = find_path(&device.children, target) {
            let mut path = Vec::with_capacity(child_path.len() + 1);
            path.push(device);
            path.append(&mut child_path);
            return Some(path);
        }
    }
    None
}

fn flatten(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    let mut nodes = Vec::new();
    for device in devices {
        nodes.push(device);
        nodes.extend(flatten(&device.children));
    }
    nodes
}

fn device_path(device: &BlockDevice) -> String {
    device.path.clone().unwrap_or_else(|| device.name.clone())
}

fn node_alias(device: &BlockDevice, alias: &str) -> bool {
    device.path.as_deref() == Some(alias)
        || device
            .kernel_name
            .as_ref()
            .is_some_and(|name| format!("/dev/{name}") == alias)
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

fn lv_device(lv: &LvmLogicalVolume, device: &BlockDevice) -> bool {
    device
        .path
        .as_deref()
        .is_some_and(|path| lv_alias(lv, path))
}

fn adapter(code: &str, message: impl Into<String>, device: Option<String>) -> RouteIssue {
    RouteIssue {
        kind: RouteIssueKind::AdapterRequired,
        code: code.to_owned(),
        message: message.into(),
        device,
    }
}

fn blocker(code: &str, message: impl Into<String>, device: Option<String>) -> RouteIssue {
    RouteIssue {
        kind: RouteIssueKind::Blocker,
        code: code.to_owned(),
        message: message.into(),
        device,
    }
}
