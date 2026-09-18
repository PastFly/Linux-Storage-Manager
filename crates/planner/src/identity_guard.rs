use lsm_core::{BlockDevice, HostSnapshot, LvmLogicalVolume, NodeKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{analyze_layer_route, LayerRouteStatus};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetIdentityManifest {
    pub schema_version: u32,
    pub target: String,
    pub manifest_digest: String,
    pub resolved_device: String,
    pub route_status: LayerRouteStatus,
    pub route_issue_codes: Vec<String>,
    pub devices: Vec<DeviceIdentity>,
    pub partitions: Vec<PartitionGeometryIdentity>,
    pub lvm: Vec<LvmIdentity>,
    pub filesystem: Option<FilesystemIdentity>,
    pub mounts: Vec<MountIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceIdentity {
    pub kind: NodeKind,
    pub path: String,
    pub kernel_name: Option<String>,
    pub parent_kernel_name: Option<String>,
    pub size_bytes: u64,
    pub start_512_sector: Option<u64>,
    pub logical_sector_bytes: Option<u64>,
    pub uuid: Option<String>,
    pub partition_uuid: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub filesystem_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartitionGeometryIdentity {
    pub partition: String,
    pub disk: Option<String>,
    pub table_label: Option<String>,
    pub table_id: Option<String>,
    pub sector_size_bytes: Option<u64>,
    pub start_sector: Option<u64>,
    pub size_sectors: Option<u64>,
    pub record_uuid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LvmIdentityKind {
    PhysicalVolume,
    VolumeGroup,
    LogicalVolume,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LvmIdentity {
    pub kind: LvmIdentityKind,
    pub name: String,
    pub uuid: Option<String>,
    pub size_bytes: u64,
    pub free_bytes: Option<u64>,
    pub extent_size_bytes: Option<u64>,
    pub free_extent_count: Option<u64>,
    pub pv_count: Option<u64>,
    pub lv_count: Option<u64>,
    pub attributes: Option<String>,
    pub layout: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesystemIdentity {
    pub device: String,
    pub fs_type: String,
    pub fs_version: Option<String>,
    pub uuid: Option<String>,
    pub backing_device_size_bytes: u64,
    pub observed_filesystem_size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MountIdentity {
    pub target: String,
    pub source: Option<String>,
    pub fs_type: Option<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityChange {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IdentityRevalidation {
    pub matches: bool,
    pub baseline_digest: String,
    pub fresh_digest: Option<String>,
    pub changes: Vec<IdentityChange>,
}

#[derive(Debug, Error)]
pub enum IdentityGuardError {
    #[error("target route could not resolve one device")]
    UnresolvedTarget,
    #[error("resolved target device is absent from the storage graph")]
    ResolvedDeviceMissing,
    #[error("could not serialize target identity manifest: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn capture_target_identity(
    snapshot: &HostSnapshot,
    target: &str,
) -> Result<TargetIdentityManifest, IdentityGuardError> {
    let route = analyze_layer_route(snapshot, target);
    let resolved_device = route
        .resolved_device
        .clone()
        .ok_or(IdentityGuardError::UnresolvedTarget)?;

    let nodes = flatten(&snapshot.storage.block_devices);
    let device = nodes
        .iter()
        .copied()
        .find(|device| device_path(device) == resolved_device)
        .ok_or(IdentityGuardError::ResolvedDeviceMissing)?;
    let path = find_path(&snapshot.storage.block_devices, device)
        .ok_or(IdentityGuardError::ResolvedDeviceMissing)?;

    let devices = path
        .iter()
        .map(|device| DeviceIdentity {
            kind: device.kind,
            path: device_path(device),
            kernel_name: device.kernel_name.clone(),
            parent_kernel_name: device.parent_kernel_name.clone(),
            size_bytes: device.size_bytes,
            start_512_sector: device.start_512_sector,
            logical_sector_bytes: device.logical_sector_bytes,
            uuid: device.uuid.clone(),
            partition_uuid: device.partition_uuid.clone(),
            model: device.model.clone(),
            serial: device.serial.clone(),
            filesystem_type: device
                .filesystem
                .as_ref()
                .map(|filesystem| filesystem.fs_type.clone()),
        })
        .collect::<Vec<_>>();

    let mut partitions = path
        .iter()
        .filter(|device| device.kind == NodeKind::Partition)
        .map(|device| partition_identity(snapshot, device))
        .collect::<Vec<_>>();
    partitions.sort_by(|left, right| left.partition.cmp(&right.partition));

    let mut lvm = collect_lvm_identity(snapshot, &path);
    lvm.sort_by(|left, right| {
        format!("{:?}", left.kind)
            .cmp(&format!("{:?}", right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });

    let filesystem = device.filesystem.as_ref().and_then(|filesystem| {
        if matches!(filesystem.fs_type.as_str(), "LVM2_member" | "swap") {
            None
        } else {
            let path = device_path(device);
            let matching_evidence = snapshot
                .filesystem_preflight
                .iter()
                .filter(|evidence| {
                    evidence.device == path
                        && evidence.fs_type == filesystem.fs_type
                        && route.mountpoint.as_deref().is_none_or(|mountpoint| {
                            evidence.mountpoint.as_deref() == Some(mountpoint)
                        })
                })
                .collect::<Vec<_>>();
            let observed_filesystem_size_bytes = if matching_evidence.len() == 1 {
                matching_evidence
                    .first()
                    .and_then(|evidence| evidence.size_bytes)
            } else {
                None
            };

            Some(FilesystemIdentity {
                device: path,
                fs_type: filesystem.fs_type.clone(),
                fs_version: filesystem.version.clone(),
                uuid: device.uuid.clone(),
                backing_device_size_bytes: device.size_bytes,
                observed_filesystem_size_bytes,
            })
        }
    });

    let mut mounts = snapshot
        .mounts
        .iter()
        .filter(|mount| {
            route
                .mountpoint
                .as_deref()
                .is_some_and(|mountpoint| mount.target == mountpoint)
                || mount.source.as_deref().is_some_and(|source| {
                    node_alias(device, source)
                        || snapshot.lvm.as_ref().is_some_and(|inventory| {
                            inventory
                                .logical_volumes
                                .iter()
                                .any(|lv| lv_device(lv, device) && lv_alias(lv, source))
                        })
                })
        })
        .map(|mount| {
            let mut options = mount.options.clone();
            options.sort();
            MountIdentity {
                target: mount.target.clone(),
                source: mount.source.clone(),
                fs_type: mount.fs_type.clone(),
                options,
            }
        })
        .collect::<Vec<_>>();
    mounts.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.source.cmp(&right.source))
    });

    let mut route_issue_codes = route
        .issues
        .iter()
        .map(|issue| issue.code.clone())
        .collect::<Vec<_>>();
    route_issue_codes.sort();

    let mut manifest = TargetIdentityManifest {
        schema_version: 1,
        target: target.to_owned(),
        manifest_digest: String::new(),
        resolved_device,
        route_status: route.status,
        route_issue_codes,
        devices,
        partitions,
        lvm,
        filesystem,
        mounts,
    };
    manifest.manifest_digest = fingerprint(&manifest)?;
    Ok(manifest)
}

pub fn revalidate_target_identity(
    baseline: &TargetIdentityManifest,
    fresh_snapshot: &HostSnapshot,
) -> IdentityRevalidation {
    let fresh = match capture_target_identity(fresh_snapshot, &baseline.target) {
        Ok(fresh) => fresh,
        Err(error) => {
            return IdentityRevalidation {
                matches: false,
                baseline_digest: baseline.manifest_digest.clone(),
                fresh_digest: None,
                changes: vec![IdentityChange {
                    code: "fresh-target-unresolved".to_owned(),
                    message: error.to_string(),
                }],
            };
        }
    };

    if baseline.manifest_digest == fresh.manifest_digest {
        return IdentityRevalidation {
            matches: true,
            baseline_digest: baseline.manifest_digest.clone(),
            fresh_digest: Some(fresh.manifest_digest),
            changes: Vec::new(),
        };
    }

    let mut changes = Vec::new();
    compare_field(
        &mut changes,
        "resolved-device-changed",
        "resolved target device changed",
        &baseline.resolved_device,
        &fresh.resolved_device,
    );
    compare_field(
        &mut changes,
        "route-status-changed",
        "storage route support state changed",
        &baseline.route_status,
        &fresh.route_status,
    );
    compare_field(
        &mut changes,
        "route-issues-changed",
        "storage route diagnostics changed",
        &baseline.route_issue_codes,
        &fresh.route_issue_codes,
    );
    compare_field(
        &mut changes,
        "device-chain-changed",
        "one or more target block-device identities/capacities changed",
        &baseline.devices,
        &fresh.devices,
    );
    compare_field(
        &mut changes,
        "partition-geometry-changed",
        "target partition-table geometry or identity changed",
        &baseline.partitions,
        &fresh.partitions,
    );
    compare_field(
        &mut changes,
        "lvm-identity-changed",
        "target PV/VG/LV identity or allocation facts changed",
        &baseline.lvm,
        &fresh.lvm,
    );
    compare_field(
        &mut changes,
        "filesystem-identity-changed",
        "target filesystem identity/type/version/capacity changed",
        &baseline.filesystem,
        &fresh.filesystem,
    );
    compare_field(
        &mut changes,
        "mount-identity-changed",
        "target mount source/options changed",
        &baseline.mounts,
        &fresh.mounts,
    );

    if changes.is_empty() {
        changes.push(IdentityChange {
            code: "manifest-digest-changed".to_owned(),
            message: "target identity manifest changed in an unclassified field".to_owned(),
        });
    }

    IdentityRevalidation {
        matches: false,
        baseline_digest: baseline.manifest_digest.clone(),
        fresh_digest: Some(fresh.manifest_digest),
        changes,
    }
}

fn partition_identity(snapshot: &HostSnapshot, device: &BlockDevice) -> PartitionGeometryIdentity {
    let partition = device_path(device);
    let mut matches = snapshot.partition_tables.iter().filter_map(|table| {
        table
            .partitions
            .iter()
            .find(|record| record.node == partition)
            .map(|record| (table, record))
    });

    let first = matches.next();
    if matches.next().is_some() {
        return PartitionGeometryIdentity {
            partition,
            disk: None,
            table_label: None,
            table_id: None,
            sector_size_bytes: None,
            start_sector: None,
            size_sectors: None,
            record_uuid: device.partition_uuid.clone(),
        };
    }

    let Some((table, record)) = first else {
        return PartitionGeometryIdentity {
            partition,
            disk: device
                .parent_kernel_name
                .as_ref()
                .map(|parent| format!("/dev/{parent}")),
            table_label: device.partition_table.clone(),
            table_id: None,
            sector_size_bytes: device.logical_sector_bytes,
            start_sector: device.start_512_sector,
            size_sectors: None,
            record_uuid: device.partition_uuid.clone(),
        };
    };

    PartitionGeometryIdentity {
        partition,
        disk: Some(table.device.clone()),
        table_label: table.label.clone(),
        table_id: table.id.clone(),
        sector_size_bytes: table.sector_size_bytes,
        start_sector: Some(record.start_sector),
        size_sectors: Some(record.size_sectors),
        record_uuid: record
            .uuid
            .clone()
            .or_else(|| device.partition_uuid.clone()),
    }
}

fn collect_lvm_identity(snapshot: &HostSnapshot, path: &[&BlockDevice]) -> Vec<LvmIdentity> {
    let Some(inventory) = snapshot.lvm.as_ref() else {
        return Vec::new();
    };
    let mut identities = Vec::new();
    let mut volume_groups = Vec::<String>::new();

    for device in path {
        if device
            .filesystem
            .as_ref()
            .is_some_and(|filesystem| filesystem.fs_type == "LVM2_member")
        {
            for pv in inventory
                .physical_volumes
                .iter()
                .filter(|pv| node_alias(device, &pv.name))
            {
                identities.push(LvmIdentity {
                    kind: LvmIdentityKind::PhysicalVolume,
                    name: pv.name.clone(),
                    uuid: pv.uuid.clone(),
                    size_bytes: pv.size_bytes,
                    free_bytes: Some(pv.free_bytes),
                    extent_size_bytes: None,
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: None,
                    layout: None,
                    role: None,
                });
                if let Some(vg_name) = pv.vg_name.clone() {
                    if !volume_groups.contains(&vg_name) {
                        volume_groups.push(vg_name);
                    }
                }
            }
        }

        if device.kind == NodeKind::Lvm {
            for lv in inventory
                .logical_volumes
                .iter()
                .filter(|lv| lv_device(lv, device))
            {
                identities.push(LvmIdentity {
                    kind: LvmIdentityKind::LogicalVolume,
                    name: lv
                        .path
                        .clone()
                        .unwrap_or_else(|| format!("/dev/{}/{}", lv.vg_name, lv.name)),
                    uuid: lv.uuid.clone(),
                    size_bytes: lv.size_bytes,
                    free_bytes: None,
                    extent_size_bytes: None,
                    free_extent_count: None,
                    pv_count: None,
                    lv_count: None,
                    attributes: lv.attributes.clone(),
                    layout: lv.layout.clone(),
                    role: lv.role.clone(),
                });
                if !volume_groups.contains(&lv.vg_name) {
                    volume_groups.push(lv.vg_name.clone());
                }
            }
        }
    }

    for vg_name in volume_groups {
        for vg in inventory
            .volume_groups
            .iter()
            .filter(|vg| vg.name == vg_name)
        {
            identities.push(LvmIdentity {
                kind: LvmIdentityKind::VolumeGroup,
                name: vg.name.clone(),
                uuid: vg.uuid.clone(),
                size_bytes: vg.size_bytes,
                free_bytes: Some(vg.free_bytes),
                extent_size_bytes: vg.extent_size_bytes,
                free_extent_count: vg.free_extent_count,
                pv_count: Some(vg.pv_count),
                lv_count: Some(vg.lv_count),
                attributes: vg.attributes.clone(),
                layout: None,
                role: None,
            });
        }
    }
    identities
}

fn compare_field<T: PartialEq>(
    changes: &mut Vec<IdentityChange>,
    code: &str,
    message: &str,
    baseline: &T,
    fresh: &T,
) {
    if baseline != fresh {
        changes.push(IdentityChange {
            code: code.to_owned(),
            message: message.to_owned(),
        });
    }
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
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
