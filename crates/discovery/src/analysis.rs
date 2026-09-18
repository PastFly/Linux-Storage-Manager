mod geometry;
mod identity;

use identity::{logical_volume_matches_device, unique, ResolutionFailure};

use std::collections::BTreeSet;

use lsm_core::{
    BlockDevice, DiagnosticSeverity, ExtendAnalysis, ExtendabilityStatus, HostSnapshot,
    NodeKind,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtendAnalysisError {
    #[error("storage target {0:?} was not found in the discovered topology")]
    TargetNotFound(String),
}

pub fn analyze_extendability(
    snapshot: &HostSnapshot,
    target: &str,
) -> Result<ExtendAnalysis, ExtendAnalysisError> {
    let device = match identity::resolve_target(snapshot, target) {
        Ok(device) => device,
        Err(ResolutionFailure::NotFound) => {
            return Err(ExtendAnalysisError::TargetNotFound(target.to_owned()));
        }
        Err(ResolutionFailure::Refused(reason)) => {
            return Ok(ExtendAnalysis {
                target: target.to_owned(),
                device: None,
                filesystem: None,
                current_size_bytes: None,
                immediate_growth_bytes: None,
                potential_underlying_growth_bytes: None,
                status: ExtendabilityStatus::Unknown,
                reasons: vec![reason.to_owned(), "Advisory only; no device was selected and no operations are proposed.".to_owned()],
                steps: Vec::new(),
            });
        }
    };

    let filesystem = device
        .filesystem
        .as_ref()
        .map(|filesystem| filesystem.fs_type.clone());

    // A contradictory snapshot must not yield a capacity claim, even for LVM free space.
    if snapshot
        .diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
    {
        return Ok(base_analysis(
            target,
            device,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec!["error-level diagnostics invalidate this advisory analysis".to_owned()],
            Vec::new(),
        ));
    }

    let Some(fs_type) = filesystem.as_deref() else {
        return Ok(base_analysis(
            target,
            device,
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
            device,
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
            device,
            ExtendabilityStatus::NeedsGeometry,
            None,
            None,
            vec![
                "the target is not a directly supported LVM or partition growth topology".to_owned(),
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
    let Some(lvm) = snapshot.lvm.as_ref() else {
        return Ok(base_analysis(
            target,
            device,
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

    let Some(lv) = unique(lvm.logical_volumes.iter().filter(|lv| logical_volume_matches_device(lv, device))) else {
        return Ok(base_analysis(
            target,
            device,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec![
                "lsblk identifies the target as LVM, but no unique matching logical volume was found in the LVM inventory"
                    .to_owned(),
            ],
            Vec::new(),
        ));
    };

    let Some(vg) = unique(lvm.volume_groups.iter().filter(|vg| vg.name == lv.vg_name)) else {
        return Ok(base_analysis(
            target,
            device,
            ExtendabilityStatus::Unknown,
            None,
            None,
            vec![format!(
                "logical volume `{}/{}` references volume group `{}`, but that VG is absent or duplicated in the inventory",
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
            device,
            status,
            Some(vg.free_bytes),
            None,
            reasons,
            steps,
        ));
    }

    let capacity = analyze_vg_underlying_capacity(snapshot, &vg.name);

    if capacity.complete && capacity.bytes > 0 {
        let mut steps = vec![
            format!(
                "grow the LVM PV partition(s) with detected adjacent capacity (partition-table-bounded estimate: {} bytes)",
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
            device,
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
            device,
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
        device,
        ExtendabilityStatus::NeedsUnderlyingCapacity,
        Some(0),
        Some(0),
        vec![format!(
            "volume group `{}` has no free extents and no adjacent partition capacity was detected below its PVs",
            vg.name
        )],
        vec![
            "inspect existing PV container capacity and GPT placement before adding capacity".to_owned(),
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
    match geometry::adjacent_capacity(snapshot, device) {
        Some(bytes) if bytes > 0 => base_analysis(
            target,
            device,
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
            device,
            ExtendabilityStatus::NeedsUnderlyingCapacity,
            None,
            Some(0),
            vec!["no adjacent free space exists inside the reported table bounds; GPT relocation and unused capacity inside the current partition are not assessed".to_owned()],
            vec!["inspect current container capacity and GPT placement before adding a disk; M0 does not modify either".to_owned()],
        ),
        None => base_analysis(
            target,
            device,
            ExtendabilityStatus::NeedsGeometry,
            None,
            None,
            vec![
                "partition-table evidence is incomplete, ambiguous, unsupported or inconsistent with lsblk; no capacity is claimed"
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

    let expected_pvs = unique(lvm.volume_groups.iter().filter(|vg| vg.name == vg_name))
        .map(|vg| vg.pv_count);
    if pvs.is_empty() || expected_pvs != u64::try_from(pvs.len()).ok() {
        return UnderlyingCapacity {
            bytes: 0,
            complete: false,
        };
    }

    let mut bytes = 0_u64;
    let mut complete = true;

    let mut seen_pvs = BTreeSet::new();
    let mut seen_devices = BTreeSet::new();
    let mut seen_uuids = BTreeSet::new();
    for pv in pvs {
        if !seen_pvs.insert(pv.name.as_str()) {
            complete = false;
            continue;
        }
        let Ok(device) = identity::resolve_source(snapshot, &pv.name) else {
            complete = false;
            continue;
        };

        let valid_identity = match (device.path.as_deref(), pv.uuid.as_deref()) {
            (Some(path), Some(uuid)) if !uuid.is_empty() => {
                seen_devices.insert(path)
                    && seen_uuids.insert(uuid)
                    && device.uuid.as_deref() == Some(uuid)
            }
            _ => false,
        };
        if device.kind != NodeKind::Partition || !valid_identity {
            complete = false;
            continue;
        }

        match geometry::adjacent_capacity(snapshot, device) {
            Some(free) => match bytes.checked_add(free) {
                Some(total) => bytes = total,
                None => complete = false,
            },
            None => complete = false,
        }
    }

    UnderlyingCapacity { bytes, complete }
}

fn base_analysis(
    target: &str,
    device: &BlockDevice,
    status: ExtendabilityStatus,
    immediate_growth_bytes: Option<u64>,
    potential_underlying_growth_bytes: Option<u64>,
    reasons: Vec<String>,
    steps: Vec<String>,
) -> ExtendAnalysis {
    let mut reasons = reasons;
    reasons.push("Advisory only: no writes, no filesystem health check, no execution authorization. Use plan extend for the stricter nonexecutable preview.".to_owned());
    ExtendAnalysis {
        target: target.to_owned(),
        device: Some(device.path.clone().unwrap_or_else(|| device.name.clone())),
        filesystem: device.filesystem.as_ref().map(|fs| fs.fs_type.clone()),
        current_size_bytes: Some(device.size_bytes),
        immediate_growth_bytes,
        potential_underlying_growth_bytes,
        status,
        reasons,
        steps,
    }
}
