//! Read-only, in-memory plan previews. No process, filesystem or device I/O.
//! A preview is NOT an executable plan or authorization to modify storage.

use lsm_core::{
    BlockDevice, CollectorState, DiagnosticSeverity, HostCapabilities, HostSnapshot,
    LvmLogicalVolume, NodeKind,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Growth {
    ByBytes(u64),
    MaxFree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendRequest {
    pub target: String,
    pub growth: Growth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Preview,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    NotApplicable,
    Reversible,
    Irreversible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Operation {
    RevalidateSnapshot,
    BackupLvmMetadata {
        vg_uuid: String,
    },
    ExtendLogicalVolume {
        lv_uuid: String,
        additional_extents: u64,
        expected_lv_size_bytes: u64,
    },
    GrowFilesystem {
        fs_type: String,
        mountpoint: String,
    },
    RediscoverAndVerify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    pub id: u32,
    pub depends_on: Vec<u32>,
    pub operation: Operation,
    pub reversibility: Reversibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SizeChange {
    pub device: String,
    pub current_lv_size_bytes: u64,
    pub requested_growth_bytes: u64,
    pub rounded_growth_bytes: u64,
    pub expected_lv_size_bytes: u64,
    pub extent_size_bytes: u64,
    pub remaining_vg_free_bytes: u64,
}

// Private fields, no setters and deliberately no Deserialize implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanPreview {
    schema_version: u32,
    plan_id: String,
    snapshot_digest: String,
    dry_run: bool,
    executable: bool,
    status: PlanStatus,
    request: ExtendRequest,
    size_change: Option<SizeChange>,
    blockers: Vec<Blocker>,
    steps: Vec<PlanStep>,
    notices: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PlannerError {
    #[error("could not serialize planner input: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("size must be a positive whole number followed by B, KiB, MiB, GiB or TiB")]
    InvalidSize,
    #[error("size is outside the supported u64 byte range")]
    SizeOverflow,
}

impl PlanPreview {
    pub fn status(&self) -> PlanStatus {
        self.status
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    pub fn blockers(&self) -> &[Blocker] {
        &self.blockers
    }

    pub fn size_change(&self) -> Option<&SizeChange> {
        self.size_change.as_ref()
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// Exact-input freshness check only. Does not validate runtime safety or authorize writes.
    /// Any array ordering or usage change can conservatively invalidate this preview.
    pub fn matches_basis(
        &self,
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> Result<bool, PlannerError> {
        Ok(self.status == PlanStatus::Preview
            && self.snapshot_digest == fingerprint(&(snapshot, capabilities))?)
    }

    pub fn render_text(&self) -> String {
        let mut text = format!(
            "DRY RUN ONLY - no commands executed; not an execution authorization\n\
             Plan: {}\nStatus: {:?}\nTarget: {:?}\n",
            self.plan_id, self.status, self.request.target
        );
        if let Some(size) = &self.size_change {
            text.push_str(&format!(
                "LV size: {} -> {} bytes\nRequested growth: {} bytes\n\
                 Extent-aligned growth: {} bytes\nVG free after preview: {} bytes\n",
                size.current_lv_size_bytes,
                size.expected_lv_size_bytes,
                size.requested_growth_bytes,
                size.rounded_growth_bytes,
                size.remaining_vg_free_bytes
            ));
        }
        for blocker in &self.blockers {
            text.push_str(&format!(
                "BLOCKED [{}]: {}\n",
                blocker.code, blocker.message
            ));
        }
        for step in &self.steps {
            // Debug formatting escapes control characters in externally supplied strings.
            text.push_str(&format!(
                "{}. {:?} [reversibility: {:?}]\n",
                step.id, step.operation, step.reversibility
            ));
        }
        for notice in &self.notices {
            text.push_str(&format!("Note: {notice}\n"));
        }
        text
    }
}

/// Exact, overflow-checked binary units; no floats, signs, exponents or implicit units.
pub fn parse_growth_size(input: &str) -> Result<u64, PlannerError> {
    let split = input.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, unit) = input.split_at(split);
    if digits.is_empty() {
        return Err(PlannerError::InvalidSize);
    }
    let factor = match unit {
        "B" => 1,
        "KiB" => 1_u64 << 10,
        "MiB" => 1_u64 << 20,
        "GiB" => 1_u64 << 30,
        "TiB" => 1_u64 << 40,
        _ => return Err(PlannerError::InvalidSize),
    };
    let bytes = digits
        .parse::<u64>()
        .map_err(|_| PlannerError::SizeOverflow)?
        .checked_mul(factor)
        .ok_or(PlannerError::SizeOverflow)?;
    if bytes == 0 {
        return Err(PlannerError::InvalidSize);
    }
    Ok(bytes)
}

pub fn plan_extend(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: ExtendRequest,
) -> Result<PlanPreview, PlannerError> {
    let mut plan = PlanPreview {
        schema_version: 1,
        plan_id: String::new(),
        snapshot_digest: fingerprint(&(snapshot, capabilities))?,
        dry_run: true,
        executable: false,
        status: PlanStatus::Blocked,
        request,
        size_change: None,
        blockers: Vec::new(),
        steps: Vec::new(),
        notices: vec![
            "M1A produces previews only. No backup, resize, mount or other command is run.".into(),
            "The preview covers LV capacity, not measured filesystem capacity or health.".into(),
            "A future executor needs fresh identity/health checks, locks, verified backups and explicit approval.".into(),
            "Metadata backups are not backups of user data; filesystem growth has no automatic rollback.".into(),
        ],
    };
    match build_candidate(snapshot, capabilities, &plan.request) {
        Ok((size, steps)) => {
            plan.status = PlanStatus::Preview;
            plan.size_change = Some(size);
            plan.steps = steps;
        }
        Err(blocker) => plan.blockers.push(blocker),
    }
    // Includes all preview content except the ID itself (empty at this point).
    plan.plan_id = fingerprint(&plan)?;
    Ok(plan)
}

fn fingerprint(value: &impl Serialize) -> Result<String, PlannerError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn blocked(code: &str, message: &str) -> Blocker {
    Blocker {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn ensure(condition: bool, code: &str, message: &str) -> Result<(), Blocker> {
    if condition {
        Ok(())
    } else {
        Err(blocked(code, message))
    }
}

fn unique<T>(mut items: impl Iterator<Item = T>, code: &str) -> Result<T, Blocker> {
    let first = items
        .next()
        .ok_or_else(|| blocked(code, "required evidence is absent"))?;
    ensure(
        items.next().is_none(),
        code,
        "evidence is ambiguous or duplicated",
    )?;
    Ok(first)
}

fn build_candidate(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: &ExtendRequest,
) -> Result<(SizeChange, Vec<PlanStep>), Blocker> {
    // Missing collector records are NOT treated as successful discovery.
    for component in [
        "lsblk",
        "partition_tables",
        "mounts",
        "fstab",
        "swap",
        "lvm",
    ] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|s| s.component == component),
            "collector-incomplete",
        )?;
        ensure(
            status.state == CollectorState::Complete,
            "collector-incomplete",
            "all six collectors must complete for the initial preview profile",
        )?;
    }
    ensure(
        !snapshot
            .diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error),
        "diagnostic-error",
        "the snapshot contains error-level diagnostics",
    )?;
    ensure(
        !request.target.is_empty() && !request.target.chars().any(char::is_control),
        "invalid-target",
        "target must be a nonempty device path or exact mountpoint",
    )?;

    let lvm = snapshot
        .lvm
        .as_ref()
        .ok_or_else(|| blocked("lvm-missing", "LVM inventory is absent"))?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let source = if request.target.starts_with("/dev/") {
        request.target.as_str()
    } else {
        unique(
            snapshot
                .mounts
                .iter()
                .filter(|m| m.target == request.target),
            "ambiguous-target",
        )?
        .source
        .as_deref()
        .ok_or_else(|| blocked("unknown-source", "mount source is absent"))?
    };
    // Resolve all common aliases; never accept the first match silently.
    let lv = unique(
        lvm.logical_volumes.iter().filter(|lv| {
            lv_alias(lv, source)
                || nodes
                    .iter()
                    .any(|d| node_alias(d, source) && lv_device(lv, d))
        }),
        "ambiguous-lv",
    )?;
    let device = unique(
        nodes.iter().copied().filter(|d| lv_device(lv, d)),
        "ambiguous-device",
    )?;
    ensure(
        device.kind == NodeKind::Lvm,
        "unsupported-layout",
        "target must be an LVM logical volume",
    )?;
    ensure(
        device.children.is_empty(),
        "unsupported-layout",
        "stacked consumers above the LV are not supported",
    )?;
    ensure(
        supported_chain(&snapshot.storage.block_devices, device, true),
        "unsupported-layout",
        "encrypted, RAID, multipath or unknown ancestor layers are not supported",
    )?;
    ensure(
        lv.layout.as_deref() == Some("linear")
            && lv.role.as_deref() == Some("public")
            && lv.attributes.as_deref() == Some("-wi-ao----"),
        "unsupported-lv",
        "M1A requires a public, linear, writable, active LV with normal inherited allocation",
    )?;
    let vg = unique(
        lvm.volume_groups.iter().filter(|v| v.name == lv.vg_name),
        "ambiguous-vg",
    )?;
    ensure(
        vg.attributes.as_deref() == Some("wz--n-") && vg.missing_pv_count == Some(0),
        "unsupported-vg",
        "VG must be local, writable, resizable, nonpartial and nonshared",
    )?;
    ensure(
        vg.pv_count == 1,
        "multi-pv-not-supported",
        "M1A previews are limited to a single-PV VG",
    )?;
    let pv = unique(
        lvm.physical_volumes
            .iter()
            .filter(|p| p.vg_name.as_deref() == Some(vg.name.as_str())),
        "ambiguous-pv",
    )?;
    let pv_device = unique(
        nodes.iter().copied().filter(|d| node_alias(d, &pv.name)),
        "pv-not-resolved",
    )?;
    ensure(
        matches!(
            pv_device.kind,
            NodeKind::Disk | NodeKind::Partition | NodeKind::Loop
        ) && contains_device(pv_device, device)
            && pv_device.filesystem.as_ref().map(|fs| fs.fs_type.as_str()) == Some("LVM2_member"),
        "pv-topology-mismatch",
        "the PV must be the verified ancestor of this LV",
    )?;
    for id in [&pv.uuid, &vg.uuid, &lv.uuid, &device.uuid] {
        ensure(
            id.as_deref().is_some_and(|s| !s.is_empty()),
            "identity-missing",
            "PV, VG, LV and filesystem UUIDs are required",
        )?;
    }
    ensure(
        pv_device.uuid == pv.uuid,
        "pv-uuid-mismatch",
        "lsblk and LVM disagree on the PV UUID",
    )?;
    ensure(
        lv.size_bytes == device.size_bytes
            && lv.size_bytes > 0
            && pv.size_bytes <= pv_device.size_bytes
            && vg.size_bytes <= pv.size_bytes
            && vg.free_bytes <= vg.size_bytes
            && pv.free_bytes == vg.free_bytes,
        "capacity-mismatch",
        "LVM and block-device capacities are inconsistent",
    )?;

    let fs = device
        .filesystem
        .as_ref()
        .ok_or_else(|| blocked("filesystem-missing", "filesystem type is absent"))?;
    ensure(
        matches!(fs.fs_type.as_str(), "ext4" | "xfs"),
        "unsupported-filesystem",
        "only ext4 and XFS previews are supported",
    )?;
    let mount = unique(
        snapshot.mounts.iter().filter(|m| {
            m.source
                .as_deref()
                .is_some_and(|s| node_alias(device, s) || lv_alias(lv, s))
        }),
        "mount-not-unique",
    )?;
    ensure(
        mount.fs_type.as_deref() == Some(fs.fs_type.as_str())
            && mount.options.iter().any(|o| o == "rw")
            && !mount
                .options
                .iter()
                .any(|o| matches!(o.as_str(), "ro" | "bind" | "rbind"))
            && device.mountpoints == vec![mount.target.clone()]
            && snapshot
                .mounts
                .iter()
                .filter(|m| m.target == mount.target)
                .count()
                == 1,
        "mount-state-mismatch",
        "one matching read-write mount must be confirmed by lsblk and findmnt",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|s| node_alias(device, &s.name) || lv_alias(lv, &s.name)),
        "active-swap",
        "the target is reported as active swap",
    )?;
    for tool in [
        "vgcfgbackup",
        "lvextend",
        if fs.fs_type == "xfs" {
            "xfs_growfs"
        } else {
            "resize2fs"
        },
    ] {
        let capability = unique(
            capabilities.tools.iter().filter(|t| t.name == tool),
            "tool-unavailable",
        )?;
        ensure(
            capability.available,
            "tool-unavailable",
            "a required future operation tool is unavailable",
        )?;
    }
    let extent = vg
        .extent_size_bytes
        .ok_or_else(|| blocked("extent-missing", "VG extent size is unknown"))?;
    let free_extents = vg
        .free_extent_count
        .ok_or_else(|| blocked("extent-missing", "free extent count is unknown"))?;
    ensure(
        extent >= 512 && extent.is_power_of_two(),
        "invalid-extent",
        "invalid VG extent size",
    )?;
    ensure(
        free_extents.checked_mul(extent) == Some(vg.free_bytes)
            && vg.size_bytes % extent == 0
            && lv.size_bytes % extent == 0,
        "extent-mismatch",
        "reported bytes and extent counts do not agree",
    )?;
    let requested = match request.growth {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => vg.free_bytes,
    };
    ensure(
        requested > 0,
        "no-growth",
        "requested growth or existing VG free capacity is zero",
    )?;
    let extents = requested / extent + u64::from(requested % extent != 0);
    ensure(extents <= free_extents, "insufficient-capacity", "extent-rounded request exceeds existing VG free space; partition/PV resize is not attempted")?;
    let rounded = extents
        .checked_mul(extent)
        .ok_or_else(|| blocked("size-overflow", "growth exceeds u64"))?;
    let new_size = lv
        .size_bytes
        .checked_add(rounded)
        .ok_or_else(|| blocked("size-overflow", "new LV size exceeds u64"))?;
    let size = SizeChange {
        device: device.path.clone().unwrap_or_else(|| device.name.clone()),
        current_lv_size_bytes: lv.size_bytes,
        requested_growth_bytes: requested,
        rounded_growth_bytes: rounded,
        expected_lv_size_bytes: new_size,
        extent_size_bytes: extent,
        remaining_vg_free_bytes: vg.free_bytes - rounded,
    };
    let steps = vec![
        step(
            1,
            Operation::RevalidateSnapshot,
            Reversibility::NotApplicable,
        ),
        step(
            2,
            Operation::BackupLvmMetadata {
                vg_uuid: vg.uuid.clone().unwrap_or_default(),
            },
            Reversibility::Reversible,
        ),
        step(
            3,
            Operation::ExtendLogicalVolume {
                lv_uuid: lv.uuid.clone().unwrap_or_default(),
                additional_extents: extents,
                expected_lv_size_bytes: new_size,
            },
            Reversibility::Irreversible,
        ),
        step(
            4,
            Operation::GrowFilesystem {
                fs_type: fs.fs_type.clone(),
                mountpoint: mount.target.clone(),
            },
            Reversibility::Irreversible,
        ),
        step(
            5,
            Operation::RediscoverAndVerify,
            Reversibility::NotApplicable,
        ),
    ];
    Ok((size, steps))
}

fn step(id: u32, operation: Operation, reversibility: Reversibility) -> PlanStep {
    PlanStep {
        id,
        depends_on: if id == 1 { Vec::new() } else { vec![id - 1] },
        operation,
        reversibility,
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

fn node_alias(device: &BlockDevice, alias: &str) -> bool {
    device.path.as_deref() == Some(alias)
        || device
            .kernel_name
            .as_ref()
            .is_some_and(|n| format!("/dev/{n}") == alias)
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

fn contains_device(parent: &BlockDevice, target: &BlockDevice) -> bool {
    parent
        .children
        .iter()
        .any(|child| std::ptr::eq(child, target) || contains_device(child, target))
}

fn supported_chain(devices: &[BlockDevice], target: &BlockDevice, safe: bool) -> bool {
    devices.iter().any(|device| {
        if std::ptr::eq(device, target) {
            return safe;
        }
        let safe = safe
            && matches!(
                device.kind,
                NodeKind::Disk | NodeKind::Partition | NodeKind::Loop
            );
        supported_chain(&device.children, target, safe)
    })
}
