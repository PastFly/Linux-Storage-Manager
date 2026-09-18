//! Read-only, in-memory plan previews. No process, filesystem or device I/O.
//! A preview is NOT an executable plan or authorization to modify storage.

use lsm_core::{
    BlockDevice, CollectorState, DiagnosticSeverity, HostCapabilities, HostSnapshot,
    LvmLogicalVolume, NodeKind, PartitionTable,
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
    BackupPartitionTableMetadata {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    ExtendPartition {
        partition: String,
        start_sector: u64,
        old_size_sectors: u64,
        new_size_sectors: u64,
        sector_size_bytes: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartitionSizeChange {
    pub device: String,
    pub disk: String,
    pub current_partition_size_bytes: u64,
    pub requested_growth_bytes: u64,
    pub rounded_growth_bytes: u64,
    pub expected_partition_size_bytes: u64,
    pub sector_size_bytes: u64,
    pub remaining_adjacent_free_bytes: u64,
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
    partition_size_change: Option<PartitionSizeChange>,
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

    pub fn partition_size_change(&self) -> Option<&PartitionSizeChange> {
        self.partition_size_change.as_ref()
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
        if let Some(size) = &self.partition_size_change {
            text.push_str(&format!(
                "Partition size: {} -> {} bytes\nRequested growth: {} bytes\n\
                 Sector-aligned growth: {} bytes\nAdjacent free after preview: {} bytes\n",
                size.current_partition_size_bytes,
                size.expected_partition_size_bytes,
                size.requested_growth_bytes,
                size.rounded_growth_bytes,
                size.remaining_adjacent_free_bytes
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
        partition_size_change: None,
        blockers: Vec::new(),
        steps: Vec::new(),
        notices: vec![
            "M1A produces previews only. No backup, resize, mount or other command is run.".into(),
            "The preview covers block-layer capacity, not measured filesystem capacity or health.".into(),
            "A future executor needs fresh identity/health checks, locks, verified backups and explicit approval.".into(),
            "Metadata backups are not backups of user data; filesystem growth has no automatic rollback.".into(),
        ],
    };
    match try_build_partition_candidate(snapshot, capabilities, &plan.request) {
        Ok(Some((size, steps))) => {
            plan.status = PlanStatus::Preview;
            plan.partition_size_change = Some(size);
            plan.steps = steps;
        }
        Ok(None) => match build_candidate(snapshot, capabilities, &plan.request) {
            Ok((size, steps)) => {
                plan.status = PlanStatus::Preview;
                plan.size_change = Some(size);
                plan.steps = steps;
            }
            Err(blocker) => plan.blockers.push(blocker),
        },
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

fn try_build_partition_candidate(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: &ExtendRequest,
) -> Result<Option<(PartitionSizeChange, Vec<PlanStep>)>, Blocker> {
    ensure(
        !request.target.is_empty() && !request.target.chars().any(char::is_control),
        "invalid-target",
        "target must be a nonempty device path or exact mountpoint",
    )?;

    let nodes = flatten(&snapshot.storage.block_devices);
    let source = if request.target.starts_with("/dev/") {
        request.target.as_str()
    } else {
        unique(
            snapshot
                .mounts
                .iter()
                .filter(|mount| mount.target == request.target),
            "ambiguous-target",
        )?
        .source
        .as_deref()
        .ok_or_else(|| blocked("unknown-source", "mount source is absent"))?
    };

    let partition_matches: Vec<_> = nodes
        .iter()
        .copied()
        .filter(|device| device.kind == NodeKind::Partition && node_alias(device, source))
        .collect();
    if partition_matches.is_empty() {
        return Ok(None);
    }
    let device = unique(partition_matches.into_iter(), "ambiguous-device")?;

    for component in ["lsblk", "partition_tables", "mounts", "fstab", "swap"] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component),
            "collector-incomplete",
        )?;
        ensure(
            status.state == CollectorState::Complete,
            "collector-incomplete",
            "all direct-partition preview collectors must complete",
        )?;
    }
    ensure(
        !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        "diagnostic-error",
        "the snapshot contains error-level diagnostics",
    )?;

    ensure(
        device.children.is_empty(),
        "unsupported-layout",
        "stacked consumers above the partition are not supported",
    )?;
    let fs = device
        .filesystem
        .as_ref()
        .ok_or_else(|| blocked("filesystem-missing", "filesystem type is absent"))?;
    ensure(
        matches!(fs.fs_type.as_str(), "ext4" | "xfs"),
        "unsupported-filesystem",
        "direct partition preview supports only ext4 and XFS",
    )?;

    let mount = unique(
        snapshot.mounts.iter().filter(|mount| {
            mount
                .source
                .as_deref()
                .is_some_and(|source| node_alias(device, source))
        }),
        "mount-not-unique",
    )?;
    ensure(
        mount.fs_type.as_deref() == Some(fs.fs_type.as_str())
            && mount.options.iter().any(|option| option == "rw")
            && !mount
                .options
                .iter()
                .any(|option| matches!(option.as_str(), "ro" | "bind" | "rbind"))
            && device.mountpoints == vec![mount.target.clone()]
            && snapshot
                .mounts
                .iter()
                .filter(|candidate| candidate.target == mount.target)
                .count()
                == 1,
        "mount-state-mismatch",
        "one matching read-write mount must be confirmed by lsblk and findmnt",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|swap| node_alias(device, &swap.name)),
        "active-swap",
        "the target is reported as active swap",
    )?;

    for tool in [
        "sfdisk",
        if fs.fs_type == "xfs" {
            "xfs_growfs"
        } else {
            "resize2fs"
        },
    ] {
        let capability = unique(
            capabilities
                .tools
                .iter()
                .filter(|capability| capability.name == tool),
            "tool-unavailable",
        )?;
        ensure(
            capability.available,
            "tool-unavailable",
            "a required future operation tool is unavailable",
        )?;
    }

    let parent_name = device
        .parent_kernel_name
        .as_deref()
        .ok_or_else(|| blocked("parent-missing", "partition parent is unknown"))?;
    let disk = unique(
        nodes.iter().copied().filter(|candidate| {
            matches!(candidate.kind, NodeKind::Disk | NodeKind::Loop)
                && candidate.kernel_name.as_deref() == Some(parent_name)
        }),
        "parent-not-resolved",
    )?;
    let disk_path = disk
        .path
        .as_deref()
        .ok_or_else(|| blocked("parent-not-resolved", "disk path is absent"))?;
    let device_path = device
        .path
        .as_deref()
        .ok_or_else(|| blocked("device-path-missing", "partition path is absent"))?;
    let table = unique(
        snapshot
            .partition_tables
            .iter()
            .filter(|table| table.device == disk_path),
        "partition-table-not-unique",
    )?;
    let sector = table
        .sector_size_bytes
        .ok_or_else(|| blocked("sector-size-missing", "partition sector size is unknown"))?;
    ensure(
        sector >= 512 && sector.is_power_of_two() && device.logical_sector_bytes == Some(sector),
        "sector-size-mismatch",
        "partition-table and block-device logical sector sizes disagree",
    )?;

    let record = unique(
        table
            .partitions
            .iter()
            .filter(|record| record.node == device_path),
        "partition-record-not-unique",
    )?;
    let start_bytes = record
        .start_sector
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "partition start exceeds u64"))?;
    ensure(
        device
            .start_512_sector
            .and_then(|start| start.checked_mul(512))
            == Some(start_bytes),
        "partition-start-mismatch",
        "lsblk and partition table disagree on partition start",
    )?;
    let current_size = record
        .size_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "partition size exceeds u64"))?;
    ensure(
        current_size == device.size_bytes,
        "partition-size-mismatch",
        "lsblk and partition table disagree on target partition size",
    )?;

    let adjacent_sectors = adjacent_free_sectors(disk, table, record)?;
    let adjacent_bytes = adjacent_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "adjacent capacity exceeds u64"))?;
    let requested = match request.growth {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => adjacent_bytes,
    };
    ensure(
        requested > 0,
        "no-growth",
        "requested growth or verified adjacent capacity is zero",
    )?;
    let growth_sectors = requested / sector + u64::from(requested % sector != 0);
    ensure(
        growth_sectors <= adjacent_sectors,
        "insufficient-adjacent-capacity",
        "sector-rounded request exceeds verified adjacent free space",
    )?;
    let rounded = growth_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "growth exceeds u64"))?;
    let new_size_sectors = record
        .size_sectors
        .checked_add(growth_sectors)
        .ok_or_else(|| blocked("size-overflow", "new partition size exceeds u64"))?;
    let expected_size = new_size_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "new partition size exceeds u64"))?;

    let label = table.label.clone().ok_or_else(|| {
        blocked(
            "partition-label-missing",
            "partition table label is unknown",
        )
    })?;
    let size = PartitionSizeChange {
        device: device_path.to_owned(),
        disk: disk_path.to_owned(),
        current_partition_size_bytes: current_size,
        requested_growth_bytes: requested,
        rounded_growth_bytes: rounded,
        expected_partition_size_bytes: expected_size,
        sector_size_bytes: sector,
        remaining_adjacent_free_bytes: adjacent_bytes - rounded,
    };
    let steps = vec![
        step(
            1,
            Operation::RevalidateSnapshot,
            Reversibility::NotApplicable,
        ),
        step(
            2,
            Operation::BackupPartitionTableMetadata {
                disk: disk_path.to_owned(),
                table_label: label,
                table_id: table.id.clone(),
            },
            Reversibility::Reversible,
        ),
        step(
            3,
            Operation::ExtendPartition {
                partition: device_path.to_owned(),
                start_sector: record.start_sector,
                old_size_sectors: record.size_sectors,
                new_size_sectors,
                sector_size_bytes: sector,
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

    Ok(Some((size, steps)))
}

fn adjacent_free_sectors(
    disk: &BlockDevice,
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
) -> Result<u64, Blocker> {
    let sector = table
        .sector_size_bytes
        .ok_or_else(|| blocked("sector-size-missing", "partition sector size is unknown"))?;
    let disk_sectors = disk.size_bytes / sector;
    let label = table.label.as_deref().ok_or_else(|| {
        blocked(
            "partition-label-missing",
            "partition table label is unknown",
        )
    })?;

    match label {
        "dos" => adjacent_free_dos(table, target, disk_sectors),
        "gpt" => adjacent_free_gpt(table, target),
        _ => Err(blocked(
            "unsupported-partition-table",
            "direct partition preview supports only DOS/MBR and GPT",
        )),
    }
}

fn adjacent_free_gpt(
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
) -> Result<u64, Blocker> {
    let first = table
        .first_lba
        .ok_or_else(|| blocked("gpt-bounds-missing", "GPT first usable LBA is unknown"))?;
    let last = table
        .last_lba
        .ok_or_else(|| blocked("gpt-bounds-missing", "GPT last usable LBA is unknown"))?;
    let limit = last
        .checked_add(1)
        .ok_or_else(|| blocked("size-overflow", "GPT usable limit exceeds u64"))?;

    let mut ranges = Vec::new();
    for record in &table.partitions {
        let end = record
            .start_sector
            .checked_add(record.size_sectors)
            .ok_or_else(|| blocked("size-overflow", "partition range exceeds u64"))?;
        ensure(
            record.size_sectors > 0 && record.start_sector >= first && end <= limit,
            "invalid-partition-range",
            "GPT partition lies outside the usable range",
        )?;
        ranges.push((record.start_sector, end, record.node.as_str()));
    }
    ranges.sort_unstable();
    ensure(
        !ranges.windows(2).any(|pair| pair[0].1 > pair[1].0),
        "overlapping-partitions",
        "GPT partition ranges overlap",
    )?;
    adjacent_from_ranges(&ranges, target, limit)
}

fn adjacent_free_dos(
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
    disk_sectors: u64,
) -> Result<u64, Blocker> {
    let limit = disk_sectors.min(u64::from(u32::MAX) + 1);
    let mut extended = Vec::new();
    for record in &table.partitions {
        let kind =
            parse_dos_type(record.partition_type.as_deref().ok_or_else(|| {
                blocked("partition-type-missing", "DOS partition type is unknown")
            })?)?;
        if matches!(kind, 0x05 | 0x0f | 0x85) {
            let end = record
                .start_sector
                .checked_add(record.size_sectors)
                .ok_or_else(|| blocked("size-overflow", "extended range exceeds u64"))?;
            extended.push((record.start_sector, end, record.node.as_str()));
        }
    }
    ensure(
        extended.len() <= 1,
        "unsupported-dos-layout",
        "multiple extended partition containers are not supported",
    )?;

    let target_kind = parse_dos_type(
        target
            .partition_type
            .as_deref()
            .ok_or_else(|| blocked("partition-type-missing", "DOS partition type is unknown"))?,
    )?;
    ensure(
        !matches!(target_kind, 0x05 | 0x0f | 0x85),
        "unsupported-dos-layout",
        "extended partition containers cannot be grown as filesystem targets",
    )?;
    if let Some((ext_start, ext_end, _)) = extended.first() {
        ensure(
            !(target.start_sector >= *ext_start
                && target
                    .start_sector
                    .checked_add(target.size_sectors)
                    .is_some_and(|end| end <= *ext_end)),
            "unsupported-logical-partition",
            "logical partition growth inside an extended container is not supported",
        )?;
    }

    let mut primary = Vec::new();
    for record in &table.partitions {
        let end = record
            .start_sector
            .checked_add(record.size_sectors)
            .ok_or_else(|| blocked("size-overflow", "partition range exceeds u64"))?;
        ensure(
            record.size_sectors > 0 && record.start_sector >= 1 && end <= limit,
            "invalid-partition-range",
            "DOS partition lies outside the addressable range",
        )?;
        let kind =
            parse_dos_type(record.partition_type.as_deref().ok_or_else(|| {
                blocked("partition-type-missing", "DOS partition type is unknown")
            })?)?;
        ensure(
            kind != 0x00 && kind != 0xee,
            "unsupported-dos-layout",
            "empty/protective DOS partition types are not supported",
        )?;

        let inside_extended = extended.first().is_some_and(|(start, finish, node)| {
            record.node != *node && record.start_sector >= *start && end <= *finish
        });
        if !inside_extended {
            primary.push((record.start_sector, end, record.node.as_str()));
        }
    }
    primary.sort_unstable();
    ensure(
        !primary.windows(2).any(|pair| pair[0].1 > pair[1].0),
        "overlapping-partitions",
        "DOS primary/extended partition ranges overlap",
    )?;
    adjacent_from_ranges(&primary, target, limit)
}

fn adjacent_from_ranges(
    ranges: &[(u64, u64, &str)],
    target: &lsm_core::PartitionRecord,
    limit: u64,
) -> Result<u64, Blocker> {
    let index = ranges
        .iter()
        .position(|range| range.2 == target.node)
        .ok_or_else(|| {
            blocked(
                "target-not-primary",
                "target partition is not a supported boundary",
            )
        })?;
    let end = ranges[index].1;
    let next = ranges.get(index + 1).map_or(limit, |range| range.0);
    next.checked_sub(end).ok_or_else(|| {
        blocked(
            "overlapping-partitions",
            "next partition overlaps the target",
        )
    })
}

fn parse_dos_type(raw: &str) -> Result<u8, Blocker> {
    let trimmed = raw.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u8::from_str_radix(normalized, 16)
        .map_err(|_| blocked("invalid-partition-type", "DOS partition type is invalid"))
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
