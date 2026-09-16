//! Advisory partition-tail capacity, never an authorization or a write plan.
//! Require agreement with every sibling; unknown data is not free space.

use std::collections::BTreeSet;

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind, PartitionTable};

pub(super) fn adjacent_capacity(snapshot: &HostSnapshot, target: &BlockDevice) -> Option<u64> {
    for component in ["lsblk", "partition_tables"] {
        let status = one(snapshot.collectors.iter().filter(|s| s.component == component))?;
        if status.state != CollectorState::Complete {
            return None;
        }
    }
    let mut parents = Vec::new();
    collect_parents(&snapshot.storage.block_devices, target, &mut parents);
    let disk = one(parents.into_iter())?;
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop) {
        return None;
    }
    let disk_path = disk.path.as_deref()?;
    let target_path = target.path.as_deref()?;
    let table = one(snapshot.partition_tables.iter().filter(|t| t.device == disk_path))?;
    let sector = table.sector_size_bytes?;
    if !matches!(sector, 512 | 4096)
        || disk.logical_sector_bytes != Some(sector)
        || disk.size_bytes == 0
        || disk.size_bytes % sector != 0
        || table.unit.as_deref() != Some("sectors")
        || table.label != disk.partition_table
    {
        return None;
    }
    let (first, limit) = usable_bounds(table, disk.size_bytes / sector)?;
    if disk.children.len() != table.partitions.len() || table.partitions.is_empty() {
        return None;
    }

    let parent_name = disk.kernel_name.as_deref()?;
    let mut names = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    let mut ranges = Vec::new();
    for record in &table.partitions {
        if !names.insert(record.node.as_str()) {
            return None;
        }
        let child = one(disk.children.iter().filter(|d| d.path.as_deref() == Some(record.node.as_str())))?;
        let start = record.start_sector.checked_mul(sector)?;
        let size = record.size_sectors.checked_mul(sector)?;
        let end = record.start_sector.checked_add(record.size_sectors)?;
        if child.kind != NodeKind::Partition
            || child.parent_kernel_name.as_deref() != Some(parent_name)
            || child.logical_sector_bytes != Some(sector)
            || child.start_512_sector?.checked_mul(512)? != start
            || child.size_bytes != size
            || record.size_sectors == 0
            || record.start_sector < first
            || end > limit
        {
            return None;
        }
        match (table.label.as_deref(), record.uuid.as_deref(), child.partition_uuid.as_deref()) {
            (Some("gpt"), Some(a), Some(b)) if !a.is_empty() && a.eq_ignore_ascii_case(b) => {
                if !uuids.insert(a.to_ascii_lowercase()) {
                    return None;
                }
            }
            (Some("gpt"), _, _) => return None,
            (_, Some(a), Some(b)) if !a.eq_ignore_ascii_case(b) => return None,
            _ => {}
        }
        ranges.push((record.start_sector, end, record.node.as_str()));
    }
    ranges.sort_unstable();
    // Reject overlap anywhere, including a partition starting before the target.
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return None;
    }
    let index = ranges.iter().position(|range| range.2 == target_path)?;
    let end = ranges[index].1;
    let next = ranges.get(index + 1).map_or(limit, |range| range.0);
    next.checked_sub(end)?.checked_mul(sector)
}

fn usable_bounds(table: &PartitionTable, disk_sectors: u64) -> Option<(u64, u64)> {
    match table.label.as_deref()? {
        "gpt" => {
            // last_lba is INCLUSIVE and in the table's logical sectors, not 512-byte units.
            // Never extrapolate beyond it when a VM disk has grown or GPT needs repair.
            let first = table.first_lba?;
            let limit = table.last_lba?.checked_add(1)?;
            if first < 2 || first >= limit || limit >= disk_sectors {
                return None;
            }
            Some((first, limit))
        }
        "dos" => {
            // No extended/logical partitions or protective/hybrid MBR interpretation.
            if table.partitions.len() > 4 {
                return None;
            }
            for record in &table.partitions {
                let raw = record.partition_type.as_deref()?;
                let kind = u8::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16).ok()?;
                if matches!(kind, 0x00 | 0x05 | 0x0f | 0x85 | 0xee) {
                    return None;
                }
            }
            // Conservatively stay within the primary MBR 32-bit address range.
            let limit = disk_sectors.min(u64::from(u32::MAX) + 1);
            (limit > 1).then_some((1, limit))
        }
        _ => None,
    }
}

fn one<T>(mut items: impl Iterator<Item = T>) -> Option<T> {
    let first = items.next()?;
    items.next().is_none().then_some(first)
}

fn collect_parents<'a>(
    devices: &'a [BlockDevice],
    target: &BlockDevice,
    parents: &mut Vec<&'a BlockDevice>,
) {
    for device in devices {
        if device.children.iter().any(|child| child.path.is_some() && child.path == target.path) {
            parents.push(device);
        }
        collect_parents(&device.children, target, parents);
    }
}
