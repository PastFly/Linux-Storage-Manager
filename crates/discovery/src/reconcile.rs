use std::collections::{HashMap, HashSet};

use lsm_core::{
    BlockDevice, DiagnosticSeverity, HostSnapshot, LvmLogicalVolume, NodeKind, PartitionTable,
    StorageDiagnostic,
};

const LSBLK_START_SECTOR_BYTES: u64 = 512;

pub fn reconcile_snapshot(snapshot: &HostSnapshot) -> Vec<StorageDiagnostic> {
    let mut diagnostics = Vec::new();

    reconcile_partition_tables(snapshot, &mut diagnostics);
    reconcile_lvm(snapshot, &mut diagnostics);
    reconcile_mounts(snapshot, &mut diagnostics);
    reconcile_fstab(snapshot, &mut diagnostics);
    reconcile_swaps(snapshot, &mut diagnostics);

    diagnostics
}

fn reconcile_partition_tables(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    for table in &snapshot.partition_tables {
        let Some(disk) = find_graph_alias(&snapshot.storage.block_devices, &table.device) else {
            diagnostics.push(StorageDiagnostic {
                code: "sfdisk-disk-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "sfdisk returned a partition table for a disk that is absent from the lsblk topology"
                    .to_owned(),
                device: Some(table.device.clone()),
            });
            continue;
        };

        if let (Some(lsblk_label), Some(sfdisk_label)) =
            (disk.partition_table.as_deref(), table.label.as_deref())
        {
            if !lsblk_label.eq_ignore_ascii_case(sfdisk_label) {
                diagnostics.push(StorageDiagnostic {
                    code: "partition-table-label-mismatch".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "lsblk reports partition-table type `{lsblk_label}`, but sfdisk reports `{sfdisk_label}`"
                    ),
                    device: Some(table.device.clone()),
                });
            }
        }

        if let (Some(lsblk_sector), Some(sfdisk_sector)) =
            (disk.logical_sector_bytes, table.sector_size_bytes)
        {
            if lsblk_sector != sfdisk_sector {
                diagnostics.push(StorageDiagnostic {
                    code: "logical-sector-size-mismatch".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "lsblk reports logical sector size {lsblk_sector}, but sfdisk reports {sfdisk_sector}"
                    ),
                    device: Some(table.device.clone()),
                });
            }
        }

        let Some(sector_size) = table.sector_size_bytes else {
            diagnostics.push(StorageDiagnostic {
                code: "sfdisk-sector-size-missing".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "sfdisk JSON did not include a sector size; authoritative byte geometry cannot be verified"
                    .to_owned(),
                device: Some(table.device.clone()),
            });
            continue;
        };

        reconcile_sfdisk_partitions(snapshot, disk, table, sector_size, diagnostics);
    }
}

fn reconcile_sfdisk_partitions(
    snapshot: &HostSnapshot,
    disk: &BlockDevice,
    table: &PartitionTable,
    sector_size: u64,
    diagnostics: &mut Vec<StorageDiagnostic>,
) {
    for partition in &table.partitions {
        let Some(lsblk_partition) =
            find_graph_alias(&snapshot.storage.block_devices, &partition.node)
        else {
            diagnostics.push(StorageDiagnostic {
                code: "sfdisk-partition-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "sfdisk reports a partition that is absent from the lsblk topology"
                    .to_owned(),
                device: Some(partition.node.clone()),
            });
            continue;
        };

        let sfdisk_start_bytes = partition.start_sector.checked_mul(sector_size);
        let lsblk_start_bytes = lsblk_partition
            .start_512_sector
            .and_then(|start| start.checked_mul(LSBLK_START_SECTOR_BYTES));

        match (lsblk_start_bytes, sfdisk_start_bytes) {
            (Some(lsblk_start), Some(sfdisk_start)) if lsblk_start != sfdisk_start => {
                diagnostics.push(StorageDiagnostic {
                    code: "partition-start-mismatch".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "lsblk start offset is {lsblk_start} bytes, but sfdisk reports {sfdisk_start} bytes"
                    ),
                    device: Some(partition.node.clone()),
                });
            }
            (None, Some(_)) => diagnostics.push(StorageDiagnostic {
                code: "lsblk-partition-start-missing".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: "sfdisk reports partition geometry, but lsblk did not provide START for the partition"
                    .to_owned(),
                device: Some(partition.node.clone()),
            }),
            (Some(_), None) | (None, None) => diagnostics.push(StorageDiagnostic {
                code: "partition-start-overflow".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "partition start offset could not be represented safely in bytes"
                    .to_owned(),
                device: Some(partition.node.clone()),
            }),
            _ => {}
        }

        match partition.size_sectors.checked_mul(sector_size) {
            Some(sfdisk_size) if sfdisk_size != lsblk_partition.size_bytes => {
                diagnostics.push(StorageDiagnostic {
                    code: "partition-size-mismatch".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "lsblk reports partition size {} bytes, but sfdisk reports {sfdisk_size} bytes",
                        lsblk_partition.size_bytes
                    ),
                    device: Some(partition.node.clone()),
                });
            }
            None => diagnostics.push(StorageDiagnostic {
                code: "partition-size-overflow".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "partition size from sfdisk could not be represented safely in bytes"
                    .to_owned(),
                device: Some(partition.node.clone()),
            }),
            _ => {}
        }

        if let (Some(lsblk_uuid), Some(sfdisk_uuid)) = (
            lsblk_partition.partition_uuid.as_deref(),
            partition.uuid.as_deref(),
        ) {
            if !lsblk_uuid.eq_ignore_ascii_case(sfdisk_uuid) {
                diagnostics.push(StorageDiagnostic {
                    code: "partition-uuid-mismatch".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "lsblk reports PARTUUID `{lsblk_uuid}`, but sfdisk reports `{sfdisk_uuid}`"
                    ),
                    device: Some(partition.node.clone()),
                });
            }
        }
    }

    for child in disk
        .children
        .iter()
        .filter(|child| child.kind == NodeKind::Partition)
    {
        let Some(path) = child.path.as_deref() else {
            continue;
        };
        if !table
            .partitions
            .iter()
            .any(|partition| partition.node == path)
        {
            diagnostics.push(StorageDiagnostic {
                code: "lsblk-partition-not-in-sfdisk".to_owned(),
                severity: DiagnosticSeverity::Error,
                message: "lsblk reports a direct disk partition that is absent from the authoritative sfdisk table"
                    .to_owned(),
                device: Some(path.to_owned()),
            });
        }
    }
}

fn reconcile_lvm(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    let Some(lvm) = snapshot.lvm.as_ref() else {
        return;
    };

    for pv in &lvm.physical_volumes {
        if pv.name.starts_with("/dev/")
            && !graph_has_alias(&snapshot.storage.block_devices, &pv.name)
        {
            diagnostics.push(StorageDiagnostic {
                code: "lvm-pv-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message:
                    "LVM reports a physical volume that is not represented in the lsblk topology"
                        .to_owned(),
                device: Some(pv.name.clone()),
            });
        }
    }

    for lv in &lvm.logical_volumes {
        if !lv_present_in_graph(snapshot, lv) {
            diagnostics.push(StorageDiagnostic {
                code: "lvm-lv-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: format!(
                    "LVM reports logical volume `{}/{}` but no matching lsblk node was found",
                    lv.vg_name, lv.name
                ),
                device: lv.path.clone(),
            });
        }
    }
}

fn reconcile_mounts(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    let mut targets = HashMap::<&str, usize>::new();

    for mount in &snapshot.mounts {
        *targets.entry(mount.target.as_str()).or_default() += 1;

        let Some(source) = mount.source.as_deref() else {
            continue;
        };

        if is_block_source(source) && !source_resolves_to_graph(snapshot, source) {
            diagnostics.push(StorageDiagnostic {
                code: "mounted-device-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: format!(
                    "active mount `{}` references block source `{source}` that is not represented in the discovered topology",
                    mount.target
                ),
                device: Some(source.to_owned()),
            });
        }
    }

    for (target, count) in targets {
        if count > 1 {
            diagnostics.push(StorageDiagnostic {
                code: "duplicate-active-mount-target".to_owned(),
                severity: DiagnosticSeverity::Info,
                message: format!(
                    "mount target `{target}` appears {count} times in the active mount table; this can be intentional for over-mounts"
                ),
                device: None,
            });
        }
    }
}

fn reconcile_fstab(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    let mut targets = HashMap::<&str, usize>::new();
    let mut uuids = HashSet::new();
    let mut partuuids = HashSet::new();
    collect_ids(&snapshot.storage.block_devices, &mut uuids, &mut partuuids);

    for entry in &snapshot.fstab {
        *targets.entry(entry.target.as_str()).or_default() += 1;

        if let Some(uuid) = entry.source.strip_prefix("UUID=") {
            if !uuids.contains(uuid) {
                diagnostics.push(StorageDiagnostic {
                    code: "fstab-uuid-not-discovered".to_owned(),
                    severity: DiagnosticSeverity::Warning,
                    message: format!(
                        "fstab target `{}` references UUID `{uuid}` that is absent from the discovered block topology",
                        entry.target
                    ),
                    device: Some(entry.source.clone()),
                });
            }
        } else if let Some(partuuid) = entry.source.strip_prefix("PARTUUID=") {
            if !partuuids.contains(partuuid) {
                diagnostics.push(StorageDiagnostic {
                    code: "fstab-partuuid-not-discovered".to_owned(),
                    severity: DiagnosticSeverity::Warning,
                    message: format!(
                        "fstab target `{}` references PARTUUID `{partuuid}` that is absent from the discovered block topology",
                        entry.target
                    ),
                    device: Some(entry.source.clone()),
                });
            }
        } else if is_block_source(&entry.source)
            && !source_resolves_to_graph(snapshot, &entry.source)
        {
            diagnostics.push(StorageDiagnostic {
                code: "fstab-device-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: format!(
                    "fstab target `{}` references block source `{}` that is not represented in the discovered topology",
                    entry.target, entry.source
                ),
                device: Some(entry.source.clone()),
            });
        }
    }

    for (target, count) in targets {
        if target != "none" && count > 1 {
            diagnostics.push(StorageDiagnostic {
                code: "duplicate-fstab-target".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: format!(
                    "fstab contains {count} entries for target `{target}`; verify that the duplicate is intentional"
                ),
                device: None,
            });
        }
    }
}

fn reconcile_swaps(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    for swap in &snapshot.swaps {
        if swap.kind != "file"
            && is_block_source(&swap.name)
            && !source_resolves_to_graph(snapshot, &swap.name)
        {
            diagnostics.push(StorageDiagnostic {
                code: "swap-device-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message:
                    "active block-device swap is not represented in the discovered lsblk topology"
                        .to_owned(),
                device: Some(swap.name.clone()),
            });
        }
    }
}

fn source_resolves_to_graph(snapshot: &HostSnapshot, source: &str) -> bool {
    if source == "/dev/root" || graph_has_alias(&snapshot.storage.block_devices, source) {
        return true;
    }

    snapshot
        .lvm
        .as_ref()
        .map(|lvm| {
            lvm.logical_volumes.iter().any(|lv| {
                lv_aliases(lv).iter().any(|alias| alias.as_str() == source)
                    && lv_present_in_graph(snapshot, lv)
            })
        })
        .unwrap_or(false)
}

fn lv_present_in_graph(snapshot: &HostSnapshot, lv: &LvmLogicalVolume) -> bool {
    lv_aliases(lv)
        .iter()
        .any(|alias| graph_has_alias(&snapshot.storage.block_devices, alias))
}

fn lv_aliases(lv: &LvmLogicalVolume) -> Vec<String> {
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

fn is_block_source(source: &str) -> bool {
    source.starts_with("/dev/")
}

fn graph_has_alias(devices: &[BlockDevice], alias: &str) -> bool {
    find_graph_alias(devices, alias).is_some()
}

fn find_graph_alias<'a>(devices: &'a [BlockDevice], alias: &str) -> Option<&'a BlockDevice> {
    for device in devices {
        if device.path.as_deref() == Some(alias)
            || device
                .kernel_name
                .as_deref()
                .map(|name| format!("/dev/{name}") == alias)
                .unwrap_or(false)
            || format!("/dev/{}", device.name) == alias
        {
            return Some(device);
        }

        if let Some(found) = find_graph_alias(&device.children, alias) {
            return Some(found);
        }
    }
    None
}

fn collect_ids<'a>(
    devices: &'a [BlockDevice],
    uuids: &mut HashSet<&'a str>,
    partuuids: &mut HashSet<&'a str>,
) {
    for device in devices {
        if let Some(uuid) = device.uuid.as_deref() {
            uuids.insert(uuid);
        }
        if let Some(partuuid) = device.partition_uuid.as_deref() {
            partuuids.insert(partuuid);
        }
        collect_ids(&device.children, uuids, partuuids);
    }
}
