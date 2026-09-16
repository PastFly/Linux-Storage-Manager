use std::collections::{HashMap, HashSet};

use lsm_core::{
    BlockDevice, DiagnosticSeverity, HostSnapshot, LvmLogicalVolume, StorageDiagnostic,
};

pub fn reconcile_snapshot(snapshot: &HostSnapshot) -> Vec<StorageDiagnostic> {
    let mut diagnostics = Vec::new();

    reconcile_lvm(snapshot, &mut diagnostics);
    reconcile_mounts(snapshot, &mut diagnostics);
    reconcile_fstab(snapshot, &mut diagnostics);
    reconcile_swaps(snapshot, &mut diagnostics);

    diagnostics
}

fn reconcile_lvm(snapshot: &HostSnapshot, diagnostics: &mut Vec<StorageDiagnostic>) {
    let Some(lvm) = snapshot.lvm.as_ref() else {
        return;
    };

    for pv in &lvm.physical_volumes {
        if pv.name.starts_with("/dev/") && !graph_has_alias(&snapshot.storage.block_devices, &pv.name)
        {
            diagnostics.push(StorageDiagnostic {
                code: "lvm-pv-not-in-lsblk".to_owned(),
                severity: DiagnosticSeverity::Warning,
                message: "LVM reports a physical volume that is not represented in the lsblk topology"
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
    collect_ids(
        &snapshot.storage.block_devices,
        &mut uuids,
        &mut partuuids,
    );

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
                message: "active block-device swap is not represented in the discovered lsblk topology"
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
                lv_aliases(lv).iter().any(|alias| alias == source)
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
    devices.iter().any(|device| {
        device.path.as_deref() == Some(alias)
            || device
                .kernel_name
                .as_deref()
                .map(|name| format!("/dev/{name}") == alias)
                .unwrap_or(false)
            || format!("/dev/{}", device.name) == alias
            || graph_has_alias(&device.children, alias)
    })
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
