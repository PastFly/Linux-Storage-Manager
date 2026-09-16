use lsm_core::{
    BlockDevice, DiagnosticSeverity, NodeKind, StorageDiagnostic, StorageGraph,
};

pub fn diagnose_storage(graph: &StorageGraph) -> Vec<StorageDiagnostic> {
    let mut diagnostics = Vec::new();
    for device in &graph.block_devices {
        inspect_device(device, None, &mut diagnostics);
    }
    diagnostics
}

fn inspect_device(
    device: &BlockDevice,
    parent: Option<&BlockDevice>,
    diagnostics: &mut Vec<StorageDiagnostic>,
) {
    let device_name = device
        .path
        .clone()
        .unwrap_or_else(|| device.name.clone());

    if device.kind == NodeKind::Unknown {
        diagnostics.push(StorageDiagnostic {
            code: "unknown-node-kind".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "lsblk reported a device type that Linux Storage Manager does not yet classify"
                .to_owned(),
            device: Some(device_name.clone()),
        });
    }

    if device.filesystem.is_some() && device.size_bytes == 0 {
        diagnostics.push(StorageDiagnostic {
            code: "filesystem-on-zero-size-device".to_owned(),
            severity: DiagnosticSeverity::Warning,
            message: "a filesystem was reported on a zero-size block device".to_owned(),
            device: Some(device_name.clone()),
        });
    }

    if device.kind == NodeKind::Partition {
        if let Some(parent) = parent {
            if parent.kind == NodeKind::Disk && device.size_bytes > parent.size_bytes {
                diagnostics.push(StorageDiagnostic {
                    code: "partition-larger-than-disk".to_owned(),
                    severity: DiagnosticSeverity::Error,
                    message: "partition size is larger than its parent disk size".to_owned(),
                    device: Some(device_name.clone()),
                });
            }

            if let (Some(expected), Some(reported)) = (
                parent.kernel_name.as_deref(),
                device.parent_kernel_name.as_deref(),
            ) {
                if expected != reported {
                    diagnostics.push(StorageDiagnostic {
                        code: "partition-parent-mismatch".to_owned(),
                        severity: DiagnosticSeverity::Warning,
                        message: format!(
                            "partition reports parent kernel name `{reported}`, but tree parent is `{expected}`"
                        ),
                        device: Some(device_name.clone()),
                    });
                }
            }
        }
    }

    for child in &device.children {
        inspect_device(child, Some(device), diagnostics);
    }
}
