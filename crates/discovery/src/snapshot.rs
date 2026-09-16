use std::io::ErrorKind;

use lsm_core::{CollectorState, CollectorStatus, HostSnapshot};
use thiserror::Error;

use crate::{
    diagnose_storage, discover_fstab, discover_lvm, discover_mounts, discover_partition_tables,
    discover_storage, discover_swaps, reconcile_snapshot, DiscoveryError, FstabDiscoveryError,
    LvmDiscoveryError, MountDiscoveryError, PartitionTableDiscoveryError, SwapDiscoveryError,
};

#[derive(Debug, Error)]
pub enum SnapshotDiscoveryError {
    #[error(transparent)]
    Storage(#[from] DiscoveryError),
}

pub fn discover_snapshot() -> Result<HostSnapshot, SnapshotDiscoveryError> {
    let storage = discover_storage()?;
    let diagnostics = diagnose_storage(&storage);
    let mut collectors = vec![CollectorStatus {
        component: "lsblk".to_owned(),
        state: CollectorState::Complete,
        detail: None,
    }];

    let partition_tables = match discover_partition_tables(&storage) {
        Ok(value) => {
            collectors.push(complete("partition_tables"));
            value
        }
        Err(error) => {
            collectors.push(failed_partition_tables(&error));
            Vec::new()
        }
    };

    let mounts = match discover_mounts() {
        Ok(value) => {
            collectors.push(complete("mounts"));
            value
        }
        Err(error) => {
            collectors.push(failed_mounts(&error));
            Vec::new()
        }
    };

    let fstab = match discover_fstab() {
        Ok(value) => {
            collectors.push(complete("fstab"));
            value
        }
        Err(error) => {
            collectors.push(failed_fstab(&error));
            Vec::new()
        }
    };

    let swaps = match discover_swaps() {
        Ok(value) => {
            collectors.push(complete("swap"));
            value
        }
        Err(error) => {
            collectors.push(failed_swap(&error));
            Vec::new()
        }
    };

    let lvm = match discover_lvm() {
        Ok(value) => {
            collectors.push(complete("lvm"));
            Some(value)
        }
        Err(error) => {
            collectors.push(failed_lvm(&error));
            None
        }
    };

    let mut snapshot = HostSnapshot {
        storage,
        partition_tables,
        mounts,
        fstab,
        swaps,
        lvm,
        diagnostics,
        collectors,
    };

    let reconciliation = reconcile_snapshot(&snapshot);
    snapshot.diagnostics.extend(reconciliation);

    Ok(snapshot)
}

fn complete(component: &str) -> CollectorStatus {
    CollectorStatus {
        component: component.to_owned(),
        state: CollectorState::Complete,
        detail: None,
    }
}

fn failed_partition_tables(error: &PartitionTableDiscoveryError) -> CollectorStatus {
    let unavailable = matches!(
        error,
        PartitionTableDiscoveryError::Io { source, .. } if source.kind() == ErrorKind::NotFound
    );
    failed("partition_tables", error.to_string(), unavailable)
}

fn failed_mounts(error: &MountDiscoveryError) -> CollectorStatus {
    let unavailable = matches!(error, MountDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
    failed("mounts", error.to_string(), unavailable)
}

fn failed_fstab(error: &FstabDiscoveryError) -> CollectorStatus {
    let unavailable = matches!(error, FstabDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
    failed("fstab", error.to_string(), unavailable)
}

fn failed_swap(error: &SwapDiscoveryError) -> CollectorStatus {
    let unavailable = matches!(error, SwapDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
    failed("swap", error.to_string(), unavailable)
}

fn failed_lvm(error: &LvmDiscoveryError) -> CollectorStatus {
    let unavailable = matches!(
        error,
        LvmDiscoveryError::Io { source, .. } if source.kind() == ErrorKind::NotFound
    );
    failed("lvm", error.to_string(), unavailable)
}

fn failed(component: &str, detail: String, unavailable: bool) -> CollectorStatus {
    CollectorStatus {
        component: component.to_owned(),
        state: if unavailable {
            CollectorState::Unavailable
        } else {
            CollectorState::Failed
        },
        detail: Some(detail),
    }
}
