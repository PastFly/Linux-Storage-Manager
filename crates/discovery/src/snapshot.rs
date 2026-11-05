use std::io::ErrorKind;

use lsm_core::{CollectorState, CollectorStatus, HostSnapshot};
use thiserror::Error;

use crate::{
    diagnose_storage, discover_fstab, discover_swaps, reconcile_snapshot, DiscoveryError,
    FstabDiscoveryError, LvmDiscoveryError, MountDiscoveryError, PartitionTableDiscoveryError,
    SwapDiscoveryError,
};
use crate::{DiscoveryCommandRunner, SystemDiscoveryRunner};

#[derive(Debug, Error)]
pub enum SnapshotDiscoveryError {
    #[error(transparent)]
    Storage(#[from] DiscoveryError),
}

pub fn discover_snapshot() -> Result<HostSnapshot, SnapshotDiscoveryError> {
    discover_snapshot_with_runner(&SystemDiscoveryRunner)
}

pub fn discover_snapshot_with_runner(
    runner: &dyn DiscoveryCommandRunner,
) -> Result<HostSnapshot, SnapshotDiscoveryError> {
    let storage = crate::discover_storage_with_runner(runner)?;
    let diagnostics = diagnose_storage(&storage);
    let mut collectors = vec![CollectorStatus {
        component: "lsblk".to_owned(),
        state: CollectorState::Complete,
        detail: None,
    }];

    let partition_tables = match crate::discover_partition_tables_with_runner(&storage, runner) {
        Ok(value) => {
            collectors.push(complete("partition_tables"));
            value
        }
        Err(error) => {
            collectors.push(failed_partition_tables(&error));
            Vec::new()
        }
    };

    let mounts = match crate::discover_mounts_with_runner(runner) {
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

    let lvm = match crate::discover_lvm_with_runner(runner) {
        Ok(value) => {
            collectors.push(complete("lvm"));
            Some(value)
        }
        Err(error) => {
            collectors.push(failed_lvm(&error));
            None
        }
    };

    let filesystem_preflight = crate::discover_filesystem_preflight_with_runner(&storage, runner);
    collectors.push(complete("filesystem_preflight"));

    let mut snapshot = HostSnapshot {
        storage,
        partition_tables,
        mounts,
        fstab,
        swaps,
        lvm,
        filesystem_preflight,
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
    let unavailable =
        matches!(error, MountDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
    failed("mounts", error.to_string(), unavailable)
}

fn failed_fstab(error: &FstabDiscoveryError) -> CollectorStatus {
    let unavailable =
        matches!(error, FstabDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
    failed("fstab", error.to_string(), unavailable)
}

fn failed_swap(error: &SwapDiscoveryError) -> CollectorStatus {
    let unavailable =
        matches!(error, SwapDiscoveryError::Io(source) if source.kind() == ErrorKind::NotFound);
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
