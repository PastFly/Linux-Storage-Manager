use std::process::Command;

use lsm_core::{NodeKind, PartitionRecord, PartitionTable, StorageGraph};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PartitionTableDiscoveryError {
    #[error("required command `sfdisk` could not be executed for `{device}`: {source}")]
    Io {
        device: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`sfdisk --json {device}` failed with status {status}: {stderr}")]
    CommandFailed {
        device: String,
        status: String,
        stderr: String,
    },
    #[error("invalid JSON from `sfdisk --json {device}`: {source}")]
    InvalidJson {
        device: String,
        #[source]
        source: serde_json::Error,
    },
}

pub fn discover_partition_tables(
    graph: &StorageGraph,
) -> Result<Vec<PartitionTable>, PartitionTableDiscoveryError> {
    let mut tables = Vec::new();

    for disk in &graph.block_devices {
        if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop) || disk.partition_table.is_none() {
            continue;
        }

        let Some(device) = disk.path.as_deref() else {
            continue;
        };

        let output = Command::new("sfdisk")
            .args(["--json", device])
            .output()
            .map_err(|source| PartitionTableDiscoveryError::Io {
                device: device.to_owned(),
                source,
            })?;

        if !output.status.success() {
            return Err(PartitionTableDiscoveryError::CommandFailed {
                device: device.to_owned(),
                status: output.status.to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }

        tables.push(parse_sfdisk_json_for_device(
            device,
            &String::from_utf8_lossy(&output.stdout),
        )?);
    }

    Ok(tables)
}

pub fn parse_sfdisk_json(input: &str) -> Result<PartitionTable, PartitionTableDiscoveryError> {
    parse_sfdisk_json_for_device("fixture", input)
}

fn parse_sfdisk_json_for_device(
    device: &str,
    input: &str,
) -> Result<PartitionTable, PartitionTableDiscoveryError> {
    let raw: SfdiskOutput = serde_json::from_str(input).map_err(|source| {
        PartitionTableDiscoveryError::InvalidJson {
            device: device.to_owned(),
            source,
        }
    })?;

    let table = raw.partitiontable;
    Ok(PartitionTable {
        device: table.device,
        label: table.label,
        id: table.id,
        unit: table.unit,
        first_lba: table.firstlba,
        last_lba: table.lastlba,
        sector_size_bytes: table.sectorsize,
        partitions: table
            .partitions
            .into_iter()
            .map(|partition| PartitionRecord {
                node: partition.node,
                start_sector: partition.start,
                size_sectors: partition.size,
                partition_type: partition.partition_type,
                uuid: partition.uuid,
                name: partition.name,
                attrs: partition.attrs,
                bootable: partition.bootable,
            })
            .collect(),
    })
}

#[derive(Debug, Deserialize)]
struct SfdiskOutput {
    partitiontable: SfdiskPartitionTable,
}

#[derive(Debug, Deserialize)]
struct SfdiskPartitionTable {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    id: Option<String>,
    device: String,
    #[serde(default)]
    unit: Option<String>,
    #[serde(default)]
    firstlba: Option<u64>,
    #[serde(default)]
    lastlba: Option<u64>,
    #[serde(default)]
    sectorsize: Option<u64>,
    #[serde(default)]
    partitions: Vec<SfdiskPartition>,
}

#[derive(Debug, Deserialize)]
struct SfdiskPartition {
    node: String,
    start: u64,
    size: u64,
    #[serde(rename = "type", default)]
    partition_type: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    attrs: Option<String>,
    #[serde(default)]
    bootable: Option<bool>,
}
