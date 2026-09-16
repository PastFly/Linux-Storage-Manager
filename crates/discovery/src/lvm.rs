use std::process::Command;

use lsm_core::{LvmInventory, LvmLogicalVolume, LvmPhysicalVolume, LvmVolumeGroup};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LvmDiscoveryError {
    #[error("required command `{command}` could not be executed: {source}")]
    Io {
        command: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("`{command}` failed with status {status}: {stderr}")]
    CommandFailed {
        command: &'static str,
        status: String,
        stderr: String,
    },
    #[error("invalid JSON from `{command}`: {source}")]
    InvalidJson {
        command: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid numeric field `{field}` from LVM: {value}")]
    InvalidNumber { field: &'static str, value: String },
}

pub fn discover_lvm() -> Result<LvmInventory, LvmDiscoveryError> {
    Ok(LvmInventory {
        physical_volumes: parse_pvs_json(&run_report(
            "pvs",
            "pv_name,pv_uuid,vg_name,pv_size,pv_free",
        )?)?,
        volume_groups: parse_vgs_json(&run_report(
            "vgs",
            "vg_name,vg_uuid,vg_size,vg_free,pv_count,lv_count",
        )?)?,
        logical_volumes: parse_lvs_json(&run_report(
            "lvs",
            "lv_name,lv_path,lv_uuid,vg_name,lv_size,lv_attr",
        )?)?,
    })
}

fn run_report(command: &'static str, columns: &str) -> Result<String, LvmDiscoveryError> {
    let output = Command::new(command)
        .args([
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "--options",
            columns,
        ])
        .output()
        .map_err(|source| LvmDiscoveryError::Io { command, source })?;

    if !output.status.success() {
        return Err(LvmDiscoveryError::CommandFailed {
            command,
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn parse_pvs_json(input: &str) -> Result<Vec<LvmPhysicalVolume>, LvmDiscoveryError> {
    let output: PvsOutput = parse_json("pvs", input)?;
    output
        .report
        .into_iter()
        .flat_map(|report| report.pv)
        .map(|row| {
            Ok(LvmPhysicalVolume {
                name: row.pv_name,
                uuid: optional(row.pv_uuid),
                vg_name: optional(row.vg_name),
                size_bytes: parse_bytes("pv_size", &row.pv_size)?,
                free_bytes: parse_bytes("pv_free", &row.pv_free)?,
            })
        })
        .collect()
}

pub fn parse_vgs_json(input: &str) -> Result<Vec<LvmVolumeGroup>, LvmDiscoveryError> {
    let output: VgsOutput = parse_json("vgs", input)?;
    output
        .report
        .into_iter()
        .flat_map(|report| report.vg)
        .map(|row| {
            Ok(LvmVolumeGroup {
                name: row.vg_name,
                uuid: optional(row.vg_uuid),
                size_bytes: parse_bytes("vg_size", &row.vg_size)?,
                free_bytes: parse_bytes("vg_free", &row.vg_free)?,
                pv_count: parse_integer("pv_count", &row.pv_count)?,
                lv_count: parse_integer("lv_count", &row.lv_count)?,
            })
        })
        .collect()
}

pub fn parse_lvs_json(input: &str) -> Result<Vec<LvmLogicalVolume>, LvmDiscoveryError> {
    let output: LvsOutput = parse_json("lvs", input)?;
    output
        .report
        .into_iter()
        .flat_map(|report| report.lv)
        .map(|row| {
            Ok(LvmLogicalVolume {
                name: row.lv_name,
                path: optional(row.lv_path),
                uuid: optional(row.lv_uuid),
                vg_name: row.vg_name,
                size_bytes: parse_bytes("lv_size", &row.lv_size)?,
                attributes: optional(row.lv_attr),
            })
        })
        .collect()
}

fn parse_json<'de, T>(command: &'static str, input: &'de str) -> Result<T, LvmDiscoveryError>
where
    T: Deserialize<'de>,
{
    serde_json::from_str(input).map_err(|source| LvmDiscoveryError::InvalidJson { command, source })
}

fn optional(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn parse_bytes(field: &'static str, value: &str) -> Result<u64, LvmDiscoveryError> {
    parse_number(field, value)
}

fn parse_integer(field: &'static str, value: &str) -> Result<u64, LvmDiscoveryError> {
    parse_number(field, value)
}

fn parse_number(field: &'static str, value: &str) -> Result<u64, LvmDiscoveryError> {
    let trimmed = value.trim();
    if let Ok(value) = trimmed.parse::<u64>() {
        return Ok(value);
    }

    let value = trimmed
        .parse::<f64>()
        .map_err(|_| LvmDiscoveryError::InvalidNumber {
            field,
            value: value.to_owned(),
        })?;

    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return Err(LvmDiscoveryError::InvalidNumber {
            field,
            value: trimmed.to_owned(),
        });
    }

    Ok(value.round() as u64)
}

#[derive(Debug, Deserialize)]
struct PvsOutput {
    #[serde(default)]
    report: Vec<PvsReport>,
}

#[derive(Debug, Deserialize)]
struct PvsReport {
    #[serde(default)]
    pv: Vec<PvRow>,
}

#[derive(Debug, Deserialize)]
struct PvRow {
    #[serde(default)]
    pv_name: String,
    #[serde(default)]
    pv_uuid: String,
    #[serde(default)]
    vg_name: String,
    #[serde(default)]
    pv_size: String,
    #[serde(default)]
    pv_free: String,
}

#[derive(Debug, Deserialize)]
struct VgsOutput {
    #[serde(default)]
    report: Vec<VgsReport>,
}

#[derive(Debug, Deserialize)]
struct VgsReport {
    #[serde(default)]
    vg: Vec<VgRow>,
}

#[derive(Debug, Deserialize)]
struct VgRow {
    #[serde(default)]
    vg_name: String,
    #[serde(default)]
    vg_uuid: String,
    #[serde(default)]
    vg_size: String,
    #[serde(default)]
    vg_free: String,
    #[serde(default)]
    pv_count: String,
    #[serde(default)]
    lv_count: String,
}

#[derive(Debug, Deserialize)]
struct LvsOutput {
    #[serde(default)]
    report: Vec<LvsReport>,
}

#[derive(Debug, Deserialize)]
struct LvsReport {
    #[serde(default)]
    lv: Vec<LvRow>,
}

#[derive(Debug, Deserialize)]
struct LvRow {
    #[serde(default)]
    lv_name: String,
    #[serde(default)]
    lv_path: String,
    #[serde(default)]
    lv_uuid: String,
    #[serde(default)]
    vg_name: String,
    #[serde(default)]
    lv_size: String,
    #[serde(default)]
    lv_attr: String,
}
