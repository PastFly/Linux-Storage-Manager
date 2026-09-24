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
    #[error("LVM `{0}` response has no report envelope")]
    MissingReport(&'static str),
}

pub fn discover_lvm() -> Result<LvmInventory, LvmDiscoveryError> {
    Ok(LvmInventory {
        physical_volumes: parse_pvs_json(&run_report(
            "pvs", "pv_name,pv_uuid,vg_name,pv_size,pv_free,pe_start",
        )?)?,
        volume_groups: parse_vgs_json(&run_report(
            "vgs",
            "vg_name,vg_uuid,vg_size,vg_free,pv_count,lv_count,vg_extent_size,vg_free_count,vg_missing_pv_count,vg_attr",
        )?)?,
        logical_volumes: parse_lvs_json(&run_report(
            "lvs", "lv_name,lv_path,lv_uuid,vg_name,lv_size,lv_attr,lv_layout,lv_role",
        )?)?,
    })
}

fn run_report(command: &'static str, columns: &str) -> Result<String, LvmDiscoveryError> {
    // --readonly intentionally is not used: it omits device-mapper activation/use facts.
    let output = Command::new(command)
        .env("LC_ALL", "C")
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
    require_report("pvs", output.report.len())?;
    output
        .report
        .into_iter()
        .flat_map(|report| report.pv)
        .map(|row| {
            Ok(LvmPhysicalVolume {
                name: row.pv_name,
                uuid: optional(row.pv_uuid),
                vg_name: optional(row.vg_name),
                size_bytes: parse_number("pv_size", &row.pv_size)?,
                free_bytes: parse_number("pv_free", &row.pv_free)?,
                pe_start_bytes: optional_number("pe_start", optional(row.pe_start))?,
            })
        })
        .collect()
}

pub fn parse_vgs_json(input: &str) -> Result<Vec<LvmVolumeGroup>, LvmDiscoveryError> {
    let output: VgsOutput = parse_json("vgs", input)?;
    require_report("vgs", output.report.len())?;
    output
        .report
        .into_iter()
        .flat_map(|report| report.vg)
        .map(|row| {
            Ok(LvmVolumeGroup {
                name: row.vg_name,
                uuid: optional(row.vg_uuid),
                size_bytes: parse_number("vg_size", &row.vg_size)?,
                free_bytes: parse_number("vg_free", &row.vg_free)?,
                pv_count: parse_number("pv_count", &row.pv_count)?,
                lv_count: parse_number("lv_count", &row.lv_count)?,
                extent_size_bytes: optional_number("vg_extent_size", row.vg_extent_size)?,
                free_extent_count: optional_number("vg_free_count", row.vg_free_count)?,
                missing_pv_count: optional_number("vg_missing_pv_count", row.vg_missing_pv_count)?,
                attributes: optional(row.vg_attr),
            })
        })
        .collect()
}

pub fn parse_lvs_json(input: &str) -> Result<Vec<LvmLogicalVolume>, LvmDiscoveryError> {
    let output: LvsOutput = parse_json("lvs", input)?;
    require_report("lvs", output.report.len())?;
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
                size_bytes: parse_number("lv_size", &row.lv_size)?,
                attributes: optional(row.lv_attr),
                layout: optional(row.lv_layout),
                role: optional(row.lv_role),
            })
        })
        .collect()
}

fn require_report(command: &'static str, count: usize) -> Result<(), LvmDiscoveryError> {
    if count == 0 {
        Err(LvmDiscoveryError::MissingReport(command))
    } else {
        Ok(())
    }
}

fn parse_json<'de, T: Deserialize<'de>>(
    command: &'static str,
    input: &'de str,
) -> Result<T, LvmDiscoveryError> {
    serde_json::from_str(input).map_err(|source| LvmDiscoveryError::InvalidJson { command, source })
}

fn optional(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn optional_number(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<u64>, LvmDiscoveryError> {
    value.map(|value| parse_number(field, &value)).transpose()
}

// LVM byte reports may contain ".00". Accept exact integers only, never f64 rounding.
fn parse_number(field: &'static str, value: &str) -> Result<u64, LvmDiscoveryError> {
    let invalid = || LvmDiscoveryError::InvalidNumber {
        field,
        value: value.to_owned(),
    };
    let trimmed = value.trim();
    let integer = if let Some((integer, fractional)) = trimmed.split_once('.') {
        if fractional.is_empty() || !fractional.bytes().all(|b| b == b'0') {
            return Err(invalid());
        }
        integer
    } else {
        trimmed
    };
    if integer.is_empty() || !integer.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    integer.parse::<u64>().map_err(|_| invalid())
}

#[derive(Debug, Deserialize)]
struct PvsOutput {
    report: Vec<PvsReport>,
}
#[derive(Debug, Deserialize)]
struct PvsReport {
    pv: Vec<PvRow>,
}
#[derive(Debug, Deserialize)]
struct PvRow {
    pv_name: String,
    #[serde(default)]
    pv_uuid: String,
    #[serde(default)]
    vg_name: String,
    pv_size: String,
    pv_free: String,
    #[serde(default)]
    pe_start: String,
}

#[derive(Debug, Deserialize)]
struct VgsOutput {
    report: Vec<VgsReport>,
}
#[derive(Debug, Deserialize)]
struct VgsReport {
    vg: Vec<VgRow>,
}
#[derive(Debug, Deserialize)]
struct VgRow {
    vg_name: String,
    #[serde(default)]
    vg_uuid: String,
    vg_size: String,
    vg_free: String,
    pv_count: String,
    lv_count: String,
    #[serde(default)]
    vg_extent_size: Option<String>,
    #[serde(default)]
    vg_free_count: Option<String>,
    #[serde(default)]
    vg_missing_pv_count: Option<String>,
    #[serde(default)]
    vg_attr: String,
}

#[derive(Debug, Deserialize)]
struct LvsOutput {
    report: Vec<LvsReport>,
}
#[derive(Debug, Deserialize)]
struct LvsReport {
    lv: Vec<LvRow>,
}
#[derive(Debug, Deserialize)]
struct LvRow {
    lv_name: String,
    #[serde(default)]
    lv_path: String,
    #[serde(default)]
    lv_uuid: String,
    vg_name: String,
    lv_size: String,
    #[serde(default)]
    lv_attr: String,
    #[serde(default)]
    lv_layout: String,
    #[serde(default)]
    lv_role: String,
}
