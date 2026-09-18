use std::process::Command;

use lsm_core::MountEntry;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MountDiscoveryError {
    #[error("required command `findmnt` could not be executed: {0}")]
    Io(#[from] std::io::Error),
    #[error("`findmnt` failed with status {status}: {stderr}")]
    CommandFailed { status: String, stderr: String },
    #[error("invalid `findmnt` JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

pub fn discover_mounts() -> Result<Vec<MountEntry>, MountDiscoveryError> {
    let output = Command::new("findmnt")
        .args([
            "--json",
            "--bytes",
            "--output",
            "SOURCE,TARGET,FSTYPE,OPTIONS",
        ])
        .output()?;

    if !output.status.success() {
        return Err(MountDiscoveryError::CommandFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    parse_findmnt_json(&String::from_utf8_lossy(&output.stdout))
}

pub fn parse_findmnt_json(input: &str) -> Result<Vec<MountEntry>, MountDiscoveryError> {
    let raw: FindmntOutput = serde_json::from_str(input)?;
    let mut mounts = Vec::new();
    for filesystem in raw.filesystems {
        flatten(filesystem, &mut mounts);
    }
    Ok(mounts)
}

fn flatten(node: FindmntNode, mounts: &mut Vec<MountEntry>) {
    mounts.push(MountEntry {
        source: node.source,
        target: node.target,
        fs_type: node.fstype,
        options: node
            .options
            .map(|value| {
                value
                    .split(',')
                    .filter(|option| !option.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    });

    for child in node.children {
        flatten(child, mounts);
    }
}

#[derive(Debug, Deserialize)]
struct FindmntOutput {
    #[serde(default)]
    filesystems: Vec<FindmntNode>,
}

#[derive(Debug, Deserialize)]
struct FindmntNode {
    #[serde(default)]
    source: Option<String>,
    target: String,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    options: Option<String>,
    #[serde(default)]
    children: Vec<FindmntNode>,
}
