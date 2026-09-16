use std::fs;

use lsm_core::SwapEntry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SwapDiscoveryError {
    #[error("could not read /proc/swaps: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid /proc/swaps line {line}: {content}")]
    InvalidLine { line: usize, content: String },
    #[error("invalid numeric field `{field}` on /proc/swaps line {line}: {value}")]
    InvalidNumber {
        line: usize,
        field: &'static str,
        value: String,
    },
    #[error("swap size overflow on /proc/swaps line {line}")]
    SizeOverflow { line: usize },
}

pub fn discover_swaps() -> Result<Vec<SwapEntry>, SwapDiscoveryError> {
    parse_proc_swaps(&fs::read_to_string("/proc/swaps")?)
}

pub fn parse_proc_swaps(input: &str) -> Result<Vec<SwapEntry>, SwapDiscoveryError> {
    let mut swaps = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        if index == 0 || line.trim().is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(SwapDiscoveryError::InvalidLine {
                line: line_number,
                content: line.to_owned(),
            });
        }

        let size_kib = parse_u64(fields[2], line_number, "size")?;
        let used_kib = parse_u64(fields[3], line_number, "used")?;
        let priority = fields[4]
            .parse::<i32>()
            .map_err(|_| SwapDiscoveryError::InvalidNumber {
                line: line_number,
                field: "priority",
                value: fields[4].to_owned(),
            })?;

        swaps.push(SwapEntry {
            name: unescape_proc_path(fields[0]),
            kind: fields[1].to_owned(),
            size_bytes: size_kib
                .checked_mul(1024)
                .ok_or(SwapDiscoveryError::SizeOverflow { line: line_number })?,
            used_bytes: used_kib
                .checked_mul(1024)
                .ok_or(SwapDiscoveryError::SizeOverflow { line: line_number })?,
            priority,
        });
    }

    Ok(swaps)
}

fn parse_u64(
    value: &str,
    line: usize,
    field: &'static str,
) -> Result<u64, SwapDiscoveryError> {
    value
        .parse::<u64>()
        .map_err(|_| SwapDiscoveryError::InvalidNumber {
            line,
            field,
            value: value.to_owned(),
        })
}

fn unescape_proc_path(value: &str) -> String {
    value
        .replace("\\134", "\\")
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
}
