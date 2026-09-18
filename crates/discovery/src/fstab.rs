use std::fs;

use lsm_core::FstabEntry;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FstabDiscoveryError {
    #[error("could not read /etc/fstab: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid /etc/fstab line {line}: expected 4 to 6 fields, got {fields}")]
    InvalidLine { line: usize, fields: usize },
    #[error("invalid numeric field `{field}` on /etc/fstab line {line}: {value}")]
    InvalidNumber {
        line: usize,
        field: &'static str,
        value: String,
    },
}

pub fn discover_fstab() -> Result<Vec<FstabEntry>, FstabDiscoveryError> {
    parse_fstab(&fs::read_to_string("/etc/fstab")?)
}

pub fn parse_fstab(input: &str) -> Result<Vec<FstabEntry>, FstabDiscoveryError> {
    let mut entries = Vec::new();

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if !(4..=6).contains(&fields.len()) {
            return Err(FstabDiscoveryError::InvalidLine {
                line: line_number,
                fields: fields.len(),
            });
        }

        let dump = if fields.len() >= 5 {
            parse_u32(fields[4], line_number, "dump")?
        } else {
            0
        };
        let pass = if fields.len() >= 6 {
            parse_u32(fields[5], line_number, "pass")?
        } else {
            0
        };

        entries.push(FstabEntry {
            source: unescape_fstab(fields[0]),
            target: unescape_fstab(fields[1]),
            fs_type: fields[2].to_owned(),
            options: fields[3]
                .split(',')
                .filter(|option| !option.is_empty())
                .map(str::to_owned)
                .collect(),
            dump,
            pass,
        });
    }

    Ok(entries)
}

fn parse_u32(value: &str, line: usize, field: &'static str) -> Result<u32, FstabDiscoveryError> {
    value
        .parse::<u32>()
        .map_err(|_| FstabDiscoveryError::InvalidNumber {
            line,
            field,
            value: value.to_owned(),
        })
}

fn unescape_fstab(value: &str) -> String {
    value
        .replace("\\134", "\\")
        .replace("\\040", " ")
        .replace("\\011", "\t")
}
