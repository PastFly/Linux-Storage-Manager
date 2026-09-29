use std::fs;
use std::io;
use std::path::Path;

use lsm_core::HibernationResumeEvidence;
use thiserror::Error;

const PROC_CMDLINE: &str = "/proc/cmdline";
const SYS_POWER_RESUME: &str = "/sys/power/resume";
const SYS_POWER_RESUME_OFFSET: &str = "/sys/power/resume_offset";

#[derive(Debug, Error)]
pub enum HibernationResumeDiscoveryError {
    #[error("could not read hibernation/resume evidence from {path}: {source}")]
    Io {
        path: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("kernel resume_offset value is not an unsigned integer: {0}")]
    InvalidKernelResumeOffset(String),
    #[error("sysfs resume value is malformed: {0}")]
    InvalidSysfsResume(String),
    #[error("sysfs resume_offset value is not an unsigned integer: {0}")]
    InvalidSysfsResumeOffset(String),
}

pub fn parse_kernel_resume_evidence(
    cmdline: &str,
) -> Result<(Vec<String>, Vec<u64>), HibernationResumeDiscoveryError> {
    let mut targets = Vec::new();
    let mut offsets = Vec::new();

    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix("resume=") {
            if !value.is_empty() {
                targets.push(value.to_owned());
            }
        } else if let Some(value) = token.strip_prefix("resume_offset=") {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| HibernationResumeDiscoveryError::InvalidKernelResumeOffset(value.to_owned()))?;
            offsets.push(parsed);
        }
    }

    targets.sort();
    targets.dedup();
    offsets.sort_unstable();
    offsets.dedup();
    Ok((targets, offsets))
}

pub fn parse_sysfs_resume(value: &str) -> Result<Option<String>, HibernationResumeDiscoveryError> {
    let value = value.trim();
    let Some((major, minor)) = value.split_once(':') else {
        return Err(HibernationResumeDiscoveryError::InvalidSysfsResume(value.to_owned()));
    };
    let major = major
        .parse::<u64>()
        .map_err(|_| HibernationResumeDiscoveryError::InvalidSysfsResume(value.to_owned()))?;
    let minor = minor
        .parse::<u64>()
        .map_err(|_| HibernationResumeDiscoveryError::InvalidSysfsResume(value.to_owned()))?;

    if major == 0 && minor == 0 {
        Ok(None)
    } else {
        Ok(Some(format!("{major}:{minor}")))
    }
}

pub fn parse_sysfs_resume_offset(
    value: &str,
) -> Result<Option<u64>, HibernationResumeDiscoveryError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let offset = value
        .parse::<u64>()
        .map_err(|_| HibernationResumeDiscoveryError::InvalidSysfsResumeOffset(value.to_owned()))?;
    Ok((offset != 0).then_some(offset))
}

fn read_optional(path: &'static str) -> Result<Option<String>, HibernationResumeDiscoveryError> {
    match fs::read_to_string(Path::new(path)) {
        Ok(value) => Ok(Some(value)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(HibernationResumeDiscoveryError::Io { path, source }),
    }
}

pub fn discover_hibernation_resume_evidence(
) -> Result<HibernationResumeEvidence, HibernationResumeDiscoveryError> {
    let cmdline = fs::read_to_string(PROC_CMDLINE).map_err(|source| {
        HibernationResumeDiscoveryError::Io {
            path: PROC_CMDLINE,
            source,
        }
    })?;
    let (kernel_resume_targets, kernel_resume_offsets) = parse_kernel_resume_evidence(&cmdline)?;

    let sysfs_resume = match read_optional(SYS_POWER_RESUME)? {
        Some(value) => parse_sysfs_resume(&value)?,
        None => None,
    };
    let sysfs_resume_offset = match read_optional(SYS_POWER_RESUME_OFFSET)? {
        Some(value) => parse_sysfs_resume_offset(&value)?,
        None => None,
    };

    Ok(HibernationResumeEvidence {
        kernel_resume_targets,
        kernel_resume_offsets,
        sysfs_resume,
        sysfs_resume_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_cmdline_extracts_only_resume_tokens() {
        let (targets, offsets) = parse_kernel_resume_evidence(
            "quiet root=UUID=root resume=UUID=swap resume_offset=8192 splash",
        )
        .unwrap();
        assert_eq!(targets, vec!["UUID=swap"]);
        assert_eq!(offsets, vec![8192]);
    }

    #[test]
    fn duplicate_resume_tokens_are_canonicalized() {
        let (targets, offsets) = parse_kernel_resume_evidence(
            "resume=/dev/sda2 resume=/dev/sda2 resume_offset=42 resume_offset=42",
        )
        .unwrap();
        assert_eq!(targets, vec!["/dev/sda2"]);
        assert_eq!(offsets, vec![42]);
    }

    #[test]
    fn malformed_kernel_resume_offset_fails_closed() {
        assert!(matches!(
            parse_kernel_resume_evidence("resume_offset=not-a-number"),
            Err(HibernationResumeDiscoveryError::InvalidKernelResumeOffset(_))
        ));
    }

    #[test]
    fn sysfs_zero_device_means_no_active_resume_device() {
        assert_eq!(parse_sysfs_resume("0:0\n").unwrap(), None);
        assert_eq!(parse_sysfs_resume("8:2").unwrap(), Some("8:2".into()));
    }

    #[test]
    fn nonzero_sysfs_resume_offset_is_retained() {
        assert_eq!(parse_sysfs_resume_offset("0\n").unwrap(), None);
        assert_eq!(parse_sysfs_resume_offset("4096\n").unwrap(), Some(4096));
    }
}
