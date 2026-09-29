use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;

use lsm_core::FilesystemSpaceEvidence;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FilesystemSpaceDiscoveryError {
    #[error("filesystem-space path is empty or contains an embedded NUL byte")]
    InvalidPath,
    #[error("statvfs failed for {path}: {source}")]
    Statvfs {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("filesystem-space byte count overflowed u64")]
    SizeOverflow,
}

pub fn discover_filesystem_space(
    path: &str,
) -> Result<FilesystemSpaceEvidence, FilesystemSpaceDiscoveryError> {
    if path.is_empty() {
        return Err(FilesystemSpaceDiscoveryError::InvalidPath);
    }
    let c_path = CString::new(path).map_err(|_| FilesystemSpaceDiscoveryError::InvalidPath)?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(FilesystemSpaceDiscoveryError::Statvfs {
            path: path.to_owned(),
            source: io::Error::last_os_error(),
        });
    }
    let stats = unsafe { stats.assume_init() };
    let block_size_bytes = if stats.f_frsize > 0 {
        u64::try_from(stats.f_frsize).map_err(|_| FilesystemSpaceDiscoveryError::SizeOverflow)?
    } else {
        u64::try_from(stats.f_bsize).map_err(|_| FilesystemSpaceDiscoveryError::SizeOverflow)?
    };
    if block_size_bytes == 0 {
        return Err(FilesystemSpaceDiscoveryError::SizeOverflow);
    }
    let blocks =
        u64::try_from(stats.f_blocks).map_err(|_| FilesystemSpaceDiscoveryError::SizeOverflow)?;
    let available_blocks =
        u64::try_from(stats.f_bavail).map_err(|_| FilesystemSpaceDiscoveryError::SizeOverflow)?;
    let total_bytes = blocks
        .checked_mul(block_size_bytes)
        .ok_or(FilesystemSpaceDiscoveryError::SizeOverflow)?;
    let available_bytes = available_blocks
        .checked_mul(block_size_bytes)
        .ok_or(FilesystemSpaceDiscoveryError::SizeOverflow)?;

    Ok(FilesystemSpaceEvidence {
        path: path.to_owned(),
        block_size_bytes,
        total_bytes,
        available_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_filesystem_space_is_readable() {
        let evidence = discover_filesystem_space("/").unwrap();
        assert_eq!(evidence.path, "/");
        assert!(evidence.block_size_bytes > 0);
        assert!(evidence.total_bytes > 0);
        assert!(evidence.available_bytes <= evidence.total_bytes);
    }

    #[test]
    fn embedded_nul_path_is_rejected_before_syscall() {
        assert!(matches!(
            discover_filesystem_space("/tmp/bad\0path"),
            Err(FilesystemSpaceDiscoveryError::InvalidPath)
        ));
    }
}
