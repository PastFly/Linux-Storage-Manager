//! Opt-in fs-verity helper; not a production recovery proof.
//!
//! The digest is an fs-verity measurement, not a traditional file SHA-256.
//! These helpers neither sync/publish files nor authenticate paths or content.
#![allow(dead_code)]
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

// Linux UAPI encodings for the supported x86_64 and aarch64 ABIs. Other
// architectures fail closed before issuing an ioctl.
const FS_IOC_ENABLE_VERITY: libc::c_ulong = 0x4080_6685;
const FS_IOC_MEASURE_VERITY: libc::c_ulong = 0xc004_6686;
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;
const SHA256_SIZE: usize = 32;
const MERKLE_BLOCK_SIZE: u32 = 4096;

#[repr(C)]
struct EnableArg {
    version: u32,
    hash_algorithm: u32,
    block_size: u32,
    salt_size: u32,
    salt_ptr: u64,
    sig_size: u32,
    reserved1: u32,
    sig_ptr: u64,
    reserved2: [u64; 11],
}

// The first four bytes match struct fsverity_digest; the fixed array supplies
// the caller-owned storage for the kernel's variable-length digest.
#[repr(C)]
struct DigestBuffer {
    algorithm: u16,
    size: u16,
    digest: [u8; SHA256_SIZE],
}

fn require_readonly_regular(file: &File) -> io::Result<()> {
    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fs-verity ioctl ABI unsupported on this architecture",
        ));
    }
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & (libc::O_ACCMODE | libc::O_PATH) != libc::O_RDONLY || !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fs-verity requires a read-only regular file descriptor",
        ));
    }
    Ok(())
}

pub(crate) fn enable(file: &File) -> io::Result<()> {
    require_readonly_regular(file)?;
    let arg = EnableArg {
        version: 1,
        hash_algorithm: u32::from(FS_VERITY_HASH_ALG_SHA256),
        block_size: MERKLE_BLOCK_SIZE,
        salt_size: 0,
        salt_ptr: 0,
        sig_size: 0,
        reserved1: 0,
        sig_ptr: 0,
        reserved2: [0; 11],
    };
    let result = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_ENABLE_VERITY, &arg) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn checked_digest(result: DigestBuffer) -> io::Result<[u8; SHA256_SIZE]> {
    if result.algorithm != FS_VERITY_HASH_ALG_SHA256 || usize::from(result.size) != SHA256_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected fs-verity digest algorithm or length",
        ));
    }
    Ok(result.digest)
}

pub(crate) fn measure(file: &File) -> io::Result<[u8; SHA256_SIZE]> {
    require_readonly_regular(file)?;
    let mut result = DigestBuffer {
        algorithm: 0,
        size: SHA256_SIZE as u16,
        digest: [0; SHA256_SIZE],
    };
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_MEASURE_VERITY, &mut result) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    checked_digest(result)
}

#[cfg(test)]
#[path = "backup_verity_tests.rs"]
mod tests;
