use super::{enable, measure};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[test]
fn ioctl_layout_matches_linux_uapi() {
    assert_eq!(std::mem::size_of::<super::EnableArg>(), 128);
    assert_eq!(std::mem::size_of::<super::DigestBuffer>(), 36);
    assert_eq!(std::mem::offset_of!(super::DigestBuffer, digest), 4);
}

#[test]
fn rejects_unexpected_digest_algorithm_and_length() {
    let digest = [7; 32];
    assert!(super::checked_digest(super::DigestBuffer {
        algorithm: 2,
        size: 32,
        digest,
    })
    .is_err());
    assert!(super::checked_digest(super::DigestBuffer {
        algorithm: 1,
        size: 31,
        digest,
    })
    .is_err());
    assert_eq!(
        super::checked_digest(super::DigestBuffer {
            algorithm: 1,
            size: 32,
            digest,
        })
        .unwrap(),
        digest
    );
}

#[test]
fn rejects_non_regular_descriptor_without_ioctl() {
    let file = File::open("/dev/null").unwrap();
    assert_eq!(
        enable(&file).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        measure(&file).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str) -> Self {
        assert_eq!(
            std::env::var("LSM_TEST_DISPOSABLE_VERITY").as_deref(),
            Ok("1")
        );
        let root = PathBuf::from(
            std::env::var_os("LSM_TEST_DISPOSABLE_VERITY_DIR")
                .expect("disposable ext4 mount required"),
        );
        assert!(root.is_absolute());
        let root_file = File::open(&root).unwrap();
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstatfs(root_file.as_raw_fd(), &mut stat) },
            0
        );
        assert_eq!(stat.f_type as u64, 0xef53, "test root must be ext4");
        Self(root.join(format!("lsm-verity-{}-{name}", std::process::id())))
    }
    fn create(&self) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.0)
            .unwrap();
        file.write_all(b"fs-verity fixture\n").unwrap();
        file.sync_all().unwrap();
    }
    fn read(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
#[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
fn rejects_open_writer_and_preserves_sealing_after_writer_closes() {
    let fixture = Fixture::new("writer");
    fixture.create();
    let writer = OpenOptions::new().write(true).open(&fixture.0).unwrap();
    assert_eq!(
        enable(&fixture.read()).unwrap_err().raw_os_error(),
        Some(libc::ETXTBSY)
    );
    drop(writer);
    enable(&fixture.read()).unwrap();
}

#[test]
#[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
fn rejects_existing_writable_mapping_after_its_fd_is_closed() {
    let fixture = Fixture::new("mapping");
    fixture.create();
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.0)
        .unwrap();
    let len = writer.metadata().unwrap().len() as usize;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            writer.as_raw_fd(),
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    drop(writer);
    let result = enable(&fixture.read());
    assert_eq!(unsafe { libc::munmap(mapping, len) }, 0);
    assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ETXTBSY));
    enable(&fixture.read()).unwrap();
}

#[test]
#[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
fn measurement_survives_close_and_reopen_and_write_open_is_rejected() {
    let fixture = Fixture::new("reopen");
    fixture.create();
    let file = fixture.read();
    enable(&file).unwrap();
    let first = measure(&file).unwrap();
    // Independently derived from the Linux fs-verity descriptor and Merkle
    // format for this fixture, SHA-256, a 4096-byte block, and no salt.
    let encoded = first.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        encoded,
        "8d3d5855c72633119cff59b5ac979bd8e19876dd3f0865c57d58972aeefd5fba"
    );
    file.sync_all().unwrap();
    drop(file);
    let mut reopened = fixture.read();
    assert_eq!(first, measure(&reopened).unwrap());
    assert_eq!(
        enable(&reopened).unwrap_err().raw_os_error(),
        Some(libc::EEXIST)
    );
    let mut data = Vec::new();
    reopened.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"fs-verity fixture\n");
    assert_eq!(
        OpenOptions::new()
            .write(true)
            .open(&fixture.0)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPERM)
    );
}

#[test]
#[ignore = "requires explicitly designated disposable ext4 fs-verity filesystem"]
fn rejects_non_readonly_fd_and_non_verity_measurement() {
    let fixture = Fixture::new("wrong-fd");
    fixture.create();
    let writable = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.0)
        .unwrap();
    assert!(enable(&writable).is_err());
    assert!(measure(&writable).is_err());
    drop(writable);
    assert_eq!(
        measure(&fixture.read()).unwrap_err().raw_os_error(),
        Some(libc::ENODATA)
    );
}
