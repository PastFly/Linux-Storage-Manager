use super::{enable, measure};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

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
    file.sync_all().unwrap();
    drop(file);
    let mut reopened = fixture.read();
    assert_eq!(first, measure(&reopened).unwrap());
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
