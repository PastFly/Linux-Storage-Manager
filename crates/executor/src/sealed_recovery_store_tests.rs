use super::*;
use crate::sealed_recovery::{
    tests::{disposable_mount, with_fixture},
    SealedRecovery,
};
use std::fs::{self, File};
use std::path::Path;

#[test]
fn publishes_sealed_record_at_real_attempt_path() {
    if !disposable_mount() || std::env::var_os("LSM_TEST_SEALED_UNSUPPORTED").is_some() {
        return;
    }
    with_fixture(|session, manifest, receipt, copies| {
        let sealed = SealedRecovery::seal(session, manifest, receipt, copies).unwrap();
        let root = Path::new(manifest.artifact_directory());
        let record_dir = root.with_file_name(format!(
            "{}.record",
            root.file_name().unwrap().to_str().unwrap()
        ));
        fs::create_dir(&record_dir).unwrap();
        let result = PublishedRecovery::publish(session, sealed, File::open(&record_dir).unwrap());
        assert!(result.is_ok());
        drop(result);
        fs::remove_dir_all(record_dir).unwrap();
    });
}
