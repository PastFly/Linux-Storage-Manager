use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use lsm_planner::JournalPhase;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    BackupExpectedIdentity, LockedExecutionSession, MetadataBackupKind, MetadataBackupManifest,
    MetadataBackupRequirement, MUTATION_ENABLED,
};

const MAX_BACKUP_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupArtifactReceipt {
    pub ordinal: u32,
    pub kind: MetadataBackupKind,
    pub artifact_path: String,
    pub expected_identity: BackupExpectedIdentity,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetadataBackupReceipt {
    schema_version: u32,
    receipt_id: String,
    manifest_id: String,
    handoff_id: String,
    plan_id: String,
    target_manifest_digest: String,
    mutation_enabled: bool,
    artifacts: Vec<BackupArtifactReceipt>,
}

impl MetadataBackupReceipt {
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub fn handoff_id(&self) -> &str {
        &self.handoff_id
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn target_manifest_digest(&self) -> &str {
        &self.target_manifest_digest
    }

    pub fn mutation_enabled(&self) -> bool {
        self.mutation_enabled
    }

    pub fn artifacts(&self) -> &[BackupArtifactReceipt] {
        &self.artifacts
    }
}

#[derive(Debug, Error)]
pub enum BackupCaptureError {
    #[error("metadata backup capture requires a successfully identity-revalidated locked session")]
    SessionNotRevalidated,
    #[error("mutation-enabled execution is forbidden in the backup capture foundation")]
    MutationEnabled,
    #[error("backup manifest is not bound to the exact locked handoff")]
    ManifestBindingMismatch,
    #[error("backup artifact directory does not match the frozen handoff")]
    ArtifactDirectoryMismatch,
    #[error("backup capture command is not an exact supported non-mutating command")]
    UnsupportedCaptureCommand,
    #[error("backup artifact directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("backup artifact path is unsafe: {0}")]
    UnsafeArtifact(PathBuf),
    #[error("backup artifact already exists: {0}")]
    ArtifactExists(PathBuf),
    #[error("backup artifact is empty")]
    EmptyArtifact,
    #[error("backup artifact exceeds the maximum supported size")]
    ArtifactTooLarge,
    #[error("backup capture command {program} exited with status {status}")]
    CommandFailed { program: String, status: String },
    #[error("backup capture I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize backup receipt basis: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn capture_metadata_backups(
    session: &LockedExecutionSession<'_>,
    manifest: &MetadataBackupManifest,
) -> Result<MetadataBackupReceipt, BackupCaptureError> {
    capture_with_runner(session, manifest, None, &SystemCaptureRunner)
}

trait CaptureRunner {
    fn capture_partition_table(&self, disk: &str, output: &Path) -> Result<(), BackupCaptureError>;
    fn capture_lvm_metadata(&self, vg_name: &str, output: &Path) -> Result<(), BackupCaptureError>;
}

struct SystemCaptureRunner;

impl CaptureRunner for SystemCaptureRunner {
    fn capture_partition_table(&self, disk: &str, output: &Path) -> Result<(), BackupCaptureError> {
        let file = create_artifact_file(output)?;
        let stdout = file
            .try_clone()
            .map_err(|source| io_error(output, source))?;
        let status = Command::new("sfdisk")
            .arg("--dump")
            .arg(disk)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::null())
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .status()
            .map_err(|source| io_error(Path::new("sfdisk"), source))?;
        if !status.success() {
            return Err(BackupCaptureError::CommandFailed {
                program: "sfdisk".to_owned(),
                status: status.to_string(),
            });
        }
        file.sync_all().map_err(|source| io_error(output, source))
    }

    fn capture_lvm_metadata(&self, vg_name: &str, output: &Path) -> Result<(), BackupCaptureError> {
        ensure_artifact_absent(output)?;
        let status = Command::new("vgcfgbackup")
            .arg("--file")
            .arg(output)
            .arg(vg_name)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .status()
            .map_err(|source| io_error(Path::new("vgcfgbackup"), source))?;
        if !status.success() {
            return Err(BackupCaptureError::CommandFailed {
                program: "vgcfgbackup".to_owned(),
                status: status.to_string(),
            });
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(output)
            .map_err(|source| io_error(output, source))?;
        file.sync_all().map_err(|source| io_error(output, source))
    }
}

fn capture_with_runner(
    session: &LockedExecutionSession<'_>,
    manifest: &MetadataBackupManifest,
    root_override: Option<&Path>,
    runner: &dyn CaptureRunner,
) -> Result<MetadataBackupReceipt, BackupCaptureError> {
    validate_binding(session, manifest)?;

    let expected_root = Path::new(manifest.artifact_directory());
    let production_root = Path::new(crate::BACKUP_DIRECTORY).join(session.handoff().handoff_id());
    if expected_root != production_root {
        return Err(BackupCaptureError::ArtifactDirectoryMismatch);
    }

    let artifact_root = root_override.unwrap_or(expected_root);
    ensure_secure_directory(artifact_root)?;

    let mut receipts = Vec::with_capacity(manifest.requirements().len());
    for requirement in manifest.requirements() {
        validate_requirement(requirement)?;
        let file_name = Path::new(&requirement.artifact_path)
            .file_name()
            .ok_or_else(|| {
                BackupCaptureError::UnsafeArtifact(PathBuf::from(&requirement.artifact_path))
            })?;
        let actual_path = artifact_root.join(file_name);
        if actual_path.parent() != Some(artifact_root) {
            return Err(BackupCaptureError::UnsafeArtifact(actual_path));
        }

        match &requirement.expected_identity {
            BackupExpectedIdentity::PartitionTable { disk, .. } => {
                runner.capture_partition_table(disk, &actual_path)?;
            }
            BackupExpectedIdentity::LvmVolumeGroup { vg_name, .. } => {
                runner.capture_lvm_metadata(vg_name, &actual_path)?;
            }
        }

        let (size_bytes, sha256) = verify_artifact(&actual_path)?;
        receipts.push(BackupArtifactReceipt {
            ordinal: requirement.ordinal,
            kind: requirement.kind,
            artifact_path: requirement.artifact_path.clone(),
            expected_identity: requirement.expected_identity.clone(),
            size_bytes,
            sha256,
        });
    }

    let receipt_id = fingerprint(&(
        1_u32,
        manifest.manifest_id(),
        manifest.handoff_id(),
        manifest.plan_id(),
        manifest.target_manifest_digest(),
        false,
        &receipts,
    ))?;

    Ok(MetadataBackupReceipt {
        schema_version: 1,
        receipt_id,
        manifest_id: manifest.manifest_id().to_owned(),
        handoff_id: manifest.handoff_id().to_owned(),
        plan_id: manifest.plan_id().to_owned(),
        target_manifest_digest: manifest.target_manifest_digest().to_owned(),
        mutation_enabled: false,
        artifacts: receipts,
    })
}

fn validate_binding(
    session: &LockedExecutionSession<'_>,
    manifest: &MetadataBackupManifest,
) -> Result<(), BackupCaptureError> {
    if MUTATION_ENABLED || session.mutation_enabled() || manifest.mutation_enabled() {
        return Err(BackupCaptureError::MutationEnabled);
    }
    if session.journal().phase != JournalPhase::IdentityRevalidated {
        return Err(BackupCaptureError::SessionNotRevalidated);
    }
    let handoff = session.handoff();
    if manifest.handoff_id() != handoff.handoff_id()
        || manifest.plan_id() != handoff.plan().plan_id()
        || manifest.target_manifest_digest() != handoff.target_identity().manifest_digest
        || !manifest.owner_acceptance_required()
    {
        return Err(BackupCaptureError::ManifestBindingMismatch);
    }
    Ok(())
}

fn validate_requirement(requirement: &MetadataBackupRequirement) -> Result<(), BackupCaptureError> {
    if requirement.capture.mutates_storage_metadata || requirement.capture.stdin_path.is_some() {
        return Err(BackupCaptureError::UnsupportedCaptureCommand);
    }
    let artifact = requirement.artifact_path.as_str();
    match (&requirement.kind, &requirement.expected_identity) {
        (
            MetadataBackupKind::PartitionTable,
            BackupExpectedIdentity::PartitionTable { disk, .. },
        ) => {
            if requirement.capture.program != "sfdisk"
                || requirement.capture.args != ["--dump".to_owned(), disk.clone()]
                || requirement.capture.stdout_path.as_deref() != Some(artifact)
            {
                return Err(BackupCaptureError::UnsupportedCaptureCommand);
            }
        }
        (
            MetadataBackupKind::LvmVolumeGroup,
            BackupExpectedIdentity::LvmVolumeGroup { vg_name, .. },
        ) => {
            if requirement.capture.program != "vgcfgbackup"
                || requirement.capture.args
                    != ["--file".to_owned(), artifact.to_owned(), vg_name.clone()]
                || requirement.capture.stdout_path.is_some()
            {
                return Err(BackupCaptureError::UnsupportedCaptureCommand);
            }
        }
        _ => return Err(BackupCaptureError::UnsupportedCaptureCommand),
    }
    Ok(())
}

fn ensure_secure_directory(path: &Path) -> Result<(), BackupCaptureError> {
    if !path.is_absolute() {
        return Err(BackupCaptureError::UnsafeDirectory(path.to_path_buf()));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                current.push("/");
                continue;
            }
            Component::Normal(part) => current.push(part),
            _ => return Err(BackupCaptureError::UnsafeDirectory(path.to_path_buf())),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(BackupCaptureError::UnsafeDirectory(current));
                }
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                let mut builder = DirBuilder::new();
                builder.mode(0o700);
                if let Err(source) = builder.create(&current) {
                    if source.kind() != io::ErrorKind::AlreadyExists {
                        return Err(io_error(&current, source));
                    }
                }
                let metadata =
                    fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(BackupCaptureError::UnsafeDirectory(current));
                }
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn ensure_artifact_absent(path: &Path) -> Result<(), BackupCaptureError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(BackupCaptureError::ArtifactExists(path.to_path_buf())),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn create_artifact_file(path: &Path) -> Result<File, BackupCaptureError> {
    ensure_artifact_absent(path)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))
}

fn verify_artifact(path: &Path) -> Result<(u64, String), BackupCaptureError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupCaptureError::UnsafeArtifact(path.to_path_buf()));
    }
    if metadata.len() == 0 {
        return Err(BackupCaptureError::EmptyArtifact);
    }
    if metadata.len() > MAX_BACKUP_ARTIFACT_BYTES {
        return Err(BackupCaptureError::ArtifactTooLarge);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error(path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BACKUP_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    if bytes.len() as u64 > MAX_BACKUP_ARTIFACT_BYTES {
        return Err(BackupCaptureError::ArtifactTooLarge);
    }
    if bytes.is_empty() {
        return Err(BackupCaptureError::EmptyArtifact);
    }
    Ok((bytes.len() as u64, format!("{:x}", Sha256::digest(&bytes))))
}

fn fingerprint(value: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn io_error(path: &Path, source: io::Error) -> BackupCaptureError {
    BackupCaptureError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeRunner {
        calls: Mutex<Vec<(String, String)>>,
        payload: &'static [u8],
    }

    impl FakeRunner {
        fn new(payload: &'static [u8]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                payload,
            }
        }
    }

    impl CaptureRunner for FakeRunner {
        fn capture_partition_table(
            &self,
            disk: &str,
            output: &Path,
        ) -> Result<(), BackupCaptureError> {
            self.calls
                .lock()
                .unwrap()
                .push(("sfdisk".to_owned(), disk.to_owned()));
            let mut file = create_artifact_file(output)?;
            use std::io::Write;
            file.write_all(self.payload)
                .map_err(|source| io_error(output, source))?;
            file.sync_all().map_err(|source| io_error(output, source))
        }

        fn capture_lvm_metadata(
            &self,
            vg_name: &str,
            output: &Path,
        ) -> Result<(), BackupCaptureError> {
            self.calls
                .lock()
                .unwrap()
                .push(("vgcfgbackup".to_owned(), vg_name.to_owned()));
            let mut file = create_artifact_file(output)?;
            use std::io::Write;
            file.write_all(self.payload)
                .map_err(|source| io_error(output, source))?;
            file.sync_all().map_err(|source| io_error(output, source))
        }
    }

    #[test]
    fn artifact_verifier_hashes_nonempty_regular_files() {
        let root =
            std::env::temp_dir().join(format!("lsm-backup-capture-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        ensure_secure_directory(&root).unwrap();
        let path = root.join("artifact");
        fs::write(&path, b"verified-backup").unwrap();

        let (size, digest) = verify_artifact(&path).unwrap();

        assert_eq!(size, 15);
        assert_eq!(digest.len(), 64);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn artifact_verifier_rejects_empty_files() {
        let root =
            std::env::temp_dir().join(format!("lsm-backup-empty-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        ensure_secure_directory(&root).unwrap();
        let path = root.join("artifact");
        fs::write(&path, b"").unwrap();

        assert!(matches!(
            verify_artifact(&path),
            Err(BackupCaptureError::EmptyArtifact)
        ));
        let _ = fs::remove_dir_all(root);
    }

    fn direct_fixture() -> (lsm_core::HostSnapshot, lsm_core::HostCapabilities) {
        use lsm_core::{FilesystemPreflightEvidence, FilesystemProbeState};
        use serde_json::json;

        const GIB: u64 = 1 << 30;
        let sector = 512_u64;
        let partition_bytes = 10 * GIB;
        let mut snapshot: lsm_core::HostSnapshot = serde_json::from_value(json!({
            "storage":{"block_devices":[{
                "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
                "size_bytes":20*GIB,"logical_sector_bytes":sector,
                "model":"Virtual Disk","serial":"BACKUP-CAPTURE-TEST","mountpoints":[],"children":[{
                    "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                    "size_bytes":partition_bytes,"start_512_sector":2048,
                    "logical_sector_bytes":sector,"uuid":"fs-data","partition_uuid":"part-data",
                    "partition_table":"gpt","filesystem":{"fs_type":"ext4","version":"1.0"},
                    "mountpoints":["/data"],"parent_kernel_name":"sda","children":[]
                }]
            }]},
            "partition_tables":[{
                "device":"/dev/sda","label":"gpt","id":"gpt-backup-capture","unit":"sectors",
                "first_lba":34,"last_lba":(20*GIB/sector)-34,
                "sector_size_bytes":sector,
                "partitions":[{
                    "node":"/dev/sda1","start_sector":2048,
                    "size_sectors":partition_bytes/sector,
                    "partition_type":"0FC63DAF-8483-4772-8E79-3D69D8477DE4",
                    "uuid":"part-data","name":null,"attrs":null,"bootable":null
                }]
            }],
            "mounts":[{
                "source":"/dev/sda1","target":"/data","fs_type":"ext4","options":["rw","relatime"]
            }],
            "fstab":[],
            "swaps":[],
            "lvm":null,
            "filesystem_preflight":[],
            "diagnostics":[],
            "collectors":[
                {"component":"lsblk","state":"complete"},
                {"component":"partition_tables","state":"complete"},
                {"component":"mounts","state":"complete"},
                {"component":"fstab","state":"complete"},
                {"component":"swap","state":"complete"}
            ]
        }))
        .unwrap();
        snapshot
            .filesystem_preflight
            .push(FilesystemPreflightEvidence {
                device: "/dev/sda1".into(),
                mountpoint: Some("/data".into()),
                fs_type: "ext4".into(),
                fs_version: Some("1.0".into()),
                state: FilesystemProbeState::Verified,
                filesystem_state: Some("clean".into()),
                revision: Some("1".into()),
                features: vec![
                    "has_journal".into(),
                    "extent".into(),
                    "64bit".into(),
                    "metadata_csum".into(),
                ],
                block_size_bytes: Some(4096),
                block_count: Some(partition_bytes / 4096),
                size_bytes: Some(partition_bytes),
                grow_check_passed: None,
                detail: None,
            });
        let capabilities = serde_json::from_value(json!({"tools":[
            {"name":"sfdisk","available":true},
            {"name":"resize2fs","available":true},
            {"name":"e2fsck","available":true}
        ]}))
        .unwrap();
        (snapshot, capabilities)
    }

    fn direct_handoff(
        snapshot: &lsm_core::HostSnapshot,
        capabilities: &lsm_core::HostCapabilities,
    ) -> lsm_planner::FrozenExecutionHandoff {
        use lsm_planner::{
            build_frozen_execution_handoff, plan_extend, ExtendRequest, Growth, PlanStatus,
        };
        const GIB: u64 = 1 << 30;
        let plan = plan_extend(
            snapshot,
            capabilities,
            ExtendRequest {
                target: "/data".into(),
                growth: Growth::ByBytes(GIB),
            },
        )
        .unwrap();
        assert_eq!(plan.status(), PlanStatus::Preview);
        build_frozen_execution_handoff(snapshot, capabilities, &plan).unwrap()
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lsm-backup-capture-session-test-{}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn exact_revalidated_session_can_capture_manifest_with_fake_runner() {
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let manifest = crate::build_metadata_backup_manifest(&handoff).unwrap();
        assert_eq!(manifest.requirements().len(), 1);

        let lock = temp_path("lock").join("storage.lock");
        let root = temp_path("artifacts");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(&root);
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        let result = session.revalidate(&snapshot, &capabilities).unwrap();
        assert_eq!(result.status, crate::LockedRevalidationStatus::Revalidated);

        let runner = FakeRunner::new(b"label: gpt\ndevice: /dev/sda\n");
        let receipt = capture_with_runner(&session, &manifest, Some(&root), &runner).unwrap();

        assert!(!receipt.mutation_enabled());
        assert_eq!(receipt.manifest_id(), manifest.manifest_id());
        assert_eq!(receipt.handoff_id(), handoff.handoff_id());
        assert_eq!(receipt.artifacts().len(), 1);
        assert_eq!(
            receipt.artifacts()[0].kind,
            MetadataBackupKind::PartitionTable
        );
        assert!(receipt.artifacts()[0].size_bytes > 0);
        assert_eq!(receipt.artifacts()[0].sha256.len(), 64);
        assert_eq!(
            runner.calls.lock().unwrap().as_slice(),
            [("sfdisk".to_owned(), "/dev/sda".to_owned())]
        );

        drop(session);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn backup_capture_is_rejected_before_locked_identity_revalidation() {
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let manifest = crate::build_metadata_backup_manifest(&handoff).unwrap();
        let lock = temp_path("not-revalidated-lock").join("storage.lock");
        let root = temp_path("not-revalidated-artifacts");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(&root);
        let session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();

        let result = capture_with_runner(
            &session,
            &manifest,
            Some(&root),
            &FakeRunner::new(b"unused"),
        );

        assert!(matches!(
            result,
            Err(BackupCaptureError::SessionNotRevalidated)
        ));
        assert!(!root.exists());

        drop(session);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
    }

    #[test]
    fn mutation_flag_remains_disabled() {
        assert!(!std::hint::black_box(MUTATION_ENABLED));
    }
}
