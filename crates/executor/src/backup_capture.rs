use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process::Command;

use lsm_planner::JournalPhase;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    BackupExpectedIdentity, LockedExecutionSession, MetadataBackupKind, MetadataBackupManifest,
    MetadataBackupRequirement, MUTATION_ENABLED,
};

const MAX_BACKUP_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const BACKUP_RECEIPT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupArtifactReceipt {
    pub ordinal: u32,
    pub kind: MetadataBackupKind,
    pub artifact_path: String,
    pub expected_identity: BackupExpectedIdentity,
    pub device_id: u64,
    pub inode: u64,
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
    session_id: String,
    journal_id: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackupReceiptRevalidation {
    receipt_id: String,
    manifest_id: String,
    handoff_id: String,
    plan_id: String,
    target_manifest_digest: String,
    session_id: String,
    journal_id: String,
    matches: bool,
    blockers: Vec<String>,
}

impl BackupReceiptRevalidation {
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

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn journal_id(&self) -> &str {
        &self.journal_id
    }

    pub fn matches(&self) -> bool {
        self.matches
    }

    pub fn blockers(&self) -> &[String] {
        &self.blockers
    }
}

#[derive(Debug, Error)]
pub enum BackupCaptureError {
    #[error("trusted backup tool resolution failed: {0}")]
    TrustedTool(#[from] crate::TrustedToolError),
    #[error("trusted backup tool pinning failed: {0}")]
    ToolPin(#[from] crate::PrivilegedToolPinError),
    #[error("trusted backup tool identity changed before execution")]
    ToolIdentityChanged,
    #[error("backup tool descriptor execution failed: {0}")]
    ToolExecution(#[from] crate::PrivilegedDescriptorExecError),
    #[error("partition table backup exceeds the descriptor output limit")]
    BackupOutputTruncated,
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

pub fn revalidate_metadata_backup_receipt(
    manifest: &MetadataBackupManifest,
    receipt: &MetadataBackupReceipt,
) -> Result<BackupReceiptRevalidation, BackupCaptureError> {
    revalidate_receipt_at_root(manifest, receipt, None)
}

#[cfg(feature = "disposable-loop-harness")]
pub fn capture_metadata_backups_at_disposable_root(
    session: &LockedExecutionSession<'_>,
    manifest: &MetadataBackupManifest,
    owned_root: &Path,
) -> Result<MetadataBackupReceipt, BackupCaptureError> {
    capture_with_runner(session, manifest, Some(owned_root), &SystemCaptureRunner)
}

#[cfg(feature = "disposable-loop-harness")]
pub fn revalidate_metadata_backup_receipt_at_disposable_root(
    manifest: &MetadataBackupManifest,
    receipt: &MetadataBackupReceipt,
    owned_root: &Path,
) -> Result<BackupReceiptRevalidation, BackupCaptureError> {
    revalidate_receipt_at_root(manifest, receipt, Some(owned_root))
}

trait CaptureRunner {
    fn capture_partition_table(&self, disk: &str, output: &Path) -> Result<(), BackupCaptureError>;
    fn capture_lvm_metadata(&self, vg_name: &str, output: &Path) -> Result<(), BackupCaptureError>;
}

struct SystemCaptureRunner;

pub(crate) fn run_trusted_read_only_tool(
    program: crate::PrivilegedProgram,
    args: Vec<String>,
) -> Result<crate::DescriptorExecOutcome, BackupCaptureError> {
    let expected = crate::resolve_trusted_privileged_tool(program)?;
    let (file, _) = crate::privileged_pin::pin_trusted_tool(&expected)?;
    let snapshot = crate::privileged_pin::snapshot_trusted_tool(&file, &expected)?;
    if crate::resolve_trusted_privileged_tool(program)? != expected {
        return Err(BackupCaptureError::ToolIdentityChanged);
    }
    let mut argv = vec![program.as_str().to_owned()];
    argv.extend(args);
    Ok(
        crate::privileged_exec::execute_descriptor_stage_with_stdout_limit(
            &snapshot,
            program,
            &argv,
            "/usr/sbin:/usr/bin:/sbin:/bin",
            "C",
            None,
            MAX_BACKUP_ARTIFACT_BYTES as usize,
        )?,
    )
}

impl CaptureRunner for SystemCaptureRunner {
    fn capture_partition_table(&self, disk: &str, output: &Path) -> Result<(), BackupCaptureError> {
        let mut file = create_artifact_file(output)?;
        let result = run_trusted_read_only_tool(
            crate::PrivilegedProgram::Sfdisk,
            vec!["--dump".into(), disk.into()],
        )?;
        if result.exit_code != 0 {
            return Err(BackupCaptureError::CommandFailed {
                program: "sfdisk".to_owned(),
                status: result.exit_code.to_string(),
            });
        }
        if result.stdout_truncated {
            return Err(BackupCaptureError::BackupOutputTruncated);
        }
        file.write_all(&result.stdout)
            .map_err(|source| io_error(output, source))?;
        file.sync_all().map_err(|source| io_error(output, source))
    }

    fn capture_lvm_metadata(&self, vg_name: &str, output: &Path) -> Result<(), BackupCaptureError> {
        ensure_artifact_absent(output)?;
        let output_arg = output
            .to_str()
            .ok_or_else(|| BackupCaptureError::UnsafeArtifact(output.to_path_buf()))?;
        let result = run_trusted_read_only_tool(
            crate::PrivilegedProgram::Vgcfgbackup,
            vec!["--file".into(), output_arg.into(), vg_name.into()],
        )?;
        if result.exit_code != 0 {
            return Err(BackupCaptureError::CommandFailed {
                program: "vgcfgbackup".to_owned(),
                status: result.exit_code.to_string(),
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
    let attempt_root = production_root.join(&session.journal().journal_id);
    if expected_root != production_root && expected_root != attempt_root {
        return Err(BackupCaptureError::ArtifactDirectoryMismatch);
    }

    let overridden_root = root_override.map(|root| {
        if expected_root == attempt_root {
            root.join(&session.journal().journal_id)
        } else {
            root.to_path_buf()
        }
    });
    let artifact_root = overridden_root.as_deref().unwrap_or(expected_root);
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

        let (size_bytes, sha256, device_id, inode) = verify_artifact(&actual_path)?;
        receipts.push(BackupArtifactReceipt {
            ordinal: requirement.ordinal,
            kind: requirement.kind,
            artifact_path: requirement.artifact_path.clone(),
            expected_identity: requirement.expected_identity.clone(),
            device_id,
            inode,
            size_bytes,
            sha256,
        });
    }

    sync_backup_directory(artifact_root)?;

    let receipt_id = fingerprint(&(
        BACKUP_RECEIPT_SCHEMA_VERSION,
        manifest.manifest_id(),
        manifest.handoff_id(),
        manifest.plan_id(),
        manifest.target_manifest_digest(),
        session.session_id(),
        &session.journal().journal_id,
        false,
        &receipts,
    ))?;

    Ok(MetadataBackupReceipt {
        schema_version: BACKUP_RECEIPT_SCHEMA_VERSION,
        receipt_id,
        manifest_id: manifest.manifest_id().to_owned(),
        handoff_id: manifest.handoff_id().to_owned(),
        plan_id: manifest.plan_id().to_owned(),
        target_manifest_digest: manifest.target_manifest_digest().to_owned(),
        session_id: session.session_id().to_owned(),
        journal_id: session.journal().journal_id.clone(),
        mutation_enabled: false,
        artifacts: receipts,
    })
}

fn revalidate_receipt_at_root(
    manifest: &MetadataBackupManifest,
    receipt: &MetadataBackupReceipt,
    root_override: Option<&Path>,
) -> Result<BackupReceiptRevalidation, BackupCaptureError> {
    let mut blockers = Vec::new();

    if manifest.mutation_enabled() || receipt.mutation_enabled || MUTATION_ENABLED {
        blockers.push("mutation-enabled backup evidence is forbidden".to_owned());
    }
    if receipt.schema_version != BACKUP_RECEIPT_SCHEMA_VERSION {
        blockers.push("receipt schema version is unsupported".to_owned());
    }
    if receipt.manifest_id != manifest.manifest_id()
        || receipt.handoff_id != manifest.handoff_id()
        || receipt.plan_id != manifest.plan_id()
        || receipt.target_manifest_digest != manifest.target_manifest_digest()
    {
        blockers
            .push("receipt identity does not match the exact frozen backup manifest".to_owned());
    }

    let production_root = Path::new(crate::BACKUP_DIRECTORY).join(manifest.handoff_id());
    let attempt_root = production_root.join(&receipt.journal_id);
    if Path::new(manifest.artifact_directory()) != production_root
        && Path::new(manifest.artifact_directory()) != attempt_root
    {
        blockers.push("backup artifact directory does not match the frozen handoff".to_owned());
    }

    let expected_receipt_id = fingerprint(&(
        BACKUP_RECEIPT_SCHEMA_VERSION,
        manifest.manifest_id(),
        manifest.handoff_id(),
        manifest.plan_id(),
        manifest.target_manifest_digest(),
        &receipt.session_id,
        &receipt.journal_id,
        false,
        &receipt.artifacts,
    ))?;
    if receipt.receipt_id != expected_receipt_id {
        blockers.push("receipt ID does not match its serialized artifact evidence".to_owned());
    }

    if receipt.artifacts.len() != manifest.requirements().len() {
        blockers.push(format!(
            "receipt artifact count {} does not match manifest requirement count {}",
            receipt.artifacts.len(),
            manifest.requirements().len()
        ));
    }

    let overridden_root = root_override.map(|root| {
        if Path::new(manifest.artifact_directory()) == attempt_root {
            root.join(&receipt.journal_id)
        } else {
            root.to_path_buf()
        }
    });
    let artifact_root = overridden_root
        .as_deref()
        .unwrap_or_else(|| Path::new(manifest.artifact_directory()));
    if let Err(error) = verify_existing_secure_directory(artifact_root) {
        blockers.push(format!("artifact directory verification failed: {error}"));
    }

    for requirement in manifest.requirements() {
        if let Err(error) = validate_requirement(requirement) {
            blockers.push(format!(
                "manifest requirement {} is invalid: {error}",
                requirement.ordinal
            ));
            continue;
        }

        let matching = receipt
            .artifacts
            .iter()
            .filter(|artifact| artifact.ordinal == requirement.ordinal)
            .collect::<Vec<_>>();
        let artifact = match matching.as_slice() {
            [artifact] => *artifact,
            [] => {
                blockers.push(format!(
                    "receipt is missing artifact ordinal {}",
                    requirement.ordinal
                ));
                continue;
            }
            _ => {
                blockers.push(format!(
                    "receipt contains duplicate artifact ordinal {}",
                    requirement.ordinal
                ));
                continue;
            }
        };

        if artifact.kind != requirement.kind
            || artifact.artifact_path != requirement.artifact_path
            || artifact.expected_identity != requirement.expected_identity
        {
            blockers.push(format!(
                "receipt artifact {} does not match the frozen manifest requirement",
                requirement.ordinal
            ));
            continue;
        }

        let Some(file_name) = Path::new(&requirement.artifact_path).file_name() else {
            blockers.push(format!(
                "receipt artifact {} has an unsafe path",
                requirement.ordinal
            ));
            continue;
        };
        let actual_path = artifact_root.join(file_name);
        if actual_path.parent() != Some(artifact_root) {
            blockers.push(format!(
                "receipt artifact {} escapes the artifact directory",
                requirement.ordinal
            ));
            continue;
        }

        match verify_artifact(&actual_path) {
            Ok((size_bytes, sha256, device_id, inode)) => {
                if device_id != artifact.device_id || inode != artifact.inode {
                    blockers.push(format!(
                        "receipt artifact {} inode identity changed",
                        artifact.ordinal
                    ));
                }
                if size_bytes != artifact.size_bytes {
                    blockers.push(format!(
                        "receipt artifact {} size changed: expected {}, found {}",
                        requirement.ordinal, artifact.size_bytes, size_bytes
                    ));
                }
                if sha256 != artifact.sha256 {
                    blockers.push(format!(
                        "receipt artifact {} SHA-256 changed",
                        requirement.ordinal
                    ));
                }
            }
            Err(error) => blockers.push(format!(
                "receipt artifact {} verification failed: {error}",
                requirement.ordinal
            )),
        }
    }

    blockers.sort();
    blockers.dedup();
    Ok(BackupReceiptRevalidation {
        receipt_id: receipt.receipt_id.clone(),
        manifest_id: manifest.manifest_id().to_owned(),
        handoff_id: manifest.handoff_id().to_owned(),
        plan_id: manifest.plan_id().to_owned(),
        target_manifest_digest: manifest.target_manifest_digest().to_owned(),
        session_id: receipt.session_id.clone(),
        journal_id: receipt.journal_id.clone(),
        matches: blockers.is_empty(),
        blockers,
    })
}

fn verify_existing_secure_directory(path: &Path) -> Result<(), BackupCaptureError> {
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

        let metadata =
            fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
        if !crate::journal_store::trusted_journal_directory(&metadata, current == path) {
            return Err(BackupCaptureError::UnsafeDirectory(current));
        }
    }
    Ok(())
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
                if !crate::journal_store::trusted_journal_directory(&metadata, current == path) {
                    return Err(BackupCaptureError::UnsafeDirectory(current));
                }
                let parent = current
                    .parent()
                    .ok_or_else(|| BackupCaptureError::UnsafeDirectory(current.clone()))?;
                sync_backup_directory(parent)?;
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
                if !crate::journal_store::trusted_journal_directory(&metadata, current == path) {
                    return Err(BackupCaptureError::UnsafeDirectory(current));
                }
                let parent = current
                    .parent()
                    .ok_or_else(|| BackupCaptureError::UnsafeDirectory(current.clone()))?;
                sync_backup_directory(parent)?;
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn sync_backup_directory(path: &Path) -> Result<(), BackupCaptureError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
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

fn verify_artifact(path: &Path) -> Result<(u64, String, u64, u64), BackupCaptureError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !crate::journal_store::trusted_journal_file(&metadata) {
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
    let opened = file.metadata().map_err(|source| io_error(path, source))?;
    if !crate::journal_store::trusted_journal_file(&opened)
        || opened.dev() != metadata.dev()
        || opened.ino() != metadata.ino()
    {
        return Err(BackupCaptureError::UnsafeArtifact(path.to_path_buf()));
    }
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
    Ok((
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(&bytes)),
        opened.dev(),
        opened.ino(),
    ))
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
pub(crate) fn test_backup_receipt_revalidation(
    session: &LockedExecutionSession<'_>,
    handoff_id: &str,
    plan_id: &str,
    target_manifest_digest: &str,
    matches: bool,
    blockers: Vec<String>,
) -> BackupReceiptRevalidation {
    BackupReceiptRevalidation {
        receipt_id: "b".repeat(64),
        manifest_id: "a".repeat(64),
        handoff_id: handoff_id.to_owned(),
        plan_id: plan_id.to_owned(),
        target_manifest_digest: target_manifest_digest.to_owned(),
        session_id: session.session_id().to_owned(),
        journal_id: session.journal().journal_id.clone(),
        matches,
        blockers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    #[test]
    fn backup_capture_does_not_execute_tools_from_untrusted_path() {
        const CHILD: &str = "LSM_UNTRUSTED_BACKUP_PATH_CHILD";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = PathBuf::from(root);
            let runner = SystemCaptureRunner;
            let _ =
                runner.capture_partition_table("/dev/lsm-nonexistent-test", &root.join("table"));
            let _ = runner.capture_lvm_metadata("lsm-nonexistent-test", &root.join("vg"));
            assert!(
                !root.join("executed").exists(),
                "untrusted PATH tool was executed"
            );
            return;
        }
        let root =
            std::env::temp_dir().join(format!("lsm-untrusted-path-test-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        for name in ["sfdisk", "vgcfgbackup"] {
            let path = root.join(name);
            fs::write(
                &path,
                b"#!/bin/sh\nprintf injected > \"$LSM_UNTRUSTED_BACKUP_PATH_CHILD/executed\"\n",
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("backup_capture::tests::backup_capture_does_not_execute_tools_from_untrusted_path")
            .arg("--nocapture")
            .env(CHILD, &root)
            .env("PATH", &root)
            .status()
            .unwrap();
        let _ = fs::remove_dir_all(root);
        assert!(
            status.success(),
            "backup capture executed a tool from an untrusted PATH"
        );
    }

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
    fn revalidation_rejects_same_content_replacement_with_different_inode() {
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let root = temp_path("same-content-inode-replacement");
        fs::create_dir(&root).unwrap();
        let lock = root.join("lock/storage.lock");
        let store = crate::DurableJournalStore::at(root.join("journals"));
        let backup_root = root.join("backups");
        let mut session =
            crate::LockedExecutionSession::begin_durable_at_paths(&handoff, &lock, &store).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let manifest = crate::build_metadata_backup_manifest_for_session(&session).unwrap();
        let receipt = capture_with_runner(
            &session,
            &manifest,
            Some(&backup_root),
            &FakeRunner::new(b"identical backup"),
        )
        .unwrap();
        let name = Path::new(&receipt.artifacts()[0].artifact_path)
            .file_name()
            .unwrap();
        let path = backup_root.join(&session.journal().journal_id).join(name);
        let original = File::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"identical backup").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(
            original.metadata().unwrap().ino(),
            fs::metadata(&path).unwrap().ino()
        );
        assert!(
            !revalidate_receipt_at_root(&manifest, &receipt, Some(&backup_root))
                .unwrap()
                .matches()
        );
        drop(session);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn separate_attempts_capture_distinct_backups_without_reusing_prior_evidence() {
        use lsm_planner::JournalTransition;
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let root = temp_path("attempt-specific-backups");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let lock = root.join("lock/storage.lock");
        let store = crate::DurableJournalStore::at(root.join("journals"));
        let backup_root = root.join("backups");
        let mut first =
            crate::LockedExecutionSession::begin_durable_at_paths(&handoff, &lock, &store).unwrap();
        first.revalidate(&snapshot, &capabilities).unwrap();
        let first_manifest = crate::build_metadata_backup_manifest_for_session(&first).unwrap();
        let first_receipt = capture_with_runner(
            &first,
            &first_manifest,
            Some(&backup_root),
            &FakeRunner::new(b"first backup"),
        )
        .unwrap();
        assert!(
            revalidate_receipt_at_root(&first_manifest, &first_receipt, Some(&backup_root))
                .unwrap()
                .matches()
        );
        let mut first_journal = first.journal().clone();
        drop(first);
        first_journal
            .apply(JournalTransition::Abort {
                reason: "operator confirmed no mutation",
            })
            .unwrap();
        store.test_overwrite(&first_journal).unwrap();
        let mut second =
            crate::LockedExecutionSession::begin_durable_at_paths(&handoff, &lock, &store).unwrap();
        second.revalidate(&snapshot, &capabilities).unwrap();
        let second_manifest = crate::build_metadata_backup_manifest_for_session(&second).unwrap();
        let second_receipt = capture_with_runner(
            &second,
            &second_manifest,
            Some(&backup_root),
            &FakeRunner::new(b"second backup"),
        )
        .unwrap();
        assert!(
            revalidate_receipt_at_root(&second_manifest, &second_receipt, Some(&backup_root))
                .unwrap()
                .matches()
        );
        assert_ne!(first_receipt.receipt_id(), second_receipt.receipt_id());
        assert!(backup_root.join(&first_journal.journal_id).is_dir());
        assert!(backup_root.join(&second.journal().journal_id).is_dir());
        drop(second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_verifier_hashes_nonempty_regular_files() {
        let root =
            std::env::temp_dir().join(format!("lsm-backup-capture-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        ensure_secure_directory(&root).unwrap();
        let path = root.join("artifact");
        fs::write(&path, b"verified-backup").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let (size, digest, _, _) = verify_artifact(&path).unwrap();

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
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

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
    fn backup_directory_creation_fails_when_parent_directory_cannot_be_synced() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let parent = temp_path("backup-unsynced-parent");
        let _ = fs::remove_dir_all(&parent);
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
        let root = parent.join("backups");
        let first = ensure_secure_directory(&root);
        let retry = ensure_secure_directory(&root);
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(parent).unwrap();
        assert!(first.is_err());
        assert!(
            retry.is_err(),
            "an existing unsynced backup directory must not make a retry succeed"
        );
    }

    #[test]
    fn backup_evidence_rejects_writable_directory_and_unsafe_file() {
        let root = temp_path("unsafe-backup-evidence");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        let directory_result = ensure_secure_directory(&root);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = root.join("artifact");
        fs::write(&artifact, b"backup").unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o644)).unwrap();
        let file_result = verify_artifact(&artifact);
        fs::remove_dir_all(root).unwrap();
        assert!(
            directory_result.is_err(),
            "writable backup directory was accepted"
        );
        assert!(file_result.is_err(), "unsafe backup artifact was accepted");
    }

    #[test]
    fn backup_capture_fails_when_artifact_directory_cannot_be_synced() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let manifest = crate::build_metadata_backup_manifest(&handoff).unwrap();
        let lock = temp_path("sync-failure-lock").join("storage.lock");
        let root = temp_path("sync-failure-artifacts");
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o300)).unwrap();
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        session.revalidate(&snapshot, &capabilities).unwrap();
        let result = capture_with_runner(
            &session,
            &manifest,
            Some(&root),
            &FakeRunner::new(b"valid backup"),
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        drop(session);
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
        assert!(
            result.is_err(),
            "backup directory sync failure must fail closed"
        );
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
        assert_eq!(serde_json::to_value(&receipt).unwrap()["schema_version"], 2);
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
        let revalidation = revalidate_receipt_at_root(&manifest, &receipt, Some(&root)).unwrap();
        assert!(revalidation.matches());
        assert!(revalidation.blockers().is_empty());

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

    fn captured_direct_fixture(
        suffix: &str,
    ) -> (
        lsm_planner::FrozenExecutionHandoff,
        MetadataBackupManifest,
        MetadataBackupReceipt,
        PathBuf,
        PathBuf,
    ) {
        let (snapshot, capabilities) = direct_fixture();
        let handoff = direct_handoff(&snapshot, &capabilities);
        let manifest = crate::build_metadata_backup_manifest(&handoff).unwrap();
        let lock = temp_path(&format!("{suffix}-lock")).join("storage.lock");
        let root = temp_path(&format!("{suffix}-artifacts"));
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(&root);
        let mut session = crate::LockedExecutionSession::begin_at_path(&handoff, &lock).unwrap();
        let revalidation = session.revalidate(&snapshot, &capabilities).unwrap();
        assert_eq!(
            revalidation.status,
            crate::LockedRevalidationStatus::Revalidated
        );
        let receipt = capture_with_runner(
            &session,
            &manifest,
            Some(&root),
            &FakeRunner::new(b"label: gpt\ndevice: /dev/sda\n"),
        )
        .unwrap();
        drop(session);
        (handoff, manifest, receipt, lock, root)
    }

    #[test]
    fn receipt_revalidation_detects_tampered_artifact_bytes() {
        let (_handoff, manifest, receipt, lock, root) = captured_direct_fixture("tamper");
        let file_name = Path::new(&receipt.artifacts()[0].artifact_path)
            .file_name()
            .unwrap();
        fs::write(root.join(file_name), b"tampered-backup").unwrap();

        let result = revalidate_receipt_at_root(&manifest, &receipt, Some(&root)).unwrap();

        assert!(!result.matches());
        assert!(result
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("SHA-256 changed")));
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn receipt_revalidation_detects_missing_artifact() {
        let (_handoff, manifest, receipt, lock, root) = captured_direct_fixture("missing");
        let file_name = Path::new(&receipt.artifacts()[0].artifact_path)
            .file_name()
            .unwrap();
        fs::remove_file(root.join(file_name)).unwrap();

        let result = revalidate_receipt_at_root(&manifest, &receipt, Some(&root)).unwrap();

        assert!(!result.matches());
        assert!(result
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("verification failed")));
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn receipt_revalidation_rejects_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let (_handoff, manifest, receipt, lock, root) = captured_direct_fixture("symlink");
        let file_name = Path::new(&receipt.artifacts()[0].artifact_path)
            .file_name()
            .unwrap();
        let artifact = root.join(file_name);
        let foreign = root.join("foreign");
        fs::write(&foreign, b"label: gpt\ndevice: /dev/sda\n").unwrap();
        fs::remove_file(&artifact).unwrap();
        symlink(&foreign, &artifact).unwrap();

        let result = revalidate_receipt_at_root(&manifest, &receipt, Some(&root)).unwrap();

        assert!(!result.matches());
        assert!(result
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("unsafe")));
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn receipt_revalidation_rejects_receipt_identity_tampering() {
        let (_handoff, manifest, mut receipt, lock, root) = captured_direct_fixture("receipt-id");
        receipt.receipt_id = "0".repeat(64);

        let result = revalidate_receipt_at_root(&manifest, &receipt, Some(&root)).unwrap();

        assert!(!result.matches());
        assert!(result
            .blockers()
            .iter()
            .any(|blocker| blocker.contains("receipt ID")));
        let _ = fs::remove_dir_all(lock.parent().unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn mutation_flag_remains_disabled() {
        assert!(!std::hint::black_box(MUTATION_ENABLED));
    }
}
