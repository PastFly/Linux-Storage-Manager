use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProductionMutationExecutionPermit;

pub const PRODUCTION_MUTATION_SPAWN_CLAIM_DIRECTORY: &str =
    "/var/lib/linux-storage-manager/journal/spawn-claims";
pub const PRODUCTION_MUTATION_SPAWN_CLAIM_COMPILED: bool =
    cfg!(feature = "production-mutation-spawn-claim");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationSpawnClaim {
    pub schema_version: u32,
    pub claim_id: String,
    pub execution_permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub execution_id: String,
    pub launch_permit_id: String,
    pub launch_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub target: String,
    pub resolved_device: String,
    pub mutation_may_have_started: bool,
    pub process_spawned: bool,
}

impl ProductionMutationSpawnClaim {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.claim_id == self.expected_claim_id()?)
    }

    fn expected_claim_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.execution_permit_id,
            &self.activation_id,
            &self.consent_receipt_id,
            &self.execution_id,
            &self.launch_permit_id,
            &self.launch_id,
            self.plan_step_id,
            &self.command_digest,
            &self.target,
            &self.resolved_device,
            self.mutation_may_have_started,
            self.process_spawned,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error)]
pub enum ProductionMutationSpawnClaimError {
    #[error("production mutation spawn-claim feature is not compiled")]
    FeatureDisabled,
    #[error("production spawn claim requires root EUID")]
    NotRoot,
    #[error("production execution permit integrity check failed")]
    ExecutionPermitInvalid,
    #[error("production execution permit unexpectedly reports mutation/process execution enabled")]
    ExecutionPermitAlreadyEnabled,
    #[error("spawn claim directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("spawn claim identity is invalid")]
    InvalidIdentity,
    #[error("this exact production execution step was already claimed")]
    AlreadyClaimed,
    #[error("spawn claim serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("spawn claim I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(path: &Path, source: io::Error) -> ProductionMutationSpawnClaimError {
    ProductionMutationSpawnClaimError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_execution_permit(
    permit: &ProductionMutationExecutionPermit,
) -> Result<(), ProductionMutationSpawnClaimError> {
    if permit.schema_version != 1
        || !permit.integrity_matches().unwrap_or(false)
        || !permit.compile_feature_enabled
        || !is_digest(&permit.permit_id)
        || !is_digest(&permit.activation_id)
        || !is_digest(&permit.consent_receipt_id)
        || !is_digest(&permit.execution_id)
        || !is_digest(&permit.launch_permit_id)
        || !is_digest(&permit.launch_id)
        || !is_digest(&permit.command_digest)
        || permit.plan_step_id == 0
        || permit.target.is_empty()
        || permit.resolved_device.is_empty()
    {
        return Err(ProductionMutationSpawnClaimError::ExecutionPermitInvalid);
    }
    if permit.mutation_enabled || permit.process_spawned {
        return Err(ProductionMutationSpawnClaimError::ExecutionPermitAlreadyEnabled);
    }
    Ok(())
}

fn ensure_secure_directory(
    path: &Path,
    require_root_owner: bool,
) -> Result<(), ProductionMutationSpawnClaimError> {
    if !path.is_absolute() {
        return Err(ProductionMutationSpawnClaimError::UnsafeDirectory(
            path.to_path_buf(),
        ));
    }

    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                current.push(Path::new("/"));
                continue;
            }
            Component::Normal(part) => current.push(part),
            _ => {
                return Err(ProductionMutationSpawnClaimError::UnsafeDirectory(
                    path.to_path_buf(),
                ));
            }
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(ProductionMutationSpawnClaimError::UnsafeDirectory(
                        current,
                    ));
                }
                if require_root_owner
                    && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0)
                {
                    return Err(ProductionMutationSpawnClaimError::UnsafeDirectory(
                        current,
                    ));
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
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || (require_root_owner
                        && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0))
                {
                    return Err(ProductionMutationSpawnClaimError::UnsafeDirectory(
                        current,
                    ));
                }
            }
            Err(source) => return Err(io_error(&current, source)),
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ProductionMutationSpawnClaimError> {
    let directory = File::open(path).map_err(|source| io_error(path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(path, source))
}

fn build_claim(
    permit: &ProductionMutationExecutionPermit,
) -> Result<ProductionMutationSpawnClaim, ProductionMutationSpawnClaimError> {
    validate_execution_permit(permit)?;

    let mut claim = ProductionMutationSpawnClaim {
        schema_version: 1,
        claim_id: String::new(),
        execution_permit_id: permit.permit_id.clone(),
        activation_id: permit.activation_id.clone(),
        consent_receipt_id: permit.consent_receipt_id.clone(),
        execution_id: permit.execution_id.clone(),
        launch_permit_id: permit.launch_permit_id.clone(),
        launch_id: permit.launch_id.clone(),
        plan_step_id: permit.plan_step_id,
        command_digest: permit.command_digest.clone(),
        target: permit.target.clone(),
        resolved_device: permit.resolved_device.clone(),
        mutation_may_have_started: true,
        process_spawned: false,
    };
    claim.claim_id = claim.expected_claim_id()?;
    Ok(claim)
}

fn persist_claim_at(
    directory: &Path,
    permit: &ProductionMutationExecutionPermit,
    require_root_owner: bool,
) -> Result<ProductionMutationSpawnClaim, ProductionMutationSpawnClaimError> {
    ensure_secure_directory(directory, require_root_owner)?;
    let claim = build_claim(permit)?;
    let path = directory.join(format!(
        "{}-{}.json",
        permit.execution_id, permit.plan_step_id
    ));
    let bytes = serde_json::to_vec(&claim)?;

    // create_new is the one-shot primitive. Once the pathname exists, even a
    // partial write after a crash must block replay and force reconciliation.
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ProductionMutationSpawnClaimError::AlreadyClaimed);
        }
        Err(source) => return Err(io_error(&path, source)),
    };

    file.write_all(&bytes)
        .map_err(|source| io_error(&path, source))?;
    file.write_all(b"\n")
        .map_err(|source| io_error(&path, source))?;
    file.sync_all().map_err(|source| io_error(&path, source))?;
    drop(file);
    sync_directory(directory)?;

    Ok(claim)
}

/// Durably consume one production execution step before any future process
/// spawn. The claim is intentionally never deleted: an execution ID/step pair
/// is one-shot forever, including across crashes and reboots.
///
/// A failure after create_new may leave a partial claim file. That is safe:
/// the next attempt receives AlreadyClaimed and must enter reconciliation.
pub fn persist_production_mutation_spawn_claim(
    permit: &ProductionMutationExecutionPermit,
) -> Result<ProductionMutationSpawnClaim, ProductionMutationSpawnClaimError> {
    if !PRODUCTION_MUTATION_SPAWN_CLAIM_COMPILED {
        return Err(ProductionMutationSpawnClaimError::FeatureDisabled);
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(ProductionMutationSpawnClaimError::NotRoot);
    }
    persist_claim_at(
        Path::new(PRODUCTION_MUTATION_SPAWN_CLAIM_DIRECTORY),
        permit,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProductionMutationProfile;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn permit() -> ProductionMutationExecutionPermit {
        let mut value = ProductionMutationExecutionPermit {
            schema_version: 1,
            permit_id: String::new(),
            activation_id: digest('a'),
            consent_receipt_id: digest('b'),
            execution_id: digest('c'),
            profile: ProductionMutationProfile::ExistingSinglePvLvmFilesystem,
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            launch_permit_id: digest('d'),
            launch_id: digest('e'),
            plan_step_id: 3,
            command_digest: digest('f'),
            compile_feature_enabled: true,
            mutation_enabled: false,
            process_spawned: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.activation_id,
            &value.consent_receipt_id,
            &value.execution_id,
            value.profile,
            &value.target,
            &value.resolved_device,
            &value.launch_permit_id,
            &value.launch_id,
            value.plan_step_id,
            &value.command_digest,
            value.compile_feature_enabled,
            value.mutation_enabled,
            value.process_spawned,
        ))
        .unwrap();
        value.permit_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "lsm-production-spawn-claim-{}-{}-{name}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn exact_execution_step_can_be_claimed_only_once() {
        let root = root("one-shot");
        let permit = permit();

        let first = persist_claim_at(&root, &permit, false).unwrap();
        assert!(first.integrity_matches().unwrap());
        assert!(first.mutation_may_have_started);
        assert!(!first.process_spawned);

        assert!(matches!(
            persist_claim_at(&root, &permit, false),
            Err(ProductionMutationSpawnClaimError::AlreadyClaimed)
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn another_step_gets_a_distinct_one_shot_claim() {
        let root = root("step-scope");
        let first = permit();
        persist_claim_at(&root, &first, false).unwrap();

        let mut second = permit();
        second.plan_step_id = 4;
        let bytes = serde_json::to_vec(&(
            second.schema_version,
            &second.activation_id,
            &second.consent_receipt_id,
            &second.execution_id,
            second.profile,
            &second.target,
            &second.resolved_device,
            &second.launch_permit_id,
            &second.launch_id,
            second.plan_step_id,
            &second.command_digest,
            second.compile_feature_enabled,
            second.mutation_enabled,
            second.process_spawned,
        ))
        .unwrap();
        second.permit_id = format!("{:x}", Sha256::digest(bytes));

        let claim = persist_claim_at(&root, &second, false).unwrap();
        assert_eq!(claim.plan_step_id, 4);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_execution_permit_is_rejected_before_claim_creation() {
        let root = root("tampered");
        let mut permit = permit();
        permit.command_digest = digest('9');

        assert!(matches!(
            persist_claim_at(&root, &permit, false),
            Err(ProductionMutationSpawnClaimError::ExecutionPermitInvalid)
        ));

        fs::remove_dir_all(root).unwrap();
    }
}
