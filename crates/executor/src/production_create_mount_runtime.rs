use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind};
use lsm_discovery::discover_snapshot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::privileged_launch::inspect_elf;
use crate::{
    resolve_trusted_privileged_tool, ElfExecutionIdentity, PrivilegedLaunchSpecError,
    PrivilegedProgram, ProductionCreateActivationIntent, ProductionCreateMountActivationIntent,
    TrustedToolError, TrustedToolIdentity,
};

pub const PRODUCTION_CREATE_MOUNT_RUNTIME_PREFLIGHT_COMPILED: bool =
    cfg!(feature = "production-create-mount-runtime-preflight");

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";
const TOOL_READ_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateMountRuntimePreflightReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub mount_activation_id: String,
    pub create_activation_id: String,
    pub filesystem_receipt_id: String,
    pub journal_id: String,
    pub create_launch_id: String,
    pub disk: String,
    pub partition_device: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub mountpoint: String,
    pub mountpoint_device_id: u64,
    pub mountpoint_inode: u64,
    pub mountpoint_uid: u32,
    pub mountpoint_mode: u32,
    pub fstab_source: String,
    pub mount: TrustedToolIdentity,
    pub runtime_ready: bool,
    pub execution_enabled: bool,
    pub process_spawned: bool,
    pub mount_performed: bool,
    pub fstab_changed: bool,
}

#[derive(Serialize)]
struct PreflightDigestPayload<'a> {
    schema_version: u32,
    mount_activation_id: &'a str,
    create_activation_id: &'a str,
    filesystem_receipt_id: &'a str,
    journal_id: &'a str,
    create_launch_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    filesystem: &'a str,
    filesystem_uuid: &'a str,
    mountpoint: &'a str,
    mountpoint_device_id: u64,
    mountpoint_inode: u64,
    mountpoint_uid: u32,
    mountpoint_mode: u32,
    fstab_source: &'a str,
    mount: &'a TrustedToolIdentity,
    runtime_ready: bool,
    execution_enabled: bool,
    process_spawned: bool,
    mount_performed: bool,
    fstab_changed: bool,
}

impl ProductionCreateMountRuntimePreflightReceipt {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.receipt_id == self.expected_receipt_id()?)
    }

    fn expected_receipt_id(&self) -> Result<String, serde_json::Error> {
        let payload = PreflightDigestPayload {
            schema_version: self.schema_version,
            mount_activation_id: &self.mount_activation_id,
            create_activation_id: &self.create_activation_id,
            filesystem_receipt_id: &self.filesystem_receipt_id,
            journal_id: &self.journal_id,
            create_launch_id: &self.create_launch_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            filesystem: &self.filesystem,
            filesystem_uuid: &self.filesystem_uuid,
            mountpoint: &self.mountpoint,
            mountpoint_device_id: self.mountpoint_device_id,
            mountpoint_inode: self.mountpoint_inode,
            mountpoint_uid: self.mountpoint_uid,
            mountpoint_mode: self.mountpoint_mode,
            fstab_source: &self.fstab_source,
            mount: &self.mount,
            runtime_ready: self.runtime_ready,
            execution_enabled: self.execution_enabled,
            process_spawned: self.process_spawned,
            mount_performed: self.mount_performed,
            fstab_changed: self.fstab_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateMountRuntimePreflightError {
    #[error("production create mount runtime preflight feature is not compiled")]
    FeatureDisabled,
    #[error("create mount activation chain is invalid")]
    AuthorizationInvalid,
    #[error("create mount activation does not bind the exact completed create scope")]
    BindingMismatch,
    #[error("fresh storage collectors required for mount activation are incomplete")]
    CollectorIncomplete,
    #[error("fresh disk/partition/filesystem identity or geometry changed")]
    FilesystemBindingMismatch,
    #[error("fresh filesystem UUID no longer matches the sealed mount activation")]
    FilesystemUuidMismatch,
    #[error("mountpoint pathname or frozen inode metadata changed")]
    MountpointIdentityChanged,
    #[error("mountpoint must remain empty before runtime activation")]
    MountpointNotEmpty,
    #[error("filesystem or mountpoint is already mounted or active as swap")]
    RuntimeConflict,
    #[error("filesystem or mountpoint has a conflicting fstab binding")]
    FstabConflict,
    #[error("mountpoint inspection failed at {path}: {source}")]
    MountpointIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("trusted mount tool resolution failed: {0}")]
    Tool(#[from] TrustedToolError),
    #[error("fresh mount preflight discovery failed: {0}")]
    Discovery(String),
    #[error("mount runtime preflight serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug)]
pub struct PinnedProductionCreateMountTool {
    preflight_receipt_id: String,
    pub mount: TrustedToolIdentity,
    mount_file: File,
}

impl PinnedProductionCreateMountTool {
    pub fn preflight_receipt_id(&self) -> &str {
        &self.preflight_receipt_id
    }

    pub(crate) fn mount_file(&self) -> &File {
        &self.mount_file
    }

    pub fn revalidate(
        &self,
        preflight: &ProductionCreateMountRuntimePreflightReceipt,
    ) -> Result<(), ProductionCreateMountToolLeaseError> {
        validate_mount_preflight_receipt(preflight)?;
        if self.preflight_receipt_id != preflight.receipt_id || self.mount != preflight.mount {
            return Err(ProductionCreateMountToolLeaseError::PreflightInvalid);
        }
        validate_open_mount_tool(self.mount_file(), &self.mount)
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateMountToolLeaseError {
    #[error("mount runtime preflight integrity or state is invalid")]
    PreflightInvalid,
    #[error("mount preflight tool identity is bound to the wrong program")]
    ProgramMismatch,
    #[error("pinned mount executable no longer matches trusted identity")]
    ToolIdentityMismatch,
    #[error("mount executable pinning I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateMountLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub executable: TrustedToolIdentity,
    pub elf: ElfExecutionIdentity,
    pub stdin_len: u64,
    pub stdin_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateMountRuntimeLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub mount_activation_id: String,
    pub preflight_receipt_id: String,
    pub disk: String,
    pub partition_device: String,
    pub filesystem: String,
    pub filesystem_uuid: String,
    pub mountpoint: String,
    pub fstab_source: String,
    pub mount: ProductionCreateMountLaunchStage,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub descriptor_exec_api: String,
    pub require_mountpoint_identity_revalidation_before_spawn: bool,
    pub mtab_write_enabled: bool,
    pub execution_enabled: bool,
    pub process_spawned: bool,
    pub mount_performed: bool,
    pub fstab_changed: bool,
}

#[derive(Serialize)]
struct MountLaunchDigestPayload<'a> {
    schema_version: u32,
    mount_activation_id: &'a str,
    preflight_receipt_id: &'a str,
    disk: &'a str,
    partition_device: &'a str,
    filesystem: &'a str,
    filesystem_uuid: &'a str,
    mountpoint: &'a str,
    fstab_source: &'a str,
    mount: &'a ProductionCreateMountLaunchStage,
    fixed_path: &'a str,
    fixed_locale: &'a str,
    descriptor_exec_api: &'a str,
    require_mountpoint_identity_revalidation_before_spawn: bool,
    mtab_write_enabled: bool,
    execution_enabled: bool,
    process_spawned: bool,
    mount_performed: bool,
    fstab_changed: bool,
}

impl ProductionCreateMountRuntimeLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let payload = MountLaunchDigestPayload {
            schema_version: self.schema_version,
            mount_activation_id: &self.mount_activation_id,
            preflight_receipt_id: &self.preflight_receipt_id,
            disk: &self.disk,
            partition_device: &self.partition_device,
            filesystem: &self.filesystem,
            filesystem_uuid: &self.filesystem_uuid,
            mountpoint: &self.mountpoint,
            fstab_source: &self.fstab_source,
            mount: &self.mount,
            fixed_path: &self.fixed_path,
            fixed_locale: &self.fixed_locale,
            descriptor_exec_api: &self.descriptor_exec_api,
            require_mountpoint_identity_revalidation_before_spawn: self
                .require_mountpoint_identity_revalidation_before_spawn,
            mtab_write_enabled: self.mtab_write_enabled,
            execution_enabled: self.execution_enabled,
            process_spawned: self.process_spawned,
            mount_performed: self.mount_performed,
            fstab_changed: self.fstab_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateMountRuntimeLaunchError {
    #[error("production create mount runtime preflight feature is not compiled")]
    FeatureDisabled,
    #[error("mount activation/preflight integrity or binding is invalid")]
    AuthorizationInvalid,
    #[error("pinned mount executable lease is invalid: {0}")]
    ToolLease(#[from] ProductionCreateMountToolLeaseError),
    #[error("mountpoint identity changed after the fresh preflight")]
    MountpointIdentityChanged,
    #[error("mountpoint became non-empty after the fresh preflight")]
    MountpointNotEmpty,
    #[error("mountpoint revalidation failed at {path}: {source}")]
    MountpointIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("mount launch argument contains an embedded NUL byte")]
    EmbeddedNul,
    #[error("mount launch executable is not a supported native ELF: {0}")]
    Executable(#[from] PrivilegedLaunchSpecError),
    #[error("mount runtime launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn expected_partition_table(policy: lsm_planner::CreatePartitionTablePolicy) -> &'static str {
    match policy {
        lsm_planner::CreatePartitionTablePolicy::Gpt => "gpt",
        lsm_planner::CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn expected_partition_device(disk: &str) -> Option<String> {
    if !disk.starts_with("/dev/")
        || disk.as_bytes().contains(&0)
        || disk.len() <= "/dev/".len()
        || disk.ends_with('/')
    {
        return None;
    }
    let suffix = if disk.as_bytes().last().is_some_and(u8::is_ascii_digit) {
        "p1"
    } else {
        "1"
    };
    Some(format!("{disk}{suffix}"))
}

fn flatten<'a>(devices: &'a [BlockDevice], output: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        output.push(device);
        flatten(&device.children, output);
    }
}

fn required_collectors_complete(snapshot: &HostSnapshot) -> bool {
    ["lsblk", "partition_tables", "mounts", "fstab", "swap"]
        .into_iter()
        .all(|component| {
            let matches = snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component)
                .collect::<Vec<_>>();
            matches.len() == 1 && matches[0].state == CollectorState::Complete
        })
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn reserved_mountpoint(path: &Path) -> bool {
    [
        "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/tmp", "/usr", "/var",
    ]
    .into_iter()
    .any(|reserved| path == Path::new(reserved))
}

fn mountpoint_io(
    path: &Path,
    source: std::io::Error,
) -> ProductionCreateMountRuntimePreflightError {
    ProductionCreateMountRuntimePreflightError::MountpointIo {
        path: path.to_path_buf(),
        source,
    }
}

fn revalidate_mountpoint_identity(
    activation: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreateMountRuntimePreflightError> {
    if activation.mountpoint.is_empty()
        || activation.mountpoint.as_bytes().contains(&0)
        || activation.mountpoint.chars().any(char::is_control)
        || activation.mountpoint_uid != 0
        || activation.mountpoint_mode & 0o022 != 0
    {
        return Err(ProductionCreateMountRuntimePreflightError::MountpointIdentityChanged);
    }

    let path = Path::new(&activation.mountpoint);
    if !safe_absolute_path(path) || reserved_mountpoint(path) {
        return Err(ProductionCreateMountRuntimePreflightError::MountpointIdentityChanged);
    }

    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(ProductionCreateMountRuntimePreflightError::MountpointIdentityChanged),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| mountpoint_io(&current, source))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(ProductionCreateMountRuntimePreflightError::MountpointIdentityChanged);
        }
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| mountpoint_io(path, source))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != activation.mountpoint_device_id
        || metadata.ino() != activation.mountpoint_inode
        || metadata.uid() != activation.mountpoint_uid
        || metadata.mode() != activation.mountpoint_mode
    {
        return Err(ProductionCreateMountRuntimePreflightError::MountpointIdentityChanged);
    }

    let mut entries = fs::read_dir(path).map_err(|source| mountpoint_io(path, source))?;
    if entries.next().is_some() {
        return Err(ProductionCreateMountRuntimePreflightError::MountpointNotEmpty);
    }
    Ok(())
}

fn validate_activation_binding(
    create: &ProductionCreateActivationIntent,
    mount: &ProductionCreateMountActivationIntent,
) -> Result<(), ProductionCreateMountRuntimePreflightError> {
    if create.schema_version != 1
        || mount.schema_version != 1
        || !create.integrity_matches().unwrap_or(false)
        || !mount.integrity_matches().unwrap_or(false)
        || !create.compile_feature_enabled
        || !mount.compile_feature_enabled
        || create.execution_enabled
        || create.partition_table_changed
        || create.filesystem_formatted
        || mount.execution_enabled
        || mount.mount_performed
        || mount.fstab_changed
    {
        return Err(ProductionCreateMountRuntimePreflightError::AuthorizationInvalid);
    }

    let expected_partition = expected_partition_device(&create.disk)
        .ok_or(ProductionCreateMountRuntimePreflightError::BindingMismatch)?;
    let expected_fstab_source = format!("UUID={}", mount.filesystem_uuid);
    let expected_pass = if create.filesystem == "ext4" { 2 } else { 0 };
    let expected_options = ["defaults", "nofail"];

    if mount.create_activation_id != create.activation_id
        || mount.disk != create.disk
        || mount.partition_device != expected_partition
        || mount.filesystem != create.filesystem
        || mount.fstab_source != expected_fstab_source
        || mount
            .fstab_options
            .iter()
            .map(String::as_str)
            .ne(expected_options)
        || mount.fstab_dump != 0
        || mount.fstab_pass != expected_pass
        || mount.mountpoint_uid != 0
        || mount.mountpoint_mode & 0o022 != 0
    {
        return Err(ProductionCreateMountRuntimePreflightError::BindingMismatch);
    }
    Ok(())
}

fn validate_fresh_snapshot(
    create: &ProductionCreateActivationIntent,
    mount: &ProductionCreateMountActivationIntent,
    snapshot: &HostSnapshot,
) -> Result<(), ProductionCreateMountRuntimePreflightError> {
    if !required_collectors_complete(snapshot) {
        return Err(ProductionCreateMountRuntimePreflightError::CollectorIncomplete);
    }

    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == create.disk)
        .collect::<Vec<_>>();
    if tables.len() != 1 {
        return Err(ProductionCreateMountRuntimePreflightError::FilesystemBindingMismatch);
    }
    let table = tables[0];
    if table.label.as_deref() != Some(expected_partition_table(create.partition_table))
        || table.unit.as_deref() != Some("sectors")
        || table.sector_size_bytes != Some(create.logical_sector_bytes)
        || table.partitions.len() != 1
        || table.partitions[0].node != mount.partition_device
        || table.partitions[0].start_sector != create.partition_start_sector
        || table.partitions[0].size_sectors != create.partition_sector_count
    {
        return Err(ProductionCreateMountRuntimePreflightError::FilesystemBindingMismatch);
    }

    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);
    let disks = nodes
        .iter()
        .copied()
        .filter(|device| device.path.as_deref() == Some(create.disk.as_str()))
        .collect::<Vec<_>>();
    let partitions = nodes
        .iter()
        .copied()
        .filter(|device| device.path.as_deref() == Some(mount.partition_device.as_str()))
        .collect::<Vec<_>>();
    if disks.len() != 1 || partitions.len() != 1 {
        return Err(ProductionCreateMountRuntimePreflightError::FilesystemBindingMismatch);
    }
    let disk = disks[0];
    let partition = partitions[0];

    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
        || disk.size_bytes != create.disk_size_bytes
        || disk.logical_sector_bytes != Some(create.logical_sector_bytes)
        || disk.model != create.disk_model
        || disk.serial != create.disk_serial
        || disk.partition_table.as_deref() != Some(expected_partition_table(create.partition_table))
        || partition.kind != NodeKind::Partition
        || partition.size_bytes != create.partition_size_bytes
        || partition.logical_sector_bytes != Some(create.logical_sector_bytes)
        || partition.parent_kernel_name != disk.kernel_name
        || partition
            .filesystem
            .as_ref()
            .is_none_or(|filesystem| filesystem.fs_type != create.filesystem)
        || !partition.mountpoints.is_empty()
    {
        return Err(ProductionCreateMountRuntimePreflightError::FilesystemBindingMismatch);
    }

    if partition
        .uuid
        .as_deref()
        .is_none_or(|uuid| !uuid.eq_ignore_ascii_case(&mount.filesystem_uuid))
    {
        return Err(ProductionCreateMountRuntimePreflightError::FilesystemUuidMismatch);
    }

    let uuid_source = format!("UUID={}", mount.filesystem_uuid);
    if snapshot.mounts.iter().any(|entry| {
        entry.target == mount.mountpoint
            || entry.source.as_deref() == Some(mount.partition_device.as_str())
            || entry
                .source
                .as_deref()
                .is_some_and(|source| source.eq_ignore_ascii_case(&uuid_source))
    }) || snapshot.swaps.iter().any(|entry| {
        entry.name == mount.partition_device || entry.name.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountRuntimePreflightError::RuntimeConflict);
    }

    if snapshot.fstab.iter().any(|entry| {
        entry.target == mount.mountpoint
            || entry.source == mount.partition_device
            || entry.source.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountRuntimePreflightError::FstabConflict);
    }

    Ok(())
}

fn prepare_from_snapshot(
    create: &ProductionCreateActivationIntent,
    mount_activation: &ProductionCreateMountActivationIntent,
    snapshot: &HostSnapshot,
) -> Result<ProductionCreateMountRuntimePreflightReceipt, ProductionCreateMountRuntimePreflightError>
{
    if !PRODUCTION_CREATE_MOUNT_RUNTIME_PREFLIGHT_COMPILED {
        return Err(ProductionCreateMountRuntimePreflightError::FeatureDisabled);
    }
    validate_activation_binding(create, mount_activation)?;
    validate_fresh_snapshot(create, mount_activation, snapshot)?;
    revalidate_mountpoint_identity(mount_activation)?;

    let mount_tool = resolve_trusted_privileged_tool(PrivilegedProgram::Mount)?;
    let mut receipt = ProductionCreateMountRuntimePreflightReceipt {
        schema_version: 1,
        receipt_id: String::new(),
        mount_activation_id: mount_activation.mount_activation_id.clone(),
        create_activation_id: create.activation_id.clone(),
        filesystem_receipt_id: mount_activation.filesystem_receipt_id.clone(),
        journal_id: mount_activation.journal_id.clone(),
        create_launch_id: mount_activation.launch_id.clone(),
        disk: mount_activation.disk.clone(),
        partition_device: mount_activation.partition_device.clone(),
        filesystem: mount_activation.filesystem.clone(),
        filesystem_uuid: mount_activation.filesystem_uuid.clone(),
        mountpoint: mount_activation.mountpoint.clone(),
        mountpoint_device_id: mount_activation.mountpoint_device_id,
        mountpoint_inode: mount_activation.mountpoint_inode,
        mountpoint_uid: mount_activation.mountpoint_uid,
        mountpoint_mode: mount_activation.mountpoint_mode,
        fstab_source: mount_activation.fstab_source.clone(),
        mount: mount_tool,
        runtime_ready: true,
        execution_enabled: false,
        process_spawned: false,
        mount_performed: false,
        fstab_changed: false,
    };
    receipt.receipt_id = receipt.expected_receipt_id()?;
    Ok(receipt)
}

/// Re-discover all mount-relevant host state, prove the exact completed Create
/// geometry/filesystem/UUID and revalidate the frozen mountpoint inode before
/// resolving the trusted mount executable. This function never spawns a process.
pub fn prepare_production_create_mount_runtime_preflight(
    create: &ProductionCreateActivationIntent,
    mount_activation: &ProductionCreateMountActivationIntent,
) -> Result<ProductionCreateMountRuntimePreflightReceipt, ProductionCreateMountRuntimePreflightError>
{
    let snapshot = discover_snapshot().map_err(|error| {
        ProductionCreateMountRuntimePreflightError::Discovery(error.to_string())
    })?;
    prepare_from_snapshot(create, mount_activation, &snapshot)
}

fn validate_mount_preflight_receipt(
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
) -> Result<(), ProductionCreateMountToolLeaseError> {
    if preflight.schema_version != 1
        || !preflight.integrity_matches().unwrap_or(false)
        || !preflight.runtime_ready
        || preflight.execution_enabled
        || preflight.process_spawned
        || preflight.mount_performed
        || preflight.fstab_changed
    {
        return Err(ProductionCreateMountToolLeaseError::PreflightInvalid);
    }
    if preflight.mount.program != PrivilegedProgram::Mount {
        return Err(ProductionCreateMountToolLeaseError::ProgramMismatch);
    }
    Ok(())
}

fn sha256_open_file(file: &File, expected_size: u64) -> Result<String, std::io::Error> {
    let mut digest = Sha256::new();
    let mut offset = 0_u64;
    let mut buffer = [0_u8; TOOL_READ_CHUNK];

    while offset < expected_size {
        let remaining = (expected_size - offset) as usize;
        let want = remaining.min(buffer.len());
        let read = file.read_at(&mut buffer[..want], offset)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| std::io::Error::other("mount tool hash offset overflow"))?;
    }
    if offset != expected_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "trusted mount tool size changed while hashing",
        ));
    }
    let mut probe = [0_u8; 1];
    if file.read_at(&mut probe, expected_size)? != 0 {
        return Err(std::io::Error::other(
            "trusted mount tool grew while hashing",
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn validate_open_mount_tool(
    file: &File,
    identity: &TrustedToolIdentity,
) -> Result<(), ProductionCreateMountToolLeaseError> {
    let metadata = file.metadata()?;
    if identity.program != PrivilegedProgram::Mount {
        return Err(ProductionCreateMountToolLeaseError::ProgramMismatch);
    }
    if !metadata.file_type().is_file()
        || metadata.dev() != identity.device_id
        || metadata.ino() != identity.inode
        || metadata.uid() != identity.uid
        || metadata.mode() != identity.mode
        || metadata.len() != identity.size_bytes
        || sha256_open_file(file, identity.size_bytes)? != identity.sha256
    {
        return Err(ProductionCreateMountToolLeaseError::ToolIdentityMismatch);
    }
    Ok(())
}

fn open_exact_mount_tool(
    identity: &TrustedToolIdentity,
) -> Result<File, ProductionCreateMountToolLeaseError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(&identity.canonical_path))?;
    validate_open_mount_tool(&file, identity)?;
    Ok(file)
}

/// Pin the exact trusted mount executable object by open descriptor. No process
/// is spawned and no mount or persistent configuration state is changed.
pub fn pin_production_create_mount_tool(
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
) -> Result<PinnedProductionCreateMountTool, ProductionCreateMountToolLeaseError> {
    validate_mount_preflight_receipt(preflight)?;
    let mount_file = open_exact_mount_tool(&preflight.mount)?;
    Ok(PinnedProductionCreateMountTool {
        preflight_receipt_id: preflight.receipt_id.clone(),
        mount: preflight.mount.clone(),
        mount_file,
    })
}

fn validate_launch_binding(
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
) -> Result<(), ProductionCreateMountRuntimeLaunchError> {
    validate_mount_preflight_receipt(preflight)
        .map_err(|_| ProductionCreateMountRuntimeLaunchError::AuthorizationInvalid)?;
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || activation.execution_enabled
        || activation.mount_performed
        || activation.fstab_changed
        || preflight.mount_activation_id != activation.mount_activation_id
        || preflight.create_activation_id != activation.create_activation_id
        || preflight.filesystem_receipt_id != activation.filesystem_receipt_id
        || preflight.journal_id != activation.journal_id
        || preflight.create_launch_id != activation.launch_id
        || preflight.disk != activation.disk
        || preflight.partition_device != activation.partition_device
        || preflight.filesystem != activation.filesystem
        || !preflight
            .filesystem_uuid
            .eq_ignore_ascii_case(&activation.filesystem_uuid)
        || preflight.mountpoint != activation.mountpoint
        || preflight.mountpoint_device_id != activation.mountpoint_device_id
        || preflight.mountpoint_inode != activation.mountpoint_inode
        || preflight.mountpoint_uid != activation.mountpoint_uid
        || preflight.mountpoint_mode != activation.mountpoint_mode
        || preflight.fstab_source != activation.fstab_source
    {
        return Err(ProductionCreateMountRuntimeLaunchError::AuthorizationInvalid);
    }
    Ok(())
}

fn exact_mount_argv(
    filesystem: &str,
    source: &str,
    mountpoint: &str,
) -> Result<Vec<String>, ProductionCreateMountRuntimeLaunchError> {
    for value in [filesystem, source, mountpoint] {
        if value.is_empty() || value.as_bytes().contains(&0) || value.chars().any(char::is_control)
        {
            return Err(ProductionCreateMountRuntimeLaunchError::EmbeddedNul);
        }
    }
    Ok(vec![
        "mount".into(),
        "-n".into(),
        "-t".into(),
        filesystem.into(),
        "-o".into(),
        "rw".into(),
        source.into(),
        mountpoint.into(),
    ])
}

fn map_mountpoint_launch_error(
    error: ProductionCreateMountRuntimePreflightError,
) -> ProductionCreateMountRuntimeLaunchError {
    match error {
        ProductionCreateMountRuntimePreflightError::MountpointNotEmpty => {
            ProductionCreateMountRuntimeLaunchError::MountpointNotEmpty
        }
        ProductionCreateMountRuntimePreflightError::MountpointIo { path, source } => {
            ProductionCreateMountRuntimeLaunchError::MountpointIo { path, source }
        }
        _ => ProductionCreateMountRuntimeLaunchError::MountpointIdentityChanged,
    }
}

/// Freeze the exact descriptor-based mount launch contract after revalidating
/// both the pinned mount executable and the frozen mountpoint inode again.
/// The argv uses mount -n so /etc/mtab cannot be changed by this future stage.
/// This layer remains non-spawning and does not write /etc/fstab.
pub fn build_production_create_mount_runtime_launch_spec(
    activation: &ProductionCreateMountActivationIntent,
    preflight: &ProductionCreateMountRuntimePreflightReceipt,
    tool: &PinnedProductionCreateMountTool,
) -> Result<ProductionCreateMountRuntimeLaunchSpec, ProductionCreateMountRuntimeLaunchError> {
    if !PRODUCTION_CREATE_MOUNT_RUNTIME_PREFLIGHT_COMPILED {
        return Err(ProductionCreateMountRuntimeLaunchError::FeatureDisabled);
    }
    validate_launch_binding(activation, preflight)?;
    tool.revalidate(preflight)?;
    revalidate_mountpoint_identity(activation).map_err(map_mountpoint_launch_error)?;

    let argv = exact_mount_argv(
        &activation.filesystem,
        &activation.fstab_source,
        &activation.mountpoint,
    )?;
    let stage = ProductionCreateMountLaunchStage {
        program: PrivilegedProgram::Mount,
        argv,
        executable: preflight.mount.clone(),
        elf: inspect_elf(tool.mount_file())?,
        stdin_len: 0,
        stdin_sha256: None,
    };

    let mut launch = ProductionCreateMountRuntimeLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        mount_activation_id: activation.mount_activation_id.clone(),
        preflight_receipt_id: preflight.receipt_id.clone(),
        disk: activation.disk.clone(),
        partition_device: activation.partition_device.clone(),
        filesystem: activation.filesystem.clone(),
        filesystem_uuid: activation.filesystem_uuid.clone(),
        mountpoint: activation.mountpoint.clone(),
        fstab_source: activation.fstab_source.clone(),
        mount: stage,
        fixed_path: FIXED_PATH.into(),
        fixed_locale: FIXED_LOCALE.into(),
        descriptor_exec_api: "fexecve".into(),
        require_mountpoint_identity_revalidation_before_spawn: true,
        mtab_write_enabled: false,
        execution_enabled: false,
        process_spawned: false,
        mount_performed: false,
        fstab_changed: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_runtime_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_MOUNT_RUNTIME_PREFLIGHT_COMPILED,
            cfg!(feature = "production-create-mount-runtime-preflight")
        );
    }

    #[test]
    fn exact_mount_argv_uses_uuid_source_and_disables_mtab_writes() {
        let argv = exact_mount_argv(
            "ext4",
            "UUID=123e4567-e89b-12d3-a456-426614174000",
            "/mnt/data",
        )
        .unwrap();
        assert_eq!(
            argv,
            vec![
                "mount",
                "-n",
                "-t",
                "ext4",
                "-o",
                "rw",
                "UUID=123e4567-e89b-12d3-a456-426614174000",
                "/mnt/data",
            ]
        );
    }

    #[test]
    fn mount_argv_rejects_embedded_nul() {
        assert!(matches!(
            exact_mount_argv("ext4", "UUID=abc", "/mnt/data\0other"),
            Err(ProductionCreateMountRuntimeLaunchError::EmbeddedNul)
        ));
    }

    #[test]
    fn critical_direct_mountpoints_are_rejected() {
        assert!(reserved_mountpoint(Path::new("/etc")));
        assert!(reserved_mountpoint(Path::new("/root")));
        assert!(reserved_mountpoint(Path::new("/tmp")));
        assert!(!reserved_mountpoint(Path::new("/mnt/data")));
    }

    #[test]
    fn expected_partition_device_handles_digit_suffix_disks() {
        assert_eq!(
            expected_partition_device("/dev/nvme0n1").as_deref(),
            Some("/dev/nvme0n1p1")
        );
        assert_eq!(
            expected_partition_device("/dev/sda").as_deref(),
            Some("/dev/sda1")
        );
    }
}
