use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use lsm_core::{BlockDevice, CollectorState, HostSnapshot, NodeKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProductionCreateActivationIntent, ProductionCreateFilesystemExecutionReceipt,
    ProductionCreateRuntimeJournal, ProductionCreateRuntimePhase,
};

pub const PRODUCTION_CREATE_MOUNT_ACTIVATION_COMPILED: bool =
    cfg!(feature = "production-create-mount-activation");

const DEFAULT_FSTAB_OPTIONS: &[&str] = &["defaults", "nofail"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateMountActivationIntent {
    pub schema_version: u32,
    pub mount_activation_id: String,
    pub create_activation_id: String,
    pub filesystem_receipt_id: String,
    pub journal_id: String,
    pub launch_id: String,
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
    pub fstab_options: Vec<String>,
    pub fstab_dump: u32,
    pub fstab_pass: u32,
    pub persist_to_fstab: bool,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
    pub mount_performed: bool,
    pub fstab_changed: bool,
}

#[derive(Serialize)]
struct MountActivationDigestPayload<'a> {
    schema_version: u32,
    create_activation_id: &'a str,
    filesystem_receipt_id: &'a str,
    journal_id: &'a str,
    launch_id: &'a str,
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
    fstab_options: &'a [String],
    fstab_dump: u32,
    fstab_pass: u32,
    persist_to_fstab: bool,
    compile_feature_enabled: bool,
    execution_enabled: bool,
    mount_performed: bool,
    fstab_changed: bool,
}

impl ProductionCreateMountActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.mount_activation_id == self.expected_mount_activation_id()?)
    }

    fn expected_mount_activation_id(&self) -> Result<String, serde_json::Error> {
        let payload = MountActivationDigestPayload {
            schema_version: self.schema_version,
            create_activation_id: &self.create_activation_id,
            filesystem_receipt_id: &self.filesystem_receipt_id,
            journal_id: &self.journal_id,
            launch_id: &self.launch_id,
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
            fstab_options: &self.fstab_options,
            fstab_dump: self.fstab_dump,
            fstab_pass: self.fstab_pass,
            persist_to_fstab: self.persist_to_fstab,
            compile_feature_enabled: self.compile_feature_enabled,
            execution_enabled: self.execution_enabled,
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
pub enum ProductionCreateMountActivationError {
    #[error("production create mount activation feature is not compiled")]
    FeatureDisabled,
    #[error("completed Create authorization/receipt/journal chain is invalid")]
    AuthorizationInvalid,
    #[error("fresh filesystem binding does not match the completed Create result")]
    FilesystemBindingMismatch,
    #[error("fresh filesystem UUID is absent or malformed")]
    FilesystemUuidInvalid,
    #[error("mountpoint is outside the safe absolute-directory profile")]
    UnsafeMountpoint,
    #[error("mountpoint directory must be empty before activation")]
    MountpointNotEmpty,
    #[error("filesystem or mountpoint is already mounted or active as swap")]
    RuntimeConflict,
    #[error("filesystem or mountpoint already has a conflicting fstab binding")]
    FstabConflict,
    #[error("mountpoint inspection failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("mount activation serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn io_error(path: &Path, source: io::Error) -> ProductionCreateMountActivationError {
    ProductionCreateMountActivationError::Io {
        path: path.to_path_buf(),
        source,
    }
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

fn inspect_safe_empty_mountpoint(
    mountpoint: &str,
    required_uid: u32,
) -> Result<fs::Metadata, ProductionCreateMountActivationError> {
    if mountpoint.is_empty()
        || mountpoint.as_bytes().contains(&0)
        || mountpoint.chars().any(char::is_control)
    {
        return Err(ProductionCreateMountActivationError::UnsafeMountpoint);
    }
    let path = Path::new(mountpoint);
    if !safe_absolute_path(path) || reserved_mountpoint(path) {
        return Err(ProductionCreateMountActivationError::UnsafeMountpoint);
    }

    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(value) => current.push(value),
            _ => return Err(ProductionCreateMountActivationError::UnsafeMountpoint),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|source| io_error(&current, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.mode() & 0o022 != 0 {
            return Err(ProductionCreateMountActivationError::UnsafeMountpoint);
        }
    }

    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if metadata.uid() != required_uid
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.mode() & 0o022 != 0
    {
        return Err(ProductionCreateMountActivationError::UnsafeMountpoint);
    }

    let mut entries = fs::read_dir(path).map_err(|source| io_error(path, source))?;
    if entries.next().is_some() {
        return Err(ProductionCreateMountActivationError::MountpointNotEmpty);
    }
    Ok(metadata)
}

fn canonical_filesystem_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

fn flatten<'a>(devices: &'a [BlockDevice], output: &mut Vec<&'a BlockDevice>) {
    for device in devices {
        output.push(device);
        flatten(&device.children, output);
    }
}

fn expected_partition_table(policy: lsm_planner::CreatePartitionTablePolicy) -> &'static str {
    match policy {
        lsm_planner::CreatePartitionTablePolicy::Gpt => "gpt",
        lsm_planner::CreatePartitionTablePolicy::Dos => "dos",
    }
}

fn verify_completed_chain(
    activation: &ProductionCreateActivationIntent,
    filesystem_receipt: &ProductionCreateFilesystemExecutionReceipt,
    journal: &ProductionCreateRuntimeJournal,
) -> Result<(), ProductionCreateMountActivationError> {
    if activation.schema_version != 1
        || filesystem_receipt.schema_version != 1
        || journal.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !filesystem_receipt.integrity_matches().unwrap_or(false)
        || !journal.integrity_matches().unwrap_or(false)
        || !filesystem_receipt.partition_mapped_verified
        || !filesystem_receipt.filesystem_formatted
        || !filesystem_receipt.journal_completed
        || journal.phase != ProductionCreateRuntimePhase::Completed
        || !journal.mutation_may_have_started
        || !journal.partition_table_may_have_changed
        || !journal.filesystem_may_have_changed
        || filesystem_receipt.journal_id != journal.journal_id
        || filesystem_receipt.launch_id != journal.launch_id
        || filesystem_receipt.disk != activation.disk
        || filesystem_receipt.disk != journal.disk
        || filesystem_receipt.partition_device != journal.partition_device
        || filesystem_receipt.filesystem != activation.filesystem
        || filesystem_receipt.filesystem != journal.filesystem
        || journal.activation_id != activation.activation_id
    {
        return Err(ProductionCreateMountActivationError::AuthorizationInvalid);
    }
    Ok(())
}

fn fresh_filesystem_uuid(
    activation: &ProductionCreateActivationIntent,
    filesystem_receipt: &ProductionCreateFilesystemExecutionReceipt,
    snapshot: &HostSnapshot,
    mountpoint: &str,
) -> Result<String, ProductionCreateMountActivationError> {
    let partition_collectors = snapshot
        .collectors
        .iter()
        .filter(|status| status.component == "partition_tables")
        .collect::<Vec<_>>();
    if partition_collectors.len() != 1 || partition_collectors[0].state != CollectorState::Complete
    {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }

    let tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == activation.disk)
        .collect::<Vec<_>>();
    if tables.len() != 1 {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }
    let table = tables[0];
    if table.label.as_deref() != Some(expected_partition_table(activation.partition_table))
        || table.unit.as_deref() != Some("sectors")
        || table.sector_size_bytes != Some(activation.logical_sector_bytes)
        || table.partitions.len() != 1
    {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }
    let partition_geometry = &table.partitions[0];
    if partition_geometry.node != filesystem_receipt.partition_device
        || partition_geometry.start_sector != activation.partition_start_sector
        || partition_geometry.size_sectors != activation.partition_sector_count
    {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }

    let mut nodes = Vec::new();
    flatten(&snapshot.storage.block_devices, &mut nodes);

    let disks = nodes
        .iter()
        .copied()
        .filter(|device| device.path.as_deref() == Some(activation.disk.as_str()))
        .collect::<Vec<_>>();
    let partitions = nodes
        .iter()
        .copied()
        .filter(|device| {
            device.path.as_deref() == Some(filesystem_receipt.partition_device.as_str())
        })
        .collect::<Vec<_>>();

    if disks.len() != 1 || partitions.len() != 1 {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }
    let disk = disks[0];
    let partition = partitions[0];
    if !matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
        || disk.size_bytes != activation.disk_size_bytes
        || disk.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || disk.model != activation.disk_model
        || disk.serial != activation.disk_serial
        || partition.kind != NodeKind::Partition
        || partition.size_bytes != activation.partition_size_bytes
        || partition.logical_sector_bytes != Some(activation.logical_sector_bytes)
        || partition.parent_kernel_name != disk.kernel_name
        || partition
            .filesystem
            .as_ref()
            .is_none_or(|filesystem| filesystem.fs_type != activation.filesystem)
        || !partition.mountpoints.is_empty()
    {
        return Err(ProductionCreateMountActivationError::FilesystemBindingMismatch);
    }

    let uuid = partition
        .uuid
        .as_deref()
        .filter(|value| canonical_filesystem_uuid(value))
        .ok_or(ProductionCreateMountActivationError::FilesystemUuidInvalid)?;

    let uuid_source = format!("UUID={uuid}");
    if snapshot.mounts.iter().any(|entry| {
        entry.target == mountpoint
            || entry.source.as_deref() == Some(filesystem_receipt.partition_device.as_str())
            || entry
                .source
                .as_deref()
                .is_some_and(|source| source.eq_ignore_ascii_case(&uuid_source))
    }) || snapshot.swaps.iter().any(|entry| {
        entry.name == filesystem_receipt.partition_device
            || entry.name.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountActivationError::RuntimeConflict);
    }

    if snapshot.fstab.iter().any(|entry| {
        entry.target == mountpoint
            || entry.source == filesystem_receipt.partition_device
            || entry.source.eq_ignore_ascii_case(&uuid_source)
    }) {
        return Err(ProductionCreateMountActivationError::FstabConflict);
    }

    Ok(uuid.to_owned())
}

/// Seal the first post-format mount/persistence contract without executing it.
///
/// M2A12 accepts only an exact completed M2A11 filesystem, rebinds a fresh UUID
/// from the same partition, and freezes an existing empty root-owned mountpoint.
/// No directory is created, no mount process is spawned and /etc/fstab is not
/// changed by this layer.
pub fn seal_production_create_mount_activation_intent(
    activation: &ProductionCreateActivationIntent,
    filesystem_receipt: &ProductionCreateFilesystemExecutionReceipt,
    journal: &ProductionCreateRuntimeJournal,
    snapshot: &HostSnapshot,
    mountpoint: &str,
    persist_to_fstab: bool,
) -> Result<ProductionCreateMountActivationIntent, ProductionCreateMountActivationError> {
    if !PRODUCTION_CREATE_MOUNT_ACTIVATION_COMPILED {
        return Err(ProductionCreateMountActivationError::FeatureDisabled);
    }

    verify_completed_chain(activation, filesystem_receipt, journal)?;
    let filesystem_uuid =
        fresh_filesystem_uuid(activation, filesystem_receipt, snapshot, mountpoint)?;
    let mountpoint_metadata = inspect_safe_empty_mountpoint(mountpoint, 0)?;
    let fstab_source = format!("UUID={filesystem_uuid}");
    let fstab_pass = if activation.filesystem == "ext4" {
        2
    } else {
        0
    };

    let mut intent = ProductionCreateMountActivationIntent {
        schema_version: 1,
        mount_activation_id: String::new(),
        create_activation_id: activation.activation_id.clone(),
        filesystem_receipt_id: filesystem_receipt.receipt_id.clone(),
        journal_id: journal.journal_id.clone(),
        launch_id: filesystem_receipt.launch_id.clone(),
        disk: activation.disk.clone(),
        partition_device: filesystem_receipt.partition_device.clone(),
        filesystem: activation.filesystem.clone(),
        filesystem_uuid,
        mountpoint: mountpoint.to_owned(),
        mountpoint_device_id: mountpoint_metadata.dev(),
        mountpoint_inode: mountpoint_metadata.ino(),
        mountpoint_uid: mountpoint_metadata.uid(),
        mountpoint_mode: mountpoint_metadata.mode(),
        fstab_source,
        fstab_options: DEFAULT_FSTAB_OPTIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        fstab_dump: 0,
        fstab_pass,
        persist_to_fstab,
        compile_feature_enabled: true,
        execution_enabled: false,
        mount_performed: false,
        fstab_changed: false,
    };
    intent.mount_activation_id = intent.expected_mount_activation_id()?;
    Ok(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_core::{Filesystem, StorageGraph};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_directory(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir().unwrap().join(format!(
            ".lsm-mount-activation-{}-{stamp}-{name}",
            std::process::id()
        ))
    }

    #[test]
    fn filesystem_uuid_profile_is_canonical() {
        assert!(canonical_filesystem_uuid(
            "123e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(!canonical_filesystem_uuid("not-a-filesystem-uuid"));
    }

    #[test]
    fn empty_nonwritable_directory_can_be_frozen_by_identity() {
        let path = temp_directory("empty");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        let metadata =
            inspect_safe_empty_mountpoint(path.to_str().unwrap(), unsafe { libc::geteuid() })
                .unwrap();
        assert_eq!(metadata.ino(), fs::metadata(&path).unwrap().ino());

        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn symlink_mountpoint_is_rejected() {
        let target = temp_directory("target");
        let link = temp_directory("link");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert!(matches!(
            inspect_safe_empty_mountpoint(link.to_str().unwrap(), unsafe { libc::geteuid() }),
            Err(ProductionCreateMountActivationError::UnsafeMountpoint)
        ));

        fs::remove_file(link).unwrap();
        fs::remove_dir(target).unwrap();
    }

    #[test]
    fn fresh_filesystem_binding_rejects_an_already_mounted_partition() {
        let activation = ProductionCreateActivationIntent {
            schema_version: 1,
            activation_id: "a".repeat(64),
            profile: crate::ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
            create_intent_id: "b".repeat(64),
            create_plan_id: "c".repeat(64),
            source_id: "space-".to_owned() + &"d".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            partition_table: lsm_planner::CreatePartitionTablePolicy::Gpt,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        let receipt = ProductionCreateFilesystemExecutionReceipt {
            schema_version: 1,
            receipt_id: "e".repeat(64),
            journal_id: "f".repeat(64),
            launch_id: "1".repeat(64),
            partition_receipt_id: "2".repeat(64),
            disk: activation.disk.clone(),
            partition_device: "/dev/loop7p1".into(),
            filesystem: "ext4".into(),
            partition_mapped_verified: true,
            filesystem_formatted: true,
            journal_completed: true,
        };
        let disk = BlockDevice {
            name: "loop7".into(),
            kernel_name: Some("loop7".into()),
            path: Some("/dev/loop7".into()),
            kind: NodeKind::Loop,
            size_bytes: activation.disk_size_bytes,
            start_512_sector: None,
            logical_sector_bytes: Some(512),
            filesystem: None,
            mountpoints: vec![],
            parent_kernel_name: None,
            model: activation.disk_model.clone(),
            serial: activation.disk_serial.clone(),
            uuid: None,
            partition_uuid: None,
            partition_table: Some("gpt".into()),
            children: vec![BlockDevice {
                name: "loop7p1".into(),
                kernel_name: Some("loop7p1".into()),
                path: Some("/dev/loop7p1".into()),
                kind: NodeKind::Partition,
                size_bytes: activation.partition_size_bytes,
                start_512_sector: Some(activation.partition_start_sector),
                logical_sector_bytes: Some(512),
                filesystem: Some(Filesystem {
                    fs_type: "ext4".into(),
                    version: None,
                }),
                mountpoints: vec!["/mnt/data".into()],
                parent_kernel_name: Some("loop7".into()),
                model: None,
                serial: None,
                uuid: Some("123e4567-e89b-12d3-a456-426614174000".into()),
                partition_uuid: None,
                partition_table: None,
                children: vec![],
            }],
        };
        let snapshot = HostSnapshot {
            storage: StorageGraph {
                block_devices: vec![disk],
            },
            partition_tables: vec![],
            mounts: vec![],
            fstab: vec![],
            swaps: vec![],
            lvm: None,
            filesystem_preflight: vec![],
            diagnostics: vec![],
            collectors: vec![],
        };

        assert!(matches!(
            fresh_filesystem_uuid(&activation, &receipt, &snapshot, "/mnt/data"),
            Err(ProductionCreateMountActivationError::FilesystemBindingMismatch)
        ));
    }

    #[test]
    fn mount_activation_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_CREATE_MOUNT_ACTIVATION_COMPILED,
            cfg!(feature = "production-create-mount-activation")
        );
    }
}
