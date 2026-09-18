use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageGraph {
    pub block_devices: Vec<BlockDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    pub name: String,
    pub kernel_name: Option<String>,
    pub path: Option<String>,
    pub kind: NodeKind,
    pub size_bytes: u64,
    pub start_512_sector: Option<u64>,
    pub logical_sector_bytes: Option<u64>,
    pub filesystem: Option<Filesystem>,
    pub mountpoints: Vec<String>,
    pub parent_kernel_name: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub uuid: Option<String>,
    pub partition_uuid: Option<String>,
    pub partition_table: Option<String>,
    pub children: Vec<BlockDevice>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Disk,
    Partition,
    Lvm,
    Crypt,
    Raid,
    Multipath,
    Loop,
    Rom,
    Zram,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filesystem {
    pub fs_type: String,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemProbeState {
    Verified,
    Partial,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPreflightEvidence {
    pub device: String,
    pub mountpoint: Option<String>,
    pub fs_type: String,
    pub fs_version: Option<String>,
    pub state: FilesystemProbeState,
    pub filesystem_state: Option<String>,
    pub revision: Option<String>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub block_size_bytes: Option<u64>,
    #[serde(default)]
    pub block_count: Option<u64>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    pub grow_check_passed: Option<bool>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub tools: Vec<ToolCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountEntry {
    pub source: Option<String>,
    pub target: String,
    pub fs_type: Option<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FstabEntry {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: Vec<String>,
    pub dump: u32,
    pub pass: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapEntry {
    pub name: String,
    pub kind: String,
    pub size_bytes: u64,
    pub used_bytes: u64,
    pub priority: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LvmInventory {
    pub physical_volumes: Vec<LvmPhysicalVolume>,
    pub volume_groups: Vec<LvmVolumeGroup>,
    pub logical_volumes: Vec<LvmLogicalVolume>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LvmPhysicalVolume {
    pub name: String,
    pub uuid: Option<String>,
    pub vg_name: Option<String>,
    pub size_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LvmVolumeGroup {
    pub name: String,
    pub uuid: Option<String>,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub pv_count: u64,
    pub lv_count: u64,
    #[serde(default)]
    pub extent_size_bytes: Option<u64>,
    #[serde(default)]
    pub free_extent_count: Option<u64>,
    #[serde(default)]
    pub missing_pv_count: Option<u64>,
    #[serde(default)]
    pub attributes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LvmLogicalVolume {
    pub name: String,
    pub path: Option<String>,
    pub uuid: Option<String>,
    pub vg_name: String,
    pub size_bytes: u64,
    pub attributes: Option<String>,
    #[serde(default)]
    pub layout: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionTable {
    pub device: String,
    pub label: Option<String>,
    pub id: Option<String>,
    pub unit: Option<String>,
    pub first_lba: Option<u64>,
    pub last_lba: Option<u64>,
    pub sector_size_bytes: Option<u64>,
    pub partitions: Vec<PartitionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionRecord {
    pub node: String,
    pub start_sector: u64,
    pub size_sectors: u64,
    pub partition_type: Option<String>,
    pub uuid: Option<String>,
    pub name: Option<String>,
    pub attrs: Option<String>,
    pub bootable: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub device: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorState {
    Complete,
    Unavailable,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorStatus {
    pub component: String,
    pub state: CollectorState,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub storage: StorageGraph,
    pub partition_tables: Vec<PartitionTable>,
    pub mounts: Vec<MountEntry>,
    pub fstab: Vec<FstabEntry>,
    pub swaps: Vec<SwapEntry>,
    pub lvm: Option<LvmInventory>,
    #[serde(default)]
    pub filesystem_preflight: Vec<FilesystemPreflightEvidence>,
    pub diagnostics: Vec<StorageDiagnostic>,
    pub collectors: Vec<CollectorStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendabilityStatus {
    Ready,
    NeedsUnderlyingResize,
    NeedsUnderlyingCapacity,
    NeedsGeometry,
    RequiresMount,
    UnsupportedFilesystem,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendAnalysis {
    pub target: String,
    pub device: Option<String>,
    pub filesystem: Option<String>,
    pub current_size_bytes: Option<u64>,
    pub immediate_growth_bytes: Option<u64>,
    pub potential_underlying_growth_bytes: Option<u64>,
    pub status: ExtendabilityStatus,
    pub reasons: Vec<String>,
    pub steps: Vec<String>,
}
