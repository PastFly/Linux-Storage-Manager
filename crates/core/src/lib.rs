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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCapabilities {
    pub tools: Vec<ToolCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    pub available: bool,
}
