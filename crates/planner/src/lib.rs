//! Read-only, in-memory plan previews. No process, filesystem or device I/O.
//! A preview is NOT an executable plan or authorization to modify storage.

mod execution_guard;
mod execution_handoff;
mod filesystem_policy;
mod identity_guard;
mod route_graph;

pub use route_graph::{
    analyze_layer_route, LayerRoute, LayerRouteStatus, RouteIssue, RouteIssueKind, RouteLayer,
    RouteLayerKind,
};

pub use identity_guard::{
    capture_target_identity, revalidate_target_identity, DeviceIdentity, FilesystemIdentity,
    IdentityChange, IdentityGuardError, IdentityRevalidation, LvmIdentity, LvmIdentityKind,
    MountIdentity, PartitionGeometryIdentity, TargetIdentityManifest,
};

pub use execution_guard::{
    build_execution_guard_plan, build_execution_start_binding, ExactApprovalBinding,
    ExecutionGuardError, ExecutionGuardPlan, ExecutionStartBinding, ExecutionStartBindingError,
    GuardGate, GuardGateKind, GuardPlanStatus, JournalError, JournalEvent, JournalPhase,
    JournalTransition, LockScope, OperationJournal, OperationLockPlan, ResumeDisposition,
    VerifiedMutationBoundaryBinding, HOST_STORAGE_LOCK_PATH, JOURNAL_DIRECTORY,
};

pub use execution_handoff::{
    build_frozen_execution_handoff, ExecutionHandoffError, ExecutionHandoffStatus,
    FrozenExecutionHandoff,
};

pub use filesystem_policy::{
    decide_filesystem_growth, FilesystemCheckKind, FilesystemDecisionState,
    FilesystemGrowthDecision, ReadOnlyFilesystemCheck,
};

use lsm_core::{
    BlockDevice, CollectorState, DiagnosticSeverity, FilesystemProbeState, HostCapabilities,
    HostSnapshot, LvmLogicalVolume, NodeKind, PartitionTable,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Growth {
    ByBytes(u64),
    MaxFree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendRequest {
    pub target: String,
    pub growth: Growth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    Preview,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightState {
    Verified,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreflightCheck {
    pub code: String,
    pub state: PreflightState,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    NotApplicable,
    Reversible,
    Irreversible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum Operation {
    RevalidateSnapshot,
    BackupLvmMetadata {
        vg_uuid: String,
    },
    BackupPartitionTableMetadata {
        disk: String,
        table_label: String,
        table_id: Option<String>,
    },
    ExtendPartition {
        partition: String,
        start_sector: u64,
        old_size_sectors: u64,
        new_size_sectors: u64,
        sector_size_bytes: u64,
    },
    ResizePhysicalVolume {
        pv_uuid: String,
        expected_pv_size_bytes: u64,
    },
    ExtendLogicalVolume {
        lv_uuid: String,
        additional_extents: u64,
        expected_lv_size_bytes: u64,
    },
    GrowFilesystem {
        fs_type: String,
        mountpoint: String,
    },
    RediscoverAndVerify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    pub id: u32,
    pub depends_on: Vec<u32>,
    pub operation: Operation,
    pub reversibility: Reversibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SizeChange {
    pub device: String,
    pub current_lv_size_bytes: u64,
    pub requested_growth_bytes: u64,
    pub rounded_growth_bytes: u64,
    pub expected_lv_size_bytes: u64,
    pub extent_size_bytes: u64,
    pub remaining_vg_free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PartitionSizeChange {
    pub device: String,
    pub disk: String,
    pub current_partition_size_bytes: u64,
    pub requested_growth_bytes: u64,
    pub rounded_growth_bytes: u64,
    pub expected_partition_size_bytes: u64,
    pub sector_size_bytes: u64,
    pub remaining_adjacent_free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesystemSizeChange {
    pub device: String,
    pub mountpoint: String,
    pub fs_type: String,
    pub current_filesystem_size_bytes: u64,
    pub backing_device_size_bytes: u64,
    pub requested_growth_bytes: u64,
    pub rounded_growth_bytes: u64,
    pub expected_filesystem_size_bytes: u64,
    pub filesystem_block_size_bytes: u64,
    pub remaining_backing_free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayoutOpportunity {
    pub code: String,
    pub disk: String,
    pub target: String,
    pub sector_size_bytes: u64,
    pub max_target_growth_bytes: u64,
    pub disk_tail_free_bytes: u64,
    pub swap_bytes: u64,
    pub blocking_devices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayoutAlternative {
    pub code: String,
    pub summary: String,
    pub disk: String,
    pub target: String,
    pub requested_growth_bytes: u64,
    pub disk_tail_free_bytes: u64,
    pub swap_bytes: u64,
    pub required_partition_growth_bytes: u64,
    pub remaining_raw_tail_bytes: u64,
    pub blocking_devices: Vec<String>,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrowthRouteAlternative {
    pub code: String,
    pub summary: String,
    pub target: String,
    pub disk: String,
    pub partition: Option<String>,
    pub physical_volume: String,
    pub volume_group: String,
    pub logical_volume: String,
    pub extent_size_bytes: u64,
    pub sector_size_bytes: u64,
    pub existing_vg_free_bytes: u64,
    pub pv_device_slack_bytes: u64,
    pub adjacent_partition_free_bytes: u64,
    pub max_growth_bytes: u64,
    pub requested_growth_bytes: u64,
    pub required_partition_growth_bytes: u64,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendTargetKind {
    DirectPartition,
    LvmLogicalVolume,
    WholeBlockFilesystem,
    LayeredOrOther,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendPlannerProfile {
    DirectPartition,
    Lvm,
    WholeBlockFilesystem,
    LegacyFailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendRouteAdapter {
    pub profile: ExtendPlannerProfile,
    pub resolved_device: Option<String>,
    pub mountpoint: Option<String>,
    pub status: LayerRouteStatus,
    pub issue_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendTargetAvailability {
    PreviewReady,
    Advisory,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtendTarget {
    pub target: String,
    pub device: String,
    pub mountpoint: Option<String>,
    pub filesystem: String,
    pub kind: ExtendTargetKind,
    pub current_block_size_bytes: u64,
    pub verified_growth_bytes: Option<u64>,
    pub layout_growth_bytes: Option<u64>,
    pub availability: ExtendTargetAvailability,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningSpaceKind {
    BlankDisk,
    DiskGap,
    DiskTail,
    LvmFreeExtents,
    BlockedDisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisioningOpportunity {
    pub id: String,
    pub code: String,
    pub kind: ProvisioningSpaceKind,
    pub source: String,
    pub disk: Option<String>,
    pub volume_group: Option<String>,
    pub available_bytes: u64,
    pub sector_size_bytes: Option<u64>,
    pub start_sector: Option<u64>,
    pub sector_count: Option<u64>,
    pub advisory_only: bool,
    pub future_actions: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatePurpose {
    Filesystem,
    Swap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatePartitionTablePolicy {
    Gpt,
    Dos,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateRequest {
    pub source_id: String,
    pub size: Growth,
    pub purpose: CreatePurpose,
    pub filesystem: Option<String>,
    pub mountpoint: Option<String>,
    pub partition_table: Option<CreatePartitionTablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateAllocation {
    pub requested_bytes: u64,
    pub rounded_bytes: u64,
    pub available_bytes: u64,
    pub remaining_bytes: u64,
    pub allocation_unit_bytes: u64,
    pub start_sector: Option<u64>,
    pub sector_count: Option<u64>,
    pub volume_group: Option<String>,
    pub partition_table: Option<CreatePartitionTablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateSourceAdapter {
    pub source_id: String,
    pub kind: ProvisioningSpaceKind,
    pub disk: Option<String>,
    pub volume_group: Option<String>,
    pub allocation_unit_bytes: u64,
    pub available_bytes: u64,
    pub start_sector: Option<u64>,
    pub sector_count: Option<u64>,
    pub partition_table: Option<CreatePartitionTablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatePlanPreview {
    schema_version: u32,
    plan_id: String,
    dry_run: bool,
    executable: bool,
    status: PlanStatus,
    request: CreateRequest,
    source: Option<ProvisioningOpportunity>,
    allocation: Option<CreateAllocation>,
    blockers: Vec<Blocker>,
    steps: Vec<String>,
    notices: Vec<String>,
}

const CREATE_PARTITION_ALIGNMENT_BYTES: u64 = 1024 * 1024;
const GPT_PARTITION_ENTRY_COUNT: u64 = 128;
const GPT_PARTITION_ENTRY_SIZE_BYTES: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlankDiskGeometry {
    sector_size_bytes: u64,
    start_sector: u64,
    available_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PartitionFreeRange {
    start_sector: u64,
    sector_count: u64,
    is_tail: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PartitionFreeSpace {
    ranges: Vec<PartitionFreeRange>,
    sector_size_bytes: u64,
}

// Private fields, no setters and deliberately no Deserialize implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanPreview {
    schema_version: u32,
    plan_id: String,
    snapshot_digest: String,
    dry_run: bool,
    executable: bool,
    status: PlanStatus,
    request: ExtendRequest,
    size_change: Option<SizeChange>,
    partition_size_change: Option<PartitionSizeChange>,
    filesystem_size_change: Option<FilesystemSizeChange>,
    layout_alternatives: Vec<LayoutAlternative>,
    growth_route_alternatives: Vec<GrowthRouteAlternative>,
    blockers: Vec<Blocker>,
    preflight_checks: Vec<PreflightCheck>,
    steps: Vec<PlanStep>,
    notices: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PlannerError {
    #[error("could not serialize planner input: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("size must be a positive whole number followed by B, KiB, MiB, GiB or TiB")]
    InvalidSize,
    #[error("size is outside the supported u64 byte range")]
    SizeOverflow,
}

impl CreatePlanPreview {
    pub fn status(&self) -> PlanStatus {
        self.status
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn source(&self) -> Option<&ProvisioningOpportunity> {
        self.source.as_ref()
    }

    pub fn allocation(&self) -> Option<&CreateAllocation> {
        self.allocation.as_ref()
    }

    pub fn blockers(&self) -> &[Blocker] {
        &self.blockers
    }

    pub fn steps(&self) -> &[String] {
        &self.steps
    }

    pub fn render_text(&self) -> String {
        let mut text = format!(
            "DRY RUN ONLY - no commands executed; not an execution authorization\nPlan: {}\nStatus: {:?}\nSource ID: {}\nPurpose: {:?}\n",
            self.plan_id, self.status, self.request.source_id, self.request.purpose
        );
        if let Some(source) = &self.source {
            text.push_str(&format!(
                "Source: {} ({:?})\nAvailable: {} bytes\n",
                source.source, source.kind, source.available_bytes
            ));
        }
        if let Some(allocation) = &self.allocation {
            text.push_str(&format!(
                "Requested: {} bytes\nAllocated: {} bytes\nAvailable under selected policy: {} bytes\nRemaining: {} bytes\nAllocation unit: {} bytes\n",
                allocation.requested_bytes,
                allocation.rounded_bytes,
                allocation.available_bytes,
                allocation.remaining_bytes,
                allocation.allocation_unit_bytes
            ));
            if let Some(policy) = allocation.partition_table {
                text.push_str(&format!("Partition table: {policy:?}\n"));
            }
            if let Some(start_sector) = allocation.start_sector {
                text.push_str(&format!("Start sector: {start_sector}\n"));
            }
            if let Some(sector_count) = allocation.sector_count {
                text.push_str(&format!("Sector count: {sector_count}\n"));
            }
        }
        for blocker in &self.blockers {
            text.push_str(&format!(
                "BLOCKED [{}]: {}\n",
                blocker.code, blocker.message
            ));
        }
        for (index, step) in self.steps.iter().enumerate() {
            text.push_str(&format!("{}. {}\n", index + 1, step));
        }
        for notice in &self.notices {
            text.push_str(&format!("Note: {notice}\n"));
        }
        text
    }
}

impl PlanPreview {
    pub fn status(&self) -> PlanStatus {
        self.status
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    pub fn blockers(&self) -> &[Blocker] {
        &self.blockers
    }

    pub fn preflight_checks(&self) -> &[PreflightCheck] {
        &self.preflight_checks
    }

    pub fn size_change(&self) -> Option<&SizeChange> {
        self.size_change.as_ref()
    }

    pub fn partition_size_change(&self) -> Option<&PartitionSizeChange> {
        self.partition_size_change.as_ref()
    }

    pub fn filesystem_size_change(&self) -> Option<&FilesystemSizeChange> {
        self.filesystem_size_change.as_ref()
    }

    pub fn layout_alternatives(&self) -> &[LayoutAlternative] {
        &self.layout_alternatives
    }

    pub fn growth_route_alternatives(&self) -> &[GrowthRouteAlternative] {
        &self.growth_route_alternatives
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn target(&self) -> &str {
        &self.request.target
    }

    pub fn basis_digest(&self) -> &str {
        &self.snapshot_digest
    }

    /// Exact-input freshness check only. Does not validate runtime safety or authorize writes.
    /// Any array ordering or usage change can conservatively invalidate this preview.
    pub fn matches_basis(
        &self,
        snapshot: &HostSnapshot,
        capabilities: &HostCapabilities,
    ) -> Result<bool, PlannerError> {
        Ok(self.status == PlanStatus::Preview
            && self.snapshot_digest == fingerprint(&(snapshot, capabilities))?)
    }

    pub fn render_text(&self) -> String {
        let mut text = format!(
            "DRY RUN ONLY - no commands executed; not an execution authorization\n\
             Plan: {}\nStatus: {:?}\nTarget: {:?}\n",
            self.plan_id, self.status, self.request.target
        );
        if let Some(size) = &self.size_change {
            text.push_str(&format!(
                "LV size: {} -> {} bytes\nRequested growth: {} bytes\n\
                 Extent-aligned growth: {} bytes\nVG free after preview: {} bytes\n",
                size.current_lv_size_bytes,
                size.expected_lv_size_bytes,
                size.requested_growth_bytes,
                size.rounded_growth_bytes,
                size.remaining_vg_free_bytes
            ));
        }
        if let Some(size) = &self.partition_size_change {
            text.push_str(&format!(
                "Partition size: {} -> {} bytes\nRequested growth: {} bytes\n\
                 Sector-aligned growth: {} bytes\nAdjacent free after preview: {} bytes\n",
                size.current_partition_size_bytes,
                size.expected_partition_size_bytes,
                size.requested_growth_bytes,
                size.rounded_growth_bytes,
                size.remaining_adjacent_free_bytes
            ));
        }
        if let Some(size) = &self.filesystem_size_change {
            text.push_str(&format!(
                "Filesystem size: {} -> {} bytes\nBacking device: {} bytes\nRequested growth: {} bytes\n\
                 Filesystem-block-aligned growth: {} bytes\nBacking free after preview: {} bytes\n",
                size.current_filesystem_size_bytes,
                size.expected_filesystem_size_bytes,
                size.backing_device_size_bytes,
                size.requested_growth_bytes,
                size.rounded_growth_bytes,
                size.remaining_backing_free_bytes
            ));
        }
        for alternative in &self.layout_alternatives {
            text.push_str(&format!(
                "Layout alternative [{}]: {}\nDisk tail free: {} bytes\nSwap to migrate: {} bytes\n",
                alternative.code,
                alternative.summary,
                alternative.disk_tail_free_bytes,
                alternative.swap_bytes
            ));
            for step in &alternative.steps {
                text.push_str(&format!("  Alternative step: {step}\n"));
            }
        }
        for route in &self.growth_route_alternatives {
            text.push_str(&format!(
                "Growth route [{}]: {}\nMax growth: {} bytes\nUnderlying partition growth: {} bytes\n",
                route.code,
                route.summary,
                route.max_growth_bytes,
                route.required_partition_growth_bytes
            ));
            for step in &route.steps {
                text.push_str(&format!("  Route step: {step}\n"));
            }
        }
        for blocker in &self.blockers {
            text.push_str(&format!(
                "BLOCKED [{}]: {}\n",
                blocker.code, blocker.message
            ));
        }
        for check in &self.preflight_checks {
            text.push_str(&format!(
                "Preflight {:?} [{}]: {}\n",
                check.state, check.code, check.message
            ));
        }
        for step in &self.steps {
            // Debug formatting escapes control characters in externally supplied strings.
            text.push_str(&format!(
                "{}. {:?} [reversibility: {:?}]\n",
                step.id, step.operation, step.reversibility
            ));
        }
        for notice in &self.notices {
            text.push_str(&format!("Note: {notice}\n"));
        }
        text
    }
}

/// Exact, overflow-checked binary units; no floats, signs, exponents or implicit units.
pub fn parse_growth_size(input: &str) -> Result<u64, PlannerError> {
    let split = input.bytes().take_while(u8::is_ascii_digit).count();
    let (digits, unit) = input.split_at(split);
    if digits.is_empty() {
        return Err(PlannerError::InvalidSize);
    }
    let factor = match unit {
        "B" => 1,
        "KiB" => 1_u64 << 10,
        "MiB" => 1_u64 << 20,
        "GiB" => 1_u64 << 30,
        "TiB" => 1_u64 << 40,
        _ => return Err(PlannerError::InvalidSize),
    };
    let bytes = digits
        .parse::<u64>()
        .map_err(|_| PlannerError::SizeOverflow)?
        .checked_mul(factor)
        .ok_or(PlannerError::SizeOverflow)?;
    if bytes == 0 {
        return Err(PlannerError::InvalidSize);
    }
    Ok(bytes)
}

pub fn list_extend_targets(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
) -> Vec<ExtendTarget> {
    let mut targets = Vec::new();

    for device in flatten(&snapshot.storage.block_devices) {
        let Some(filesystem) = device.filesystem.as_ref() else {
            continue;
        };
        if matches!(filesystem.fs_type.as_str(), "swap" | "LVM2_member")
            || device
                .mountpoints
                .iter()
                .any(|mount| mount.as_str() == "[SWAP]")
            || !device.children.is_empty()
        {
            continue;
        }

        let device_path = device.path.clone().unwrap_or_else(|| device.name.clone());
        let mountpoint = device
            .mountpoints
            .iter()
            .find(|mount| mount.as_str() != "[SWAP]")
            .cloned();
        let target = mountpoint.clone().unwrap_or_else(|| device_path.clone());

        let preview = plan_extend(
            snapshot,
            capabilities,
            ExtendRequest {
                target: target.clone(),
                growth: Growth::MaxFree,
            },
        );

        let verified_growth_bytes = preview.as_ref().ok().and_then(|plan| {
            plan.size_change()
                .map(|change| change.rounded_growth_bytes)
                .or_else(|| {
                    plan.partition_size_change()
                        .map(|change| change.rounded_growth_bytes)
                })
                .or_else(|| {
                    plan.filesystem_size_change()
                        .map(|change| change.rounded_growth_bytes)
                })
        });
        let layout_growth_bytes = [
            analyze_layout_opportunity(snapshot, &target)
                .map(|opportunity| opportunity.max_target_growth_bytes),
            analyze_lvm_underlying_growth(
                snapshot,
                &ExtendRequest {
                    target: target.clone(),
                    growth: Growth::MaxFree,
                },
            )
            .map(|route| route.max_growth_bytes),
        ]
        .into_iter()
        .flatten()
        .max();

        let (availability, reason) = match &preview {
            Ok(plan) if plan.status() == PlanStatus::Preview => {
                let reason = if layout_growth_bytes
                    .is_some_and(|bytes| bytes > verified_growth_bytes.unwrap_or(0))
                {
                    "verified growth is available; additional underlying capacity was also detected"
                        .to_owned()
                } else {
                    "verified read-only growth preview is available".to_owned()
                };
                (ExtendTargetAvailability::PreviewReady, reason)
            }
            Ok(plan) if layout_growth_bytes.is_some_and(|bytes| bytes > 0) => (
                ExtendTargetAvailability::Advisory,
                plan.blockers()
                    .first()
                    .map(|blocker| {
                        format!(
                            "{}; a non-executable underlying-capacity route is available",
                            blocker.message
                        )
                    })
                    .unwrap_or_else(|| {
                        "a non-executable underlying-capacity route is available".to_owned()
                    }),
            ),
            Ok(plan) => (
                ExtendTargetAvailability::Blocked,
                plan.blockers()
                    .first()
                    .map(|blocker| blocker.message.clone())
                    .unwrap_or_else(|| "no verified growth path is currently available".to_owned()),
            ),
            Err(error) => (
                ExtendTargetAvailability::Blocked,
                format!("planner error: {error}"),
            ),
        };

        let kind = match resolve_extend_route_adapter(snapshot, &target).profile {
            ExtendPlannerProfile::DirectPartition => ExtendTargetKind::DirectPartition,
            ExtendPlannerProfile::Lvm => ExtendTargetKind::LvmLogicalVolume,
            ExtendPlannerProfile::WholeBlockFilesystem => ExtendTargetKind::WholeBlockFilesystem,
            ExtendPlannerProfile::LegacyFailClosed => ExtendTargetKind::LayeredOrOther,
        };

        targets.push(ExtendTarget {
            target,
            device: device_path,
            mountpoint,
            filesystem: filesystem.fs_type.clone(),
            kind,
            current_block_size_bytes: device.size_bytes,
            verified_growth_bytes,
            layout_growth_bytes,
            availability,
            reason,
        });
    }

    targets.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.device.cmp(&right.device))
    });
    targets
}

fn provisioning_opportunity_id(
    kind: ProvisioningSpaceKind,
    source: &str,
    disk: Option<&str>,
    volume_group: Option<&str>,
    start_sector: Option<u64>,
    sector_count: Option<u64>,
) -> String {
    let material = format!(
        "{kind:?}|{source}|{}|{}|{}|{}",
        disk.unwrap_or("-"),
        volume_group.unwrap_or("-"),
        start_sector
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_owned()),
        sector_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_owned())
    );
    format!("space-{:x}", Sha256::digest(material.as_bytes()))
}

fn blocked_disk_opportunity(
    disk: &BlockDevice,
    disk_path: &str,
    code: &str,
    reason: &str,
) -> ProvisioningOpportunity {
    ProvisioningOpportunity {
        id: provisioning_opportunity_id(
            ProvisioningSpaceKind::BlockedDisk,
            disk_path,
            Some(disk_path),
            None,
            None,
            None,
        ),
        code: code.to_owned(),
        kind: ProvisioningSpaceKind::BlockedDisk,
        source: disk_path.to_owned(),
        disk: Some(disk_path.to_owned()),
        volume_group: None,
        available_bytes: 0,
        sector_size_bytes: disk.logical_sector_bytes,
        start_sector: None,
        sector_count: None,
        advisory_only: true,
        future_actions: vec![
            "inspect and reconcile the partition table with recovery-capable tooling".to_owned(),
            "rediscover storage and require authoritative geometry before provisioning".to_owned(),
        ],
        blockers: vec![reason.to_owned()],
    }
}

pub fn list_provisioning_opportunities(snapshot: &HostSnapshot) -> Vec<ProvisioningOpportunity> {
    let mut opportunities = Vec::new();

    if let Some(lvm) = snapshot.lvm.as_ref() {
        for vg in &lvm.volume_groups {
            if vg.free_bytes == 0 {
                continue;
            }
            opportunities.push(ProvisioningOpportunity {
                id: provisioning_opportunity_id(
                    ProvisioningSpaceKind::LvmFreeExtents,
                    &format!("VG {}", vg.name),
                    None,
                    Some(&vg.name),
                    None,
                    None,
                ),
                code: "lvm-vg-free".to_owned(),
                kind: ProvisioningSpaceKind::LvmFreeExtents,
                source: format!("VG {}", vg.name),
                disk: None,
                volume_group: Some(vg.name.clone()),
                available_bytes: vg.free_bytes,
                sector_size_bytes: None,
                start_sector: None,
                sector_count: None,
                advisory_only: true,
                future_actions: vec![
                    "create a new logical volume".to_owned(),
                    "format it with a supported filesystem".to_owned(),
                    "mount it and optionally persist the mount".to_owned(),
                ],
                blockers: vec![
                    "storage-mutating Create executor is not implemented in M1A".to_owned()
                ],
            });
        }
    }

    let partition_tables_complete = snapshot
        .collectors
        .iter()
        .filter(|status| status.component == "partition_tables")
        .collect::<Vec<_>>();
    let partition_tables_complete = partition_tables_complete.len() == 1
        && partition_tables_complete[0].state == CollectorState::Complete;

    for disk in flatten(&snapshot.storage.block_devices)
        .into_iter()
        .filter(|device| matches!(device.kind, NodeKind::Disk | NodeKind::Loop))
    {
        let Some(disk_path) = disk.path.as_ref() else {
            continue;
        };

        let matching_tables: Vec<_> = snapshot
            .partition_tables
            .iter()
            .filter(|table| table.device == *disk_path)
            .collect();

        if matching_tables.is_empty()
            && disk.children.is_empty()
            && disk.filesystem.is_none()
            && disk.partition_table.is_none()
        {
            let mut blockers =
                vec!["storage-mutating Create executor is not implemented in M1A".to_owned()];
            if !partition_tables_complete {
                blockers.push(
                    "authoritative partition-table discovery must complete before creation"
                        .to_owned(),
                );
            }
            opportunities.push(ProvisioningOpportunity {
                id: provisioning_opportunity_id(
                    ProvisioningSpaceKind::BlankDisk,
                    disk_path,
                    Some(disk_path),
                    None,
                    None,
                    None,
                ),
                code: "blank-disk".to_owned(),
                kind: ProvisioningSpaceKind::BlankDisk,
                source: disk_path.clone(),
                disk: Some(disk_path.clone()),
                volume_group: None,
                available_bytes: disk.size_bytes,
                sector_size_bytes: disk.logical_sector_bytes,
                start_sector: None,
                sector_count: None,
                advisory_only: true,
                future_actions: vec![
                    "choose GPT or DOS/MBR according to host and boot constraints".to_owned(),
                    "create a partition with validated alignment".to_owned(),
                    "optionally build LVM, then format and mount".to_owned(),
                ],
                blockers,
            });
            continue;
        }

        if !partition_tables_complete {
            if !matching_tables.is_empty() {
                opportunities.push(blocked_disk_opportunity(
                    disk,
                    disk_path,
                    "partition-table-discovery-incomplete",
                    "authoritative partition-table discovery is incomplete; provisioning geometry is not trusted",
                ));
            }
            continue;
        }

        if matching_tables.is_empty() {
            continue;
        }

        if matching_tables.len() != 1 {
            opportunities.push(blocked_disk_opportunity(
                disk,
                disk_path,
                "partition-table-evidence-ambiguous",
                "multiple authoritative partition-table records refer to the same disk",
            ));
            continue;
        }

        let table = matching_tables[0];
        let Some(free_space) = partition_free_ranges(disk, table) else {
            opportunities.push(blocked_disk_opportunity(
                disk,
                disk_path,
                "partition-table-geometry-unusable",
                "partition-table label or geometry is unsupported, incomplete or internally inconsistent; recovery/reconciliation is required before provisioning",
            ));
            continue;
        };

        for range in free_space.ranges {
            if range.sector_count == 0 {
                continue;
            }
            let Some(available_bytes) =
                range.sector_count.checked_mul(free_space.sector_size_bytes)
            else {
                continue;
            };
            let Some(end_sector) = range.start_sector.checked_add(range.sector_count) else {
                continue;
            };
            let mut blockers =
                vec!["storage-mutating Create executor is not implemented in M1A".to_owned()];
            blockers.push(
                "partition alignment, partition-number allocation and boot constraints must be revalidated before creation"
                    .to_owned(),
            );
            if table.label.as_deref() == Some("dos") {
                blockers.push(
                    "DOS/MBR primary-slot and extended/logical constraints must be revalidated before partition creation"
                        .to_owned(),
                );
            }

            let opportunity_kind = if range.is_tail {
                ProvisioningSpaceKind::DiskTail
            } else {
                ProvisioningSpaceKind::DiskGap
            };
            let opportunity_source = if range.is_tail {
                format!("{disk_path} tail")
            } else {
                format!(
                    "{disk_path} free sectors {}..{}",
                    range.start_sector,
                    end_sector.saturating_sub(1)
                )
            };

            opportunities.push(ProvisioningOpportunity {
                id: provisioning_opportunity_id(
                    opportunity_kind,
                    &opportunity_source,
                    Some(disk_path),
                    None,
                    Some(range.start_sector),
                    Some(range.sector_count),
                ),
                code: if range.is_tail {
                    "disk-tail".to_owned()
                } else {
                    "disk-gap".to_owned()
                },
                kind: opportunity_kind,
                source: opportunity_source,
                disk: Some(disk_path.clone()),
                volume_group: None,
                available_bytes,
                sector_size_bytes: Some(free_space.sector_size_bytes),
                start_sector: Some(range.start_sector),
                sector_count: Some(range.sector_count),
                advisory_only: true,
                future_actions: vec![
                    "create a new partition inside this verified free range".to_owned(),
                    "optionally initialize it as an LVM PV and attach/create a VG".to_owned(),
                    "create a filesystem, mount it and optionally persist the mount".to_owned(),
                ],
                blockers,
            });
        }
    }

    opportunities.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.code.cmp(&right.code))
    });
    opportunities
}

fn ceil_div(value: u64, divisor: u64) -> Option<u64> {
    if divisor == 0 {
        return None;
    }
    Some(value / divisor + u64::from(value % divisor != 0))
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return None;
    }
    let remainder = value % alignment;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(alignment.checked_sub(remainder)?)
    }
}

fn blank_disk_geometry(
    snapshot: &HostSnapshot,
    source: &ProvisioningOpportunity,
    policy: CreatePartitionTablePolicy,
) -> Result<BlankDiskGeometry, Blocker> {
    let collector = unique(
        snapshot
            .collectors
            .iter()
            .filter(|status| status.component == "partition_tables"),
        "collector-incomplete",
    )?;
    ensure(
        collector.state == CollectorState::Complete,
        "collector-incomplete",
        "authoritative partition-table discovery must complete before blank-disk planning",
    )?;

    let disk_path = source.disk.as_deref().ok_or_else(|| {
        blocked(
            "blank-disk-identity-missing",
            "blank-disk source has no device path",
        )
    })?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let disk = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| device.path.as_deref() == Some(disk_path)),
        "blank-disk-not-resolved",
    )?;
    ensure(
        matches!(disk.kind, NodeKind::Disk | NodeKind::Loop)
            && disk.children.is_empty()
            && disk.filesystem.is_none()
            && disk.partition_table.is_none()
            && disk.mountpoints.is_empty(),
        "blank-disk-state-changed",
        "selected source is no longer a plain unpartitioned, unmounted disk/loop device",
    )?;
    ensure(
        snapshot
            .partition_tables
            .iter()
            .all(|table| table.device != disk_path),
        "blank-disk-table-present",
        "authoritative discovery now reports a partition table on the selected blank disk",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|swap| node_alias(disk, &swap.name)),
        "blank-disk-active-swap",
        "selected blank disk is reported as active swap",
    )?;
    ensure(
        !snapshot.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic
                    .device
                    .as_deref()
                    .is_none_or(|device| device == disk_path || node_alias(disk, device))
        }),
        "diagnostic-error",
        "an error-level diagnostic affects the selected blank disk",
    )?;

    let sector = disk.logical_sector_bytes.ok_or_else(|| {
        blocked(
            "create-sector-size-missing",
            "blank-disk logical sector size is unknown",
        )
    })?;
    ensure(
        sector >= 512
            && sector.is_power_of_two()
            && disk.size_bytes > 0
            && disk.size_bytes % sector == 0
            && source.sector_size_bytes == Some(sector)
            && source.available_bytes == disk.size_bytes,
        "blank-disk-geometry-mismatch",
        "blank-disk source and current block-device geometry do not agree",
    )?;

    let disk_sectors = disk.size_bytes / sector;
    let alignment_sectors = ceil_div(CREATE_PARTITION_ALIGNMENT_BYTES, sector)
        .ok_or_else(|| {
            blocked(
                "create-alignment-invalid",
                "could not derive partition alignment",
            )
        })?
        .max(1);

    let (raw_first_usable, usable_end_exclusive) = match policy {
        CreatePartitionTablePolicy::Gpt => {
            let entry_bytes = GPT_PARTITION_ENTRY_COUNT
                .checked_mul(GPT_PARTITION_ENTRY_SIZE_BYTES)
                .ok_or_else(|| blocked("size-overflow", "GPT entry-table size exceeds u64"))?;
            let entry_sectors = ceil_div(entry_bytes, sector).ok_or_else(|| {
                blocked(
                    "create-gpt-geometry-invalid",
                    "could not derive GPT entry-table sectors",
                )
            })?;
            let first = 2_u64
                .checked_add(entry_sectors)
                .ok_or_else(|| blocked("size-overflow", "GPT first usable sector exceeds u64"))?;
            let trailing = entry_sectors
                .checked_add(1)
                .ok_or_else(|| blocked("size-overflow", "GPT trailing metadata exceeds u64"))?;
            let end = disk_sectors.checked_sub(trailing).ok_or_else(|| {
                blocked(
                    "blank-disk-too-small",
                    "disk is too small for GPT primary/backup metadata",
                )
            })?;
            (first, end)
        }
        CreatePartitionTablePolicy::Dos => {
            let end = disk_sectors.min(u64::from(u32::MAX) + 1);
            (1, end)
        }
    };

    let start = align_up(raw_first_usable, alignment_sectors)
        .ok_or_else(|| blocked("size-overflow", "aligned partition start exceeds u64"))?;
    ensure(
        start < usable_end_exclusive,
        "blank-disk-too-small",
        "disk has no usable 1 MiB-aligned partition range after table metadata",
    )?;
    let available_sector_count = usable_end_exclusive.checked_sub(start).ok_or_else(|| {
        blocked(
            "size-overflow",
            "blank-disk usable sector range underflowed",
        )
    })?;
    let available_bytes = available_sector_count
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "blank-disk usable capacity exceeds u64"))?;
    ensure(
        available_bytes > 0,
        "blank-disk-too-small",
        "blank disk has no usable capacity after metadata and alignment",
    )?;

    Ok(BlankDiskGeometry {
        sector_size_bytes: sector,
        start_sector: start,
        available_bytes,
    })
}

pub fn resolve_create_source_adapter(
    snapshot: &HostSnapshot,
    source: &ProvisioningOpportunity,
    partition_table: Option<CreatePartitionTablePolicy>,
) -> Result<CreateSourceAdapter, Blocker> {
    if source.kind != ProvisioningSpaceKind::BlankDisk && partition_table.is_some() {
        return Err(blocked(
            "create-partition-table-unexpected",
            "partition-table policy is valid only when the selected Create source is a blank disk",
        ));
    }

    match source.kind {
        ProvisioningSpaceKind::BlockedDisk => Err(blocked(
            "create-source-unusable",
            source
                .blockers
                .first()
                .map(String::as_str)
                .unwrap_or("selected disk is blocked from provisioning until partition-table evidence is repaired"),
        )),
        ProvisioningSpaceKind::LvmFreeExtents => {
            let vg_name = source.volume_group.as_deref().ok_or_else(|| {
                blocked(
                    "create-vg-missing",
                    "the selected VG free-space source has no volume-group identity",
                )
            })?;
            let lvm = snapshot.lvm.as_ref().ok_or_else(|| {
                blocked(
                    "create-lvm-missing",
                    "LVM inventory is unavailable for the selected source",
                )
            })?;
            let mut groups = lvm.volume_groups.iter().filter(|vg| vg.name == vg_name);
            let vg = groups.next().ok_or_else(|| {
                blocked(
                    "create-vg-not-found",
                    "the selected volume group no longer exists",
                )
            })?;
            ensure(
                groups.next().is_none(),
                "create-vg-ambiguous",
                "the selected volume-group identity is ambiguous",
            )?;
            let extent = vg
                .extent_size_bytes
                .ok_or_else(|| blocked("create-extent-missing", "VG extent size is unavailable"))?;
            ensure(
                extent >= 512
                    && extent.is_power_of_two()
                    && vg.free_bytes == source.available_bytes,
                "create-capacity-mismatch",
                "VG free-space identity or extent geometry changed",
            )?;
            Ok(CreateSourceAdapter {
                source_id: source.id.clone(),
                kind: source.kind,
                disk: None,
                volume_group: Some(vg.name.clone()),
                allocation_unit_bytes: extent,
                available_bytes: vg.free_bytes,
                start_sector: None,
                sector_count: None,
                partition_table: None,
            })
        }
        ProvisioningSpaceKind::DiskGap | ProvisioningSpaceKind::DiskTail => {
            let disk_path = source.disk.as_deref().ok_or_else(|| {
                blocked(
                    "create-disk-missing",
                    "selected partition-table free space has no disk identity",
                )
            })?;
            let sector = source.sector_size_bytes.ok_or_else(|| {
                blocked(
                    "create-sector-size-missing",
                    "selected partition-table free space has no sector size",
                )
            })?;
            let start_sector = source.start_sector.ok_or_else(|| {
                blocked(
                    "create-geometry-invalid",
                    "selected partition-table free-space geometry is incomplete",
                )
            })?;
            let sector_count = source.sector_count.ok_or_else(|| {
                blocked(
                    "create-geometry-invalid",
                    "selected partition-table free-space geometry is incomplete",
                )
            })?;
            ensure(
                sector >= 512 && sector.is_power_of_two() && sector_count > 0,
                "create-geometry-invalid",
                "selected partition-table free-space geometry is incomplete",
            )?;

            let nodes = flatten(&snapshot.storage.block_devices);
            let mut disks = nodes.iter().copied().filter(|device| {
                matches!(device.kind, NodeKind::Disk | NodeKind::Loop)
                    && device.path.as_deref() == Some(disk_path)
            });
            let disk = disks.next().ok_or_else(|| {
                blocked(
                    "create-disk-not-found",
                    "selected free-space disk no longer exists",
                )
            })?;
            ensure(
                disks.next().is_none(),
                "create-disk-ambiguous",
                "selected free-space disk identity is ambiguous",
            )?;
            let mut tables = snapshot
                .partition_tables
                .iter()
                .filter(|table| table.device == disk_path);
            let table = tables.next().ok_or_else(|| {
                blocked(
                    "create-partition-table-not-found",
                    "selected disk partition table no longer exists",
                )
            })?;
            ensure(
                tables.next().is_none(),
                "create-partition-table-ambiguous",
                "selected disk partition-table identity is ambiguous",
            )?;
            let free_space = partition_free_ranges(disk, table).ok_or_else(|| {
                blocked(
                    "create-geometry-changed",
                    "selected partition-table free-space geometry can no longer be proven",
                )
            })?;
            ensure(
                free_space.sector_size_bytes == sector,
                "create-capacity-mismatch",
                "partition-table sector size changed for the selected source",
            )?;
            let expected_tail = source.kind == ProvisioningSpaceKind::DiskTail;
            ensure(
                free_space.ranges.iter().any(|range| {
                    range.start_sector == start_sector
                        && range.sector_count == sector_count
                        && range.is_tail == expected_tail
                }),
                "create-geometry-changed",
                "selected partition-table free range changed since discovery",
            )?;
            let available_bytes = sector_count
                .checked_mul(sector)
                .ok_or_else(|| blocked("size-overflow", "free-space capacity exceeds u64"))?;
            ensure(
                available_bytes == source.available_bytes,
                "create-capacity-mismatch",
                "selected partition-table free-space capacity changed",
            )?;

            Ok(CreateSourceAdapter {
                source_id: source.id.clone(),
                kind: source.kind,
                disk: Some(disk_path.to_owned()),
                volume_group: None,
                allocation_unit_bytes: sector,
                available_bytes,
                start_sector: Some(start_sector),
                sector_count: Some(sector_count),
                partition_table: None,
            })
        }
        ProvisioningSpaceKind::BlankDisk => {
            let policy = partition_table.ok_or_else(|| {
                blocked(
                    "blank-disk-policy-required",
                    "blank-disk creation requires an explicit GPT or DOS/MBR partition-table policy",
                )
            })?;
            let geometry = blank_disk_geometry(snapshot, source, policy)?;
            let disk = source.disk.clone().ok_or_else(|| {
                blocked(
                    "blank-disk-identity-missing",
                    "blank-disk source has no device path",
                )
            })?;
            let sector_count = geometry.available_bytes / geometry.sector_size_bytes;
            Ok(CreateSourceAdapter {
                source_id: source.id.clone(),
                kind: source.kind,
                disk: Some(disk),
                volume_group: None,
                allocation_unit_bytes: geometry.sector_size_bytes,
                available_bytes: geometry.available_bytes,
                start_sector: Some(geometry.start_sector),
                sector_count: Some(sector_count),
                partition_table: Some(policy),
            })
        }
    }
}

pub fn plan_create(
    snapshot: &HostSnapshot,
    request: CreateRequest,
) -> Result<CreatePlanPreview, PlannerError> {
    let mut plan = CreatePlanPreview {
        schema_version: 1,
        plan_id: String::new(),
        dry_run: true,
        executable: false,
        status: PlanStatus::Blocked,
        request,
        source: None,
        allocation: None,
        blockers: Vec::new(),
        steps: Vec::new(),
        notices: vec![
            "M1A Create plans are advisory only. No partition, LVM, filesystem, mount or swap command is executed.".into(),
            "A future executor must revalidate source geometry/capacity and choose collision-free identifiers immediately before mutation.".into(),
        ],
    };

    let opportunities = list_provisioning_opportunities(snapshot);
    let source_selector = plan.request.source_id.as_str();
    let mut matches = opportunities.into_iter().filter(|opportunity| {
        opportunity.id == source_selector
            || (source_selector.len() >= 16 && opportunity.id.starts_with(source_selector))
    });
    let Some(source) = matches.next() else {
        plan.blockers.push(blocked(
            "create-source-not-found",
            "the selected free-space source is absent from the current snapshot",
        ));
        plan.plan_id = fingerprint(&plan)?;
        return Ok(plan);
    };
    if matches.next().is_some() {
        plan.blockers.push(blocked(
            "create-source-ambiguous",
            "the selected free-space source is not unique",
        ));
        plan.plan_id = fingerprint(&plan)?;
        return Ok(plan);
    }
    plan.source = Some(source.clone());

    let source_adapter =
        match resolve_create_source_adapter(snapshot, &source, plan.request.partition_table) {
            Ok(adapter) => adapter,
            Err(blocker) => {
                plan.blockers.push(blocker);
                plan.plan_id = fingerprint(&plan)?;
                return Ok(plan);
            }
        };
    let allocation_start_sector = source_adapter.start_sector;
    let allocation_partition_table = source_adapter.partition_table;
    let allocation_unit_bytes = source_adapter.allocation_unit_bytes;
    let available_bytes = source_adapter.available_bytes;

    let requested_bytes = match plan.request.size {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => available_bytes,
    };
    if requested_bytes == 0 {
        plan.blockers.push(blocked(
            "create-size-zero",
            "requested creation size must be greater than zero",
        ));
        plan.plan_id = fingerprint(&plan)?;
        return Ok(plan);
    }
    let units = requested_bytes / allocation_unit_bytes
        + u64::from(requested_bytes % allocation_unit_bytes != 0);
    let Some(rounded_bytes) = units.checked_mul(allocation_unit_bytes) else {
        plan.blockers.push(blocked(
            "size-overflow",
            "requested creation size exceeds the supported range",
        ));
        plan.plan_id = fingerprint(&plan)?;
        return Ok(plan);
    };
    if rounded_bytes > available_bytes {
        plan.blockers.push(blocked(
            "create-insufficient-capacity",
            "allocation-unit-rounded request exceeds the selected free-space source",
        ));
        plan.plan_id = fingerprint(&plan)?;
        return Ok(plan);
    }

    match plan.request.purpose {
        CreatePurpose::Filesystem => {
            let Some(fs_type) = plan.request.filesystem.as_deref() else {
                plan.blockers.push(blocked(
                    "create-filesystem-required",
                    "filesystem purpose requires an explicit filesystem type",
                ));
                plan.plan_id = fingerprint(&plan)?;
                return Ok(plan);
            };
            if !matches!(fs_type, "ext4" | "xfs") {
                plan.blockers.push(blocked(
                    "create-filesystem-unsupported",
                    "M1A Create preview supports ext4 or XFS filesystem intent",
                ));
                plan.plan_id = fingerprint(&plan)?;
                return Ok(plan);
            }
            if let Some(mountpoint) = plan.request.mountpoint.as_deref() {
                if !mountpoint.starts_with('/')
                    || mountpoint.chars().any(char::is_control)
                    || snapshot
                        .mounts
                        .iter()
                        .any(|mount| mount.target == mountpoint)
                    || snapshot
                        .fstab
                        .iter()
                        .any(|entry| entry.target == mountpoint)
                {
                    plan.blockers.push(blocked(
                        "create-mountpoint-invalid",
                        "mountpoint must be an unused absolute path without control characters",
                    ));
                    plan.plan_id = fingerprint(&plan)?;
                    return Ok(plan);
                }
            }
        }
        CreatePurpose::Swap => {
            if plan.request.filesystem.is_some() || plan.request.mountpoint.is_some() {
                plan.blockers.push(blocked(
                    "create-swap-options-invalid",
                    "swap creation does not accept filesystem or mountpoint options",
                ));
                plan.plan_id = fingerprint(&plan)?;
                return Ok(plan);
            }
        }
    }

    let allocated_sectors = if matches!(
        source_adapter.kind,
        ProvisioningSpaceKind::BlankDisk
            | ProvisioningSpaceKind::DiskGap
            | ProvisioningSpaceKind::DiskTail
    ) {
        Some(rounded_bytes / allocation_unit_bytes)
    } else {
        None
    };

    plan.allocation = Some(CreateAllocation {
        requested_bytes,
        rounded_bytes,
        available_bytes,
        remaining_bytes: available_bytes - rounded_bytes,
        allocation_unit_bytes,
        start_sector: allocation_start_sector,
        sector_count: allocated_sectors,
        volume_group: source_adapter.volume_group.clone(),
        partition_table: allocation_partition_table,
    });

    plan.steps.push(
        "revalidate the complete storage snapshot and exact selected free-space source".to_owned(),
    );
    match source_adapter.kind {
        ProvisioningSpaceKind::BlockedDisk => {
            plan.blockers.push(blocked(
                "create-source-unusable",
                "blocked disk cannot enter a Create route",
            ));
            plan.allocation = None;
            plan.steps.clear();
            plan.plan_id = fingerprint(&plan)?;
            return Ok(plan);
        }
        ProvisioningSpaceKind::LvmFreeExtents => {
            plan.steps
                .push("create and verify LVM metadata backup".to_owned());
            plan.steps.push(format!(
                "create a new logical volume in {} with {} bytes of extent-aligned capacity",
                source_adapter.volume_group.as_deref().unwrap_or("-"),
                rounded_bytes
            ));
        }
        ProvisioningSpaceKind::DiskGap | ProvisioningSpaceKind::DiskTail => {
            plan.steps
                .push("create and verify partition-table metadata backup".to_owned());
            plan.steps.push(format!(
                "create a new partition at sector {} using {} sectors ({} bytes)",
                source_adapter.start_sector.unwrap_or(0),
                allocated_sectors.unwrap_or(0),
                rounded_bytes
            ));
        }
        ProvisioningSpaceKind::BlankDisk => {
            let Some(policy) = allocation_partition_table else {
                plan.blockers.push(blocked(
                    "blank-disk-policy-required",
                    "blank-disk partition-table policy disappeared before route construction",
                ));
                plan.allocation = None;
                plan.plan_id = fingerprint(&plan)?;
                return Ok(plan);
            };
            let label = match policy {
                CreatePartitionTablePolicy::Gpt => "GPT",
                CreatePartitionTablePolicy::Dos => "DOS/MBR",
            };
            plan.steps.push(format!(
                "verify {} is still blank and record its pre-mutation identity baseline",
                source_adapter.disk.as_deref().unwrap_or("-")
            ));
            plan.steps.push(format!(
                "initialize a {label} partition table with 1 MiB-aligned usable geometry"
            ));
            plan.steps.push(format!(
                "create one primary partition at sector {} using {} sectors ({} bytes)",
                allocation_start_sector.unwrap_or(0),
                allocated_sectors.unwrap_or(0),
                rounded_bytes
            ));
        }
    }
    match plan.request.purpose {
        CreatePurpose::Filesystem => {
            let fs_type = plan.request.filesystem.as_deref().unwrap_or("-");
            plan.steps
                .push(format!("format the new block volume as {fs_type}"));
            if let Some(mountpoint) = plan.request.mountpoint.as_deref() {
                plan.steps.push(format!(
                    "mount the new filesystem at {mountpoint} and prepare a guarded persistent mount entry"
                ));
            }
        }
        CreatePurpose::Swap => {
            plan.steps
                .push("initialize the new block volume as Linux swap".to_owned());
            plan.steps
                .push("activate swap and prepare guarded persistent swap configuration".to_owned());
        }
    }
    plan.steps
        .push("rediscover and verify the complete resulting storage topology".to_owned());
    plan.status = PlanStatus::Preview;
    plan.plan_id = fingerprint(&plan)?;
    Ok(plan)
}

fn partition_free_ranges(disk: &BlockDevice, table: &PartitionTable) -> Option<PartitionFreeSpace> {
    let sector = table.sector_size_bytes?;
    if sector < 512 || !sector.is_power_of_two() || disk.size_bytes % sector != 0 {
        return None;
    }

    let disk_sectors = disk.size_bytes / sector;
    let is_dos = table.label.as_deref() == Some("dos");
    let (first_usable, limit) = match table.label.as_deref()? {
        "gpt" => (
            table.first_lba?,
            table.last_lba?.checked_add(1)?.min(disk_sectors),
        ),
        "dos" => (1, disk_sectors),
        _ => return None,
    };
    if first_usable >= limit {
        return None;
    }

    let mut intervals = Vec::with_capacity(table.partitions.len());
    for record in &table.partitions {
        if record.size_sectors == 0 {
            return None;
        }
        let end = record.start_sector.checked_add(record.size_sectors)?;
        if record.start_sector < first_usable || end > limit {
            return None;
        }
        intervals.push((record.start_sector, end));
    }
    intervals.sort_unstable_by_key(|(start, _)| *start);

    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let has_partitions = !merged.is_empty();
    let mut free_ranges = Vec::new();
    let mut merged = merged.into_iter();
    let mut cursor = first_usable;

    if is_dos {
        let Some((_, first_end)) = merged.next() else {
            return Some(PartitionFreeSpace {
                ranges: free_ranges,
                sector_size_bytes: sector,
            });
        };
        // DOS/MBR has no authoritative first-usable-LBA field. Sectors between the
        // MBR and the first partition may contain bootloader embedding data, so they
        // are deliberately not exposed as generic provisioning space.
        cursor = first_end;
    }

    for (start, end) in merged {
        if start > cursor {
            free_ranges.push(PartitionFreeRange {
                start_sector: cursor,
                sector_count: start.checked_sub(cursor)?,
                is_tail: false,
            });
        }
        cursor = cursor.max(end);
    }
    if cursor < limit {
        free_ranges.push(PartitionFreeRange {
            start_sector: cursor,
            sector_count: limit.checked_sub(cursor)?,
            is_tail: has_partitions,
        });
    }

    Some(PartitionFreeSpace {
        ranges: free_ranges,
        sector_size_bytes: sector,
    })
}

fn extend_profile_from_route(route: &LayerRoute) -> ExtendPlannerProfile {
    let last_block_layer = route
        .layers
        .iter()
        .rev()
        .find_map(|layer| match layer.kind {
            RouteLayerKind::Disk
            | RouteLayerKind::Partition
            | RouteLayerKind::LoopDevice
            | RouteLayerKind::Encryption
            | RouteLayerKind::Raid
            | RouteLayerKind::Multipath
            | RouteLayerKind::LvmLogicalVolume
            | RouteLayerKind::Zram
            | RouteLayerKind::Rom
            | RouteLayerKind::Unknown => Some(layer.kind),
            RouteLayerKind::LvmPhysicalVolume
            | RouteLayerKind::LvmVolumeGroup
            | RouteLayerKind::Filesystem
            | RouteLayerKind::Mount => None,
        });

    match last_block_layer {
        Some(RouteLayerKind::Partition) => ExtendPlannerProfile::DirectPartition,
        Some(RouteLayerKind::LvmLogicalVolume) => ExtendPlannerProfile::Lvm,
        Some(RouteLayerKind::Disk | RouteLayerKind::LoopDevice) => {
            ExtendPlannerProfile::WholeBlockFilesystem
        }
        _ => ExtendPlannerProfile::LegacyFailClosed,
    }
}

pub fn resolve_extend_route_adapter(snapshot: &HostSnapshot, target: &str) -> ExtendRouteAdapter {
    let route = analyze_layer_route(snapshot, target);
    ExtendRouteAdapter {
        profile: extend_profile_from_route(&route),
        resolved_device: route.resolved_device.clone(),
        mountpoint: route.mountpoint.clone(),
        status: route.status,
        issue_codes: route
            .issues
            .iter()
            .map(|issue| issue.code.clone())
            .collect(),
    }
}

pub fn select_extend_planner_profile(
    snapshot: &HostSnapshot,
    target: &str,
) -> ExtendPlannerProfile {
    resolve_extend_route_adapter(snapshot, target).profile
}

fn apply_partition_outcome(
    plan: &mut PlanPreview,
    snapshot: &HostSnapshot,
    outcome: Result<Option<(PartitionSizeChange, Vec<PlanStep>)>, Blocker>,
) -> bool {
    match outcome {
        Ok(Some((size, steps))) => {
            plan.status = PlanStatus::Preview;
            plan.partition_size_change = Some(size);
            plan.preflight_checks = partition_preflight_checks();
            plan.steps = steps;
            true
        }
        Ok(None) => false,
        Err(blocker) => {
            if blocker.code == "insufficient-adjacent-capacity" {
                plan.layout_alternatives = detect_layout_alternatives(snapshot, &plan.request);
            }
            plan.blockers.push(blocker);
            true
        }
    }
}

fn apply_lvm_underlying_preview(
    plan: &mut PlanPreview,
    candidate: (
        GrowthRouteAlternative,
        SizeChange,
        Option<PartitionSizeChange>,
        Vec<PlanStep>,
    ),
) {
    let (route, size, partition_size, steps) = candidate;
    let grows_partition = partition_size.is_some();
    plan.status = PlanStatus::Preview;
    plan.size_change = Some(size);
    plan.partition_size_change = partition_size;
    plan.preflight_checks = lvm_underlying_preflight_checks(grows_partition);
    plan.steps = steps;
    plan.growth_route_alternatives.push(route);
}

fn apply_lvm_outcome(
    plan: &mut PlanPreview,
    snapshot: &HostSnapshot,
    outcome: Result<(SizeChange, Vec<PlanStep>), Blocker>,
) {
    match outcome {
        Ok((size, steps)) => {
            plan.status = PlanStatus::Preview;
            plan.size_change = Some(size);
            plan.preflight_checks = lvm_preflight_checks();
            plan.steps = steps;
        }
        Err(blocker) => {
            if matches!(blocker.code.as_str(), "insufficient-capacity" | "no-growth") {
                if let Some(candidate) =
                    build_lvm_underlying_growth_candidate(snapshot, &plan.request)
                {
                    apply_lvm_underlying_preview(plan, candidate);
                    return;
                }
                if let Some(route) = analyze_lvm_underlying_growth(snapshot, &plan.request) {
                    plan.growth_route_alternatives.push(route);
                }
            }
            plan.blockers.push(blocker);
        }
    }
}

fn build_whole_filesystem_candidate(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: &ExtendRequest,
) -> Result<(FilesystemSizeChange, Vec<PlanStep>), Blocker> {
    for component in ["lsblk", "mounts", "fstab", "swap"] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component),
            "collector-incomplete",
        )?;
        ensure(
            status.state == CollectorState::Complete,
            "collector-incomplete",
            "all whole-device filesystem preview collectors must complete",
        )?;
    }
    ensure(
        !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        "diagnostic-error",
        "the snapshot contains error-level diagnostics",
    )?;

    let route = resolve_extend_route_adapter(snapshot, &request.target);
    ensure(
        route.profile == ExtendPlannerProfile::WholeBlockFilesystem,
        "route-profile-mismatch",
        "whole-device filesystem builder received a non-whole-device semantic route",
    )?;
    let device_path = route.resolved_device.as_deref().ok_or_else(|| {
        blocked(
            "route-device-not-found",
            "whole-device filesystem target did not resolve to one device",
        )
    })?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let device = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| node_alias(device, device_path)),
        "ambiguous-device",
    )?;
    ensure(
        matches!(device.kind, NodeKind::Disk | NodeKind::Loop),
        "unsupported-layout",
        "whole-device filesystem preview requires a disk or loop-device target",
    )?;
    ensure(
        device.children.is_empty(),
        "unsupported-layout",
        "whole-device filesystem target has stacked consumers",
    )?;

    let fs = device
        .filesystem
        .as_ref()
        .ok_or_else(|| blocked("filesystem-missing", "filesystem type is absent"))?;
    ensure(
        matches!(fs.fs_type.as_str(), "ext4" | "xfs"),
        "unsupported-filesystem",
        "whole-device filesystem preview supports only ext4 and XFS",
    )?;
    ensure(
        device.uuid.as_deref().is_some_and(|uuid| !uuid.is_empty()),
        "identity-missing",
        "filesystem UUID is required for whole-device preview",
    )?;

    let mountpoint = route.mountpoint.as_deref().ok_or_else(|| {
        blocked(
            "mount-not-unique",
            "target filesystem is not uniquely mounted",
        )
    })?;
    let mount = unique(
        snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == mountpoint),
        "mount-not-unique",
    )?;
    ensure(
        mount
            .source
            .as_deref()
            .is_some_and(|source| node_alias(device, source))
            && mount.fs_type.as_deref() == Some(fs.fs_type.as_str())
            && mount.options.iter().any(|option| option == "rw")
            && !mount
                .options
                .iter()
                .any(|option| matches!(option.as_str(), "ro" | "bind" | "rbind"))
            && device.mountpoints == vec![mount.target.clone()],
        "mount-state-mismatch",
        "one matching read-write mount must be confirmed by lsblk and findmnt",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|swap| node_alias(device, &swap.name)),
        "active-swap",
        "the target is reported as active swap",
    )?;

    let grow_tool = if fs.fs_type == "xfs" {
        "xfs_growfs"
    } else {
        "resize2fs"
    };
    let capability = unique(
        capabilities
            .tools
            .iter()
            .filter(|capability| capability.name == grow_tool),
        "tool-unavailable",
    )?;
    ensure(
        capability.available,
        "tool-unavailable",
        "required filesystem grow tool is unavailable",
    )?;

    let evidence = unique(
        snapshot.filesystem_preflight.iter().filter(|evidence| {
            evidence.device == device_path
                && evidence.mountpoint.as_deref() == Some(mount.target.as_str())
                && evidence.fs_type == fs.fs_type
        }),
        "filesystem-size-evidence-missing",
    )?;
    ensure(
        evidence.state == FilesystemProbeState::Verified,
        "filesystem-size-evidence-incomplete",
        "filesystem metadata/geometry evidence must be verified",
    )?;
    let block_size = evidence.block_size_bytes.ok_or_else(|| {
        blocked(
            "filesystem-block-size-missing",
            "filesystem block size is absent from read-only metadata evidence",
        )
    })?;
    let block_count = evidence.block_count.ok_or_else(|| {
        blocked(
            "filesystem-block-count-missing",
            "filesystem block count is absent from read-only metadata evidence",
        )
    })?;
    let filesystem_size = evidence.size_bytes.ok_or_else(|| {
        blocked(
            "filesystem-size-evidence-missing",
            "filesystem size is absent from read-only metadata evidence",
        )
    })?;
    ensure(
        block_size >= 512 && block_size.is_power_of_two(),
        "filesystem-block-size-invalid",
        "filesystem block size is invalid",
    )?;
    ensure(
        block_count.checked_mul(block_size) == Some(filesystem_size),
        "filesystem-geometry-mismatch",
        "filesystem block count, block size and total size disagree",
    )?;
    ensure(
        filesystem_size > 0 && filesystem_size <= device.size_bytes,
        "filesystem-capacity-mismatch",
        "filesystem size exceeds or invalidates the backing device capacity",
    )?;

    let raw_available = device.size_bytes - filesystem_size;
    let available_blocks = raw_available / block_size;
    let max_growth = available_blocks
        .checked_mul(block_size)
        .ok_or_else(|| blocked("size-overflow", "filesystem growth exceeds u64"))?;
    ensure(
        max_growth > 0,
        "no-growth",
        "backing device has less than one filesystem block of verified free capacity",
    )?;

    let (requested, rounded) = match request.growth {
        Growth::ByBytes(bytes) => {
            ensure(bytes > 0, "no-growth", "requested growth is zero")?;
            let blocks = bytes / block_size + u64::from(bytes % block_size != 0);
            let rounded = blocks
                .checked_mul(block_size)
                .ok_or_else(|| blocked("size-overflow", "filesystem growth exceeds u64"))?;
            (bytes, rounded)
        }
        Growth::MaxFree => (max_growth, max_growth),
    };
    ensure(
        rounded <= max_growth,
        "insufficient-capacity",
        "filesystem-block-aligned request exceeds verified backing-device slack",
    )?;

    let expected_size = filesystem_size
        .checked_add(rounded)
        .ok_or_else(|| blocked("size-overflow", "new filesystem size exceeds u64"))?;
    ensure(
        expected_size <= device.size_bytes,
        "filesystem-capacity-mismatch",
        "expected filesystem size exceeds backing device capacity",
    )?;

    let size = FilesystemSizeChange {
        device: device_path.to_owned(),
        mountpoint: mount.target.clone(),
        fs_type: fs.fs_type.clone(),
        current_filesystem_size_bytes: filesystem_size,
        backing_device_size_bytes: device.size_bytes,
        requested_growth_bytes: requested,
        rounded_growth_bytes: rounded,
        expected_filesystem_size_bytes: expected_size,
        filesystem_block_size_bytes: block_size,
        remaining_backing_free_bytes: device.size_bytes - expected_size,
    };
    let steps = vec![
        step(
            1,
            Operation::RevalidateSnapshot,
            Reversibility::NotApplicable,
        ),
        step(
            2,
            Operation::GrowFilesystem {
                fs_type: fs.fs_type.clone(),
                mountpoint: mount.target.clone(),
            },
            Reversibility::Irreversible,
        ),
        step(
            3,
            Operation::RediscoverAndVerify,
            Reversibility::NotApplicable,
        ),
    ];
    Ok((size, steps))
}

fn apply_whole_filesystem_outcome(
    plan: &mut PlanPreview,
    outcome: Result<(FilesystemSizeChange, Vec<PlanStep>), Blocker>,
) {
    match outcome {
        Ok((size, steps)) => {
            plan.status = PlanStatus::Preview;
            plan.filesystem_size_change = Some(size);
            plan.preflight_checks = whole_filesystem_preflight_checks();
            plan.steps = steps;
        }
        Err(blocker) => plan.blockers.push(blocker),
    }
}

fn semantic_layer_blocker(snapshot: &HostSnapshot, target: &str) -> Option<Blocker> {
    let route = analyze_layer_route(snapshot, target);
    if route.resolved_device.is_none() || route.status == LayerRouteStatus::SupportedProfile {
        return None;
    }
    route
        .issues
        .first()
        .map(|issue| blocked(&issue.code, &issue.message))
}

fn apply_legacy_extend_profile(
    plan: &mut PlanPreview,
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
) {
    let partition = try_build_partition_candidate(snapshot, capabilities, &plan.request);
    if !apply_partition_outcome(plan, snapshot, partition) {
        let lvm = build_candidate(snapshot, capabilities, &plan.request);
        apply_lvm_outcome(plan, snapshot, lvm);
    }
}

pub fn plan_extend(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: ExtendRequest,
) -> Result<PlanPreview, PlannerError> {
    let mut plan = PlanPreview {
        schema_version: 1,
        plan_id: String::new(),
        snapshot_digest: fingerprint(&(snapshot, capabilities))?,
        dry_run: true,
        executable: false,
        status: PlanStatus::Blocked,
        request,
        size_change: None,
        partition_size_change: None,
        filesystem_size_change: None,
        layout_alternatives: Vec::new(),
        growth_route_alternatives: Vec::new(),
        blockers: Vec::new(),
        preflight_checks: Vec::new(),
        steps: Vec::new(),
        notices: vec![
            "M1A produces previews only. No backup, resize, mount or other command is run.".into(),
            "The preview covers block-layer capacity, not measured filesystem capacity or health.".into(),
            "A future executor needs fresh identity/health checks, locks, verified backups and explicit approval.".into(),
            "Metadata backups are not backups of user data; filesystem growth has no automatic rollback.".into(),
        ],
    };
    match select_extend_planner_profile(snapshot, &plan.request.target) {
        ExtendPlannerProfile::DirectPartition => {
            let partition = try_build_partition_candidate(snapshot, capabilities, &plan.request);
            if !apply_partition_outcome(&mut plan, snapshot, partition) {
                let lvm = build_candidate(snapshot, capabilities, &plan.request);
                apply_lvm_outcome(&mut plan, snapshot, lvm);
            }
        }
        ExtendPlannerProfile::Lvm => {
            if matches!(plan.request.growth, Growth::MaxFree) {
                if let Some(candidate) =
                    build_lvm_underlying_growth_candidate(snapshot, &plan.request)
                {
                    apply_lvm_underlying_preview(&mut plan, candidate);
                } else {
                    let lvm = build_candidate(snapshot, capabilities, &plan.request);
                    apply_lvm_outcome(&mut plan, snapshot, lvm);
                }
            } else {
                let lvm = build_candidate(snapshot, capabilities, &plan.request);
                apply_lvm_outcome(&mut plan, snapshot, lvm);
            }
        }
        ExtendPlannerProfile::WholeBlockFilesystem => {
            let filesystem =
                build_whole_filesystem_candidate(snapshot, capabilities, &plan.request);
            apply_whole_filesystem_outcome(&mut plan, filesystem);
        }
        ExtendPlannerProfile::LegacyFailClosed => {
            if let Some(blocker) = semantic_layer_blocker(snapshot, &plan.request.target) {
                plan.blockers.push(blocker);
            } else {
                apply_legacy_extend_profile(&mut plan, snapshot, capabilities);
            }
        }
    }

    if plan.status == PlanStatus::Preview {
        if let Some(mountpoint) = plan.steps.iter().find_map(|step| match &step.operation {
            Operation::GrowFilesystem { mountpoint, .. } => Some(mountpoint.as_str()),
            _ => None,
        }) {
            plan.preflight_checks
                .extend(filesystem_evidence_checks(snapshot, mountpoint));
        }
    }

    // Includes all preview content except the ID itself (empty at this point).
    plan.plan_id = fingerprint(&plan)?;
    Ok(plan)
}

fn preflight_check(code: &str, state: PreflightState, message: &str) -> PreflightCheck {
    PreflightCheck {
        code: code.to_owned(),
        state,
        message: message.to_owned(),
    }
}

fn common_verified_preflight() -> Vec<PreflightCheck> {
    vec![
        preflight_check(
            "collectors-complete",
            PreflightState::Verified,
            "required discovery collectors completed successfully",
        ),
        preflight_check(
            "diagnostics-clean",
            PreflightState::Verified,
            "no error-level storage diagnostics invalidate this preview",
        ),
        preflight_check(
            "mount-rw",
            PreflightState::Verified,
            "target has one matching read-write mount",
        ),
        preflight_check(
            "tooling-available",
            PreflightState::Verified,
            "required future operation tools are available",
        ),
    ]
}

fn future_execution_gates() -> Vec<PreflightCheck> {
    vec![
        preflight_check(
            "runtime-identity-recheck",
            PreflightState::Required,
            "revalidate device, filesystem and plan basis immediately before mutation",
        ),
        preflight_check(
            "filesystem-health",
            PreflightState::Required,
            "verify filesystem health, features and supported grow state",
        ),
        preflight_check(
            "exclusive-lock",
            PreflightState::Required,
            "acquire an exclusive storage-operation lock and reject concurrent mutation",
        ),
        preflight_check(
            "metadata-backup",
            PreflightState::Required,
            "create and verify the required metadata backup before irreversible steps",
        ),
        preflight_check(
            "execution-approval",
            PreflightState::Required,
            "obtain explicit approval for the exact fresh plan before execution",
        ),
    ]
}

fn partition_preflight_checks() -> Vec<PreflightCheck> {
    let mut checks = common_verified_preflight();
    checks.extend([
        preflight_check(
            "partition-geometry-consistent",
            PreflightState::Verified,
            "lsblk and partition-table sector/start/size evidence is consistent",
        ),
        preflight_check(
            "adjacent-capacity-verified",
            PreflightState::Verified,
            "requested growth fits verified adjacent free sectors",
        ),
    ]);
    checks.extend(future_execution_gates());
    checks
}

fn whole_filesystem_preflight_checks() -> Vec<PreflightCheck> {
    let mut checks = common_verified_preflight();
    checks.extend([
        preflight_check(
            "filesystem-geometry-consistent",
            PreflightState::Verified,
            "read-only filesystem block size/count/size evidence is internally consistent",
        ),
        preflight_check(
            "backing-capacity-verified",
            PreflightState::Verified,
            "requested growth fits verified unused capacity already present on the backing device",
        ),
    ]);
    checks.extend(
        future_execution_gates()
            .into_iter()
            .filter(|check| check.code != "metadata-backup"),
    );
    checks
}

fn lvm_preflight_checks() -> Vec<PreflightCheck> {
    let mut checks = common_verified_preflight();
    checks.extend([
        preflight_check(
            "lvm-identity-consistent",
            PreflightState::Verified,
            "PV, VG, LV and filesystem identities are internally consistent",
        ),
        preflight_check(
            "lvm-layout-supported",
            PreflightState::Verified,
            "LV and VG layout is within the supported linear single-PV preview profile",
        ),
        preflight_check(
            "capacity-verified",
            PreflightState::Verified,
            "requested growth fits verified free VG extents",
        ),
    ]);
    checks.extend(future_execution_gates());
    checks
}

fn lvm_underlying_preflight_checks(grows_partition: bool) -> Vec<PreflightCheck> {
    let mut checks = common_verified_preflight();
    checks.extend([
        preflight_check(
            "lvm-identity-consistent",
            PreflightState::Verified,
            "PV, VG, LV and filesystem identities are internally consistent",
        ),
        preflight_check(
            "lvm-layout-supported",
            PreflightState::Verified,
            "LV and VG layout is within the supported linear single-PV preview profile",
        ),
        preflight_check(
            "underlying-capacity-verified",
            PreflightState::Verified,
            "requested growth fits verified PV backing-device capacity and extent geometry",
        ),
    ]);
    if grows_partition {
        checks.extend([
            preflight_check(
                "partition-geometry-consistent",
                PreflightState::Verified,
                "partition-table sector/start/size evidence is consistent",
            ),
            preflight_check(
                "adjacent-capacity-verified",
                PreflightState::Verified,
                "required partition growth fits verified adjacent free sectors",
            ),
        ]);
    }
    checks.extend(future_execution_gates());
    checks
}

fn filesystem_evidence_checks(snapshot: &HostSnapshot, mountpoint: &str) -> Vec<PreflightCheck> {
    let matches: Vec<_> = snapshot
        .filesystem_preflight
        .iter()
        .filter(|evidence| evidence.mountpoint.as_deref() == Some(mountpoint))
        .collect();

    if matches.len() != 1 {
        return vec![
            preflight_check(
                "filesystem-metadata-probe",
                PreflightState::Required,
                if matches.is_empty() {
                    "collect read-only filesystem metadata evidence for the exact target before execution"
                } else {
                    "filesystem metadata evidence is ambiguous; resolve the exact target before execution"
                },
            ),
            preflight_check(
                "filesystem-version-observed",
                PreflightState::Required,
                "record the target filesystem version/revision before execution",
            ),
            preflight_check(
                "filesystem-features-observed",
                PreflightState::Required,
                "record target filesystem feature flags before execution",
            ),
        ];
    }

    let evidence = matches[0];
    let metadata_verified = matches!(
        evidence.state,
        FilesystemProbeState::Verified | FilesystemProbeState::Partial
    );

    let mut checks = vec![
        preflight_check(
            "filesystem-metadata-probe",
            if metadata_verified {
                PreflightState::Verified
            } else {
                PreflightState::Required
            },
            if metadata_verified {
                "read-only filesystem metadata probe returned target-specific evidence"
            } else {
                "filesystem metadata probe is unavailable or failed and must succeed before execution"
            },
        ),
        {
            let version = evidence
                .fs_version
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    evidence
                        .revision
                        .as_deref()
                        .filter(|value| !value.is_empty())
                });
            preflight_check(
                "filesystem-version-observed",
                if version.is_some() {
                    PreflightState::Verified
                } else {
                    PreflightState::Required
                },
                &version
                    .map(|value| format!("filesystem version/revision observed: {value}"))
                    .unwrap_or_else(|| {
                        "filesystem version/revision was not observed and must be resolved before execution"
                            .to_owned()
                    }),
            )
        },
        preflight_check(
            "filesystem-features-observed",
            if evidence.features.is_empty() {
                PreflightState::Required
            } else {
                PreflightState::Verified
            },
            if evidence.features.is_empty() {
                "filesystem feature flags were not observed and must be resolved before execution"
            } else {
                "filesystem feature flags were collected by a read-only metadata probe"
            },
        ),
    ];

    if evidence.fs_type == "ext4" {
        checks.push(preflight_check(
            "ext4-superblock-state",
            if evidence.filesystem_state.as_deref() == Some("clean") {
                PreflightState::Verified
            } else {
                PreflightState::Required
            },
            if evidence.filesystem_state.as_deref() == Some("clean") {
                "ext4 superblock reports filesystem state clean; this is not a substitute for a dedicated health check"
            } else {
                "ext4 superblock did not report a clean state; dedicated health validation is required before execution"
            },
        ));
    }

    if evidence.fs_type == "xfs" {
        checks.push(preflight_check(
            "xfs-grow-dry-run",
            if evidence.grow_check_passed == Some(true) {
                PreflightState::Verified
            } else {
                PreflightState::Required
            },
            if evidence.grow_check_passed == Some(true) {
                "xfs_growfs -n completed successfully against the mounted target without modifying it"
            } else {
                "xfs_growfs -n must succeed against the exact mounted target before execution"
            },
        ));
    }

    checks
}

fn fingerprint(value: &impl Serialize) -> Result<String, PlannerError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn blocked(code: &str, message: &str) -> Blocker {
    Blocker {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

fn ensure(condition: bool, code: &str, message: &str) -> Result<(), Blocker> {
    if condition {
        Ok(())
    } else {
        Err(blocked(code, message))
    }
}

fn unique<T>(mut items: impl Iterator<Item = T>, code: &str) -> Result<T, Blocker> {
    let first = items
        .next()
        .ok_or_else(|| blocked(code, "required evidence is absent"))?;
    ensure(
        items.next().is_none(),
        code,
        "evidence is ambiguous or duplicated",
    )?;
    Ok(first)
}

fn normalize_gpt_partition_type(raw: &str) -> Option<String> {
    let value = raw.trim();
    if value.len() != 36 {
        return None;
    }
    for (index, byte) in value.bytes().enumerate() {
        let hyphen = matches!(index, 8 | 13 | 18 | 23);
        if (hyphen && byte != b'-') || (!hyphen && !byte.is_ascii_hexdigit()) {
            return None;
        }
    }
    Some(value.to_ascii_lowercase())
}

fn ensure_partition_role_is_growable(
    table: &PartitionTable,
    record: &lsm_core::PartitionRecord,
) -> Result<(), Blocker> {
    let raw_type = record.partition_type.as_deref().ok_or_else(|| {
        blocked(
            "partition-type-missing",
            "partition type is required before a partition can be considered for growth",
        )
    })?;

    match table.label.as_deref() {
        Some("gpt") => {
            let partition_type = normalize_gpt_partition_type(raw_type).ok_or_else(|| {
                blocked(
                    "invalid-partition-type",
                    "GPT partition type GUID is malformed",
                )
            })?;
            let protected = matches!(
                partition_type.as_str(),
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
                    | "21686148-6449-6e6f-744e-656564454649"
                    | "bc13c2ff-59e6-4262-a352-b275fd6f7172"
            );
            ensure(
                !protected,
                "protected-partition-role",
                "EFI System, BIOS Boot and Extended Boot Loader partitions require a dedicated proven route",
            )
        }
        Some("dos") => {
            let partition_type = parse_dos_type(raw_type)?;
            ensure(
                !matches!(partition_type, 0xea | 0xef),
                "protected-partition-role",
                "MBR boot-loader and EFI System partitions require a dedicated proven route",
            )
        }
        _ => Ok(()),
    }
}

fn try_build_partition_candidate(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: &ExtendRequest,
) -> Result<Option<(PartitionSizeChange, Vec<PlanStep>)>, Blocker> {
    ensure(
        !request.target.is_empty() && !request.target.chars().any(char::is_control),
        "invalid-target",
        "target must be a nonempty device path or exact mountpoint",
    )?;

    let nodes = flatten(&snapshot.storage.block_devices);
    let route = resolve_extend_route_adapter(snapshot, &request.target);
    if route.profile != ExtendPlannerProfile::DirectPartition {
        return Ok(None);
    }
    let resolved_device = route.resolved_device.as_deref().ok_or_else(|| {
        blocked(
            "route-device-not-found",
            "direct-partition target did not resolve to one device",
        )
    })?;
    let device = unique(
        nodes.iter().copied().filter(|device| {
            device.kind == NodeKind::Partition && node_alias(device, resolved_device)
        }),
        "ambiguous-device",
    )?;

    for component in ["lsblk", "partition_tables", "mounts", "fstab", "swap"] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component),
            "collector-incomplete",
        )?;
        ensure(
            status.state == CollectorState::Complete,
            "collector-incomplete",
            "all direct-partition preview collectors must complete",
        )?;
    }
    ensure(
        !snapshot
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        "diagnostic-error",
        "the snapshot contains error-level diagnostics",
    )?;

    ensure(
        device.children.is_empty(),
        "unsupported-layout",
        "stacked consumers above the partition are not supported",
    )?;
    let fs = device
        .filesystem
        .as_ref()
        .ok_or_else(|| blocked("filesystem-missing", "filesystem type is absent"))?;
    ensure(
        matches!(fs.fs_type.as_str(), "ext4" | "xfs"),
        "unsupported-filesystem",
        "direct partition filesystem is unsupported; only ext4 and XFS previews are supported",
    )?;

    let mountpoint = route.mountpoint.as_deref().ok_or_else(|| {
        blocked(
            "mount-not-unique",
            "direct-partition target is not uniquely mounted",
        )
    })?;
    let mount = unique(
        snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == mountpoint),
        "mount-not-unique",
    )?;
    ensure(
        mount
            .source
            .as_deref()
            .is_some_and(|source| node_alias(device, source))
            && mount.fs_type.as_deref() == Some(fs.fs_type.as_str())
            && mount.options.iter().any(|option| option == "rw")
            && !mount
                .options
                .iter()
                .any(|option| matches!(option.as_str(), "ro" | "bind" | "rbind"))
            && device.mountpoints == vec![mount.target.clone()]
            && snapshot
                .mounts
                .iter()
                .filter(|candidate| candidate.target == mount.target)
                .count()
                == 1,
        "mount-state-mismatch",
        "one matching read-write mount must be confirmed by lsblk and findmnt",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|swap| node_alias(device, &swap.name)),
        "active-swap",
        "the target is reported as active swap",
    )?;

    for tool in [
        "sfdisk",
        if fs.fs_type == "xfs" {
            "xfs_growfs"
        } else {
            "resize2fs"
        },
    ] {
        let capability = unique(
            capabilities
                .tools
                .iter()
                .filter(|capability| capability.name == tool),
            "tool-unavailable",
        )?;
        ensure(
            capability.available,
            "tool-unavailable",
            "a required future operation tool is unavailable",
        )?;
    }

    let parent_name = device
        .parent_kernel_name
        .as_deref()
        .ok_or_else(|| blocked("parent-missing", "partition parent is unknown"))?;
    let disk = unique(
        nodes.iter().copied().filter(|candidate| {
            matches!(candidate.kind, NodeKind::Disk | NodeKind::Loop)
                && candidate.kernel_name.as_deref() == Some(parent_name)
        }),
        "parent-not-resolved",
    )?;
    let disk_path = disk
        .path
        .as_deref()
        .ok_or_else(|| blocked("parent-not-resolved", "disk path is absent"))?;
    let device_path = device
        .path
        .as_deref()
        .ok_or_else(|| blocked("device-path-missing", "partition path is absent"))?;
    let table = unique(
        snapshot
            .partition_tables
            .iter()
            .filter(|table| table.device == disk_path),
        "partition-table-not-unique",
    )?;
    let sector = table
        .sector_size_bytes
        .ok_or_else(|| blocked("sector-size-missing", "partition sector size is unknown"))?;
    ensure(
        sector >= 512 && sector.is_power_of_two() && device.logical_sector_bytes == Some(sector),
        "sector-size-mismatch",
        "partition-table and block-device logical sector sizes disagree",
    )?;

    let record = unique(
        table
            .partitions
            .iter()
            .filter(|record| record.node == device_path),
        "partition-record-not-unique",
    )?;
    ensure_partition_role_is_growable(table, record)?;
    let start_bytes = record
        .start_sector
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "partition start exceeds u64"))?;
    ensure(
        device
            .start_512_sector
            .and_then(|start| start.checked_mul(512))
            == Some(start_bytes),
        "partition-start-mismatch",
        "lsblk and partition table disagree on partition start",
    )?;
    let current_size = record
        .size_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "partition size exceeds u64"))?;
    ensure(
        current_size == device.size_bytes,
        "partition-size-mismatch",
        "lsblk and partition table disagree on target partition size",
    )?;

    let adjacent_sectors = adjacent_free_sectors(disk, table, record)?;
    let adjacent_bytes = adjacent_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "adjacent capacity exceeds u64"))?;
    let requested = match request.growth {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => adjacent_bytes,
    };
    ensure(
        requested > 0,
        "no-growth",
        "requested growth or verified adjacent capacity is zero",
    )?;
    let growth_sectors = requested / sector + u64::from(requested % sector != 0);
    ensure(
        growth_sectors <= adjacent_sectors,
        "insufficient-adjacent-capacity",
        "sector-rounded request exceeds verified adjacent free space",
    )?;
    let rounded = growth_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "growth exceeds u64"))?;
    let new_size_sectors = record
        .size_sectors
        .checked_add(growth_sectors)
        .ok_or_else(|| blocked("size-overflow", "new partition size exceeds u64"))?;
    let expected_size = new_size_sectors
        .checked_mul(sector)
        .ok_or_else(|| blocked("size-overflow", "new partition size exceeds u64"))?;

    let label = table.label.clone().ok_or_else(|| {
        blocked(
            "partition-label-missing",
            "partition table label is unknown",
        )
    })?;
    let size = PartitionSizeChange {
        device: device_path.to_owned(),
        disk: disk_path.to_owned(),
        current_partition_size_bytes: current_size,
        requested_growth_bytes: requested,
        rounded_growth_bytes: rounded,
        expected_partition_size_bytes: expected_size,
        sector_size_bytes: sector,
        remaining_adjacent_free_bytes: adjacent_bytes - rounded,
    };
    let steps = vec![
        step(
            1,
            Operation::RevalidateSnapshot,
            Reversibility::NotApplicable,
        ),
        step(
            2,
            Operation::BackupPartitionTableMetadata {
                disk: disk_path.to_owned(),
                table_label: label,
                table_id: table.id.clone(),
            },
            Reversibility::Reversible,
        ),
        step(
            3,
            Operation::ExtendPartition {
                partition: device_path.to_owned(),
                start_sector: record.start_sector,
                old_size_sectors: record.size_sectors,
                new_size_sectors,
                sector_size_bytes: sector,
            },
            Reversibility::Irreversible,
        ),
        step(
            4,
            Operation::GrowFilesystem {
                fs_type: fs.fs_type.clone(),
                mountpoint: mount.target.clone(),
            },
            Reversibility::Irreversible,
        ),
        step(
            5,
            Operation::RediscoverAndVerify,
            Reversibility::NotApplicable,
        ),
    ];

    Ok(Some((size, steps)))
}

pub fn analyze_layout_opportunity(
    snapshot: &HostSnapshot,
    target: &str,
) -> Option<LayoutOpportunity> {
    let source = if target.starts_with("/dev/") {
        target
    } else {
        let mut mounts = snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == target);
        let mount = mounts.next()?;
        if mounts.next().is_some() {
            return None;
        }
        mount.source.as_deref()?
    };

    let nodes = flatten(&snapshot.storage.block_devices);
    let mut targets = nodes
        .iter()
        .copied()
        .filter(|device| device.kind == NodeKind::Partition && node_alias(device, source));
    let target_device = targets.next()?;
    if targets.next().is_some() {
        return None;
    }

    let parent_name = target_device.parent_kernel_name.as_deref()?;
    let mut disks = nodes.iter().copied().filter(|candidate| {
        candidate.kind == NodeKind::Disk && candidate.kernel_name.as_deref() == Some(parent_name)
    });
    let disk = disks.next()?;
    if disks.next().is_some() {
        return None;
    }
    let disk_path = disk.path.as_deref()?;
    let target_path = target_device.path.as_deref()?;

    let mut tables = snapshot
        .partition_tables
        .iter()
        .filter(|table| table.device == disk_path && table.label.as_deref() == Some("dos"));
    let table = tables.next()?;
    if tables.next().is_some() {
        return None;
    }
    let sector = table.sector_size_bytes?;
    if !matches!(sector, 512 | 4096) || disk.size_bytes % sector != 0 {
        return None;
    }

    let target_record = table
        .partitions
        .iter()
        .find(|record| record.node == target_path)?;
    let target_end = target_record
        .start_sector
        .checked_add(target_record.size_sectors)?;
    let disk_sectors = disk.size_bytes / sector;

    let mut extended_records = table.partitions.iter().filter(|record| {
        parse_dos_type(record.partition_type.as_deref().unwrap_or(""))
            .map(|kind| matches!(kind, 0x05 | 0x0f | 0x85))
            .unwrap_or(false)
            && record.start_sector >= target_end
    });
    let extended = extended_records.next()?;
    if extended_records.next().is_some() {
        return None;
    }
    let extended_end = extended.start_sector.checked_add(extended.size_sectors)?;
    if extended_end > disk_sectors {
        return None;
    }

    let logicals: Vec<_> = table
        .partitions
        .iter()
        .filter(|record| {
            if record.node == extended.node {
                return false;
            }
            let Some(record_end) = record.start_sector.checked_add(record.size_sectors) else {
                return false;
            };
            record.start_sector >= extended.start_sector && record_end <= extended_end
        })
        .collect();
    if logicals.len() != 1 {
        return None;
    }
    let swap_record = logicals[0];
    if parse_dos_type(swap_record.partition_type.as_deref()?).ok()? != 0x82 {
        return None;
    }
    let active_swap = snapshot
        .swaps
        .iter()
        .find(|swap| swap.name == swap_record.node)?;
    let swap_bytes = swap_record.size_sectors.checked_mul(sector)?;
    if active_swap.size_bytes != swap_bytes {
        return None;
    }

    if table.partitions.iter().any(|record| {
        if record.node == target_record.node
            || record.node == extended.node
            || record.node == swap_record.node
        {
            return false;
        }
        record.start_sector >= target_end
    }) {
        return None;
    }

    let tail_sectors = disk_sectors.checked_sub(extended_end)?;
    let disk_tail_free_bytes = tail_sectors.checked_mul(sector)?;
    if disk_tail_free_bytes == 0 {
        return None;
    }

    let reclaimable_span_bytes = disk_sectors.checked_sub(target_end)?.checked_mul(sector)?;
    let max_target_growth_bytes = reclaimable_span_bytes.checked_sub(swap_bytes)?;
    if max_target_growth_bytes == 0 {
        return None;
    }

    Some(LayoutOpportunity {
        code: "migrate-tail-swap".to_owned(),
        disk: disk_path.to_owned(),
        target: target_path.to_owned(),
        sector_size_bytes: sector,
        max_target_growth_bytes,
        disk_tail_free_bytes,
        swap_bytes,
        blocking_devices: vec![extended.node.clone(), swap_record.node.clone()],
    })
}

fn detect_layout_alternatives(
    snapshot: &HostSnapshot,
    request: &ExtendRequest,
) -> Vec<LayoutAlternative> {
    detect_tail_swap_migration(snapshot, request)
        .into_iter()
        .collect()
}

fn detect_tail_swap_migration(
    snapshot: &HostSnapshot,
    request: &ExtendRequest,
) -> Option<LayoutAlternative> {
    let Growth::ByBytes(requested_growth_bytes) = request.growth else {
        return None;
    };
    if requested_growth_bytes == 0 {
        return None;
    }

    let opportunity = analyze_layout_opportunity(snapshot, &request.target)?;
    let requested_sectors = requested_growth_bytes / opportunity.sector_size_bytes
        + u64::from(requested_growth_bytes % opportunity.sector_size_bytes != 0);
    let rounded_requested_bytes = requested_sectors.checked_mul(opportunity.sector_size_bytes)?;
    if rounded_requested_bytes > opportunity.max_target_growth_bytes {
        return None;
    }

    let required_partition_growth_bytes =
        rounded_requested_bytes.checked_add(opportunity.swap_bytes)?;
    let remaining_raw_tail_bytes = opportunity
        .max_target_growth_bytes
        .checked_sub(rounded_requested_bytes)?;
    let extended = opportunity.blocking_devices.first()?;
    let swap = opportunity.blocking_devices.get(1)?;

    Some(LayoutAlternative {
        code: opportunity.code.clone(),
        summary: format!(
            "{} bytes of disk-tail capacity are separated from {} by DOS extended/swap layout; preserving equivalent swap as a swapfile can make the requested filesystem growth possible",
            opportunity.disk_tail_free_bytes, opportunity.target
        ),
        disk: opportunity.disk.clone(),
        target: opportunity.target.clone(),
        requested_growth_bytes,
        disk_tail_free_bytes: opportunity.disk_tail_free_bytes,
        swap_bytes: opportunity.swap_bytes,
        required_partition_growth_bytes,
        remaining_raw_tail_bytes,
        blocking_devices: opportunity.blocking_devices.clone(),
        steps: vec![
            format!(
                "verify that {swap} is not used for hibernation/resume and that swap can be safely deactivated"
            ),
            "create and verify partition-table, fstab and resume-configuration backups".to_owned(),
            format!("deactivate swap on {swap}"),
            format!(
                "remove logical swap {swap} and its extended container {extended} only after swap migration is prepared"
            ),
            format!(
                "extend {} by {} bytes so the filesystem gains the requested capacity plus room for an equivalent swapfile",
                opportunity.target, required_partition_growth_bytes
            ),
            "grow the filesystem and verify its new size".to_owned(),
            format!(
                "create and activate a swapfile of {} bytes, update persistent swap configuration, and verify swap",
                opportunity.swap_bytes
            ),
            "rediscover the complete storage layout and verify no unexpected raw tail or identity changes".to_owned(),
        ],
    })
}

pub fn analyze_lvm_underlying_growth(
    snapshot: &HostSnapshot,
    request: &ExtendRequest,
) -> Option<GrowthRouteAlternative> {
    if request.target.is_empty() || request.target.chars().any(char::is_control) {
        return None;
    }
    for component in [
        "lsblk",
        "partition_tables",
        "mounts",
        "fstab",
        "swap",
        "lvm",
    ] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|status| status.component == component),
            "collector-incomplete",
        )
        .ok()?;
        if status.state != CollectorState::Complete {
            return None;
        }
    }
    if snapshot
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return None;
    }

    let lvm = snapshot.lvm.as_ref()?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let route = resolve_extend_route_adapter(snapshot, &request.target);
    if route.profile != ExtendPlannerProfile::Lvm {
        return None;
    }
    let resolved_device = route.resolved_device.as_deref()?;
    let resolved_lv_device = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| node_alias(device, resolved_device)),
        "ambiguous-device",
    )
    .ok()?;
    let lv = unique(
        lvm.logical_volumes
            .iter()
            .filter(|lv| lv_device(lv, resolved_lv_device)),
        "ambiguous-lv",
    )
    .ok()?;
    if resolved_lv_device.kind != NodeKind::Lvm
        || !resolved_lv_device.children.is_empty()
        || !supported_chain(&snapshot.storage.block_devices, resolved_lv_device, true)
        || lv.layout.as_deref() != Some("linear")
        || lv.role.as_deref() != Some("public")
        || lv.attributes.as_deref() != Some("-wi-ao----")
    {
        return None;
    }

    let fs = resolved_lv_device.filesystem.as_ref()?;
    if !matches!(fs.fs_type.as_str(), "ext4" | "xfs") {
        return None;
    }
    let mountpoint = route.mountpoint.as_deref()?;
    let mount = unique(
        snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == mountpoint),
        "mount-not-unique",
    )
    .ok()?;
    if !mount
        .source
        .as_deref()
        .is_some_and(|source| node_alias(resolved_lv_device, source) || lv_alias(lv, source))
        || mount.fs_type.as_deref() != Some(fs.fs_type.as_str())
        || !mount.options.iter().any(|option| option == "rw")
        || mount
            .options
            .iter()
            .any(|option| matches!(option.as_str(), "ro" | "bind" | "rbind"))
        || resolved_lv_device.mountpoints != vec![mount.target.clone()]
    {
        return None;
    }

    let vg = unique(
        lvm.volume_groups.iter().filter(|vg| vg.name == lv.vg_name),
        "ambiguous-vg",
    )
    .ok()?;
    if vg.attributes.as_deref() != Some("wz--n-")
        || vg.missing_pv_count != Some(0)
        || vg.pv_count != 1
    {
        return None;
    }
    let extent = vg.extent_size_bytes?;
    let free_extents = vg.free_extent_count?;
    if extent < 512
        || !extent.is_power_of_two()
        || free_extents.checked_mul(extent) != Some(vg.free_bytes)
        || vg.size_bytes % extent != 0
        || lv.size_bytes % extent != 0
    {
        return None;
    }

    let pv = unique(
        lvm.physical_volumes
            .iter()
            .filter(|pv| pv.vg_name.as_deref() == Some(vg.name.as_str())),
        "ambiguous-pv",
    )
    .ok()?;
    let pv_device = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| node_alias(device, &pv.name)),
        "pv-not-resolved",
    )
    .ok()?;
    if !matches!(
        pv_device.kind,
        NodeKind::Disk | NodeKind::Partition | NodeKind::Loop
    ) || !contains_device(pv_device, resolved_lv_device)
        || pv_device
            .filesystem
            .as_ref()
            .map(|filesystem| filesystem.fs_type.as_str())
            != Some("LVM2_member")
        || pv_device.uuid != pv.uuid
        || pv.pe_start_bytes.is_none()
        || pv.size_bytes
            > pv_device
                .size_bytes
                .saturating_sub(pv.pe_start_bytes.unwrap_or(0))
        || pv.size_bytes % extent != 0
        || pv.free_bytes != vg.free_bytes
    {
        return None;
    }

    let pv_pe_start_bytes = pv.pe_start_bytes?;
    let pv_usable_backing_bytes = pv_device.size_bytes.checked_sub(pv_pe_start_bytes)?;
    let pv_device_slack_bytes = pv_usable_backing_bytes.checked_sub(pv.size_bytes)?;
    let mut disk_path = pv_device
        .path
        .clone()
        .unwrap_or_else(|| pv_device.name.clone());
    let mut partition_path = None;
    let mut adjacent_partition_free_bytes = 0_u64;
    let mut sector_size_bytes = pv_device.logical_sector_bytes.unwrap_or(512);

    if pv_device.kind == NodeKind::Partition {
        let parent_name = pv_device.parent_kernel_name.as_deref()?;
        let disk = unique(
            nodes.iter().copied().filter(|candidate| {
                matches!(candidate.kind, NodeKind::Disk | NodeKind::Loop)
                    && candidate.kernel_name.as_deref() == Some(parent_name)
            }),
            "parent-not-resolved",
        )
        .ok()?;
        disk_path = disk.path.clone().unwrap_or_else(|| disk.name.clone());
        let pv_path = pv_device.path.as_deref()?;
        partition_path = Some(pv_path.to_owned());

        let table = unique(
            snapshot
                .partition_tables
                .iter()
                .filter(|table| table.device == disk_path),
            "partition-table-not-unique",
        )
        .ok()?;
        sector_size_bytes = table.sector_size_bytes?;
        if sector_size_bytes < 512
            || !sector_size_bytes.is_power_of_two()
            || pv_device.logical_sector_bytes != Some(sector_size_bytes)
        {
            return None;
        }
        let record = unique(
            table
                .partitions
                .iter()
                .filter(|record| record.node == pv_path),
            "partition-record-not-unique",
        )
        .ok()?;
        let record_size_bytes = record.size_sectors.checked_mul(sector_size_bytes)?;
        let record_start_bytes = record.start_sector.checked_mul(sector_size_bytes)?;
        if record_size_bytes != pv_device.size_bytes
            || pv_device
                .start_512_sector
                .and_then(|start| start.checked_mul(512))
                != Some(record_start_bytes)
        {
            return None;
        }
        adjacent_partition_free_bytes = adjacent_free_sectors(disk, table, record)
            .ok()?
            .checked_mul(sector_size_bytes)?;
    }

    let underlying_bytes = pv_device_slack_bytes.checked_add(adjacent_partition_free_bytes)?;
    let additional_extents = underlying_bytes / extent;
    if additional_extents == 0 {
        return None;
    }
    let max_growth_bytes = free_extents
        .checked_add(additional_extents)?
        .checked_mul(extent)?;
    if max_growth_bytes <= vg.free_bytes {
        return None;
    }

    let requested_growth_bytes = match request.growth {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => max_growth_bytes,
    };
    if requested_growth_bytes == 0 {
        return None;
    }
    let requested_extents =
        requested_growth_bytes / extent + u64::from(requested_growth_bytes % extent != 0);
    if requested_extents <= free_extents
        || requested_extents > free_extents.checked_add(additional_extents)?
    {
        return None;
    }

    let required_new_extents = requested_extents.checked_sub(free_extents)?;
    let required_pv_growth_bytes = required_new_extents.checked_mul(extent)?;
    let raw_partition_growth_bytes = required_pv_growth_bytes.saturating_sub(pv_device_slack_bytes);
    let required_partition_growth_bytes = if raw_partition_growth_bytes == 0 {
        0
    } else {
        let sectors = raw_partition_growth_bytes / sector_size_bytes
            + u64::from(raw_partition_growth_bytes % sector_size_bytes != 0);
        sectors.checked_mul(sector_size_bytes)?
    };
    if required_partition_growth_bytes > adjacent_partition_free_bytes {
        return None;
    }

    let lv_path = lv
        .path
        .clone()
        .unwrap_or_else(|| format!("/dev/{}/{}", lv.vg_name, lv.name));
    let mut steps = vec![
        "revalidate the complete storage snapshot and exact device identities".to_owned(),
        "create and verify LVM metadata backup".to_owned(),
    ];
    if required_partition_growth_bytes > 0 {
        steps.push("create and verify partition-table metadata backup".to_owned());
        steps.push(format!(
            "extend {} by {} bytes without moving its start sector",
            partition_path.as_deref()?,
            required_partition_growth_bytes
        ));
        steps.push("notify/revalidate the kernel partition geometry".to_owned());
    }
    steps.push(format!(
        "resize LVM PV {} to consume the verified larger backing device",
        pv.name
    ));
    steps.push(format!(
        "extend logical volume {lv_path} by the requested extent-aligned capacity"
    ));
    steps.push(format!(
        "grow {} filesystem mounted at {}",
        fs.fs_type, mount.target
    ));
    steps.push("rediscover and verify every layer and the final filesystem size".to_owned());

    Some(GrowthRouteAlternative {
        code: if required_partition_growth_bytes > 0 {
            "grow-partition-pv-lv-filesystem".to_owned()
        } else {
            "grow-pv-lv-filesystem".to_owned()
        },
        summary: if required_partition_growth_bytes > 0 {
            "verified raw capacity can be routed through partition -> PV -> VG -> LV -> filesystem"
                .to_owned()
        } else {
            "the PV backing device is already larger than the PV; capacity can be routed through PV -> VG -> LV -> filesystem"
                .to_owned()
        },
        target: request.target.clone(),
        disk: disk_path,
        partition: partition_path,
        physical_volume: pv.name.clone(),
        volume_group: vg.name.clone(),
        logical_volume: lv_path,
        extent_size_bytes: extent,
        sector_size_bytes,
        existing_vg_free_bytes: vg.free_bytes,
        pv_device_slack_bytes,
        adjacent_partition_free_bytes,
        max_growth_bytes,
        requested_growth_bytes,
        required_partition_growth_bytes,
        steps,
    })
}

fn build_lvm_underlying_growth_candidate(
    snapshot: &HostSnapshot,
    request: &ExtendRequest,
) -> Option<(
    GrowthRouteAlternative,
    SizeChange,
    Option<PartitionSizeChange>,
    Vec<PlanStep>,
)> {
    let route = analyze_lvm_underlying_growth(snapshot, request)?;
    let lvm = snapshot.lvm.as_ref()?;
    let pv = unique(
        lvm.physical_volumes
            .iter()
            .filter(|pv| pv.name == route.physical_volume),
        "ambiguous-pv",
    )
    .ok()?;
    let vg = unique(
        lvm.volume_groups
            .iter()
            .filter(|vg| vg.name == route.volume_group),
        "ambiguous-vg",
    )
    .ok()?;
    let lv = unique(
        lvm.logical_volumes
            .iter()
            .filter(|lv| lv_alias(lv, &route.logical_volume)),
        "ambiguous-lv",
    )
    .ok()?;

    let extent = route.extent_size_bytes;
    if extent == 0 || route.existing_vg_free_bytes % extent != 0 {
        return None;
    }
    let existing_free_extents = route.existing_vg_free_bytes / extent;
    let requested_extents = route.requested_growth_bytes / extent
        + u64::from(route.requested_growth_bytes % extent != 0);
    let additional_pv_extents = requested_extents.checked_sub(existing_free_extents)?;
    if additional_pv_extents == 0 {
        return None;
    }
    let pv_growth_bytes = additional_pv_extents.checked_mul(extent)?;
    let expected_pv_size_bytes = pv.size_bytes.checked_add(pv_growth_bytes)?;
    let rounded_growth_bytes = requested_extents.checked_mul(extent)?;
    let expected_lv_size_bytes = lv.size_bytes.checked_add(rounded_growth_bytes)?;

    let adapter = resolve_extend_route_adapter(snapshot, &request.target);
    let resolved_device = adapter.resolved_device.as_deref()?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let lv_device = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| node_alias(device, resolved_device)),
        "ambiguous-device",
    )
    .ok()?;
    let fs = lv_device.filesystem.as_ref()?;
    let mountpoint = adapter.mountpoint?;

    let size = SizeChange {
        device: route.logical_volume.clone(),
        current_lv_size_bytes: lv.size_bytes,
        requested_growth_bytes: route.requested_growth_bytes,
        rounded_growth_bytes,
        expected_lv_size_bytes,
        extent_size_bytes: extent,
        remaining_vg_free_bytes: 0,
    };

    let mut next_id = 1_u32;
    let mut steps = vec![step(
        next_id,
        Operation::RevalidateSnapshot,
        Reversibility::NotApplicable,
    )];
    next_id += 1;
    steps.push(step(
        next_id,
        Operation::BackupLvmMetadata {
            vg_uuid: vg.uuid.clone()?,
        },
        Reversibility::Reversible,
    ));
    next_id += 1;

    let partition_size_change = if route.required_partition_growth_bytes > 0 {
        let partition = route.partition.as_deref()?;
        let table = unique(
            snapshot
                .partition_tables
                .iter()
                .filter(|table| table.device == route.disk),
            "partition-table-not-unique",
        )
        .ok()?;
        let label = table.label.clone()?;
        let sector = table.sector_size_bytes?;
        if sector != route.sector_size_bytes || route.required_partition_growth_bytes % sector != 0
        {
            return None;
        }
        let record = unique(
            table
                .partitions
                .iter()
                .filter(|record| record.node == partition),
            "partition-record-not-unique",
        )
        .ok()?;
        ensure_partition_role_is_growable(table, record).ok()?;

        let growth_sectors = route.required_partition_growth_bytes / sector;
        let new_size_sectors = record.size_sectors.checked_add(growth_sectors)?;
        let current_partition_size_bytes = record.size_sectors.checked_mul(sector)?;
        let expected_partition_size_bytes = new_size_sectors.checked_mul(sector)?;
        let remaining_adjacent_free_bytes = route
            .adjacent_partition_free_bytes
            .checked_sub(route.required_partition_growth_bytes)?;

        steps.push(step(
            next_id,
            Operation::BackupPartitionTableMetadata {
                disk: route.disk.clone(),
                table_label: label,
                table_id: table.id.clone(),
            },
            Reversibility::Reversible,
        ));
        next_id += 1;
        steps.push(step(
            next_id,
            Operation::ExtendPartition {
                partition: partition.to_owned(),
                start_sector: record.start_sector,
                old_size_sectors: record.size_sectors,
                new_size_sectors,
                sector_size_bytes: sector,
            },
            Reversibility::Irreversible,
        ));
        next_id += 1;

        Some(PartitionSizeChange {
            device: partition.to_owned(),
            disk: route.disk.clone(),
            current_partition_size_bytes,
            requested_growth_bytes: route.required_partition_growth_bytes,
            rounded_growth_bytes: route.required_partition_growth_bytes,
            expected_partition_size_bytes,
            sector_size_bytes: sector,
            remaining_adjacent_free_bytes,
        })
    } else {
        None
    };

    steps.push(step(
        next_id,
        Operation::ResizePhysicalVolume {
            pv_uuid: pv.uuid.clone()?,
            expected_pv_size_bytes,
        },
        Reversibility::Irreversible,
    ));
    next_id += 1;
    steps.push(step(
        next_id,
        Operation::ExtendLogicalVolume {
            lv_uuid: lv.uuid.clone()?,
            additional_extents: requested_extents,
            expected_lv_size_bytes,
        },
        Reversibility::Irreversible,
    ));
    next_id += 1;
    steps.push(step(
        next_id,
        Operation::GrowFilesystem {
            fs_type: fs.fs_type.clone(),
            mountpoint,
        },
        Reversibility::Irreversible,
    ));
    next_id += 1;
    steps.push(step(
        next_id,
        Operation::RediscoverAndVerify,
        Reversibility::NotApplicable,
    ));

    Some((route, size, partition_size_change, steps))
}

fn adjacent_free_sectors(
    disk: &BlockDevice,
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
) -> Result<u64, Blocker> {
    let sector = table
        .sector_size_bytes
        .ok_or_else(|| blocked("sector-size-missing", "partition sector size is unknown"))?;
    let disk_sectors = disk.size_bytes / sector;
    let label = table.label.as_deref().ok_or_else(|| {
        blocked(
            "partition-label-missing",
            "partition table label is unknown",
        )
    })?;

    match label {
        "dos" => adjacent_free_dos(table, target, disk_sectors),
        "gpt" => adjacent_free_gpt(table, target),
        _ => Err(blocked(
            "unsupported-partition-table",
            "direct partition preview supports only DOS/MBR and GPT",
        )),
    }
}

fn adjacent_free_gpt(
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
) -> Result<u64, Blocker> {
    let first = table
        .first_lba
        .ok_or_else(|| blocked("gpt-bounds-missing", "GPT first usable LBA is unknown"))?;
    let last = table
        .last_lba
        .ok_or_else(|| blocked("gpt-bounds-missing", "GPT last usable LBA is unknown"))?;
    let limit = last
        .checked_add(1)
        .ok_or_else(|| blocked("size-overflow", "GPT usable limit exceeds u64"))?;

    let mut ranges = Vec::new();
    for record in &table.partitions {
        let end = record
            .start_sector
            .checked_add(record.size_sectors)
            .ok_or_else(|| blocked("size-overflow", "partition range exceeds u64"))?;
        ensure(
            record.size_sectors > 0 && record.start_sector >= first && end <= limit,
            "invalid-partition-range",
            "GPT partition lies outside the usable range",
        )?;
        ranges.push((record.start_sector, end, record.node.as_str()));
    }
    ranges.sort_unstable();
    ensure(
        !ranges.windows(2).any(|pair| pair[0].1 > pair[1].0),
        "overlapping-partitions",
        "GPT partition ranges overlap",
    )?;
    adjacent_from_ranges(&ranges, target, limit)
}

fn adjacent_free_dos(
    table: &PartitionTable,
    target: &lsm_core::PartitionRecord,
    disk_sectors: u64,
) -> Result<u64, Blocker> {
    let limit = disk_sectors.min(u64::from(u32::MAX) + 1);
    let mut extended = Vec::new();
    for record in &table.partitions {
        let kind =
            parse_dos_type(record.partition_type.as_deref().ok_or_else(|| {
                blocked("partition-type-missing", "DOS partition type is unknown")
            })?)?;
        if matches!(kind, 0x05 | 0x0f | 0x85) {
            let end = record
                .start_sector
                .checked_add(record.size_sectors)
                .ok_or_else(|| blocked("size-overflow", "extended range exceeds u64"))?;
            extended.push((record.start_sector, end, record.node.as_str()));
        }
    }
    ensure(
        extended.len() <= 1,
        "unsupported-dos-layout",
        "multiple extended partition containers are not supported",
    )?;

    let target_kind = parse_dos_type(
        target
            .partition_type
            .as_deref()
            .ok_or_else(|| blocked("partition-type-missing", "DOS partition type is unknown"))?,
    )?;
    ensure(
        !matches!(target_kind, 0x05 | 0x0f | 0x85),
        "unsupported-dos-layout",
        "extended partition containers cannot be grown as filesystem targets",
    )?;
    if let Some((ext_start, ext_end, _)) = extended.first() {
        ensure(
            !(target.start_sector >= *ext_start
                && target
                    .start_sector
                    .checked_add(target.size_sectors)
                    .is_some_and(|end| end <= *ext_end)),
            "unsupported-logical-partition",
            "logical partition growth inside an extended container is not supported",
        )?;
    }

    let mut primary = Vec::new();
    for record in &table.partitions {
        let end = record
            .start_sector
            .checked_add(record.size_sectors)
            .ok_or_else(|| blocked("size-overflow", "partition range exceeds u64"))?;
        ensure(
            record.size_sectors > 0 && record.start_sector >= 1 && end <= limit,
            "invalid-partition-range",
            "DOS partition lies outside the addressable range",
        )?;
        let kind =
            parse_dos_type(record.partition_type.as_deref().ok_or_else(|| {
                blocked("partition-type-missing", "DOS partition type is unknown")
            })?)?;
        ensure(
            kind != 0x00 && kind != 0xee,
            "unsupported-dos-layout",
            "empty/protective DOS partition types are not supported",
        )?;

        let inside_extended = extended.first().is_some_and(|(start, finish, node)| {
            record.node != *node && record.start_sector >= *start && end <= *finish
        });
        if !inside_extended {
            primary.push((record.start_sector, end, record.node.as_str()));
        }
    }
    primary.sort_unstable();
    ensure(
        !primary.windows(2).any(|pair| pair[0].1 > pair[1].0),
        "overlapping-partitions",
        "DOS primary/extended partition ranges overlap",
    )?;
    adjacent_from_ranges(&primary, target, limit)
}

fn adjacent_from_ranges(
    ranges: &[(u64, u64, &str)],
    target: &lsm_core::PartitionRecord,
    limit: u64,
) -> Result<u64, Blocker> {
    let index = ranges
        .iter()
        .position(|range| range.2 == target.node)
        .ok_or_else(|| {
            blocked(
                "target-not-primary",
                "target partition is not a supported boundary",
            )
        })?;
    let end = ranges[index].1;
    let next = ranges.get(index + 1).map_or(limit, |range| range.0);
    next.checked_sub(end).ok_or_else(|| {
        blocked(
            "overlapping-partitions",
            "next partition overlaps the target",
        )
    })
}

fn parse_dos_type(raw: &str) -> Result<u8, Blocker> {
    let trimmed = raw.trim();
    let normalized = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u8::from_str_radix(normalized, 16)
        .map_err(|_| blocked("invalid-partition-type", "DOS partition type is invalid"))
}

fn build_candidate(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    request: &ExtendRequest,
) -> Result<(SizeChange, Vec<PlanStep>), Blocker> {
    // Missing collector records are NOT treated as successful discovery.
    for component in [
        "lsblk",
        "partition_tables",
        "mounts",
        "fstab",
        "swap",
        "lvm",
    ] {
        let status = unique(
            snapshot
                .collectors
                .iter()
                .filter(|s| s.component == component),
            "collector-incomplete",
        )?;
        ensure(
            status.state == CollectorState::Complete,
            "collector-incomplete",
            "all six collectors must complete for the initial preview profile",
        )?;
    }
    ensure(
        !snapshot
            .diagnostics
            .iter()
            .any(|d| d.severity == DiagnosticSeverity::Error),
        "diagnostic-error",
        "the snapshot contains error-level diagnostics",
    )?;
    ensure(
        !request.target.is_empty() && !request.target.chars().any(char::is_control),
        "invalid-target",
        "target must be a nonempty device path or exact mountpoint",
    )?;

    let lvm = snapshot
        .lvm
        .as_ref()
        .ok_or_else(|| blocked("lvm-missing", "LVM inventory is absent"))?;
    let nodes = flatten(&snapshot.storage.block_devices);
    let route = resolve_extend_route_adapter(snapshot, &request.target);
    ensure(
        route.profile == ExtendPlannerProfile::Lvm,
        "route-profile-mismatch",
        "LVM builder received a non-LVM semantic route",
    )?;
    let resolved_device = route.resolved_device.as_deref().ok_or_else(|| {
        blocked(
            "route-device-not-found",
            "LVM target did not resolve to one logical-volume device",
        )
    })?;
    let device = unique(
        nodes
            .iter()
            .copied()
            .filter(|device| node_alias(device, resolved_device)),
        "ambiguous-device",
    )?;
    let lv = unique(
        lvm.logical_volumes
            .iter()
            .filter(|lv| lv_device(lv, device)),
        "ambiguous-lv",
    )?;
    ensure(
        device.kind == NodeKind::Lvm,
        "unsupported-layout",
        "target must be an LVM logical volume",
    )?;
    ensure(
        device.children.is_empty(),
        "unsupported-layout",
        "stacked consumers above the LV are not supported",
    )?;
    ensure(
        supported_chain(&snapshot.storage.block_devices, device, true),
        "unsupported-layout",
        "encrypted, RAID, multipath or unknown ancestor layers are not supported",
    )?;
    ensure(
        lv.layout.as_deref() == Some("linear")
            && lv.role.as_deref() == Some("public")
            && lv.attributes.as_deref() == Some("-wi-ao----"),
        "unsupported-lv",
        "M1A requires a public, linear, writable, active LV with normal inherited allocation",
    )?;
    let vg = unique(
        lvm.volume_groups.iter().filter(|v| v.name == lv.vg_name),
        "ambiguous-vg",
    )?;
    ensure(
        vg.attributes.as_deref() == Some("wz--n-") && vg.missing_pv_count == Some(0),
        "unsupported-vg",
        "VG must be local, writable, resizable, nonpartial and nonshared",
    )?;
    ensure(
        vg.pv_count == 1,
        "multi-pv-not-supported",
        "M1A previews are limited to a single-PV VG",
    )?;
    let pv = unique(
        lvm.physical_volumes
            .iter()
            .filter(|p| p.vg_name.as_deref() == Some(vg.name.as_str())),
        "ambiguous-pv",
    )?;
    let pv_device = unique(
        nodes.iter().copied().filter(|d| node_alias(d, &pv.name)),
        "pv-not-resolved",
    )?;
    ensure(
        matches!(
            pv_device.kind,
            NodeKind::Disk | NodeKind::Partition | NodeKind::Loop
        ) && contains_device(pv_device, device)
            && pv_device.filesystem.as_ref().map(|fs| fs.fs_type.as_str()) == Some("LVM2_member"),
        "pv-topology-mismatch",
        "the PV must be the verified ancestor of this LV",
    )?;
    for id in [&pv.uuid, &vg.uuid, &lv.uuid, &device.uuid] {
        ensure(
            id.as_deref().is_some_and(|s| !s.is_empty()),
            "identity-missing",
            "PV, VG, LV and filesystem UUIDs are required",
        )?;
    }
    ensure(
        pv_device.uuid == pv.uuid,
        "pv-uuid-mismatch",
        "lsblk and LVM disagree on the PV UUID",
    )?;
    ensure(
        lv.size_bytes == device.size_bytes
            && lv.size_bytes > 0
            && pv.size_bytes <= pv_device.size_bytes
            && vg.size_bytes <= pv.size_bytes
            && vg.free_bytes <= vg.size_bytes
            && pv.free_bytes == vg.free_bytes,
        "capacity-mismatch",
        "LVM and block-device capacities are inconsistent",
    )?;

    let fs = device
        .filesystem
        .as_ref()
        .ok_or_else(|| blocked("filesystem-missing", "filesystem type is absent"))?;
    ensure(
        matches!(fs.fs_type.as_str(), "ext4" | "xfs"),
        "unsupported-filesystem",
        "filesystem is unsupported; only ext4 and XFS previews are supported",
    )?;
    let mountpoint = route
        .mountpoint
        .as_deref()
        .ok_or_else(|| blocked("mount-not-unique", "LVM target is not uniquely mounted"))?;
    let mount = unique(
        snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == mountpoint),
        "mount-not-unique",
    )?;
    ensure(
        mount
            .source
            .as_deref()
            .is_some_and(|source| node_alias(device, source) || lv_alias(lv, source))
            && mount.fs_type.as_deref() == Some(fs.fs_type.as_str())
            && mount.options.iter().any(|o| o == "rw")
            && !mount
                .options
                .iter()
                .any(|o| matches!(o.as_str(), "ro" | "bind" | "rbind"))
            && device.mountpoints == vec![mount.target.clone()]
            && snapshot
                .mounts
                .iter()
                .filter(|m| m.target == mount.target)
                .count()
                == 1,
        "mount-state-mismatch",
        "one matching read-write mount must be confirmed by lsblk and findmnt",
    )?;
    ensure(
        !snapshot
            .swaps
            .iter()
            .any(|s| node_alias(device, &s.name) || lv_alias(lv, &s.name)),
        "active-swap",
        "the target is reported as active swap",
    )?;
    for tool in [
        "vgcfgbackup",
        "lvextend",
        if fs.fs_type == "xfs" {
            "xfs_growfs"
        } else {
            "resize2fs"
        },
    ] {
        let capability = unique(
            capabilities.tools.iter().filter(|t| t.name == tool),
            "tool-unavailable",
        )?;
        ensure(
            capability.available,
            "tool-unavailable",
            "a required future operation tool is unavailable",
        )?;
    }
    let extent = vg
        .extent_size_bytes
        .ok_or_else(|| blocked("extent-missing", "VG extent size is unknown"))?;
    let free_extents = vg
        .free_extent_count
        .ok_or_else(|| blocked("extent-missing", "free extent count is unknown"))?;
    ensure(
        extent >= 512 && extent.is_power_of_two(),
        "invalid-extent",
        "invalid VG extent size",
    )?;
    ensure(
        free_extents.checked_mul(extent) == Some(vg.free_bytes)
            && vg.size_bytes % extent == 0
            && lv.size_bytes % extent == 0,
        "extent-mismatch",
        "reported bytes and extent counts do not agree",
    )?;
    let requested = match request.growth {
        Growth::ByBytes(bytes) => bytes,
        Growth::MaxFree => vg.free_bytes,
    };
    ensure(
        requested > 0,
        "no-growth",
        "requested growth or existing VG free capacity is zero",
    )?;
    let extents = requested / extent + u64::from(requested % extent != 0);
    ensure(extents <= free_extents, "insufficient-capacity", "extent-rounded request exceeds existing VG free space; partition/PV resize is not attempted")?;
    let rounded = extents
        .checked_mul(extent)
        .ok_or_else(|| blocked("size-overflow", "growth exceeds u64"))?;
    let new_size = lv
        .size_bytes
        .checked_add(rounded)
        .ok_or_else(|| blocked("size-overflow", "new LV size exceeds u64"))?;
    let size = SizeChange {
        device: device.path.clone().unwrap_or_else(|| device.name.clone()),
        current_lv_size_bytes: lv.size_bytes,
        requested_growth_bytes: requested,
        rounded_growth_bytes: rounded,
        expected_lv_size_bytes: new_size,
        extent_size_bytes: extent,
        remaining_vg_free_bytes: vg.free_bytes - rounded,
    };
    let steps = vec![
        step(
            1,
            Operation::RevalidateSnapshot,
            Reversibility::NotApplicable,
        ),
        step(
            2,
            Operation::BackupLvmMetadata {
                vg_uuid: vg.uuid.clone().unwrap_or_default(),
            },
            Reversibility::Reversible,
        ),
        step(
            3,
            Operation::ExtendLogicalVolume {
                lv_uuid: lv.uuid.clone().unwrap_or_default(),
                additional_extents: extents,
                expected_lv_size_bytes: new_size,
            },
            Reversibility::Irreversible,
        ),
        step(
            4,
            Operation::GrowFilesystem {
                fs_type: fs.fs_type.clone(),
                mountpoint: mount.target.clone(),
            },
            Reversibility::Irreversible,
        ),
        step(
            5,
            Operation::RediscoverAndVerify,
            Reversibility::NotApplicable,
        ),
    ];
    Ok((size, steps))
}

fn step(id: u32, operation: Operation, reversibility: Reversibility) -> PlanStep {
    PlanStep {
        id,
        depends_on: if id == 1 { Vec::new() } else { vec![id - 1] },
        operation,
        reversibility,
    }
}

fn flatten(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    let mut nodes = Vec::new();
    for device in devices {
        nodes.push(device);
        nodes.extend(flatten(&device.children));
    }
    nodes
}

fn node_alias(device: &BlockDevice, alias: &str) -> bool {
    device.path.as_deref() == Some(alias)
        || device
            .kernel_name
            .as_ref()
            .is_some_and(|n| format!("/dev/{n}") == alias)
}

fn lv_alias(lv: &LvmLogicalVolume, alias: &str) -> bool {
    lv.path.as_deref() == Some(alias)
        || format!("/dev/{}/{}", lv.vg_name, lv.name) == alias
        || format!(
            "/dev/mapper/{}-{}",
            lv.vg_name.replace('-', "--"),
            lv.name.replace('-', "--")
        ) == alias
}

fn lv_device(lv: &LvmLogicalVolume, device: &BlockDevice) -> bool {
    device
        .path
        .as_deref()
        .is_some_and(|path| lv_alias(lv, path))
}

fn contains_device(parent: &BlockDevice, target: &BlockDevice) -> bool {
    parent
        .children
        .iter()
        .any(|child| std::ptr::eq(child, target) || contains_device(child, target))
}

fn supported_chain(devices: &[BlockDevice], target: &BlockDevice, safe: bool) -> bool {
    devices.iter().any(|device| {
        if std::ptr::eq(device, target) {
            return safe;
        }
        let safe = safe
            && matches!(
                device.kind,
                NodeKind::Disk | NodeKind::Partition | NodeKind::Loop
            );
        supported_chain(&device.children, target, safe)
    })
}
