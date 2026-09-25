use lsm_core::{
    BlockDevice, DiagnosticSeverity, FilesystemProbeState, HostCapabilities, HostSnapshot,
};
use serde::Serialize;

use crate::{analyze_layer_route, LayerRouteStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemDecisionState {
    ReadyOnlineGrow,
    ReadyOfflineGrow,
    ReadOnlyHealthCheckRequired,
    OfflineHealthCheckRequired,
    MountRequired,
    Blocked,
    AdapterRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemCheckKind {
    Ext4OfflineE2fsckNoModify,
    XfsMountedScrubNoModify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadOnlyFilesystemCheck {
    pub kind: FilesystemCheckKind,
    pub tool: String,
    pub args: Vec<String>,
    pub requires_mounted: bool,
    pub requires_unmounted: bool,
    pub run_automatically_on_refresh: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilesystemGrowthDecision {
    pub target: String,
    pub device: Option<String>,
    pub mountpoint: Option<String>,
    pub fs_type: Option<String>,
    pub state: FilesystemDecisionState,
    pub metadata_state: Option<FilesystemProbeState>,
    pub read_only_check: Option<ReadOnlyFilesystemCheck>,
    pub reasons: Vec<String>,
    pub required_actions: Vec<String>,
}

impl FilesystemGrowthDecision {
    pub fn execution_ready(&self) -> bool {
        matches!(
            self.state,
            FilesystemDecisionState::ReadyOnlineGrow | FilesystemDecisionState::ReadyOfflineGrow
        )
    }
}

pub fn decide_filesystem_growth(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    target: &str,
) -> FilesystemGrowthDecision {
    let route = analyze_layer_route(snapshot, target);
    let mut decision = FilesystemGrowthDecision {
        target: target.to_owned(),
        device: route.resolved_device.clone(),
        mountpoint: route.mountpoint.clone(),
        fs_type: None,
        state: FilesystemDecisionState::Blocked,
        metadata_state: None,
        read_only_check: None,
        reasons: Vec::new(),
        required_actions: Vec::new(),
    };

    if route.status == LayerRouteStatus::Blocked {
        decision.reasons.push(
            route
                .issues
                .first()
                .map(|issue| format!("[{}] {}", issue.code, issue.message))
                .unwrap_or_else(|| "target storage route is unresolved".to_owned()),
        );
        return decision;
    }

    let Some(resolved_device) = route.resolved_device.as_deref() else {
        decision
            .reasons
            .push("target did not resolve to one filesystem device".to_owned());
        return decision;
    };
    let Some(device) = flatten(&snapshot.storage.block_devices)
        .into_iter()
        .find(|device| device_path(device) == resolved_device)
    else {
        decision
            .reasons
            .push("resolved filesystem device is absent from the storage graph".to_owned());
        return decision;
    };
    let Some(filesystem) = device.filesystem.as_ref() else {
        decision
            .reasons
            .push("resolved target has no filesystem type".to_owned());
        return decision;
    };
    decision.fs_type = Some(filesystem.fs_type.clone());

    if has_target_error_diagnostic(snapshot, &route) {
        decision.reasons.push(
            "an error-level diagnostic affects the selected storage route; filesystem growth is blocked"
                .to_owned(),
        );
        return decision;
    }

    let active_mount = route.mountpoint.as_deref().and_then(|mountpoint| {
        let matches: Vec<_> = snapshot
            .mounts
            .iter()
            .filter(|mount| mount.target == mountpoint)
            .collect();
        (matches.len() == 1).then_some(matches[0])
    });

    match filesystem.fs_type.as_str() {
        "ext4" => decide_ext4(snapshot, capabilities, device, active_mount, &mut decision),
        "xfs" => decide_xfs(snapshot, capabilities, device, active_mount, &mut decision),
        other => {
            decision.state = FilesystemDecisionState::AdapterRequired;
            decision.reasons.push(format!(
                "filesystem {other} has no executor-grade growth decision policy"
            ));
        }
    }

    decision
}

fn decide_ext4(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    device: &BlockDevice,
    mount: Option<&lsm_core::MountEntry>,
    decision: &mut FilesystemGrowthDecision,
) {
    if !tool_available(capabilities, "resize2fs") {
        decision
            .reasons
            .push("resize2fs is unavailable or capability discovery is ambiguous".to_owned());
        return;
    }

    if let Some(mount) = mount {
        if !mount_is_normal_read_write(mount) {
            decision
                .reasons
                .push("ext4 target is not mounted in a normal read-write mode".to_owned());
            return;
        }

        let evidence = exact_evidence(snapshot, device, Some(&mount.target), "ext4");
        let Some(evidence) = evidence else {
            decision.required_actions.push(
                "collect one exact read-only tune2fs metadata record for the mounted ext4 target"
                    .to_owned(),
            );
            decision.reasons.push(
                "ext4 metadata evidence is missing or ambiguous; mounted e2fsck output is not accepted as a health decision"
                    .to_owned(),
            );
            return;
        };
        decision.metadata_state = Some(evidence.state);

        if evidence.state != FilesystemProbeState::Verified {
            decision.required_actions.push(
                "resolve the ext4 metadata probe failure before planning execution".to_owned(),
            );
            decision
                .reasons
                .push("tune2fs metadata evidence is unavailable, partial or failed".to_owned());
            return;
        }

        let state = evidence
            .filesystem_state
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        let version_observed = evidence
            .fs_version
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || evidence
                .revision
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty());
        let features_observed = !evidence.features.is_empty();

        if !version_observed || !features_observed {
            decision.required_actions.push(
                "collect complete ext4 version/revision and filesystem feature evidence".to_owned(),
            );
            decision
                .reasons
                .push("ext4 metadata evidence is incomplete".to_owned());
            return;
        }

        if state.eq_ignore_ascii_case("clean") {
            decision.state = FilesystemDecisionState::ReadyOnlineGrow;
            decision.reasons.push(
                "mounted ext4 is read-write, superblock metadata reports clean state, and online resize tooling is available"
                    .to_owned(),
            );
            decision.required_actions.push(
                "do not run e2fsck on the mounted filesystem as an execution gate; revalidate target identity immediately before resize"
                    .to_owned(),
            );
            return;
        }

        decision.state = FilesystemDecisionState::OfflineHealthCheckRequired;
        decision.read_only_check = ext4_offline_check(device);
        decision.reasons.push(format!(
            "ext4 superblock state is {:?}; require an unmounted read-only e2fsck decision before mutation",
            evidence.filesystem_state
        ));
        decision.required_actions.push(
            "unmount the target in an explicit maintenance step before the read-only e2fsck check"
                .to_owned(),
        );
        return;
    }

    if !tool_available(capabilities, "e2fsck") {
        decision.reasons.push(
            "unmounted ext4 requires an offline read-only health check, but e2fsck is unavailable"
                .to_owned(),
        );
        return;
    }

    decision.state = FilesystemDecisionState::OfflineHealthCheckRequired;
    decision.read_only_check = ext4_offline_check(device);
    decision
        .reasons
        .push("unmounted ext4 requires a read-only e2fsck decision before resize".to_owned());
}

fn decide_xfs(
    snapshot: &HostSnapshot,
    capabilities: &HostCapabilities,
    device: &BlockDevice,
    mount: Option<&lsm_core::MountEntry>,
    decision: &mut FilesystemGrowthDecision,
) {
    if !tool_available(capabilities, "xfs_growfs") {
        decision
            .reasons
            .push("xfs_growfs is unavailable or capability discovery is ambiguous".to_owned());
        return;
    }

    let Some(mount) = mount else {
        decision.state = FilesystemDecisionState::MountRequired;
        decision
            .reasons
            .push("XFS must be mounted before it can be grown".to_owned());
        decision.required_actions.push(
            "mount the exact XFS target in a validated read-write state before growth".to_owned(),
        );
        return;
    };

    if !mount_is_normal_read_write(mount) {
        decision
            .reasons
            .push("XFS target is not mounted in a normal read-write mode".to_owned());
        return;
    }

    let evidence = exact_evidence(snapshot, device, Some(&mount.target), "xfs");
    let Some(evidence) = evidence else {
        decision.required_actions.push(
            "collect one exact xfs_info/xfs_growfs -n evidence record for the target".to_owned(),
        );
        decision
            .reasons
            .push("XFS dry-run growth evidence is missing or ambiguous".to_owned());
        return;
    };
    decision.metadata_state = Some(evidence.state);

    if evidence.grow_check_passed != Some(true) {
        decision
            .reasons
            .push("xfs_growfs -n did not positively validate the target growth path".to_owned());
        return;
    }

    decision.state = FilesystemDecisionState::ReadyOnlineGrow;
    decision.read_only_check = None;
    decision.reasons.push(
        "exact mounted read-write XFS growth path passed xfs_growfs -n; online growth is ready"
            .to_owned(),
    );
    if !tool_available(capabilities, "xfs_scrub") {
        decision.reasons.push(
            "xfs_scrub is unavailable; online metadata scrub is optional diagnostic evidence and is not required for XFS growth admission"
                .to_owned(),
        );
    }
}

fn ext4_offline_check(device: &BlockDevice) -> Option<ReadOnlyFilesystemCheck> {
    let path = device.path.as_ref()?;
    Some(ReadOnlyFilesystemCheck {
        kind: FilesystemCheckKind::Ext4OfflineE2fsckNoModify,
        tool: "e2fsck".to_owned(),
        args: vec!["-f".to_owned(), "-n".to_owned(), path.clone()],
        requires_mounted: false,
        requires_unmounted: true,
        run_automatically_on_refresh: false,
        rationale:
            "e2fsck results on a mounted filesystem are not accepted; run the no-modify check only while unmounted"
                .to_owned(),
    })
}

fn exact_evidence<'a>(
    snapshot: &'a HostSnapshot,
    device: &BlockDevice,
    mountpoint: Option<&str>,
    fs_type: &str,
) -> Option<&'a lsm_core::FilesystemPreflightEvidence> {
    let path = device.path.as_deref().unwrap_or(&device.name);
    let matches: Vec<_> = snapshot
        .filesystem_preflight
        .iter()
        .filter(|evidence| {
            evidence.fs_type == fs_type
                && (evidence.device == path
                    || mountpoint.is_some_and(|mountpoint| {
                        evidence.mountpoint.as_deref() == Some(mountpoint)
                    }))
        })
        .collect();
    (matches.len() == 1).then(|| matches[0])
}

fn mount_is_normal_read_write(mount: &lsm_core::MountEntry) -> bool {
    mount.options.iter().any(|option| option == "rw")
        && !mount
            .options
            .iter()
            .any(|option| matches!(option.as_str(), "ro" | "bind" | "rbind"))
}

fn tool_available(capabilities: &HostCapabilities, name: &str) -> bool {
    let matches: Vec<_> = capabilities
        .tools
        .iter()
        .filter(|tool| tool.name == name)
        .collect();
    matches.len() == 1 && matches[0].available
}

fn has_target_error_diagnostic(snapshot: &HostSnapshot, route: &crate::LayerRoute) -> bool {
    let devices = route
        .layers
        .iter()
        .filter_map(|layer| layer.device.as_deref())
        .collect::<Vec<_>>();
    snapshot.diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Error
            && diagnostic
                .device
                .as_deref()
                .is_none_or(|device| devices.contains(&device))
    })
}

fn flatten(devices: &[BlockDevice]) -> Vec<&BlockDevice> {
    let mut nodes = Vec::new();
    for device in devices {
        nodes.push(device);
        nodes.extend(flatten(&device.children));
    }
    nodes
}

fn device_path(device: &BlockDevice) -> String {
    device.path.clone().unwrap_or_else(|| device.name.clone())
}
