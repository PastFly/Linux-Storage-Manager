use lsm_core::HostSnapshot;
use lsm_planner::{analyze_layer_route, LayerRouteStatus, RouteIssueKind, RouteLayerKind};
use serde_json::json;

fn direct_snapshot() -> HostSnapshot {
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20_000_000_000u64,"mountpoints":[],"children":[{
                "name":"sda1","kernel_name":"sda1","path":"/dev/sda1","kind":"partition",
                "size_bytes":10_000_000_000u64,"start_512_sector":2048,
                "logical_sector_bytes":512,"uuid":"fs-data","partition_uuid":"part-data",
                "filesystem":{"fs_type":"ext4","version":"1.0"},
                "mountpoints":["/data"],"parent_kernel_name":"sda","children":[]
            }]
        }]},
        "partition_tables":[],
        "mounts":[
            {"source":"/dev/sda1","target":"/data","fs_type":"ext4","options":["rw"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

fn lvm_snapshot() -> HostSnapshot {
    serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"vda","kernel_name":"vda","path":"/dev/vda","kind":"disk",
            "size_bytes":20_000_000_000u64,"mountpoints":[],"children":[{
                "name":"vda1","kernel_name":"vda1","path":"/dev/vda1","kind":"partition",
                "size_bytes":18_000_000_000u64,"start_512_sector":2048,
                "logical_sector_bytes":512,"uuid":"pv-1",
                "filesystem":{"fs_type":"LVM2_member","version":"LVM2 001"},
                "mountpoints":[],"parent_kernel_name":"vda","children":[{
                    "name":"vg0-root","kernel_name":"dm-0","path":"/dev/mapper/vg0-root",
                    "kind":"lvm","size_bytes":10_000_000_000u64,"uuid":"fs-root",
                    "filesystem":{"fs_type":"xfs","version":"5"},
                    "mountpoints":["/"],"parent_kernel_name":"vda1","children":[]
                }]
            }]
        }]},
        "partition_tables":[],
        "mounts":[
            {"source":"/dev/vg0/root","target":"/","fs_type":"xfs","options":["rw"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":{
            "physical_volumes":[{
                "name":"/dev/vda1","uuid":"pv-1","vg_name":"vg0",
                "size_bytes":18_000_000_000u64,"free_bytes":8_000_000_000u64
            }],
            "volume_groups":[{
                "name":"vg0","uuid":"vg-1","size_bytes":18_000_000_000u64,
                "free_bytes":8_000_000_000u64,"pv_count":1,"lv_count":1,
                "extent_size_bytes":4_194_304u64,"free_extent_count":1907,
                "missing_pv_count":0,"attributes":"wz--n-"
            }],
            "logical_volumes":[{
                "name":"root","path":"/dev/vg0/root","uuid":"lv-root","vg_name":"vg0",
                "size_bytes":10_000_000_000u64,"attributes":"-wi-ao----",
                "layout":"linear","role":"public"
            }]
        },
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap()
}

#[test]
fn direct_partition_route_is_semantically_ordered_and_supported() {
    let snapshot = direct_snapshot();

    let route = analyze_layer_route(&snapshot, "/data");

    assert_eq!(route.status, LayerRouteStatus::SupportedProfile);
    assert_eq!(route.resolved_device.as_deref(), Some("/dev/sda1"));
    assert_eq!(route.mountpoint.as_deref(), Some("/data"));
    assert!(route.issues.is_empty());
    assert_eq!(
        route
            .layers
            .iter()
            .map(|layer| layer.kind)
            .collect::<Vec<_>>(),
        vec![
            RouteLayerKind::Disk,
            RouteLayerKind::Partition,
            RouteLayerKind::Filesystem,
            RouteLayerKind::Mount,
        ]
    );
}

#[test]
fn lvm_route_inserts_pv_vg_and_lv_semantic_layers() {
    let snapshot = lvm_snapshot();

    let route = analyze_layer_route(&snapshot, "/");

    assert_eq!(route.status, LayerRouteStatus::SupportedProfile);
    assert_eq!(
        route.resolved_device.as_deref(),
        Some("/dev/mapper/vg0-root")
    );
    assert_eq!(
        route
            .layers
            .iter()
            .map(|layer| layer.kind)
            .collect::<Vec<_>>(),
        vec![
            RouteLayerKind::Disk,
            RouteLayerKind::Partition,
            RouteLayerKind::LvmPhysicalVolume,
            RouteLayerKind::LvmVolumeGroup,
            RouteLayerKind::LvmLogicalVolume,
            RouteLayerKind::Filesystem,
            RouteLayerKind::Mount,
        ]
    );
    assert!(route
        .layers
        .iter()
        .any(|layer| layer.kind == RouteLayerKind::LvmVolumeGroup
            && layer
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("vg0"))));
}

#[test]
fn lvm_alias_target_resolves_same_route_as_mountpoint() {
    let snapshot = lvm_snapshot();

    for target in ["/dev/vg0/root", "/dev/mapper/vg0-root", "/dev/dm-0"] {
        let route = analyze_layer_route(&snapshot, target);
        assert_eq!(route.status, LayerRouteStatus::SupportedProfile, "{target}");
        assert_eq!(
            route.resolved_device.as_deref(),
            Some("/dev/mapper/vg0-root")
        );
    }
}

#[test]
fn encryption_layer_is_visible_and_requires_adapter() {
    let snapshot: HostSnapshot = serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"sda","kernel_name":"sda","path":"/dev/sda","kind":"disk",
            "size_bytes":20_000_000_000u64,"mountpoints":[],"children":[{
                "name":"sda2","kernel_name":"sda2","path":"/dev/sda2","kind":"partition",
                "size_bytes":12_000_000_000u64,"start_512_sector":2048,
                "logical_sector_bytes":512,"mountpoints":[],"parent_kernel_name":"sda",
                "children":[{
                    "name":"cryptdata","kernel_name":"dm-0","path":"/dev/mapper/cryptdata",
                    "kind":"crypt","size_bytes":11_900_000_000u64,"uuid":"crypt-fs",
                    "filesystem":{"fs_type":"ext4","version":"1.0"},
                    "mountpoints":["/secure"],"parent_kernel_name":"sda2","children":[]
                }]
            }]
        }]},
        "partition_tables":[],
        "mounts":[
            {"source":"/dev/mapper/cryptdata","target":"/secure","fs_type":"ext4","options":["rw"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap();

    let route = analyze_layer_route(&snapshot, "/secure");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route
        .layers
        .iter()
        .any(|layer| layer.kind == RouteLayerKind::Encryption));
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired && issue.code == "luks-adapter-required"
    }));
}

#[test]
fn multi_pv_lvm_route_is_visible_but_not_claimed_as_supported_profile() {
    let mut snapshot = lvm_snapshot();
    snapshot.lvm.as_mut().unwrap().volume_groups[0].pv_count = 2;

    let route = analyze_layer_route(&snapshot, "/");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired
            && issue.code == "lvm-multi-pv-adapter-required"
    }));
}

#[test]
fn inactive_linear_lv_is_visible_but_requires_adapter() {
    let mut snapshot = lvm_snapshot();
    snapshot.lvm.as_mut().unwrap().logical_volumes[0].attributes = Some("-wi-------".into());

    let route = analyze_layer_route(&snapshot, "/");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired && issue.code == "lvm-layout-adapter-required"
    }));
}

#[test]
fn nonstandard_vg_profile_is_visible_but_requires_adapter() {
    let mut snapshot = lvm_snapshot();
    snapshot.lvm.as_mut().unwrap().volume_groups[0].attributes = Some("rz--n-".into());

    let route = analyze_layer_route(&snapshot, "/");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired
            && issue.code == "lvm-vg-profile-adapter-required"
    }));
}

#[test]
fn unknown_filesystem_stays_visible_as_adapter_required() {
    let mut snapshot = direct_snapshot();
    snapshot.storage.block_devices[0].children[0]
        .filesystem
        .as_mut()
        .unwrap()
        .fs_type = "mysteryfs".into();
    snapshot.mounts[0].fs_type = Some("mysteryfs".into());

    let route = analyze_layer_route(&snapshot, "/data");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired && issue.code == "filesystem-adapter-required"
    }));
}

#[test]
fn ambiguous_mount_target_fails_closed() {
    let mut snapshot = direct_snapshot();
    snapshot.mounts.push(snapshot.mounts[0].clone());

    let route = analyze_layer_route(&snapshot, "/data");

    assert_eq!(route.status, LayerRouteStatus::Blocked);
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::Blocker && issue.code == "route-target-ambiguous"
    }));
}


#[test]
fn multipath_layer_is_visible_and_requires_dedicated_adapter() {
    let snapshot: HostSnapshot = serde_json::from_value(json!({
        "storage": {"block_devices": [{
            "name":"mpatha","kernel_name":"dm-0","path":"/dev/mapper/mpatha",
            "kind":"multipath","size_bytes":40_000_000_000u64,"uuid":"fs-san",
            "filesystem":{"fs_type":"xfs","version":"5"},
            "mountpoints":["/san"],"children":[]
        }]},
        "partition_tables":[],
        "mounts":[
            {"source":"/dev/mapper/mpatha","target":"/san","fs_type":"xfs","options":["rw"]}
        ],
        "fstab":[],
        "swaps":[],
        "lvm":null,
        "diagnostics":[],
        "collectors":[]
    }))
    .unwrap();

    let route = analyze_layer_route(&snapshot, "/san");

    assert_eq!(route.status, LayerRouteStatus::AdapterRequired);
    assert!(route
        .layers
        .iter()
        .any(|layer| layer.kind == RouteLayerKind::Multipath));
    assert!(route.issues.iter().any(|issue| {
        issue.kind == RouteIssueKind::AdapterRequired
            && issue.code == "multipath-adapter-required"
    }));
}
