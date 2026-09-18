use lsm_discovery::{
    parse_findmnt_json, parse_lvs_json, parse_proc_swaps, parse_pvs_json, parse_vgs_json,
};

#[test]
fn normalizes_mount_tree() {
    let input = r#"{
        "filesystems": [
            {
                "source": "/dev/mapper/vg0-root",
                "target": "/",
                "fstype": "ext4",
                "options": "rw,relatime",
                "children": [
                    {
                        "source": "/dev/sda1",
                        "target": "/boot/efi",
                        "fstype": "vfat",
                        "options": "rw,relatime"
                    }
                ]
            }
        ]
    }"#;

    let mounts = parse_findmnt_json(input).expect("findmnt fixture should parse");
    assert_eq!(mounts.len(), 2);
    assert_eq!(mounts[0].target, "/");
    assert_eq!(mounts[0].options, vec!["rw", "relatime"]);
    assert_eq!(mounts[1].target, "/boot/efi");
}

#[test]
fn normalizes_proc_swaps() {
    let input = "Filename\tType\tSize\tUsed\tPriority\n/swapfile\tfile\t8388604\t0\t-2\n/dev/dm-1\tpartition\t4194300\t1024\t-3\n";
    let swaps = parse_proc_swaps(input).expect("proc swaps fixture should parse");

    assert_eq!(swaps.len(), 2);
    assert_eq!(swaps[0].name, "/swapfile");
    assert_eq!(swaps[0].size_bytes, 8_589_930_496);
    assert_eq!(swaps[1].used_bytes, 1_048_576);
}

#[test]
fn normalizes_lvm_reports() {
    let pvs = r#"{"report":[{"pv":[{"pv_name":"/dev/sda2","pv_uuid":"pv-1","vg_name":"vg0","pv_size":"213674622976","pv_free":"21474836480"}]}]}"#;
    let vgs = r#"{"report":[{"vg":[{"vg_name":"vg0","vg_uuid":"vg-1","vg_size":"213674622976","vg_free":"21474836480","pv_count":"1","lv_count":"2"}]}]}"#;
    let lvs = r#"{"report":[{"lv":[{"lv_name":"root","lv_path":"/dev/vg0/root","lv_uuid":"lv-1","vg_name":"vg0","lv_size":"193273528320","lv_attr":"-wi-ao----"}]}]}"#;

    let physical_volumes = parse_pvs_json(pvs).expect("pvs fixture should parse");
    let volume_groups = parse_vgs_json(vgs).expect("vgs fixture should parse");
    let logical_volumes = parse_lvs_json(lvs).expect("lvs fixture should parse");

    assert_eq!(physical_volumes[0].vg_name.as_deref(), Some("vg0"));
    assert_eq!(volume_groups[0].free_bytes, 21_474_836_480);
    assert_eq!(volume_groups[0].lv_count, 2);
    assert_eq!(logical_volumes[0].path.as_deref(), Some("/dev/vg0/root"));
}
