use lsm_discovery::{parse_lvs_json, parse_pvs_json, parse_vgs_json};
use serde_json::json;

#[test]
fn parses_extent_and_layout_evidence() {
    let vgs = json!({"report":[{"vg":[{
        "vg_name":"vg0", "vg_uuid":"vg-1", "vg_size":"16777216.00",
        "vg_free":"8388608.00", "pv_count":"1", "lv_count":"1",
        "vg_extent_size":"4194304.00", "vg_free_count":"2",
        "vg_missing_pv_count":"0", "vg_attr":"wz--n-"
    }]}]}).to_string();
    let groups = parse_vgs_json(&vgs).unwrap();
    assert_eq!(groups[0].extent_size_bytes, Some(4_194_304));
    assert_eq!(groups[0].free_extent_count, Some(2));
    assert_eq!(groups[0].missing_pv_count, Some(0));
    let lvs = r#"{"report":[{"lv":[{"lv_name":"root","vg_name":"vg0","lv_size":"8388608.00","lv_layout":"linear","lv_role":"public"}]}]}"#;
    let volumes = parse_lvs_json(lvs).unwrap();
    assert_eq!(volumes[0].layout.as_deref(), Some("linear"));
    assert_eq!(volumes[0].role.as_deref(), Some("public"));
}

#[test]
fn integer_parser_is_exact_above_f64_precision() {
    for value in ["9007199254740993.00", "18446744073709551615.00"] {
        let input = json!({"report":[{"pv":[{
            "pv_name":"/dev/sda", "pv_size":value, "pv_free":"0"
        }]}]}).to_string();
        let parsed = parse_pvs_json(&input).unwrap();
        assert_eq!(parsed[0].size_bytes, value.trim_end_matches(".00").parse::<u64>().unwrap());
    }
}

#[test]
fn rejects_fractional_overflow_and_nonfinite_reports() {
    for value in ["1.5", "-1", "-0", "+1", "1e3", "NaN", "inf", "1.", "18446744073709551616.00"] {
        let input = json!({"report":[{"pv":[{
            "pv_name":"/dev/sda", "pv_size":value, "pv_free":"0"
        }]}]}).to_string();
        assert!(parse_pvs_json(&input).is_err(), "unexpectedly accepted {value}");
    }
}

#[test]
fn empty_inventory_is_not_a_missing_report() {
    assert!(parse_pvs_json(r#"{"report":[{"pv":[]}]}"#).unwrap().is_empty());
    for input in ["{}", r#"{"report":[]}"#, r#"{"report":[{}]}"#] {
        assert!(parse_pvs_json(input).is_err());
        assert!(parse_vgs_json(input).is_err());
        assert!(parse_lvs_json(input).is_err());
    }
}
