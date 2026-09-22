use lsm_executor::{CompiledCommandManifestStatus, NativeProgram};

fn program_name(program: NativeProgram) -> &'static str {
    match program {
        NativeProgram::Lvextend => "lvextend",
        NativeProgram::Resize2fs => "resize2fs",
        NativeProgram::XfsGrowfs => "xfs_growfs",
    }
}

fn status_name(status: CompiledCommandManifestStatus) -> &'static str {
    match status {
        CompiledCommandManifestStatus::CompiledNonExecutable => "compiled_non_executable",
    }
}

#[test]
fn m1b14_program_allowlist_is_closed_and_minimal() {
    let programs = [
        NativeProgram::Lvextend,
        NativeProgram::Resize2fs,
        NativeProgram::XfsGrowfs,
    ];

    assert_eq!(
        programs.map(program_name),
        ["lvextend", "resize2fs", "xfs_growfs"]
    );
    assert_eq!(
        serde_json::to_string(&programs).unwrap(),
        r#"["lvextend","resize2fs","xfs_growfs"]"#
    );
}

#[test]
fn m1b14_compiled_manifest_status_is_non_executable() {
    assert_eq!(
        status_name(CompiledCommandManifestStatus::CompiledNonExecutable),
        "compiled_non_executable"
    );
    assert_eq!(
        serde_json::to_string(&CompiledCommandManifestStatus::CompiledNonExecutable).unwrap(),
        r#""compiled_non_executable""#
    );
}
