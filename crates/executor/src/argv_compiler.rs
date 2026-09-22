use serde::Serialize;

/// M1B14 keeps the executable surface closed at the type level.
///
/// These variants are command identities only. This module does not resolve an executable path
/// and does not spawn a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeProgram {
    Lvextend,
    Resize2fs,
    XfsGrowfs,
}

/// M1B14 output is reviewed command data, never execution authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompiledCommandManifestStatus {
    CompiledNonExecutable,
}
