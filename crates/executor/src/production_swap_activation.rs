use std::path::{Component, Path};

use lsm_planner::{PlanStatus, SwapReplacementIntent};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Compiling this feature only permits sealing a non-executing production
/// activation object. It does not enable swapfile creation, swapon, swapoff,
/// persistent configuration edits or partition mutation.
pub const PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-activation");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionSwapReplacementProfile {
    TailSwapPartitionToExt4Swapfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapReplacementActivationReadiness {
    pub schema_version: u32,
    pub profile: ProductionSwapReplacementProfile,
    pub compile_feature_enabled: bool,
    pub intent_ready: bool,
    pub intent_integrity_verified: bool,
    pub exact_profile: bool,
    pub blockers: Vec<String>,
}

impl ProductionSwapReplacementActivationReadiness {
    pub fn ready(&self) -> bool {
        self.compile_feature_enabled
            && self.intent_ready
            && self.intent_integrity_verified
            && self.exact_profile
            && self.blockers.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapReplacementActivationIntent {
    pub schema_version: u32,
    pub activation_id: String,
    pub profile: ProductionSwapReplacementProfile,
    pub swap_replacement_intent_id: String,
    pub target: String,
    pub disk: String,
    pub retiring_swap_device: String,
    pub retiring_swap_bytes: u64,
    pub retiring_swap_priority: i32,
    pub persistent_swap_source: String,
    pub persistent_swap_target: String,
    pub persistent_swap_options: Vec<String>,
    pub persistent_swap_dump: u32,
    pub persistent_swap_pass: u32,
    pub destination_mount: String,
    pub swapfile_path: String,
    pub destination_filesystem: String,
    pub destination_available_bytes: u64,
    pub swapfile_mode: u32,
    pub compile_feature_enabled: bool,
    pub execution_enabled: bool,
}

#[derive(Serialize)]
struct ProductionSwapReplacementActivationDigestPayload<'a> {
    schema_version: u32,
    profile: ProductionSwapReplacementProfile,
    swap_replacement_intent_id: &'a str,
    target: &'a str,
    disk: &'a str,
    retiring_swap_device: &'a str,
    retiring_swap_bytes: u64,
    retiring_swap_priority: i32,
    persistent_swap_source: &'a str,
    persistent_swap_target: &'a str,
    persistent_swap_options: &'a [String],
    persistent_swap_dump: u32,
    persistent_swap_pass: u32,
    destination_mount: &'a str,
    swapfile_path: &'a str,
    destination_filesystem: &'a str,
    destination_available_bytes: u64,
    swapfile_mode: u32,
    compile_feature_enabled: bool,
    execution_enabled: bool,
}

impl ProductionSwapReplacementActivationIntent {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.activation_id == self.expected_activation_id()?)
    }

    fn expected_activation_id(&self) -> Result<String, serde_json::Error> {
        let payload = ProductionSwapReplacementActivationDigestPayload {
            schema_version: self.schema_version,
            profile: self.profile,
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            target: &self.target,
            disk: &self.disk,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_bytes: self.retiring_swap_bytes,
            retiring_swap_priority: self.retiring_swap_priority,
            persistent_swap_source: &self.persistent_swap_source,
            persistent_swap_target: &self.persistent_swap_target,
            persistent_swap_options: &self.persistent_swap_options,
            persistent_swap_dump: self.persistent_swap_dump,
            persistent_swap_pass: self.persistent_swap_pass,
            destination_mount: &self.destination_mount,
            swapfile_path: &self.swapfile_path,
            destination_filesystem: &self.destination_filesystem,
            destination_available_bytes: self.destination_available_bytes,
            swapfile_mode: self.swapfile_mode,
            compile_feature_enabled: self.compile_feature_enabled,
            execution_enabled: self.execution_enabled,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionSwapReplacementActivationError {
    #[error("production swap replacement activation feature is not compiled")]
    FeatureDisabled,
    #[error("swap replacement intent is not preview-ready and non-executable")]
    IntentNotReady,
    #[error("swap replacement intent integrity verification failed")]
    IntentIntegrityMismatch,
    #[error("swap replacement intent is outside the exact supported production profile")]
    UnsupportedProfile,
    #[error("swap replacement activation serialization failed: {0}")]
    Serialization(String),
}

fn safe_absolute_path(value: &str) -> bool {
    if value.is_empty() || value.as_bytes().contains(&0) {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn safe_device_path(value: &str) -> bool {
    safe_absolute_path(value) && value.starts_with("/dev/")
}

fn expected_swapfile_path(mountpoint: &str) -> Option<String> {
    if !safe_absolute_path(mountpoint) {
        return None;
    }
    Some(if mountpoint == "/" {
        "/.linux-storage-manager.swap".to_owned()
    } else {
        format!(
            "{}/.linux-storage-manager.swap",
            mountpoint.trim_end_matches('/')
        )
    })
}

fn no_controls(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn exact_profile(intent: &SwapReplacementIntent) -> bool {
    let (
        Some(disk),
        Some(retiring_swap_device),
        Some(retiring_swap_bytes),
        Some(retiring_swap_used_bytes),
        Some(_retiring_swap_priority),
        Some(persistent_swap_source),
        Some(persistent_swap_target),
        Some(persistent_swap_dump),
        Some(persistent_swap_pass),
        Some(destination_filesystem),
    ) = (
        intent.disk.as_deref(),
        intent.retiring_swap_device.as_deref(),
        intent.retiring_swap_bytes,
        intent.retiring_swap_used_bytes,
        intent.retiring_swap_priority,
        intent.persistent_swap_source.as_deref(),
        intent.persistent_swap_target.as_deref(),
        intent.persistent_swap_dump,
        intent.persistent_swap_pass,
        intent.destination_filesystem.as_deref(),
    )
    else {
        return false;
    };

    let Some(expected_swapfile) = expected_swapfile_path(&intent.destination_mount) else {
        return false;
    };

    intent.schema_version == 1
        && intent.status == PlanStatus::Preview
        && !intent.executable
        && intent.blockers.is_empty()
        && safe_absolute_path(&intent.target)
        && safe_device_path(disk)
        && safe_device_path(retiring_swap_device)
        && disk != retiring_swap_device
        && retiring_swap_bytes > 0
        && retiring_swap_used_bytes <= retiring_swap_bytes
        && no_controls(persistent_swap_source)
        && no_controls(persistent_swap_target)
        && !intent.persistent_swap_options.is_empty()
        && intent
            .persistent_swap_options
            .iter()
            .all(|option| no_controls(option))
        && persistent_swap_dump <= 1
        && persistent_swap_pass <= 2
        && destination_filesystem == "ext4"
        && intent.destination_available_bytes >= retiring_swap_bytes
        && intent.swapfile_mode == 0o600
        && intent.swapfile_path == expected_swapfile
        && !intent.ordered_steps.is_empty()
}

pub fn inspect_production_swap_replacement_activation_readiness(
    intent: &SwapReplacementIntent,
) -> ProductionSwapReplacementActivationReadiness {
    let mut blockers = Vec::new();

    let intent_ready = intent.ready();
    if !intent_ready {
        blockers.push("swap-replacement-intent-not-ready".to_owned());
    }

    let intent_integrity_verified = intent.integrity_matches().unwrap_or(false);
    if !intent_integrity_verified {
        blockers.push("swap-replacement-intent-integrity-mismatch".to_owned());
    }

    let profile_ok = exact_profile(intent);
    if !profile_ok {
        blockers.push("unsupported-swap-replacement-profile".to_owned());
    }

    if !PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED {
        blockers.push("production-swap-activation-feature-disabled".to_owned());
    }

    ProductionSwapReplacementActivationReadiness {
        schema_version: 1,
        profile: ProductionSwapReplacementProfile::TailSwapPartitionToExt4Swapfile,
        compile_feature_enabled: PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED,
        intent_ready,
        intent_integrity_verified,
        exact_profile: profile_ok,
        blockers,
    }
}

/// Seal the exact M1B54 swap replacement intent into a production activation
/// object. This remains non-executing: execution_enabled is always false and
/// there is no descriptor/process crossing in this feature.
pub fn seal_production_swap_replacement_activation_intent(
    intent: &SwapReplacementIntent,
) -> Result<ProductionSwapReplacementActivationIntent, ProductionSwapReplacementActivationError> {
    if !PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED {
        return Err(ProductionSwapReplacementActivationError::FeatureDisabled);
    }
    if !intent.ready() {
        return Err(ProductionSwapReplacementActivationError::IntentNotReady);
    }
    if !intent.integrity_matches().unwrap_or(false) {
        return Err(ProductionSwapReplacementActivationError::IntentIntegrityMismatch);
    }
    if !exact_profile(intent) {
        return Err(ProductionSwapReplacementActivationError::UnsupportedProfile);
    }

    let mut activation = ProductionSwapReplacementActivationIntent {
        schema_version: 1,
        activation_id: String::new(),
        profile: ProductionSwapReplacementProfile::TailSwapPartitionToExt4Swapfile,
        swap_replacement_intent_id: intent.intent_id.clone(),
        target: intent.target.clone(),
        disk: intent.disk.clone().expect("profile validated disk"),
        retiring_swap_device: intent
            .retiring_swap_device
            .clone()
            .expect("profile validated retiring swap"),
        retiring_swap_bytes: intent
            .retiring_swap_bytes
            .expect("profile validated retiring swap size"),
        retiring_swap_priority: intent
            .retiring_swap_priority
            .expect("profile validated retiring priority"),
        persistent_swap_source: intent
            .persistent_swap_source
            .clone()
            .expect("profile validated persistent source"),
        persistent_swap_target: intent
            .persistent_swap_target
            .clone()
            .expect("profile validated persistent target"),
        persistent_swap_options: intent.persistent_swap_options.clone(),
        persistent_swap_dump: intent
            .persistent_swap_dump
            .expect("profile validated persistent dump"),
        persistent_swap_pass: intent
            .persistent_swap_pass
            .expect("profile validated persistent pass"),
        destination_mount: intent.destination_mount.clone(),
        swapfile_path: intent.swapfile_path.clone(),
        destination_filesystem: intent
            .destination_filesystem
            .clone()
            .expect("profile validated destination filesystem"),
        destination_available_bytes: intent.destination_available_bytes,
        swapfile_mode: intent.swapfile_mode,
        compile_feature_enabled: true,
        execution_enabled: false,
    };
    activation.activation_id = activation.expected_activation_id().map_err(|error| {
        ProductionSwapReplacementActivationError::Serialization(error.to_string())
    })?;
    Ok(activation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsm_planner::{Blocker, SwapReplacementIntent};

    fn valid_swap_intent() -> SwapReplacementIntent {
        let mut intent = SwapReplacementIntent {
            schema_version: 1,
            intent_id: String::new(),
            executable: false,
            status: PlanStatus::Preview,
            target: "/data".into(),
            disk: Some("/dev/loop7".into()),
            retiring_swap_device: Some("/dev/loop7p5".into()),
            retiring_swap_bytes: Some(64 * 1024 * 1024),
            retiring_swap_used_bytes: Some(4096),
            retiring_swap_priority: Some(7),
            persistent_swap_source: Some("UUID=swap-uuid".into()),
            persistent_swap_target: Some("none".into()),
            persistent_swap_options: vec!["sw".into()],
            persistent_swap_dump: Some(0),
            persistent_swap_pass: Some(0),
            destination_mount: "/data".into(),
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            destination_filesystem: Some("ext4".into()),
            destination_available_bytes: 128 * 1024 * 1024,
            swapfile_mode: 0o600,
            blockers: vec![],
            ordered_steps: vec!["revalidate".into(), "activate replacement".into()],
        };
        intent.intent_id = intent.expected_intent_id().unwrap();
        intent
    }

    #[test]
    fn readiness_is_feature_bound_but_profile_and_integrity_are_independent() {
        let intent = valid_swap_intent();
        let readiness = inspect_production_swap_replacement_activation_readiness(&intent);
        assert!(readiness.intent_ready);
        assert!(readiness.intent_integrity_verified);
        assert!(readiness.exact_profile);
        assert_eq!(
            readiness.compile_feature_enabled,
            PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED
        );
    }

    #[test]
    fn exact_intent_seals_nonexecuting_activation_when_feature_is_compiled() {
        let intent = valid_swap_intent();
        if PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED {
            let activation = seal_production_swap_replacement_activation_intent(&intent).unwrap();
            assert!(activation.integrity_matches().unwrap());
            assert_eq!(activation.swap_replacement_intent_id, intent.intent_id);
            assert!(!activation.execution_enabled);
            assert!(activation.compile_feature_enabled);
        } else {
            assert_eq!(
                seal_production_swap_replacement_activation_intent(&intent),
                Err(ProductionSwapReplacementActivationError::FeatureDisabled)
            );
        }
    }

    #[test]
    fn tampering_with_frozen_intent_is_rejected() {
        let mut intent = valid_swap_intent();
        intent.swapfile_path = "/data/other.swap".into();
        let readiness = inspect_production_swap_replacement_activation_readiness(&intent);
        assert!(!readiness.intent_integrity_verified);
        assert!(!readiness.exact_profile);
        if PRODUCTION_SWAP_REPLACEMENT_ACTIVATION_COMPILED {
            assert_eq!(
                seal_production_swap_replacement_activation_intent(&intent),
                Err(ProductionSwapReplacementActivationError::IntentIntegrityMismatch)
            );
        }
    }

    #[test]
    fn arbitrary_digest_correct_but_unsupported_profile_stays_blocked() {
        let mut intent = valid_swap_intent();
        intent.destination_filesystem = Some("xfs".into());
        intent.intent_id = intent.expected_intent_id().unwrap();
        let readiness = inspect_production_swap_replacement_activation_readiness(&intent);
        assert!(readiness.intent_integrity_verified);
        assert!(!readiness.exact_profile);
        assert!(readiness
            .blockers
            .iter()
            .any(|blocker| blocker == "unsupported-swap-replacement-profile"));
    }

    #[test]
    fn blocker_cannot_be_hidden_by_rehashing() {
        let mut intent = valid_swap_intent();
        intent.blockers = vec![Blocker {
            code: "example".into(),
            message: "blocked".into(),
        }];
        intent.intent_id = intent.expected_intent_id().unwrap();
        let readiness = inspect_production_swap_replacement_activation_readiness(&intent);
        assert!(!readiness.intent_ready);
        assert!(!readiness.exact_profile);
    }
}
