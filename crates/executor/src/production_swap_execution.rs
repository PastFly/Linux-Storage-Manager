use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ProductionSwapReplacementActivationIntent, ProductionSwapReplacementConsentReceipt,
    ProductionSwapReplacementProfile,
};

/// Compiles only the non-spawning authorization object for one exact swap
/// replacement activation + consent pair.
pub const PRODUCTION_SWAP_REPLACEMENT_EXECUTION_PERMIT_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-execution-permit");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapReplacementExecutionPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub swap_replacement_intent_id: String,
    pub profile: ProductionSwapReplacementProfile,
    pub target: String,
    pub disk: String,
    pub retiring_swap_device: String,
    pub retiring_swap_bytes: u64,
    pub retiring_swap_priority: i32,
    pub swapfile_path: String,
    pub swapfile_mode: u32,
    pub compile_feature_enabled: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
}

#[derive(Serialize)]
struct ExecutionPermitDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    consent_receipt_id: &'a str,
    swap_replacement_intent_id: &'a str,
    profile: ProductionSwapReplacementProfile,
    target: &'a str,
    disk: &'a str,
    retiring_swap_device: &'a str,
    retiring_swap_bytes: u64,
    retiring_swap_priority: i32,
    swapfile_path: &'a str,
    swapfile_mode: u32,
    compile_feature_enabled: bool,
    mutation_enabled: bool,
    process_spawned: bool,
}

impl ProductionSwapReplacementExecutionPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let payload = ExecutionPermitDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            consent_receipt_id: &self.consent_receipt_id,
            swap_replacement_intent_id: &self.swap_replacement_intent_id,
            profile: self.profile,
            target: &self.target,
            disk: &self.disk,
            retiring_swap_device: &self.retiring_swap_device,
            retiring_swap_bytes: self.retiring_swap_bytes,
            retiring_swap_priority: self.retiring_swap_priority,
            swapfile_path: &self.swapfile_path,
            swapfile_mode: self.swapfile_mode,
            compile_feature_enabled: self.compile_feature_enabled,
            mutation_enabled: self.mutation_enabled,
            process_spawned: self.process_spawned,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionSwapReplacementExecutionPermitError {
    #[error("production swap replacement execution-permit feature is not compiled")]
    FeatureDisabled,
    #[error("swap replacement activation integrity check failed")]
    ActivationInvalid,
    #[error("swap replacement consent receipt integrity check failed")]
    ConsentInvalid,
    #[error("activation and consent do not describe the same exact swap replacement")]
    ConsentBindingMismatch,
    #[error("upstream swap replacement authorization unexpectedly enables execution")]
    UpstreamAlreadyEnabled,
    #[error("swap replacement execution-permit serialization failed: {0}")]
    Serialization(String),
}

fn validate_activation(
    activation: &ProductionSwapReplacementActivationIntent,
) -> Result<(), ProductionSwapReplacementExecutionPermitError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
    {
        return Err(ProductionSwapReplacementExecutionPermitError::ActivationInvalid);
    }
    if activation.execution_enabled {
        return Err(ProductionSwapReplacementExecutionPermitError::UpstreamAlreadyEnabled);
    }
    Ok(())
}

fn validate_consent(
    activation: &ProductionSwapReplacementActivationIntent,
    consent: &ProductionSwapReplacementConsentReceipt,
) -> Result<(), ProductionSwapReplacementExecutionPermitError> {
    if consent.schema_version != 1
        || !consent.integrity_matches().unwrap_or(false)
        || !consent.consent_verified
    {
        return Err(ProductionSwapReplacementExecutionPermitError::ConsentInvalid);
    }
    if consent.execution_enabled {
        return Err(ProductionSwapReplacementExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if consent.activation_id != activation.activation_id
        || consent.swap_replacement_intent_id != activation.swap_replacement_intent_id
        || consent.target != activation.target
        || consent.retiring_swap_device != activation.retiring_swap_device
        || consent.swapfile_path != activation.swapfile_path
    {
        return Err(ProductionSwapReplacementExecutionPermitError::ConsentBindingMismatch);
    }
    Ok(())
}

/// Seal M1B56 activation + M1B57 explicit consent into one exact non-spawning
/// permit. No file creation or swap process is launched here.
pub fn seal_production_swap_replacement_execution_permit(
    activation: &ProductionSwapReplacementActivationIntent,
    consent: &ProductionSwapReplacementConsentReceipt,
) -> Result<ProductionSwapReplacementExecutionPermit, ProductionSwapReplacementExecutionPermitError>
{
    if !PRODUCTION_SWAP_REPLACEMENT_EXECUTION_PERMIT_COMPILED {
        return Err(ProductionSwapReplacementExecutionPermitError::FeatureDisabled);
    }
    validate_activation(activation)?;
    validate_consent(activation, consent)?;

    let mut permit = ProductionSwapReplacementExecutionPermit {
        schema_version: 1,
        permit_id: String::new(),
        activation_id: activation.activation_id.clone(),
        consent_receipt_id: consent.receipt_id.clone(),
        swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
        profile: activation.profile,
        target: activation.target.clone(),
        disk: activation.disk.clone(),
        retiring_swap_device: activation.retiring_swap_device.clone(),
        retiring_swap_bytes: activation.retiring_swap_bytes,
        retiring_swap_priority: activation.retiring_swap_priority,
        swapfile_path: activation.swapfile_path.clone(),
        swapfile_mode: activation.swapfile_mode,
        compile_feature_enabled: true,
        mutation_enabled: false,
        process_spawned: false,
    };
    permit.permit_id = permit.expected_permit_id().map_err(|error| {
        ProductionSwapReplacementExecutionPermitError::Serialization(error.to_string())
    })?;
    Ok(permit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProductionSwapReplacementConsentFileIdentity, PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH,
    };

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn activation() -> ProductionSwapReplacementActivationIntent {
        let mut activation = ProductionSwapReplacementActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionSwapReplacementProfile::TailSwapPartitionToExt4Swapfile,
            swap_replacement_intent_id: digest('a'),
            target: "/data".into(),
            disk: "/dev/loop7".into(),
            retiring_swap_device: "/dev/loop7p5".into(),
            retiring_swap_bytes: 64 * 1024 * 1024,
            retiring_swap_priority: 7,
            persistent_swap_source: "UUID=swap-uuid".into(),
            persistent_swap_target: "none".into(),
            persistent_swap_options: vec!["sw".into()],
            persistent_swap_dump: 0,
            persistent_swap_pass: 0,
            destination_mount: "/data".into(),
            swapfile_path: "/data/.linux-storage-manager.swap".into(),
            destination_filesystem: "ext4".into(),
            destination_available_bytes: 128 * 1024 * 1024,
            swapfile_mode: 0o600,
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        activation.activation_id = activation.expected_activation_id().unwrap();
        activation
    }

    fn consent(
        activation: &ProductionSwapReplacementActivationIntent,
    ) -> ProductionSwapReplacementConsentReceipt {
        let file = ProductionSwapReplacementConsentFileIdentity {
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o600,
            link_count: 1,
            size_bytes: 256,
            sha256: digest('b'),
        };
        let mut receipt = ProductionSwapReplacementConsentReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            activation_id: activation.activation_id.clone(),
            swap_replacement_intent_id: activation.swap_replacement_intent_id.clone(),
            target: activation.target.clone(),
            retiring_swap_device: activation.retiring_swap_device.clone(),
            swapfile_path: activation.swapfile_path.clone(),
            consent_path: PRODUCTION_SWAP_REPLACEMENT_CONSENT_PATH.into(),
            consent_file: file,
            consent_verified: true,
            execution_enabled: false,
        };
        receipt.receipt_id = receipt.expected_receipt_id().unwrap();
        receipt
    }

    #[cfg(feature = "production-swap-replacement-execution-permit")]
    #[test]
    fn exact_activation_and_consent_seal_nonexecuting_permit() {
        let activation = activation();
        let consent = consent(&activation);

        let permit =
            seal_production_swap_replacement_execution_permit(&activation, &consent).unwrap();
        assert!(permit.integrity_matches().unwrap());
        assert!(permit.compile_feature_enabled);
        assert!(!permit.mutation_enabled);
        assert!(!permit.process_spawned);
        assert_eq!(
            permit.swap_replacement_intent_id,
            activation.swap_replacement_intent_id
        );
    }

    #[cfg(feature = "production-swap-replacement-execution-permit")]
    #[test]
    fn consent_for_another_activation_is_rejected() {
        let activation = activation();
        let mut consent = consent(&activation);
        consent.activation_id = digest('f');

        assert_eq!(
            seal_production_swap_replacement_execution_permit(&activation, &consent),
            Err(ProductionSwapReplacementExecutionPermitError::ConsentInvalid)
        );
    }

    #[test]
    fn default_build_keeps_swap_execution_permit_disabled() {
        if !PRODUCTION_SWAP_REPLACEMENT_EXECUTION_PERMIT_COMPILED {
            let activation = activation();
            let consent = consent(&activation);
            assert_eq!(
                seal_production_swap_replacement_execution_permit(&activation, &consent),
                Err(ProductionSwapReplacementExecutionPermitError::FeatureDisabled)
            );
        }
    }
}
