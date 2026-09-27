use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PrivilegedLaunchPermit, ProductionMutationActivationIntent, ProductionMutationConsentReceipt,
    ProductionMutationProfile,
};

/// M1B37 compiles only the final non-spawning authorization object.
/// It does not enable descriptor execution by itself.
pub const PRODUCTION_MUTATION_EXECUTION_PERMIT_COMPILED: bool =
    cfg!(feature = "production-mutation-execution-permit");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionMutationExecutionPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub execution_id: String,
    pub profile: ProductionMutationProfile,
    pub target: String,
    pub resolved_device: String,
    pub launch_permit_id: String,
    pub launch_id: String,
    pub plan_step_id: u32,
    pub command_digest: String,
    pub compile_feature_enabled: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
}

impl ProductionMutationExecutionPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.activation_id,
            &self.consent_receipt_id,
            &self.execution_id,
            self.profile,
            &self.target,
            &self.resolved_device,
            &self.launch_permit_id,
            &self.launch_id,
            self.plan_step_id,
            &self.command_digest,
            self.compile_feature_enabled,
            self.mutation_enabled,
            self.process_spawned,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductionMutationExecutionPermitError {
    #[error("production mutation execution-permit feature is not compiled")]
    FeatureDisabled,
    #[error("production activation intent integrity check failed")]
    ActivationIntentInvalid,
    #[error("production consent receipt integrity check failed")]
    ConsentReceiptInvalid,
    #[error("privileged launch permit integrity check failed")]
    LaunchPermitInvalid,
    #[error("activation and runtime consent do not describe the same exact execution")]
    ConsentBindingMismatch,
    #[error("launch permit does not belong to the activated execution")]
    LaunchExecutionMismatch,
    #[error("launch step is outside the narrow production activation scope")]
    StepOutsideActivationScope,
    #[error("upstream authorization unexpectedly reports mutation or process execution enabled")]
    UpstreamAlreadyEnabled,
    #[error("execution-permit serialization failed: {0}")]
    Serialization(String),
}

fn validate_activation(
    activation: &ProductionMutationActivationIntent,
) -> Result<(), ProductionMutationExecutionPermitError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
    {
        return Err(ProductionMutationExecutionPermitError::ActivationIntentInvalid);
    }
    if activation.execution_enabled {
        return Err(ProductionMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    Ok(())
}

fn validate_consent(
    activation: &ProductionMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<(), ProductionMutationExecutionPermitError> {
    if consent.schema_version != 1
        || !consent.integrity_matches().unwrap_or(false)
        || !consent.consent_verified
    {
        return Err(ProductionMutationExecutionPermitError::ConsentReceiptInvalid);
    }
    if consent.execution_enabled {
        return Err(ProductionMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if consent.activation_id != activation.activation_id
        || consent.execution_id != activation.execution_id
        || consent.target != activation.target
        || consent.resolved_device != activation.resolved_device
    {
        return Err(ProductionMutationExecutionPermitError::ConsentBindingMismatch);
    }
    Ok(())
}

fn validate_launch(
    activation: &ProductionMutationActivationIntent,
    launch: &PrivilegedLaunchPermit,
) -> Result<(), ProductionMutationExecutionPermitError> {
    if launch.schema_version != 1 || !launch.integrity_matches().unwrap_or(false) {
        return Err(ProductionMutationExecutionPermitError::LaunchPermitInvalid);
    }
    if launch.mutation_enabled || launch.process_spawned {
        return Err(ProductionMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if launch.execution_id != activation.execution_id {
        return Err(ProductionMutationExecutionPermitError::LaunchExecutionMismatch);
    }
    if launch.plan_step_id != activation.lv_step_id
        && launch.plan_step_id != activation.filesystem_step_id
    {
        return Err(ProductionMutationExecutionPermitError::StepOutsideActivationScope);
    }
    Ok(())
}

/// Seal activation + explicit root consent + one exact descriptor launch into
/// the final non-spawning production execution permit.
///
/// This object is intentionally still non-executing: mutation_enabled=false
/// and process_spawned=false remain part of its digest. A later reviewed gate
/// must consume this exact permit to cross the descriptor-exec boundary.
pub fn seal_production_mutation_execution_permit(
    activation: &ProductionMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
    launch: &PrivilegedLaunchPermit,
) -> Result<ProductionMutationExecutionPermit, ProductionMutationExecutionPermitError> {
    if !PRODUCTION_MUTATION_EXECUTION_PERMIT_COMPILED {
        return Err(ProductionMutationExecutionPermitError::FeatureDisabled);
    }
    validate_activation(activation)?;
    validate_consent(activation, consent)?;
    validate_launch(activation, launch)?;

    let mut permit = ProductionMutationExecutionPermit {
        schema_version: 1,
        permit_id: String::new(),
        activation_id: activation.activation_id.clone(),
        consent_receipt_id: consent.receipt_id.clone(),
        execution_id: activation.execution_id.clone(),
        profile: activation.profile,
        target: activation.target.clone(),
        resolved_device: activation.resolved_device.clone(),
        launch_permit_id: launch.permit_id.clone(),
        launch_id: launch.launch_id.clone(),
        plan_step_id: launch.plan_step_id,
        command_digest: launch.command_digest.clone(),
        compile_feature_enabled: true,
        mutation_enabled: false,
        process_spawned: false,
    };
    permit.permit_id = permit.expected_permit_id().map_err(|error| {
        ProductionMutationExecutionPermitError::Serialization(error.to_string())
    })?;
    Ok(permit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProductionMutationConsentFileIdentity, PRODUCTION_MUTATION_CONSENT_PATH};

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn activation() -> ProductionMutationActivationIntent {
        let mut value = ProductionMutationActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionMutationProfile::ExistingSinglePvLvmFilesystem,
            execution_id: digest('a'),
            source_manifest_id: digest('b'),
            native_manifest_digest: digest('c'),
            fresh_identity_digest: digest('d'),
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            lv_step_id: 3,
            filesystem_step_id: 4,
            filesystem_type: "ext4".into(),
            filesystem_mountpoint: Some("/mnt/data".into()),
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            value.profile,
            &value.execution_id,
            &value.source_manifest_id,
            &value.native_manifest_digest,
            &value.fresh_identity_digest,
            &value.target,
            &value.resolved_device,
            value.lv_step_id,
            value.filesystem_step_id,
            &value.filesystem_type,
            &value.filesystem_mountpoint,
            value.compile_feature_enabled,
            value.execution_enabled,
        ))
        .unwrap();
        value.activation_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn consent(
        activation: &ProductionMutationActivationIntent,
    ) -> ProductionMutationConsentReceipt {
        let file = ProductionMutationConsentFileIdentity {
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o600,
            link_count: 1,
            size_bytes: 256,
            sha256: digest('e'),
        };
        let mut value = ProductionMutationConsentReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            activation_id: activation.activation_id.clone(),
            execution_id: activation.execution_id.clone(),
            target: activation.target.clone(),
            resolved_device: activation.resolved_device.clone(),
            consent_path: PRODUCTION_MUTATION_CONSENT_PATH.into(),
            consent_file: file,
            consent_verified: true,
            execution_enabled: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.activation_id,
            &value.execution_id,
            &value.target,
            &value.resolved_device,
            &value.consent_path,
            &value.consent_file,
            value.consent_verified,
            value.execution_enabled,
        ))
        .unwrap();
        value.receipt_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    fn launch(
        activation: &ProductionMutationActivationIntent,
        plan_step_id: u32,
    ) -> PrivilegedLaunchPermit {
        let mut value = PrivilegedLaunchPermit {
            schema_version: 1,
            permit_id: String::new(),
            execution_id: activation.execution_id.clone(),
            execution_start_receipt_id: digest('f'),
            authorization_id: digest('1'),
            launch_id: digest('2'),
            plan_step_id,
            command_digest: digest('3'),
            mutation_enabled: false,
            process_spawned: false,
        };
        let bytes = serde_json::to_vec(&(
            value.schema_version,
            &value.execution_id,
            &value.execution_start_receipt_id,
            &value.authorization_id,
            &value.launch_id,
            value.plan_step_id,
            &value.command_digest,
            value.mutation_enabled,
            value.process_spawned,
        ))
        .unwrap();
        value.permit_id = format!("{:x}", Sha256::digest(bytes));
        value
    }

    #[cfg(feature = "production-mutation-execution-permit")]
    #[test]
    fn exact_activation_consent_and_launch_seal_nonexecuting_permit() {
        let activation = activation();
        let consent = consent(&activation);
        let launch = launch(&activation, activation.lv_step_id);

        let permit =
            seal_production_mutation_execution_permit(&activation, &consent, &launch).unwrap();
        assert!(permit.integrity_matches().unwrap());
        assert!(permit.compile_feature_enabled);
        assert!(!permit.mutation_enabled);
        assert!(!permit.process_spawned);
        assert_eq!(permit.plan_step_id, activation.lv_step_id);
    }

    #[cfg(feature = "production-mutation-execution-permit")]
    #[test]
    fn launch_outside_activation_steps_is_rejected() {
        let activation = activation();
        let consent = consent(&activation);
        let launch = launch(&activation, 99);

        assert_eq!(
            seal_production_mutation_execution_permit(&activation, &consent, &launch),
            Err(ProductionMutationExecutionPermitError::StepOutsideActivationScope)
        );
    }

    #[cfg(feature = "production-mutation-execution-permit")]
    #[test]
    fn consent_for_another_activation_is_rejected() {
        let activation = activation();
        let mut consent = consent(&activation);
        consent.activation_id = digest('9');
        let launch = launch(&activation, activation.filesystem_step_id);

        assert_eq!(
            seal_production_mutation_execution_permit(&activation, &consent, &launch),
            Err(ProductionMutationExecutionPermitError::ConsentReceiptInvalid)
        );
    }

    #[test]
    fn default_build_keeps_execution_permit_feature_disabled() {
        if !PRODUCTION_MUTATION_EXECUTION_PERMIT_COMPILED {
            let activation = activation();
            let consent = consent(&activation);
            let launch = launch(&activation, activation.lv_step_id);
            assert_eq!(
                seal_production_mutation_execution_permit(&activation, &consent, &launch),
                Err(ProductionMutationExecutionPermitError::FeatureDisabled)
            );
        }
    }
}
