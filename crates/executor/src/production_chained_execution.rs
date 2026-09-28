use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PrivilegedLaunchPermit, ProductionChainedMutationActivationIntent,
    ProductionMutationConsentReceipt,
};

pub const PRODUCTION_CHAINED_MUTATION_EXECUTION_PERMIT_COMPILED: bool =
    cfg!(feature = "production-chained-mutation-execution-permit");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionChainedMutationExecutionPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub execution_id: String,
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

impl ProductionChainedMutationExecutionPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(&(
            self.schema_version,
            &self.activation_id,
            &self.consent_receipt_id,
            &self.execution_id,
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
pub enum ProductionChainedMutationExecutionPermitError {
    #[error("chained production execution-permit feature is not compiled")]
    FeatureDisabled,
    #[error("chained production activation intent integrity check failed")]
    ActivationIntentInvalid,
    #[error("production consent receipt integrity check failed")]
    ConsentReceiptInvalid,
    #[error("privileged launch permit integrity check failed")]
    LaunchPermitInvalid,
    #[error("activation and runtime consent do not describe the same exact execution")]
    ConsentBindingMismatch,
    #[error("launch permit does not belong to the chained activation execution")]
    LaunchExecutionMismatch,
    #[error("launch step is outside the exact four-step chained activation scope")]
    StepOutsideActivationScope,
    #[error("upstream authorization unexpectedly reports mutation or process execution enabled")]
    UpstreamAlreadyEnabled,
    #[error("chained execution-permit serialization failed: {0}")]
    Serialization(String),
}

fn validate_activation(
    activation: &ProductionChainedMutationActivationIntent,
) -> Result<(), ProductionChainedMutationExecutionPermitError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
    {
        return Err(ProductionChainedMutationExecutionPermitError::ActivationIntentInvalid);
    }
    if activation.execution_enabled {
        return Err(ProductionChainedMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    Ok(())
}

fn validate_consent(
    activation: &ProductionChainedMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
) -> Result<(), ProductionChainedMutationExecutionPermitError> {
    if consent.schema_version != 1
        || !consent.integrity_matches().unwrap_or(false)
        || !consent.consent_verified
    {
        return Err(ProductionChainedMutationExecutionPermitError::ConsentReceiptInvalid);
    }
    if consent.execution_enabled {
        return Err(ProductionChainedMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if consent.activation_id != activation.activation_id
        || consent.execution_id != activation.execution_id
        || consent.target != activation.target
        || consent.resolved_device != activation.resolved_device
    {
        return Err(ProductionChainedMutationExecutionPermitError::ConsentBindingMismatch);
    }
    Ok(())
}

fn validate_launch(
    activation: &ProductionChainedMutationActivationIntent,
    launch: &PrivilegedLaunchPermit,
) -> Result<(), ProductionChainedMutationExecutionPermitError> {
    if launch.schema_version != 1 || !launch.integrity_matches().unwrap_or(false) {
        return Err(ProductionChainedMutationExecutionPermitError::LaunchPermitInvalid);
    }
    if launch.mutation_enabled || launch.process_spawned {
        return Err(ProductionChainedMutationExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if launch.execution_id != activation.execution_id {
        return Err(ProductionChainedMutationExecutionPermitError::LaunchExecutionMismatch);
    }
    let allowed = [
        activation.partition_step_id,
        activation.pv_step_id,
        activation.lv_step_id,
        activation.filesystem_step_id,
    ];
    if !allowed.contains(&launch.plan_step_id) {
        return Err(ProductionChainedMutationExecutionPermitError::StepOutsideActivationScope);
    }
    Ok(())
}

/// Seal chained activation + exact root consent + one exact descriptor launch
/// into a non-spawning execution permit.
///
/// This deliberately does not reuse the M1B37 narrow permit type. The permit
/// remains mutation_enabled=false and process_spawned=false, and no production
/// descriptor-execution API consumes it yet.
pub fn seal_production_chained_mutation_execution_permit(
    activation: &ProductionChainedMutationActivationIntent,
    consent: &ProductionMutationConsentReceipt,
    launch: &PrivilegedLaunchPermit,
) -> Result<ProductionChainedMutationExecutionPermit, ProductionChainedMutationExecutionPermitError>
{
    if !PRODUCTION_CHAINED_MUTATION_EXECUTION_PERMIT_COMPILED {
        return Err(ProductionChainedMutationExecutionPermitError::FeatureDisabled);
    }
    validate_activation(activation)?;
    validate_consent(activation, consent)?;
    validate_launch(activation, launch)?;

    let mut permit = ProductionChainedMutationExecutionPermit {
        schema_version: 1,
        permit_id: String::new(),
        activation_id: activation.activation_id.clone(),
        consent_receipt_id: consent.receipt_id.clone(),
        execution_id: activation.execution_id.clone(),
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
        ProductionChainedMutationExecutionPermitError::Serialization(error.to_string())
    })?;
    Ok(permit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProductionChainedMutationProfile, ProductionMutationConsentFileIdentity,
        PRODUCTION_MUTATION_CONSENT_PATH,
    };

    fn digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    #[derive(Serialize)]
    struct ActivationDigestPayload<'a> {
        schema_version: u32,
        profile: ProductionChainedMutationProfile,
        execution_id: &'a str,
        source_manifest_id: &'a str,
        native_manifest_digest: &'a str,
        fresh_identity_digest: &'a str,
        target: &'a str,
        resolved_device: &'a str,
        partition_step_id: u32,
        pv_step_id: u32,
        lv_step_id: u32,
        filesystem_step_id: u32,
        partition: &'a str,
        pv_uuid: &'a str,
        lv_uuid: &'a str,
        filesystem_type: &'a str,
        filesystem_mountpoint: &'a Option<String>,
        compile_feature_enabled: bool,
        execution_enabled: bool,
    }

    fn activation() -> ProductionChainedMutationActivationIntent {
        let mut value = ProductionChainedMutationActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionChainedMutationProfile::SinglePvPartitionTailLvmFilesystem,
            execution_id: digest('a'),
            source_manifest_id: digest('b'),
            native_manifest_digest: digest('c'),
            fresh_identity_digest: digest('d'),
            target: "/mnt/data".into(),
            resolved_device: "/dev/mapper/vg-data".into(),
            partition_step_id: 3,
            pv_step_id: 4,
            lv_step_id: 5,
            filesystem_step_id: 6,
            partition: "/dev/sda1".into(),
            pv_uuid: "pv-uuid".into(),
            lv_uuid: "lv-uuid".into(),
            filesystem_type: "ext4".into(),
            filesystem_mountpoint: Some("/mnt/data".into()),
            compile_feature_enabled: true,
            execution_enabled: false,
        };
        let payload = ActivationDigestPayload {
            schema_version: value.schema_version,
            profile: value.profile,
            execution_id: &value.execution_id,
            source_manifest_id: &value.source_manifest_id,
            native_manifest_digest: &value.native_manifest_digest,
            fresh_identity_digest: &value.fresh_identity_digest,
            target: &value.target,
            resolved_device: &value.resolved_device,
            partition_step_id: value.partition_step_id,
            pv_step_id: value.pv_step_id,
            lv_step_id: value.lv_step_id,
            filesystem_step_id: value.filesystem_step_id,
            partition: &value.partition,
            pv_uuid: &value.pv_uuid,
            lv_uuid: &value.lv_uuid,
            filesystem_type: &value.filesystem_type,
            filesystem_mountpoint: &value.filesystem_mountpoint,
            compile_feature_enabled: value.compile_feature_enabled,
            execution_enabled: value.execution_enabled,
        };
        value.activation_id =
            format!("{:x}", Sha256::digest(serde_json::to_vec(&payload).unwrap()));
        value
    }

    fn consent(activation: &ProductionChainedMutationActivationIntent) -> ProductionMutationConsentReceipt {
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
        activation: &ProductionChainedMutationActivationIntent,
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

    #[cfg(feature = "production-chained-mutation-execution-permit")]
    #[test]
    fn exact_chained_activation_consent_and_each_launch_step_can_seal_nonspawning_permit() {
        let activation = activation();
        let consent = consent(&activation);
        for plan_step_id in [
            activation.partition_step_id,
            activation.pv_step_id,
            activation.lv_step_id,
            activation.filesystem_step_id,
        ] {
            let permit = seal_production_chained_mutation_execution_permit(
                &activation,
                &consent,
                &launch(&activation, plan_step_id),
            )
            .unwrap();
            assert!(permit.integrity_matches().unwrap());
            assert_eq!(permit.plan_step_id, plan_step_id);
            assert!(!permit.mutation_enabled);
            assert!(!permit.process_spawned);
        }
    }

    #[cfg(feature = "production-chained-mutation-execution-permit")]
    #[test]
    fn launch_outside_chained_activation_scope_is_rejected() {
        let activation = activation();
        let consent = consent(&activation);
        assert_eq!(
            seal_production_chained_mutation_execution_permit(
                &activation,
                &consent,
                &launch(&activation, 99),
            ),
            Err(ProductionChainedMutationExecutionPermitError::StepOutsideActivationScope)
        );
    }

    #[test]
    fn default_build_keeps_chained_execution_permit_disabled() {
        if !PRODUCTION_CHAINED_MUTATION_EXECUTION_PERMIT_COMPILED {
            let activation = activation();
            let consent = consent(&activation);
            assert_eq!(
                seal_production_chained_mutation_execution_permit(
                    &activation,
                    &consent,
                    &launch(&activation, activation.partition_step_id),
                ),
                Err(ProductionChainedMutationExecutionPermitError::FeatureDisabled)
            );
        }
    }
}
