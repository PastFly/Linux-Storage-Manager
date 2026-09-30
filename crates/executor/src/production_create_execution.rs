use lsm_planner::CreatePartitionTablePolicy;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    revalidate_pinned_production_create_consent, PinnedProductionCreateConsent,
    ProductionCreateActivationIntent, ProductionCreateConsentLeaseError,
    ProductionCreateConsentReceipt, ProductionCreateProfile,
};

pub const PRODUCTION_CREATE_EXECUTION_PERMIT_COMPILED: bool =
    cfg!(feature = "production-create-execution-permit");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionCreateExecutionPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub profile: ProductionCreateProfile,
    pub create_intent_id: String,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub partition_table: CreatePartitionTablePolicy,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub compile_feature_enabled: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct ExecutionPermitDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    consent_receipt_id: &'a str,
    profile: ProductionCreateProfile,
    create_intent_id: &'a str,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    partition_table: CreatePartitionTablePolicy,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    compile_feature_enabled: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionCreateExecutionPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let payload = ExecutionPermitDigestPayload {
            schema_version: self.schema_version,
            activation_id: &self.activation_id,
            consent_receipt_id: &self.consent_receipt_id,
            profile: self.profile,
            create_intent_id: &self.create_intent_id,
            create_plan_id: &self.create_plan_id,
            source_id: &self.source_id,
            disk: &self.disk,
            disk_size_bytes: self.disk_size_bytes,
            logical_sector_bytes: self.logical_sector_bytes,
            partition_table: self.partition_table,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            compile_feature_enabled: self.compile_feature_enabled,
            mutation_enabled: self.mutation_enabled,
            process_spawned: self.process_spawned,
            partition_table_changed: self.partition_table_changed,
            filesystem_formatted: self.filesystem_formatted,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionCreateExecutionPermitError {
    #[error("production create execution-permit feature is not compiled")]
    FeatureDisabled,
    #[error("create activation integrity check failed")]
    ActivationInvalid,
    #[error("pinned create consent revalidation failed: {0}")]
    ConsentLease(#[from] ProductionCreateConsentLeaseError),
    #[error("create consent receipt integrity check failed")]
    ConsentInvalid,
    #[error("create activation and consent receipt do not bind the same exact operation")]
    ConsentBindingMismatch,
    #[error("upstream create authorization unexpectedly enables mutation or reports completed writes")]
    UpstreamAlreadyEnabled,
    #[error("create execution-permit serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_activation(
    activation: &ProductionCreateActivationIntent,
) -> Result<(), ProductionCreateExecutionPermitError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
    {
        return Err(ProductionCreateExecutionPermitError::ActivationInvalid);
    }
    if activation.execution_enabled
        || activation.partition_table_changed
        || activation.filesystem_formatted
    {
        return Err(ProductionCreateExecutionPermitError::UpstreamAlreadyEnabled);
    }
    Ok(())
}

fn validate_consent(
    activation: &ProductionCreateActivationIntent,
    consent: &ProductionCreateConsentReceipt,
) -> Result<(), ProductionCreateExecutionPermitError> {
    if consent.schema_version != 1
        || !consent.integrity_matches().unwrap_or(false)
        || !consent.consent_verified
    {
        return Err(ProductionCreateExecutionPermitError::ConsentInvalid);
    }
    if consent.execution_enabled {
        return Err(ProductionCreateExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if consent.activation_id != activation.activation_id
        || consent.create_intent_id != activation.create_intent_id
        || consent.disk != activation.disk
        || consent.filesystem != activation.filesystem
    {
        return Err(ProductionCreateExecutionPermitError::ConsentBindingMismatch);
    }
    Ok(())
}

fn seal_from_receipt(
    activation: &ProductionCreateActivationIntent,
    consent: &ProductionCreateConsentReceipt,
) -> Result<ProductionCreateExecutionPermit, ProductionCreateExecutionPermitError> {
    validate_activation(activation)?;
    validate_consent(activation, consent)?;

    let mut permit = ProductionCreateExecutionPermit {
        schema_version: 1,
        permit_id: String::new(),
        activation_id: activation.activation_id.clone(),
        consent_receipt_id: consent.receipt_id.clone(),
        profile: activation.profile,
        create_intent_id: activation.create_intent_id.clone(),
        create_plan_id: activation.create_plan_id.clone(),
        source_id: activation.source_id.clone(),
        disk: activation.disk.clone(),
        disk_size_bytes: activation.disk_size_bytes,
        logical_sector_bytes: activation.logical_sector_bytes,
        partition_table: activation.partition_table,
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        compile_feature_enabled: true,
        mutation_enabled: false,
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    permit.permit_id = permit.expected_permit_id()?;
    Ok(permit)
}

/// Revalidate the pinned M2A4 consent immediately before sealing one exact,
/// non-spawning create execution permit.
///
/// This still cannot write a partition table, spawn mkfs or mutate storage.
pub fn seal_production_create_execution_permit(
    activation: &ProductionCreateActivationIntent,
    consent_lease: &PinnedProductionCreateConsent,
) -> Result<ProductionCreateExecutionPermit, ProductionCreateExecutionPermitError> {
    if !PRODUCTION_CREATE_EXECUTION_PERMIT_COMPILED {
        return Err(ProductionCreateExecutionPermitError::FeatureDisabled);
    }
    validate_activation(activation)?;
    let consent = revalidate_pinned_production_create_consent(activation, consent_lease)?;
    seal_from_receipt(activation, &consent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProductionCreateConsentFileIdentity, PRODUCTION_CREATE_CONSENT_PATH,
    };

    fn activation() -> ProductionCreateActivationIntent {
        let mut value = ProductionCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionCreateProfile::BlankDiskSinglePartitionFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: "space-".to_owned() + &"c".repeat(64),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            partition_table: CreatePartitionTablePolicy::Gpt,
            partition_start_sector: 2048,
            partition_sector_count: 262_144,
            partition_size_bytes: 128 * 1024 * 1024,
            filesystem: "ext4".into(),
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    fn consent(activation: &ProductionCreateActivationIntent) -> ProductionCreateConsentReceipt {
        let file = ProductionCreateConsentFileIdentity {
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o600,
            link_count: 1,
            size_bytes: 256,
            sha256: "d".repeat(64),
        };
        let mut value = ProductionCreateConsentReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            activation_id: activation.activation_id.clone(),
            create_intent_id: activation.create_intent_id.clone(),
            disk: activation.disk.clone(),
            filesystem: activation.filesystem.clone(),
            consent_path: PRODUCTION_CREATE_CONSENT_PATH.into(),
            consent_file: file,
            consent_verified: true,
            execution_enabled: false,
        };
        value.receipt_id = value.expected_receipt_id().unwrap();
        value
    }

    #[cfg(feature = "production-create-execution-permit")]
    #[test]
    fn exact_activation_and_verified_consent_seal_nonspawning_permit() {
        let activation = activation();
        let consent = consent(&activation);
        let permit = seal_from_receipt(&activation, &consent).unwrap();

        assert!(permit.integrity_matches().unwrap());
        assert!(permit.compile_feature_enabled);
        assert!(!permit.mutation_enabled);
        assert!(!permit.process_spawned);
        assert!(!permit.partition_table_changed);
        assert!(!permit.filesystem_formatted);
        assert_eq!(permit.create_intent_id, activation.create_intent_id);
        assert_eq!(permit.partition_size_bytes, activation.partition_size_bytes);
    }

    #[cfg(feature = "production-create-execution-permit")]
    #[test]
    fn consent_for_another_activation_is_rejected() {
        let activation = activation();
        let mut consent = consent(&activation);
        consent.activation_id = "f".repeat(64);

        assert!(matches!(
            seal_from_receipt(&activation, &consent),
            Err(ProductionCreateExecutionPermitError::ConsentInvalid)
        ));
    }

    #[cfg(feature = "production-create-execution-permit")]
    #[test]
    fn activation_that_claims_prior_mutation_is_rejected() {
        let mut activation = activation();
        activation.partition_table_changed = true;

        assert!(matches!(
            seal_from_receipt(&activation, &consent(&activation)),
            Err(ProductionCreateExecutionPermitError::ActivationInvalid)
                | Err(ProductionCreateExecutionPermitError::UpstreamAlreadyEnabled)
        ));
    }

    #[test]
    fn default_build_keeps_create_execution_permit_disabled() {
        assert_eq!(
            PRODUCTION_CREATE_EXECUTION_PERMIT_COMPILED,
            cfg!(feature = "production-create-execution-permit")
        );
    }
}
