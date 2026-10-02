use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    revalidate_pinned_production_gpt_tail_create_consent, PinnedProductionGptTailCreateConsent,
    ProductionGptTailCreateActivationIntent, ProductionGptTailCreateConsentLeaseError,
    ProductionGptTailCreateConsentReceipt, ProductionGptTailCreateProfile,
};

pub const PRODUCTION_GPT_TAIL_CREATE_EXECUTION_PERMIT_COMPILED: bool =
    cfg!(feature = "production-gpt-tail-execution-permit");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionGptTailCreateExecutionPermit {
    pub schema_version: u32,
    pub permit_id: String,
    pub activation_id: String,
    pub consent_receipt_id: String,
    pub profile: ProductionGptTailCreateProfile,
    pub create_intent_id: String,
    pub create_plan_id: String,
    pub source_id: String,
    pub disk: String,
    pub disk_size_bytes: u64,
    pub logical_sector_bytes: u64,
    pub gpt_disk_id: String,
    pub gpt_first_lba: u64,
    pub gpt_last_lba: u64,
    pub gpt_sector_size_bytes: u64,
    pub gpt_table_sha256: String,
    pub existing_partition_count: u32,
    pub source_start_sector: u64,
    pub source_sector_count: u64,
    pub source_size_bytes: u64,
    pub partition_start_sector: u64,
    pub partition_sector_count: u64,
    pub partition_size_bytes: u64,
    pub filesystem: String,
    pub partition_slot_deferred: bool,
    pub compile_feature_enabled: bool,
    pub mutation_enabled: bool,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
    pub filesystem_formatted: bool,
}

#[derive(Serialize)]
struct PermitDigestPayload<'a> {
    schema_version: u32,
    activation_id: &'a str,
    consent_receipt_id: &'a str,
    profile: ProductionGptTailCreateProfile,
    create_intent_id: &'a str,
    create_plan_id: &'a str,
    source_id: &'a str,
    disk: &'a str,
    disk_size_bytes: u64,
    logical_sector_bytes: u64,
    gpt_disk_id: &'a str,
    gpt_first_lba: u64,
    gpt_last_lba: u64,
    gpt_sector_size_bytes: u64,
    gpt_table_sha256: &'a str,
    existing_partition_count: u32,
    source_start_sector: u64,
    source_sector_count: u64,
    source_size_bytes: u64,
    partition_start_sector: u64,
    partition_sector_count: u64,
    partition_size_bytes: u64,
    filesystem: &'a str,
    partition_slot_deferred: bool,
    compile_feature_enabled: bool,
    mutation_enabled: bool,
    process_spawned: bool,
    partition_table_changed: bool,
    filesystem_formatted: bool,
}

impl ProductionGptTailCreateExecutionPermit {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.permit_id == self.expected_permit_id()?)
    }

    pub(crate) fn expected_permit_id(&self) -> Result<String, serde_json::Error> {
        let payload = PermitDigestPayload {
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
            gpt_disk_id: &self.gpt_disk_id,
            gpt_first_lba: self.gpt_first_lba,
            gpt_last_lba: self.gpt_last_lba,
            gpt_sector_size_bytes: self.gpt_sector_size_bytes,
            gpt_table_sha256: &self.gpt_table_sha256,
            existing_partition_count: self.existing_partition_count,
            source_start_sector: self.source_start_sector,
            source_sector_count: self.source_sector_count,
            source_size_bytes: self.source_size_bytes,
            partition_start_sector: self.partition_start_sector,
            partition_sector_count: self.partition_sector_count,
            partition_size_bytes: self.partition_size_bytes,
            filesystem: &self.filesystem,
            partition_slot_deferred: self.partition_slot_deferred,
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
pub enum ProductionGptTailCreateExecutionPermitError {
    #[error("production GPT-tail create execution-permit feature is not compiled")]
    FeatureDisabled,
    #[error("GPT-tail create activation integrity check failed")]
    ActivationInvalid,
    #[error("pinned GPT-tail create consent revalidation failed: {0}")]
    ConsentLease(#[from] ProductionGptTailCreateConsentLeaseError),
    #[error("GPT-tail create consent receipt integrity check failed")]
    ConsentInvalid,
    #[error("GPT-tail activation and consent do not bind the same exact operation")]
    ConsentBindingMismatch,
    #[error("upstream GPT-tail authorization unexpectedly crossed a mutation boundary")]
    UpstreamAlreadyEnabled,
    #[error("GPT-tail create execution-permit serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_activation(
    activation: &ProductionGptTailCreateActivationIntent,
) -> Result<(), ProductionGptTailCreateExecutionPermitError> {
    if activation.schema_version != 1
        || !activation.integrity_matches().unwrap_or(false)
        || !activation.compile_feature_enabled
        || !activation.partition_slot_deferred
    {
        return Err(ProductionGptTailCreateExecutionPermitError::ActivationInvalid);
    }
    if activation.execution_enabled
        || activation.partition_table_changed
        || activation.filesystem_formatted
    {
        return Err(ProductionGptTailCreateExecutionPermitError::UpstreamAlreadyEnabled);
    }
    Ok(())
}

fn validate_consent(
    activation: &ProductionGptTailCreateActivationIntent,
    consent: &ProductionGptTailCreateConsentReceipt,
) -> Result<(), ProductionGptTailCreateExecutionPermitError> {
    if consent.schema_version != 1
        || !consent.integrity_matches().unwrap_or(false)
        || !consent.consent_verified
    {
        return Err(ProductionGptTailCreateExecutionPermitError::ConsentInvalid);
    }
    if consent.execution_enabled {
        return Err(ProductionGptTailCreateExecutionPermitError::UpstreamAlreadyEnabled);
    }
    if consent.activation_id != activation.activation_id
        || consent.create_intent_id != activation.create_intent_id
        || consent.disk != activation.disk
        || consent.gpt_disk_id != activation.gpt_disk_id
        || consent.gpt_table_sha256 != activation.gpt_table_sha256
        || consent.partition_start_sector != activation.partition_start_sector
        || consent.partition_sector_count != activation.partition_sector_count
        || consent.filesystem != activation.filesystem
    {
        return Err(ProductionGptTailCreateExecutionPermitError::ConsentBindingMismatch);
    }
    Ok(())
}

fn seal_from_receipt(
    activation: &ProductionGptTailCreateActivationIntent,
    consent: &ProductionGptTailCreateConsentReceipt,
) -> Result<ProductionGptTailCreateExecutionPermit, ProductionGptTailCreateExecutionPermitError> {
    validate_activation(activation)?;
    validate_consent(activation, consent)?;

    let mut permit = ProductionGptTailCreateExecutionPermit {
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
        gpt_disk_id: activation.gpt_disk_id.clone(),
        gpt_first_lba: activation.gpt_first_lba,
        gpt_last_lba: activation.gpt_last_lba,
        gpt_sector_size_bytes: activation.gpt_sector_size_bytes,
        gpt_table_sha256: activation.gpt_table_sha256.clone(),
        existing_partition_count: activation.existing_partition_count,
        source_start_sector: activation.source_start_sector,
        source_sector_count: activation.source_sector_count,
        source_size_bytes: activation.source_size_bytes,
        partition_start_sector: activation.partition_start_sector,
        partition_sector_count: activation.partition_sector_count,
        partition_size_bytes: activation.partition_size_bytes,
        filesystem: activation.filesystem.clone(),
        partition_slot_deferred: true,
        compile_feature_enabled: true,
        mutation_enabled: false,
        process_spawned: false,
        partition_table_changed: false,
        filesystem_formatted: false,
    };
    permit.permit_id = permit.expected_permit_id()?;
    Ok(permit)
}

/// Revalidate the pinned M2B4 consent immediately before sealing one exact,
/// non-spawning GPT-tail execution permit. Partition-slot selection remains
/// deferred and no runtime storage mutation is authorized here.
pub fn seal_production_gpt_tail_create_execution_permit(
    activation: &ProductionGptTailCreateActivationIntent,
    consent_lease: &PinnedProductionGptTailCreateConsent,
) -> Result<ProductionGptTailCreateExecutionPermit, ProductionGptTailCreateExecutionPermitError> {
    if !PRODUCTION_GPT_TAIL_CREATE_EXECUTION_PERMIT_COMPILED {
        return Err(ProductionGptTailCreateExecutionPermitError::FeatureDisabled);
    }
    validate_activation(activation)?;
    let consent = revalidate_pinned_production_gpt_tail_create_consent(activation, consent_lease)?;
    seal_from_receipt(activation, &consent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProductionGptTailCreateConsentFileIdentity, PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH,
    };

    fn activation() -> ProductionGptTailCreateActivationIntent {
        let mut value = ProductionGptTailCreateActivationIntent {
            schema_version: 1,
            activation_id: String::new(),
            profile: ProductionGptTailCreateProfile::ExistingGptTailFilesystem,
            create_intent_id: "a".repeat(64),
            create_plan_id: "b".repeat(64),
            source_id: format!("space-{}", "c".repeat(58)),
            disk: "/dev/loop7".into(),
            disk_size_bytes: 512 * 1024 * 1024,
            logical_sector_bytes: 512,
            disk_model: Some("loop-test".into()),
            disk_serial: Some("fixture-001".into()),
            gpt_disk_id: "12345678-1234-1234-1234-123456789abc".into(),
            gpt_first_lba: 34,
            gpt_last_lba: 1_048_542,
            gpt_sector_size_bytes: 512,
            gpt_table_sha256: "d".repeat(64),
            existing_partition_count: 1,
            source_start_sector: 133_120,
            source_sector_count: 915_423,
            source_size_bytes: 468_696_576,
            partition_start_sector: 133_120,
            partition_sector_count: 131_072,
            partition_size_bytes: 64 * 1024 * 1024,
            filesystem: "ext4".into(),
            partition_slot_deferred: true,
            compile_feature_enabled: true,
            execution_enabled: false,
            partition_table_changed: false,
            filesystem_formatted: false,
        };
        value.activation_id = value.expected_activation_id().unwrap();
        value
    }

    fn consent(
        activation: &ProductionGptTailCreateActivationIntent,
    ) -> ProductionGptTailCreateConsentReceipt {
        let file = ProductionGptTailCreateConsentFileIdentity {
            device_id: 1,
            inode: 2,
            uid: 0,
            mode: libc::S_IFREG | 0o600,
            link_count: 1,
            size_bytes: 512,
            sha256: "e".repeat(64),
        };
        let mut value = ProductionGptTailCreateConsentReceipt {
            schema_version: 1,
            receipt_id: String::new(),
            activation_id: activation.activation_id.clone(),
            create_intent_id: activation.create_intent_id.clone(),
            disk: activation.disk.clone(),
            gpt_disk_id: activation.gpt_disk_id.clone(),
            gpt_table_sha256: activation.gpt_table_sha256.clone(),
            partition_start_sector: activation.partition_start_sector,
            partition_sector_count: activation.partition_sector_count,
            filesystem: activation.filesystem.clone(),
            consent_path: PRODUCTION_GPT_TAIL_CREATE_CONSENT_PATH.into(),
            consent_file: file,
            consent_verified: true,
            execution_enabled: false,
        };
        value.receipt_id = value.expected_receipt_id().unwrap();
        value
    }

    #[test]
    fn exact_activation_and_consent_seal_nonspawning_permit() {
        let activation = activation();
        let consent = consent(&activation);
        let permit = seal_from_receipt(&activation, &consent).unwrap();

        assert!(permit.integrity_matches().unwrap());
        assert!(permit.compile_feature_enabled);
        assert!(permit.partition_slot_deferred);
        assert!(!permit.mutation_enabled);
        assert!(!permit.process_spawned);
        assert!(!permit.partition_table_changed);
        assert!(!permit.filesystem_formatted);
        assert_eq!(permit.gpt_table_sha256, activation.gpt_table_sha256);
        assert_eq!(
            permit.partition_sector_count,
            activation.partition_sector_count
        );
    }

    #[test]
    fn consent_for_stale_gpt_table_is_rejected() {
        let activation = activation();
        let mut consent = consent(&activation);
        consent.gpt_table_sha256 = "f".repeat(64);

        assert!(matches!(
            seal_from_receipt(&activation, &consent),
            Err(ProductionGptTailCreateExecutionPermitError::ConsentInvalid)
        ));
    }

    #[test]
    fn activation_that_claims_prior_mutation_is_rejected() {
        let mut activation = activation();
        activation.partition_table_changed = true;

        assert!(matches!(
            seal_from_receipt(&activation, &consent(&activation)),
            Err(ProductionGptTailCreateExecutionPermitError::ActivationInvalid)
                | Err(ProductionGptTailCreateExecutionPermitError::UpstreamAlreadyEnabled)
        ));
    }

    #[test]
    fn permit_feature_is_explicitly_gated() {
        assert_eq!(
            PRODUCTION_GPT_TAIL_CREATE_EXECUTION_PERMIT_COMPILED,
            cfg!(feature = "production-gpt-tail-execution-permit")
        );
    }
}
