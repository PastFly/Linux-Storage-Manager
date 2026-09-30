use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    PinnedProductionSwapPartitionRemovalTools, PrivilegedProgram,
    ProductionSwapPartitionRemovalPreflight, ProductionSwapPartitionRemovalToolLeaseError,
    TrustedToolIdentity,
};

pub const PRODUCTION_SWAP_PARTITION_REMOVAL_LAUNCH_COMPILED: bool =
    cfg!(feature = "production-swap-replacement-partition-removal-launch");

const FIXED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const FIXED_LOCALE: &str = "C";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapPartitionRemovalLaunchStage {
    pub program: PrivilegedProgram,
    pub argv: Vec<String>,
    pub tool: TrustedToolIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionSwapPartitionRemovalLaunchSpec {
    pub schema_version: u32,
    pub launch_id: String,
    pub preflight_id: String,
    pub journal_id: String,
    pub disk: String,
    pub retiring_swap_partition_number: u32,
    pub extended_partition_number: u32,
    pub sfdisk_delete: ProductionSwapPartitionRemovalLaunchStage,
    pub partx_update: ProductionSwapPartitionRemovalLaunchStage,
    pub fixed_path: String,
    pub fixed_locale: String,
    pub process_spawned: bool,
    pub partition_table_changed: bool,
}

#[derive(Serialize)]
struct LaunchDigestPayload<'a> {
    schema_version: u32,
    preflight_id: &'a str,
    journal_id: &'a str,
    disk: &'a str,
    retiring_swap_partition_number: u32,
    extended_partition_number: u32,
    sfdisk_delete: &'a ProductionSwapPartitionRemovalLaunchStage,
    partx_update: &'a ProductionSwapPartitionRemovalLaunchStage,
    fixed_path: &'a str,
    fixed_locale: &'a str,
    process_spawned: bool,
    partition_table_changed: bool,
}

impl ProductionSwapPartitionRemovalLaunchSpec {
    pub fn integrity_matches(&self) -> Result<bool, serde_json::Error> {
        Ok(self.launch_id == self.expected_launch_id()?)
    }

    fn expected_launch_id(&self) -> Result<String, serde_json::Error> {
        let payload = LaunchDigestPayload {
            schema_version: self.schema_version,
            preflight_id: &self.preflight_id,
            journal_id: &self.journal_id,
            disk: &self.disk,
            retiring_swap_partition_number: self.retiring_swap_partition_number,
            extended_partition_number: self.extended_partition_number,
            sfdisk_delete: &self.sfdisk_delete,
            partx_update: &self.partx_update,
            fixed_path: &self.fixed_path,
            fixed_locale: &self.fixed_locale,
            process_spawned: self.process_spawned,
            partition_table_changed: self.partition_table_changed,
        };
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&payload)?)
        ))
    }
}

#[derive(Debug, Error)]
pub enum ProductionSwapPartitionRemovalLaunchError {
    #[error("production swap partition-removal launch feature is not compiled")]
    FeatureDisabled,
    #[error("partition-removal preflight integrity or geometry is invalid")]
    PreflightInvalid,
    #[error("pinned partition-removal tool lease is invalid: {0}")]
    ToolLease(#[from] ProductionSwapPartitionRemovalToolLeaseError),
    #[error("partition-removal launch tool identities do not match required programs")]
    ProgramMismatch,
    #[error("partition-removal launch serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn validate_preflight(
    preflight: &ProductionSwapPartitionRemovalPreflight,
) -> Result<(), ProductionSwapPartitionRemovalLaunchError> {
    if preflight.schema_version != 1
        || !preflight.integrity_matches().unwrap_or(false)
        || preflight.mutation_enabled
        || preflight.partition_table_changed
        || preflight.table_label != "dos"
        || preflight.disk.is_empty()
        || !preflight.disk.starts_with("/dev/")
        || preflight.retiring_swap_partition_number < 5
        || preflight.extended_partition_number == 0
        || preflight.extended_partition_number >= 5
        || preflight.retiring_swap_partition_number == preflight.extended_partition_number
        || preflight.retiring_swap_size_sectors == 0
        || preflight.extended_size_sectors == 0
    {
        return Err(ProductionSwapPartitionRemovalLaunchError::PreflightInvalid);
    }
    Ok(())
}

fn build_from_identities(
    preflight: &ProductionSwapPartitionRemovalPreflight,
    sfdisk: TrustedToolIdentity,
    partx: TrustedToolIdentity,
) -> Result<ProductionSwapPartitionRemovalLaunchSpec, ProductionSwapPartitionRemovalLaunchError> {
    validate_preflight(preflight)?;
    if sfdisk.program != PrivilegedProgram::Sfdisk || partx.program != PrivilegedProgram::Partx {
        return Err(ProductionSwapPartitionRemovalLaunchError::ProgramMismatch);
    }

    // sfdisk accepts an ordered list of partition numbers for --delete. The
    // logical swap is deliberately listed before its extended container.
    let sfdisk_delete = ProductionSwapPartitionRemovalLaunchStage {
        program: PrivilegedProgram::Sfdisk,
        argv: vec![
            "sfdisk".into(),
            "--lock=yes".into(),
            "--delete".into(),
            preflight.disk.clone(),
            preflight.retiring_swap_partition_number.to_string(),
            preflight.extended_partition_number.to_string(),
        ],
        tool: sfdisk,
    };
    let partx_update = ProductionSwapPartitionRemovalLaunchStage {
        program: PrivilegedProgram::Partx,
        argv: vec!["partx".into(), "--update".into(), preflight.disk.clone()],
        tool: partx,
    };

    let mut launch = ProductionSwapPartitionRemovalLaunchSpec {
        schema_version: 1,
        launch_id: String::new(),
        preflight_id: preflight.preflight_id.clone(),
        journal_id: preflight.journal_id.clone(),
        disk: preflight.disk.clone(),
        retiring_swap_partition_number: preflight.retiring_swap_partition_number,
        extended_partition_number: preflight.extended_partition_number,
        sfdisk_delete,
        partx_update,
        fixed_path: FIXED_PATH.into(),
        fixed_locale: FIXED_LOCALE.into(),
        process_spawned: false,
        partition_table_changed: false,
    };
    launch.launch_id = launch.expected_launch_id()?;
    Ok(launch)
}

/// Freeze the exact descriptor-based partition-removal command sequence.
///
/// This is intentionally non-spawning. The future executor is not allowed to
/// derive different argv or resolve executable paths again.
pub fn build_production_swap_partition_removal_launch_spec(
    preflight: &ProductionSwapPartitionRemovalPreflight,
    tools: &PinnedProductionSwapPartitionRemovalTools,
) -> Result<ProductionSwapPartitionRemovalLaunchSpec, ProductionSwapPartitionRemovalLaunchError> {
    if !PRODUCTION_SWAP_PARTITION_REMOVAL_LAUNCH_COMPILED {
        return Err(ProductionSwapPartitionRemovalLaunchError::FeatureDisabled);
    }
    validate_preflight(preflight)?;
    tools.revalidate(preflight)?;
    build_from_identities(preflight, tools.sfdisk.clone(), tools.partx.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(program: PrivilegedProgram, name: &str) -> TrustedToolIdentity {
        TrustedToolIdentity {
            program,
            requested_path: format!("/usr/sbin/{name}"),
            canonical_path: format!("/usr/sbin/{name}"),
            device_id: 1,
            inode: if program == PrivilegedProgram::Sfdisk {
                2
            } else {
                3
            },
            uid: 0,
            mode: 0o100755,
            size_bytes: 4096,
            sha256: "a".repeat(64),
        }
    }

    fn preflight() -> ProductionSwapPartitionRemovalPreflight {
        let mut value = ProductionSwapPartitionRemovalPreflight {
            schema_version: 1,
            preflight_id: String::new(),
            journal_id: "1".repeat(64),
            activation_id: "2".repeat(64),
            persistent_config_receipt_id: "3".repeat(64),
            disk: "/dev/sda".into(),
            table_label: "dos".into(),
            table_id: Some("0x12345678".into()),
            sector_size_bytes: 512,
            retiring_swap_device: "/dev/sda5".into(),
            retiring_swap_partition_number: 5,
            retiring_swap_start_sector: 1_004_096,
            retiring_swap_size_sectors: 200_000,
            extended_partition_device: "/dev/sda2".into(),
            extended_partition_number: 2,
            extended_start_sector: 1_002_048,
            extended_size_sectors: 600_000,
            partition_backup_path: "/var/lib/linux-storage-manager/swap-runtime/backup.sfdisk"
                .into(),
            partition_backup_sha256: "b".repeat(64),
            mutation_enabled: false,
            partition_table_changed: false,
        };
        value.preflight_id = value.expected_preflight_id().unwrap();
        value
    }

    #[test]
    fn exact_launch_deletes_logical_swap_before_extended_container() {
        let preflight = preflight();
        let launch = build_from_identities(
            &preflight,
            identity(PrivilegedProgram::Sfdisk, "sfdisk"),
            identity(PrivilegedProgram::Partx, "partx"),
        )
        .unwrap();

        assert!(launch.integrity_matches().unwrap());
        assert_eq!(
            launch.sfdisk_delete.argv,
            ["sfdisk", "--lock=yes", "--delete", "/dev/sda", "5", "2"]
        );
        assert_eq!(launch.partx_update.argv, ["partx", "--update", "/dev/sda"]);
        assert!(!launch.process_spawned);
        assert!(!launch.partition_table_changed);
    }

    #[test]
    fn wrong_tool_program_fails_closed() {
        let preflight = preflight();
        assert!(matches!(
            build_from_identities(
                &preflight,
                identity(PrivilegedProgram::Partx, "partx"),
                identity(PrivilegedProgram::Partx, "partx"),
            ),
            Err(ProductionSwapPartitionRemovalLaunchError::ProgramMismatch)
        ));
    }

    #[test]
    fn launch_integrity_detects_argv_tampering() {
        let preflight = preflight();
        let mut launch = build_from_identities(
            &preflight,
            identity(PrivilegedProgram::Sfdisk, "sfdisk"),
            identity(PrivilegedProgram::Partx, "partx"),
        )
        .unwrap();
        launch.sfdisk_delete.argv[4] = "6".into();
        assert!(!launch.integrity_matches().unwrap());
    }
}
