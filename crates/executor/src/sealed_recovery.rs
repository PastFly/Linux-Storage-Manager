//! Experimental protected-copy sealing; never grants approval or mutation.
#![allow(dead_code)]

use crate::{LockedExecutionSession, MetadataBackupManifest, MetadataBackupReceipt};
use std::fs::File;

pub(crate) struct PinnedCopies {
    pub(crate) primary_dir: File,
    pub(crate) recovery_dir: File,
    pub(crate) pairs: Vec<(File, File)>,
}

#[derive(Debug)]
pub(crate) struct SealError;

pub(crate) struct SealedRecovery;

impl SealedRecovery {
    pub(crate) fn seal(
        _session: &LockedExecutionSession<'_>,
        _manifest: &MetadataBackupManifest,
        _receipt: &MetadataBackupReceipt,
        _copies: PinnedCopies,
    ) -> Result<Self, SealError> {
        Err(SealError)
    }
}

#[cfg(test)]
#[path = "sealed_recovery_tests.rs"]
mod tests;
