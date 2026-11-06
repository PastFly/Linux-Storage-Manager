//! Experimental publication only. This does not authorize approval or mutation.
#![allow(dead_code)]
use crate::sealed_recovery::SealedRecovery;
use crate::LockedExecutionSession;
use std::fs::File;

#[derive(Debug)]
pub(crate) struct PublicationError;

pub(crate) struct PublishedRecovery;

impl PublishedRecovery {
    pub(crate) fn publish(
        _session: &LockedExecutionSession<'_>,
        _sealed: SealedRecovery,
        _record_directory: File,
    ) -> Result<Self, PublicationError> {
        Err(PublicationError)
    }
}

#[cfg(test)]
#[path = "sealed_recovery_store_tests.rs"]
mod tests;
