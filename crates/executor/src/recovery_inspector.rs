//! Opt-in, read-only recovery inspection. No restore or approval authority.
#![allow(dead_code)]
#[cfg(test)]
use crate::{DurableJournalStore, LockedExecutionSession};
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct InspectionError;
pub(crate) enum Inspection {
    UnboundPrewrite { candidates: Vec<PathBuf> },
    Bound { record_id: String },
}

#[cfg(test)]
fn inspect_for_test(
    _session: &LockedExecutionSession<'_>,
    _store: &DurableJournalStore,
) -> Result<Inspection, InspectionError> {
    Err(InspectionError)
}

#[cfg(test)]
#[path = "recovery_inspector_tests.rs"]
mod tests;
