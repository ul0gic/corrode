// Does:  Groups JSON and Markdown report writers.
// Holds: Both formats consume the same scan result.

/// JSON report output.
pub mod json;
/// Markdown report output.
pub mod markdown;

use crate::types::{AdvisoryCheck, AdvisoryOutcome};

pub(crate) fn advisory_summary(checks: &[AdvisoryCheck]) -> String {
    if checks.is_empty() {
        return "Coverage unavailable".to_owned();
    }
    let mut matched = 0;
    let mut no_match = 0;
    let mut missing = 0;
    for check in checks {
        match check.outcome {
            AdvisoryOutcome::Matched { .. } => matched += 1,
            AdvisoryOutcome::NoMatch { .. } => no_match += 1,
            AdvisoryOutcome::NotAssessed { .. } => missing += 1,
        }
    }
    format!("{matched} matched, {no_match} no match, {missing} not assessed")
}

pub(crate) struct ScanOutcome {
    pub(crate) url: String,
    pub(crate) secrets: usize,
    pub(crate) vulns: usize,
    pub(crate) advisory_summary: String,
    pub(crate) status: ScanStatus,
}

pub(crate) enum ScanStatus {
    Success,
    Failed(String),
}
