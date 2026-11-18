// Does:  Groups JSON and Markdown report writers.
// Holds: Both formats consume the same scan result.

/// JSON report output.
pub mod json;
/// Markdown report output.
pub mod markdown;

pub(crate) struct ScanOutcome {
    pub(crate) url: String,
    pub(crate) secrets: usize,
    pub(crate) vulns: usize,
    pub(crate) status: ScanStatus,
}

pub(crate) enum ScanStatus {
    Success,
    Failed(String),
}
