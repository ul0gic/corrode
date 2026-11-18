// Does:  Groups browser setup and scan orchestration.
// Holds: Browser discovery and page extraction can be used independently of batch orchestration.

/// Chrome executable discovery.
pub mod chrome;
/// Browser page utilities.
pub mod page_utils;
/// Scan orchestration.
pub mod workflow;
