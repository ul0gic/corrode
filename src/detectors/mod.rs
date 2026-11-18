// Does:  Groups the scan detectors by evidence and analysis domain.
// Holds: Captured evidence can be classified and scored independently of browser collection.

/// Collection of browser and JavaScript evidence.
pub mod collectors;
/// Confidence scoring from evidence signals.
pub mod confidence;
/// API endpoint candidates inferred from captured JavaScript.
pub mod endpoints;
/// Framework manifest analysis.
pub mod manifests;
/// Confidence assignment for scan results.
pub mod scoring;
/// Secret and comment detection.
pub mod secrets;
/// Security analysis of captured responses.
pub mod security;
/// Session and storage evidence analysis.
pub mod session;
/// Source-map retrieval and analysis.
pub mod sourcemaps;
/// Static taint analysis.
pub mod taint;
/// Technology fingerprinting.
pub mod technologies;
/// Version and surface vulnerability checks.
pub mod vulnerabilities;
