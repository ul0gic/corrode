// Does:  Exposes the scanner, its evidence types, and the report writers as a library.
// Holds: Consumers can analyze captured evidence without starting the command-line workflow.

#![doc = "Passive web scanning, evidence analysis, and report generation."]
// Why: Failed fixture assertions should stop the test at the missing value or index.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

/// Endpoint candidates inferred from captured JavaScript.
pub mod api;
/// Command-line arguments and conversion to scan settings.
pub mod cli;
/// Batch inputs, configuration files, and report preferences.
pub mod config;
/// Collection, classification, and scoring of browser-visible evidence.
pub mod detectors;
/// Request and response observations from browser events.
pub mod network;
/// JSON and Markdown representations of scan results.
pub mod reporting;
/// Browser setup and orchestration of single-URL and batch scans.
pub mod scanner;
/// Shared evidence, confidence, and report data types.
pub mod types;
