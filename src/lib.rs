// Production code is held to deny for these (Cargo.toml [lints]); tests use them idiomatically.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod api;
pub mod cli;
pub mod config;
pub mod detectors;
pub mod network;
pub mod reporting;
pub mod scanner;
pub mod types;
