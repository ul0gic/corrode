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

mod api;
mod cli;
mod config;
mod detectors;
mod network;
mod reporting;
mod scanner;
mod types;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let config = cli::parse()?;
    scanner::workflow::run(config).await
}
