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
    let config = cli::parse();
    scanner::workflow::run(config).await
}
