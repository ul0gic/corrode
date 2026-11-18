// Does:  Runs the scanner with options from the command line.
// Holds: Argument and configuration errors return before the scan starts.

use anyhow::Result;
use corrode_scanner::{cli, scanner};

#[tokio::main]
async fn main() -> Result<()> {
    let config = cli::parse()?;
    scanner::workflow::run(config).await
}
