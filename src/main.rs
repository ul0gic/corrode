use anyhow::Result;
use corrode_scanner::{cli, scanner};

#[tokio::main]
async fn main() -> Result<()> {
    let config = cli::parse()?;
    scanner::workflow::run(config).await
}
