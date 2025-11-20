use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::ScanResult;

pub fn write(path: &Path, result: &ScanResult) -> Result<()> {
    let contents = serde_json::to_string_pretty(result)?;
    fs::write(path, contents)?;
    Ok(())
}
