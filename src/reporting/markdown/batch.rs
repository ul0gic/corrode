// Does:  Writes a Markdown summary of a batch scan.
// Holds: Each target has one row in input order, including failures.

use std::fs;
use std::path::Path;

use anyhow::Result;
use chrono::Utc;

use crate::reporting::{ScanOutcome, ScanStatus};

pub(crate) fn write(
    output_dir: &Path,
    outcomes: &[ScanOutcome],
    total_secrets: usize,
    total_vulns: usize,
) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("# Corrode Batch Scan Summary\n".to_owned());
    lines.push(format!("**Scan Date**: {}", Utc::now().to_rfc3339()));
    lines.push(format!("**Targets Scanned**: {}", outcomes.len()));

    let succeeded = outcomes
        .iter()
        .filter(|o| matches!(o.status, ScanStatus::Success))
        .count();
    let failed = outcomes.len() - succeeded;

    lines.push(format!("**Succeeded**: {succeeded}"));
    lines.push(format!("**Failed**: {failed}"));
    lines.push(format!("**Total Secrets**: {total_secrets}"));
    lines.push(format!("**Total Vulnerabilities**: {total_vulns}\n"));

    lines.push("---\n".to_owned());
    lines.push("## Per-Target Results\n".to_owned());
    lines.push("| URL | Secrets | Vulns | Status |".to_owned());
    lines.push("|-----|---------|-------|--------|".to_owned());

    for outcome in outcomes {
        let status = match &outcome.status {
            ScanStatus::Success => "OK".to_owned(),
            ScanStatus::Failed(msg) => {
                let truncated: String = msg.chars().take(60).collect();
                format!("FAIL: {truncated}")
            }
        };
        lines.push(format!(
            "| {} | {} | {} | {} |",
            outcome.url, outcome.secrets, outcome.vulns, status
        ));
    }

    lines.push(String::new());

    let summary_path = output_dir.join("SUMMARY.md");
    fs::write(summary_path, lines.join("\n"))?;

    Ok(())
}
