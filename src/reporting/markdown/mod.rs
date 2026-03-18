mod appendix;
mod findings;
mod network;
mod security;
mod summary;
mod technologies;

use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::ScanResult;

pub fn write(result: &ScanResult, base_output_dir: &Path) -> Result<()> {
    let mut report = Vec::new();

    // Report header
    report.push("# Corrode Security Scan Report\n".to_owned());
    report.push(format!("**Target**: {}", result.url));
    report.push(format!("**Scan Date**: {}", result.timestamp));
    report.push("**Scanner**: Corrode v0.1.0\n".to_owned());

    // Sections (ordered for operator workflow)
    report.extend(summary::render_summary(result));
    report.extend(findings::render_secrets(result));
    report.extend(security::render_security_posture(result));
    report.extend(findings::render_api_tests(result));
    report.extend(technologies::render_technologies(result));
    report.extend(network::render_network(result));
    report.extend(technologies::render_dom(result)?);
    report.extend(appendix::render_appendix(result));
    report.extend(appendix::render_recommendations());

    // Write to file
    let domain = url::Url::parse(&result.url)
        .ok()
        .and_then(|u| u.host_str().map(std::borrow::ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
        .replace('.', "-");

    let site_dir = base_output_dir.join(&domain);
    fs::create_dir_all(&site_dir)?;

    let report_path = site_dir.join("REPORT.md");
    fs::write(report_path, report.join("\n"))?;

    Ok(())
}
