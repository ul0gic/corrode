// Does:  Writes the assembled Markdown scan report.
// Holds: Report sections are assembled in a fixed order.

mod appendix;
mod assessment;
pub(crate) mod batch;
mod findings;
mod inventory;
mod leads;
mod network;
mod security;
mod sourcemaps;
/// Confidence and summary formatting.
pub mod summary;
mod taint;
mod technologies;

use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::ScanResult;

/// Writes report and evidence Markdown files under the result URL’s host directory.
///
/// ```no_run
/// # use corrode_scanner::{reporting::markdown, types::ScanResult};
/// # let result = ScanResult::default();
/// markdown::write(&result, std::path::Path::new("reports")).unwrap();
/// ```
pub fn write(result: &ScanResult, base_output_dir: &Path) -> Result<()> {
    let mut report = report_header(result, "Corrode Security Scan Report");

    report.extend(summary::render_summary(result));
    report.extend(assessment::render_advisory_checks(result));
    report.extend(findings::render_findings(result));
    report.extend(findings::render_lead_assessments(result));
    report.extend(leads::render_additional_leads(result));
    report.extend(findings::render_api_tests(result));
    report.extend(inventory::render_inventory(result));
    report.extend(technologies::render_technologies(result));
    report.extend(appendix::render_recommendations(result));
    report.push(
        "---\nFull captured evidence, including raw AST, network, DOM, route, and static-analysis \
         records, is available in [`EVIDENCE.md`](EVIDENCE.md).\n"
            .to_owned(),
    );

    let mut evidence = report_header(result, "Corrode Scan Evidence");
    evidence.push(
        "This companion artifact contains exhaustive passive observations. Entries here are not \
         automatically confirmed vulnerabilities and do not independently determine headline risk.\n"
            .to_owned(),
    );
    evidence.extend(assessment::render_advisory_checks(result));
    evidence.extend(findings::render_evidence_findings(result));
    evidence.extend(security::render_security_posture(result));
    evidence.extend(findings::render_api_tests(result));
    evidence.extend(technologies::render_technologies(result));
    evidence.extend(network::render_network(result));
    evidence.extend(technologies::render_dom(result)?);
    evidence.extend(sourcemaps::render_sourcemap_intel(result));
    evidence.extend(taint::render_taint(result));
    evidence.extend(appendix::render_appendix(result));

    let domain = url::Url::parse(&result.url)
        .ok()
        .and_then(|u| u.host_str().map(std::borrow::ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
        .replace('.', "-");

    let site_dir = base_output_dir.join(&domain);
    fs::create_dir_all(&site_dir)?;

    let report_path = site_dir.join("REPORT.md");
    fs::write(report_path, report.join("\n"))?;
    let evidence_path = site_dir.join("EVIDENCE.md");
    fs::write(evidence_path, evidence.join("\n"))?;

    Ok(())
}

fn report_header(result: &ScanResult, title: &str) -> Vec<String> {
    vec![
        format!("# {title}\n"),
        format!("**Target**: {}", result.url),
        format!("**Scan Date**: {}", result.timestamp),
        format!("**Scanner**: Corrode v{}\n", env!("CARGO_PKG_VERSION")),
    ]
}
