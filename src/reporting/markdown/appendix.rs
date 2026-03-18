use crate::types::ScanResult;

pub(crate) fn render_appendix(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    // AST findings
    if !result.javascript.ast_findings.is_empty() {
        report.push("---\n## 🧠 JavaScript AST Findings\n".to_owned());
        for finding in &result.javascript.ast_findings {
            report.push(format!("### {} @ {}", finding.kind, finding.location));
            report.push(format!("**Value**: `{}`", finding.value));
            report.push(format!("**Context**: {}\n", finding.context));
        }
    }

    // Network insights
    report.push("---\n## 📡 Network Insights\n".to_owned());
    report.push(format!(
        "- Total Requests: {}",
        result.network.total_requests
    ));
    report.push(format!(
        "- Third-party Requests: {}",
        result.network.third_party.len()
    ));
    report.push(format!(
        "- WebSockets: {}\n",
        result.network.websockets.len()
    ));

    // Source maps
    if !result.javascript.source_maps.is_empty() {
        report.push("---\n## 🗺 Source Maps\n".to_owned());
        for map in &result.javascript.source_maps {
            report.push(format!("- {map}"));
        }
    }

    report
}

pub(crate) fn render_recommendations() -> Vec<String> {
    vec![
        "---\n## 💡 Recommendations\n".to_owned(),
        "1. **Immediately rotate** any exposed secrets and credentials".to_owned(),
        "2. Remove or restrict access to source maps in production".to_owned(),
        "3. Implement proper security headers (CSP, HSTS, etc.)".to_owned(),
        "4. Review and fix all HIGH and CRITICAL vulnerabilities".to_owned(),
        "5. Disable debug mode in production".to_owned(),
        "6. Use HttpOnly, Secure, and SameSite flags on cookies\n".to_owned(),
    ]
}
