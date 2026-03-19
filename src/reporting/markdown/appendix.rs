use crate::types::ScanResult;

pub(crate) fn render_appendix(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    // AST findings
    if !result.javascript.ast_findings.is_empty() {
        report.push("---\n## JavaScript AST Findings\n".to_owned());
        for finding in &result.javascript.ast_findings {
            report.push(format!("### {} @ {}", finding.kind, finding.location));
            report.push(format!("**Value**: `{}`", finding.value));
            report.push(format!("**Context**: {}\n", finding.context));
        }
    }

    // Source maps
    if !result.javascript.source_maps.is_empty() {
        report.push("---\n## Source Maps\n".to_owned());
        for map in &result.javascript.source_maps {
            report.push(format!("- {map}"));
        }
    }

    report
}

pub(crate) fn render_recommendations(result: &ScanResult) -> Vec<String> {
    let mut recs = Vec::new();

    if !result.secrets.is_empty() {
        recs.push("**Immediately rotate** any exposed secrets and credentials".to_owned());
    }

    if !result.javascript.source_maps.is_empty() {
        recs.push("Remove or restrict access to source maps in production".to_owned());
    }

    if !result.security.missing_headers.is_empty() {
        recs.push(
            "Implement missing security headers (CSP, HSTS, X-Frame-Options, etc.)".to_owned(),
        );
    }

    let has_critical_or_high = result.vulnerabilities.iter().any(|v| {
        let s = v.severity.to_lowercase();
        s == "critical" || s == "high"
    });
    if has_critical_or_high {
        recs.push("Review and remediate all HIGH and CRITICAL vulnerabilities".to_owned());
    }

    if !result.javascript.debug_mode.is_empty() {
        recs.push("Disable debug mode and development builds in production".to_owned());
    }

    if !result.security.insecure_cookies.is_empty() {
        recs.push("Set HttpOnly, Secure, and SameSite flags on all cookies".to_owned());
    }

    if !result.security.cors_issues.is_empty() {
        recs.push(
            "Restrict CORS Access-Control-Allow-Origin to specific trusted origins".to_owned(),
        );
    }

    if !result.security.mixed_content.is_empty() {
        recs.push("Eliminate mixed content — load all resources over HTTPS".to_owned());
    }

    if recs.is_empty() {
        return vec![
            "---\n## Recommendations\n".to_owned(),
            "No actionable findings. The target presents a clean security posture based on passive analysis.\n".to_owned(),
        ];
    }

    let mut report = vec!["---\n## Recommendations\n".to_owned()];
    for (i, rec) in recs.iter().enumerate() {
        report.push(format!("{}. {rec}", i + 1));
    }
    report.push(String::new());

    report
}
