use crate::types::ScanResult;

/// Render the Security Posture section: headers, cookies, CORS, mixed content.
pub(crate) fn render_security_posture(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    let has_issues = !result.security.missing_headers.is_empty()
        || !result.security.cors_issues.is_empty()
        || !result.security.insecure_cookies.is_empty()
        || !result.security.mixed_content.is_empty();

    if !has_issues {
        return report;
    }

    report.push("---\n## Security Posture\n".to_owned());

    // Missing security headers
    if !result.security.missing_headers.is_empty() {
        report.push("### Missing Security Headers\n".to_owned());
        report.push("| Header | Status |".to_owned());
        report.push("|--------|--------|".to_owned());
        for header in &result.security.missing_headers {
            report.push(format!("| {header} | Missing |"));
        }
        report.push(String::new());
    }

    // Cookie audit
    if !result.security.insecure_cookies.is_empty() {
        report.push("### Cookie Security Issues\n".to_owned());
        for issue in &result.security.insecure_cookies {
            report.push(format!("- {issue}"));
        }
        report.push(String::new());

        // Per-cookie detail table if DOM cookies are available
        if !result.dom.cookies.is_empty() {
            report.push("**Cookie Details**:\n".to_owned());
            report.push("| Name | Secure | HttpOnly | SameSite | Domain |".to_owned());
            report.push("|------|--------|----------|----------|--------|".to_owned());
            for cookie in &result.dom.cookies {
                let secure_icon = if cookie.secure { "Yes" } else { "No" };
                let http_only_icon = if cookie.http_only { "Yes" } else { "No" };
                report.push(format!(
                    "| {} | {} | {} | {} | {} |",
                    cookie.name, secure_icon, http_only_icon, cookie.same_site, cookie.domain
                ));
            }
            report.push(String::new());
        }
    }

    // CORS issues
    if !result.security.cors_issues.is_empty() {
        report.push("### CORS Configuration Issues\n".to_owned());
        for issue in &result.security.cors_issues {
            report.push(format!("- {issue}"));
        }
        report.push(String::new());
    }

    // Mixed content
    if !result.security.mixed_content.is_empty() {
        report.push("### Mixed Content\n".to_owned());
        for issue in &result.security.mixed_content {
            report.push(format!("- {issue}"));
        }
        report.push(String::new());
    }

    report
}
