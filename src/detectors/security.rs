use crate::types::{SecurityAnalysis, Vulnerability};

pub(crate) fn analyze_security(
    cookies: &[chromiumoxide::cdp::browser_protocol::network::Cookie],
    calls: &[crate::types::ApiCall],
    target_url: &str,
) -> (Vec<Vulnerability>, SecurityAnalysis) {
    let mut vulnerabilities = Vec::new();
    let mut insecure_cookies = Vec::new();
    let mut cors_issues = Vec::new();
    let mut missing_headers = Vec::new();
    let mut mixed_content = Vec::new();

    // Check cookies
    for cookie in cookies {
        if !cookie.secure || !cookie.http_only {
            insecure_cookies.push(cookie.name.clone());
        }
    }

    if !insecure_cookies.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "Insecure Cookies".to_owned(),
            severity: "medium".to_owned(),
            description: "Cookies missing Secure/HttpOnly flags".to_owned(),
            remediation: "Set Secure and HttpOnly flags on all session cookies".to_owned(),
            url: None,
        });
    }

    let target_is_https = target_url.starts_with("https://");

    // Analyze first-party document response for headers and CORS
    for call in calls {
        // Check for wildcard CORS (on any response)
        if let Some(acao) = call
            .response_headers
            .get("access-control-allow-origin")
            .or_else(|| call.response_headers.get("Access-Control-Allow-Origin"))
        {
            if acao == "*" {
                cors_issues.push(call.url.clone());
            }
        }

        // Check for mixed content (HTTPS page loading HTTP resources)
        if target_is_https && call.url.starts_with("http://") {
            mixed_content.push(call.url.clone());
        }

        // Check security headers on the main document (first HTML response)
        if call.url == target_url || call.url.starts_with(target_url) {
            if let Some(ct) = &call.response_content_type {
                if ct.contains("text/html") {
                    let headers_lower: std::collections::HashMap<String, String> = call
                        .response_headers
                        .iter()
                        .map(|(k, v)| (k.to_lowercase(), v.clone()))
                        .collect();

                    if !headers_lower.contains_key("content-security-policy") {
                        missing_headers.push("Content-Security-Policy".to_owned());
                    }
                    if !headers_lower.contains_key("strict-transport-security") {
                        missing_headers.push("Strict-Transport-Security".to_owned());
                    }
                    if !headers_lower.contains_key("x-frame-options") {
                        missing_headers.push("X-Frame-Options".to_owned());
                    }
                    if !headers_lower.contains_key("x-content-type-options") {
                        missing_headers.push("X-Content-Type-Options".to_owned());
                    }
                }
            }
        }
    }

    // Add vulnerabilities for findings
    if !cors_issues.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "CORS Misconfiguration".to_owned(),
            severity: "medium".to_owned(),
            description: format!(
                "Wildcard Access-Control-Allow-Origin found on {} endpoint(s)",
                cors_issues.len()
            ),
            remediation: "Restrict CORS to specific trusted origins instead of using wildcard (*)"
                .to_owned(),
            url: None,
        });
    }

    if !missing_headers.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "Missing Security Headers".to_owned(),
            severity: "low".to_owned(),
            description: format!("Missing headers: {}", missing_headers.join(", ")),
            remediation: "Add security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options"
                .to_owned(),
            url: None,
        });
    }

    if !mixed_content.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "Mixed Content".to_owned(),
            severity: "low".to_owned(),
            description: format!(
                "{} HTTP resource(s) loaded on HTTPS page",
                mixed_content.len()
            ),
            remediation: "Ensure all resources are loaded over HTTPS".to_owned(),
            url: None,
        });
    }

    let security = SecurityAnalysis {
        missing_headers,
        cors_issues,
        insecure_cookies,
        mixed_content,
    };

    (vulnerabilities, security)
}
