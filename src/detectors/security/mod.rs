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
        // Check for wildcard CORS — only on responses that could carry sensitive data.
        // Skip static assets, framework internals, and CDN resources where ACAO:* is expected.
        if let Some(acao) = call
            .response_headers
            .get("access-control-allow-origin")
            .or_else(|| call.response_headers.get("Access-Control-Allow-Origin"))
        {
            if acao == "*"
                && !is_static_or_framework_url(&call.url, call.response_content_type.as_ref())
            {
                cors_issues.push(call.url.clone());
            }
        }

        // Check for mixed content (HTTPS page loading HTTP resources)
        if target_is_https && call.url.starts_with("http://") {
            mixed_content.push(call.url.clone());
        }

        // Check security headers on the main document (first HTML response)
        if call.url == target_url || call.url.starts_with(target_url) {
            check_security_headers(call, &mut missing_headers);
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

/// Check the main document response for missing security headers.
fn check_security_headers(call: &crate::types::ApiCall, missing: &mut Vec<String>) {
    let Some(ct) = &call.response_content_type else {
        return;
    };
    if !ct.contains("text/html") {
        return;
    }

    let headers_lower: std::collections::HashMap<String, String> = call
        .response_headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let required = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
    ];
    let display_names = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ];

    for (header, name) in required.iter().zip(display_names.iter()) {
        if !headers_lower.contains_key(*header) {
            missing.push((*name).to_owned());
        }
    }
}

/// Returns true if the URL/content-type indicates a static asset or framework
/// resource where `Access-Control-Allow-Origin: *` is expected and harmless.
fn is_static_or_framework_url(url: &str, content_type: Option<&String>) -> bool {
    let lower = url.to_lowercase();

    // Static file extensions
    let static_extensions = [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".map", ".webp", ".avif", ".mp4", ".webm", ".mp3", ".ogg", ".wav",
    ];
    // Check path portion (strip query string)
    let path = lower.split('?').next().unwrap_or(&lower);
    if static_extensions.iter().any(|ext| path.ends_with(ext)) {
        return true;
    }

    // Framework/platform internals
    let framework_patterns = [
        "/_next/",   // Next.js assets
        "/_nuxt/",   // Nuxt.js assets
        "/_vercel/", // Vercel analytics/internals
        "/_gatsby/", // Gatsby internals
        "/cdn-cgi/", // Cloudflare internals
        "?_rsc=",    // Next.js RSC payloads
        "&_rsc=",    // Next.js RSC payloads
        "/favicon",  // Favicons
    ];
    if framework_patterns.iter().any(|p| lower.contains(p)) {
        return true;
    }

    // Third-party CDN domains where CORS * is standard
    let cdn_domains = [
        "cdn.jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "api.iconify.design",
        "cdn.amplitude.com",
        "cdn.segment.com",
        "cdn.mxpnl.com",
    ];
    if cdn_domains.iter().any(|d| lower.contains(d)) {
        return true;
    }

    // Content-type check: font and image MIME types are always safe
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();
        if ct_lower.starts_with("font/")
            || ct_lower.starts_with("image/")
            || ct_lower.starts_with("video/")
            || ct_lower.starts_with("audio/")
            || ct_lower.contains("application/font")
            || ct_lower.contains("text/css")
            || ct_lower.contains("application/javascript")
            || ct_lower.contains("text/javascript")
        {
            return true;
        }
    }

    false
}
