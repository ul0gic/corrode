use crate::types::{
    AssessmentDisposition, EvidenceSource, FindingEvidence, SecurityAnalysis, Vulnerability,
};

pub(crate) fn analyze_security(
    cookies: &[chromiumoxide::cdp::browser_protocol::network::Cookie],
    calls: &[crate::types::ApiCall],
    target_url: &str,
) -> (Vec<Vulnerability>, SecurityAnalysis) {
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

    let target_is_https = target_url.starts_with("https://");
    let target_host = url::Url::parse(target_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase));
    let mut checked_headers = false;

    for call in calls {
        // CORS: only flag first-party URLs where wildcard is a real misconfiguration.
        // Third-party services (CDNs, analytics, consent tools) use ACAO:* by design.
        if let Some(acao) = call
            .response_headers
            .get("access-control-allow-origin")
            .or_else(|| call.response_headers.get("Access-Control-Allow-Origin"))
        {
            if acao == "*"
                && is_first_party(&call.url, target_host.as_deref())
                && !is_static_or_framework_url(&call.url, call.response_content_type.as_ref())
            {
                cors_issues.push(call.url.clone());
            }
        }

        // Mixed content: HTTPS page loading HTTP resources
        if target_is_https && call.url.starts_with("http://") {
            mixed_content.push(call.url.clone());
        }

        // Security headers: check once on the first matching HTML document response
        if !checked_headers
            && (call.url == target_url || call.url.starts_with(target_url))
            && check_security_headers(call, &mut missing_headers)
        {
            checked_headers = true;
        }
    }

    let vulnerabilities = validation_leads(
        &insecure_cookies,
        &cors_issues,
        &missing_headers,
        &mixed_content,
        target_url,
    );

    let security = SecurityAnalysis {
        missing_headers,
        cors_issues,
        insecure_cookies,
        mixed_content,
    };

    (vulnerabilities, security)
}

fn validation_leads(
    insecure_cookies: &[String],
    cors_issues: &[String],
    missing_headers: &[String],
    mixed_content: &[String],
    target_url: &str,
) -> Vec<Vulnerability> {
    let mut vulnerabilities = Vec::new();

    if !insecure_cookies.is_empty() {
        vulnerabilities.push(validation_lead(
            "Insecure Cookies",
            "medium",
            "Cookies missing Secure/HttpOnly flags",
            "Set Secure and HttpOnly flags on all session cookies",
            insecure_cookies
                .iter()
                .map(|name| FindingEvidence {
                    source: EvidenceSource::Dom,
                    location: Some(format!("Cookie: {name}")),
                    summary: "Cookie is missing Secure and/or HttpOnly".to_owned(),
                })
                .collect(),
        ));
    }

    if !cors_issues.is_empty() {
        vulnerabilities.push(validation_lead(
            "CORS Misconfiguration",
            "medium",
            &format!(
                "Wildcard Access-Control-Allow-Origin found on {} endpoint(s)",
                cors_issues.len()
            ),
            "Restrict CORS to specific trusted origins instead of using wildcard (*)",
            cors_issues
                .iter()
                .map(|url| FindingEvidence {
                    source: EvidenceSource::Network,
                    location: Some(url.clone()),
                    summary: "Observed Access-Control-Allow-Origin: *".to_owned(),
                })
                .collect(),
        ));
    }

    if !missing_headers.is_empty() {
        vulnerabilities.push(validation_lead(
            "Missing Security Headers",
            "low",
            &format!("Missing headers: {}", missing_headers.join(", ")),
            "Add security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options",
            vec![FindingEvidence {
                source: EvidenceSource::Header,
                location: Some(target_url.to_owned()),
                summary: format!("Missing headers: {}", missing_headers.join(", ")),
            }],
        ));
    }

    if !mixed_content.is_empty() {
        vulnerabilities.push(validation_lead(
            "Mixed Content",
            "low",
            &format!(
                "{} HTTP resource(s) loaded on HTTPS page",
                mixed_content.len()
            ),
            "Ensure all resources are loaded over HTTPS",
            mixed_content
                .iter()
                .map(|url| FindingEvidence {
                    source: EvidenceSource::Network,
                    location: Some(url.clone()),
                    summary: "HTTP resource observed on an HTTPS page".to_owned(),
                })
                .collect(),
        ));
    }

    vulnerabilities
}

fn validation_lead(
    vuln_type: &str,
    severity: &str,
    description: &str,
    remediation: &str,
    evidence: Vec<FindingEvidence>,
) -> Vulnerability {
    Vulnerability {
        vuln_type: vuln_type.to_owned(),
        severity: severity.to_owned(),
        description: description.to_owned(),
        remediation: remediation.to_owned(),
        url: None,
        disposition: AssessmentDisposition::Lead,
        evidence,
        confidence: None,
    }
}

/// Check the main document response for missing security headers.
/// Returns true if this was an HTML response (so caller can stop checking).
fn check_security_headers(call: &crate::types::ApiCall, missing: &mut Vec<String>) -> bool {
    let Some(ct) = &call.response_content_type else {
        return false;
    };
    if !ct.contains("text/html") {
        return false;
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

    true
}

/// Returns true if the URL belongs to the same domain as the target.
fn is_first_party(url: &str, target_host: Option<&str>) -> bool {
    let Some(target) = target_host else {
        return true;
    };
    if let Ok(parsed) = url::Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            let host_lower = host.to_lowercase();
            return host_lower == target || host_lower.ends_with(&format!(".{target}"));
        }
    }
    true
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
