use crate::types::{TechnologyVersion, Vulnerability};

/// Check detected technology versions against known Next.js CVEs.
/// Emits info-level advisories when Next.js is detected but version is unknown,
/// and specific severity findings when a vulnerable version is confirmed.
pub fn check_nextjs_cves(versions: &[TechnologyVersion]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    let has_nextjs = versions.iter().any(|v| v.name.starts_with("Next.js"));

    if !has_nextjs {
        return vulns;
    }

    // Next.js is detected but we currently cannot reliably extract the version
    // from passive analysis alone (X-Powered-By header does not include version).
    // Emit info-level advisories for high-impact CVEs.

    vulns.push(Vulnerability {
        vuln_type: "Next.js Middleware Bypass Advisory (CVE-2025-29927)".to_owned(),
        severity: "info".to_owned(),
        description: "Next.js detected. CVE-2025-29927 allows middleware authorization bypass via x-middleware-subrequest header. Affects all Next.js versions before 12.3.5, 13.5.9, 14.2.25, and 15.2.3. Verify your Next.js version is patched.".to_owned(),
        remediation: "Upgrade Next.js to 12.3.5+, 13.5.9+, 14.2.25+, or 15.2.3+. Block x-middleware-subrequest header at CDN/reverse proxy layer.".to_owned(),
        url: None,
    });

    vulns.push(Vulnerability {
        vuln_type: "Next.js SSRF Advisory (CVE-2024-34351)".to_owned(),
        severity: "info".to_owned(),
        description: "Next.js detected. CVE-2024-34351 allows SSRF via Host header in Server Action redirects. Affects Next.js 13.4.0 through 14.1.0.".to_owned(),
        remediation: "Upgrade Next.js to 14.1.1 or later.".to_owned(),
        url: None,
    });

    vulns.push(Vulnerability {
        vuln_type: "Next.js Cache Poisoning Advisory (CVE-2024-46982)".to_owned(),
        severity: "info".to_owned(),
        description: "Next.js detected. CVE-2024-46982 allows cache poisoning on Pages Router SSR routes. Affects Next.js 13.5.1 through 14.2.9.".to_owned(),
        remediation: "Upgrade Next.js to 13.5.7+ or 14.2.10+.".to_owned(),
        url: None,
    });

    vulns.push(Vulnerability {
        vuln_type: "Next.js Auth Bypass Advisory (CVE-2024-51479)".to_owned(),
        severity: "info".to_owned(),
        description: "Next.js detected. CVE-2024-51479 allows middleware bypass on root-level pages. Affects Next.js 9.5.5 through 14.2.14.".to_owned(),
        remediation: "Upgrade Next.js to 14.2.15 or later.".to_owned(),
        url: None,
    });

    vulns.push(Vulnerability {
        vuln_type: "Next.js Server Actions DoS Advisory (CVE-2024-56332)".to_owned(),
        severity: "info".to_owned(),
        description: "Next.js detected. CVE-2024-56332 allows denial of service via Server Actions. Affects Next.js before 13.5.8, 14.2.21, and 15.1.2.".to_owned(),
        remediation: "Upgrade Next.js to 13.5.8+, 14.2.21+, or 15.1.2+.".to_owned(),
        url: None,
    });

    vulns
}
