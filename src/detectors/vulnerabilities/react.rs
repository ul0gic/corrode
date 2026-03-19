use regex::Regex;
use std::sync::LazyLock;

use crate::types::Vulnerability;

// CVE-2025-55182 — RCE (Critical)
// Affected: react-server-dom-webpack < 19.1.0 (specific versions)
#[allow(clippy::unwrap_used)]
static RSC_VULN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(react-server-dom-(?:webpack|parcel|turbopack))[^0-9]{0,15}(19\.0\.0|19\.1\.0|19\.1\.1|19\.2\.0)\b",
    )
    .unwrap()
});

// CVE-2025-55183 (Source Code Exposure) + CVE-2025-55184/CVE-2025-67779 (DoS)
// Affected: 19.0.0-19.2.2
#[allow(clippy::unwrap_used)]
static RSC_SOURCE_EXPOSURE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"react-server-dom-(?:webpack|parcel|turbopack)[^0-9]{0,15}(19\.(?:0\.[0-2]|1\.[0-3]|2\.[0-2]))\b",
    )
    .unwrap()
});

// CVE-2026-23864 (DoS — January 2026)
// Affected: 19.0.0-19.2.3
#[allow(clippy::unwrap_used)]
static RSC_DOS_2026_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"react-server-dom-(?:webpack|parcel|turbopack)[^0-9]{0,15}(19\.(?:0\.[0-3]|1\.[0-4]|2\.[0-3]))\b",
    )
    .unwrap()
});

/// Detect React Server Components vulnerabilities from script content.
pub fn detect_rsc_vulns(text: &str, source: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    // CVE-2025-55182 — RCE (Critical)
    for cap in RSC_VULN_REGEX.captures_iter(text) {
        let pkg = cap.get(1).map_or("react-server-dom", |m| m.as_str());
        let ver = cap.get(2).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC RCE (CVE-2025-55182)".to_owned(),
            severity: "critical".to_owned(),
            description: format!(
                "Vulnerable {pkg} detected ({ver}). CVE-2025-55182 allows unauthenticated RCE in React Server Components/Functions."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.1/19.1.2/19.2.1 or framework patched versions (Next.js 15.x/16.x etc.).".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2025-55183 — Source Code Exposure (Medium)
    for cap in RSC_SOURCE_EXPOSURE_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC Source Code Exposure (CVE-2025-55183)".to_owned(),
            severity: "medium".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to source code exposure via Server Function .toString(). Hardcoded secrets, API keys, and database credentials in Server Functions may be exposed."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.3/19.1.4/19.2.3.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2025-55184 / CVE-2025-67779 — DoS (High)
    for cap in RSC_SOURCE_EXPOSURE_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC DoS (CVE-2025-55184/CVE-2025-67779)".to_owned(),
            severity: "high".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to denial of service. Crafted HTTP requests can trigger infinite processing loops, hanging the server."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.3/19.1.4/19.2.3.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2026-23864 — DoS (High)
    for cap in RSC_DOS_2026_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC DoS (CVE-2026-23864)".to_owned(),
            severity: "high".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to multiple DoS vectors (CVE-2026-23864) causing server crashes, OOM, or excessive CPU."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.4/19.1.5/19.2.4.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    vulns
}
