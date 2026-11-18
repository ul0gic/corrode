// Does:  Checks upstream web-serving PHP releases against the two PHP2Shell advisories.
// Holds: Both issues share one owner action and yield one finding per deployment.

use super::super::deployment::{Advisory, Php, Version};

pub(in crate::detectors::vulnerabilities) fn check(
    php: &Php,
) -> Result<Option<Advisory>, &'static str> {
    let version = php.unmodified_upstream_version;
    if !matches!(version, Version(8, 2..=5, _)) {
        return Err("This rule covers upstream PHP 8.2 through 8.5 only.");
    }
    if !php.serves_web_requests
        || !matches!(
            version,
            Version(8, 2, 0..=34)
                | Version(8, 3, 0..=35)
                | Version(8, 4, 0..=26)
                | Version(8, 5, 0..=11)
        )
    {
        return Ok(None);
    }
    Ok(Some(Advisory {
        title: "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
        cvss_version: "4.0",
        cvss_tenths: 92,
        observed: format!("upstream PHP {version} serving web requests"),
        source: "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w and https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
        remediation: "Update the deployed web runtime to a patched release on its branch (8.2.35, 8.3.36, 8.4.27 or 8.5.12 onwards).",
    }))
}
