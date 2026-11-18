// Does:  Checks the upstream NGINX HTTP/2 flow-control advisory against deployment records.
// Holds: The fixed stable branch is excluded even though its version precedes the mainline fix.

use super::super::deployment::{Advisory, Nginx, Version};

pub(in crate::detectors::vulnerabilities) fn check(nginx: &Nginx) -> Option<Advisory> {
    let v = nginx.unmodified_upstream_version;
    if !nginx.serves_http2 || !nginx.affected_since(Version(1, 9, 5)) {
        return None;
    }
    Some(Advisory {
        title: "NGINX HTTP/2 flow-control vulnerability (CVE-2026-123007)",
        cvss_version: "4.0",
        cvss_tenths: 92,
        observed: format!("upstream NGINX Open Source {v} serving HTTP/2"),
        source: "https://my.f5.com/manage/s/article/K000163926",
        remediation:
            "Upgrade NGINX Open Source to a patched stable (1.30.7+) or mainline (1.31.9+) release.",
    })
}
