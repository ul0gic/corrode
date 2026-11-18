// Does:  Checks the HTTP/2 worker-connection advisory for upstream NGINX reverse proxies.
// Holds: Reporting requires recorded connection pressure as well as the affected proxy configuration.

use super::super::deployment::{Advisory, Nginx, Version};

pub(in crate::detectors::vulnerabilities) fn check(
    nginx: &Nginx,
) -> Result<Option<Advisory>, &'static str> {
    let v = nginx.unmodified_upstream_version;
    if !nginx.serves_http2
        || nginx.proxies_to_backend == Some(false)
        || !nginx.affected_since(Version(1, 19, 7))
    {
        return Ok(None);
    }
    if nginx.proxies_to_backend.is_none() {
        return Err("The deployment record does not establish reverse proxying.");
    }
    if nginx.low_worker_connections_observed != Some(true) {
        return Err(
            "Worker connection pressure is unverified. The runtime condition could still occur.",
        );
    }
    Ok(Some(Advisory {
        title: "NGINX HTTP/2 proxy worker vulnerability (CVE-2026-123633)",
        cvss_version: "4.0",
        cvss_tenths: 92,
        observed: format!("upstream NGINX Open Source {v}, HTTP/2 proxying with observed worker connection pressure"),
        source: "https://my.f5.com/manage/s/article/K000163928",
        remediation: "Upgrade NGINX Open Source to a patched stable (1.30.7+) or mainline (1.31.9+) release.",
    }))
}
