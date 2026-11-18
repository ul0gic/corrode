// Does:  Checks exposed Vite development servers against the November virtual-module advisory.
// Holds: Static production bundles and private development servers produce no finding.

use super::super::deployment::{Advisory, Version, Vite};

pub(in crate::detectors::vulnerabilities) fn check(vite: &Vite) -> Option<Advisory> {
    let v = vite.unmodified_upstream_version;
    let affected = (Version(4, 0, 0)..=Version(6, 4, 5)).contains(&v)
        || (Version(7, 0, 0)..=Version(7, 3, 7)).contains(&v)
        || (Version(8, 0, 0)..=Version(8, 1, 6)).contains(&v)
        || matches!(v, Version(8, 2, 0..=4) | Version(8, 3, 0..=6));
    if !vite.dev_server_exposed_to_network || !affected {
        return None;
    }
    Some(Advisory {
        title: "Vite development server RCE (GHSA-p4f5-76q4-ffq7)",
        cvss_version: "4.0",
        cvss_tenths: 91,
        observed: format!("upstream Vite {v} running as an explicitly network-exposed dev server"),
        source: "https://github.com/vitejs/vite/security/advisories/GHSA-p4f5-76q4-ffq7",
        remediation: "Update to 6.4.6, 7.3.8, 8.1.7, 8.2.5, 8.3.7 or a newer patched release.",
    })
}
