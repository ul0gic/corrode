// Does:  Checks the installed server renderer against the React2Shell advisory.
// Holds: Client React versions and browser bundle text never qualify as server installation evidence.

use super::super::deployment::{Advisory, React, Version};

pub(in crate::detectors::vulnerabilities) fn check(react: &React) -> Option<Advisory> {
    let version = react.unmodified_upstream_version;
    if !react.serves_server_components
        || !matches!(
            react.package.as_str(),
            "react-server-dom-webpack" | "react-server-dom-parcel" | "react-server-dom-turbopack"
        )
        || !matches!(version, Version(19, 0 | 2, 0) | Version(19, 1, 0 | 1))
    {
        return None;
    }
    Some(Advisory {
        title: "React2Shell (CVE-2025-55182)",
        cvss_version: "3.1",
        cvss_tenths: 100,
        observed: format!("{} {version} serving React Server Components", react.package),
        source: "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components",
        remediation: "Update the deployed server renderer to a supported patched release; the first fixes were 19.0.1, 19.1.2 and 19.2.1.",
    })
}
