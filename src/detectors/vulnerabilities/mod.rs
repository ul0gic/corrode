// Does:  Runs version-based vulnerability checks.
// Holds: Only detected technology versions enter these checks.

/// Next.js version advisories.
pub mod nextjs;
/// React server component advisories.
pub mod react;
/// React server component surface analysis.
pub mod rsc;
/// `WordPress` core advisories.
pub mod wordpress;

use crate::types::{TechnologyVersion, Vulnerability};

/// Checks observed technology versions against supported advisories.
///
///     assert!(corrode_scanner::detectors::vulnerabilities::check_all(&[]).is_empty());
pub fn check_all(versions: &[TechnologyVersion]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    vulns.extend(nextjs::check_cves(versions));
    vulns.extend(wordpress::check_cves(versions));

    vulns
}
