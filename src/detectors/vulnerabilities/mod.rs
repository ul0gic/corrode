pub mod nextjs;
pub mod react;
pub mod rsc;

use crate::types::{TechnologyVersion, Vulnerability};

/// Run all vulnerability checks against detected technology versions.
pub fn check_all(versions: &[TechnologyVersion]) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    vulns.extend(nextjs::check_cves(versions));

    vulns
}
