// Does:  Runs version-based vulnerability checks.
// Holds: Browser fingerprints and owner-supplied deployment evidence have separate assessment paths.

mod deployment;
mod nginx;
mod php {
    pub(super) mod php2shell;
}
mod react {
    pub(super) mod react2shell;
}
mod vite {
    pub(super) mod dev_server_rce;
}

pub use deployment::Deployments;
// Why: Library callers can still reach the surface fingerprint through its original module path.
pub use crate::detectors::technologies::rsc;
/// `WordPress` core advisories.
pub mod wordpress;

use crate::types::{AdvisoryCheck, AdvisoryOutcome, TechnologyVersion, Vulnerability};
use url::Url;

impl AdvisoryCheck {
    fn from_evidence(
        advisory: &str,
        method: &str,
        result: Result<Option<Vulnerability>, &str>,
        no_match: &str,
    ) -> Self {
        let outcome = match result {
            Ok(Some(details)) => AdvisoryOutcome::Matched { details },
            Ok(None) => AdvisoryOutcome::NoMatch {
                reason: no_match.to_owned(),
            },
            Err(reason) => AdvisoryOutcome::NotAssessed {
                reason: reason.to_owned(),
            },
        };
        Self {
            advisory: advisory.to_owned(),
            method: method.to_owned(),
            outcome,
        }
    }
}

/// Compares deployment records and same-origin metadata, retaining the outcome of every rule.
/// ```
/// # use corrode_scanner::detectors::vulnerabilities::{assess, Deployments};
/// # use corrode_scanner::types::AdvisoryOutcome;
/// let checks = assess(&Deployments::default(), None, None, &[]);
/// assert!(checks.iter().all(|c| matches!(c.outcome, AdvisoryOutcome::NotAssessed { .. })));
/// ```
pub fn assess(
    deployments: &Deployments,
    requested: Option<&Url>,
    document: Option<&Url>,
    versions: &[TechnologyVersion],
) -> Vec<AdvisoryCheck> {
    let urls = requested
        .zip(document)
        .ok_or("Could not establish the target document URL.");
    let wp = urls.and_then(|(requested, document)| {
        if requested.origin() == document.origin() {
            wordpress::assess(versions)
        } else {
            Err("The final document belongs to a different origin.")
        }
    });
    let mut checks = deployments.assess(urls);
    checks.push(AdvisoryCheck::from_evidence(
        "WordPress CVE-2026-60137 / CVE-2026-63030",
        "Site generator metadata",
        wp,
        "The site-reported version falls outside the chain’s listed ranges.",
    ));
    checks
}

/// Checks observed technology versions against supported advisories.
///
///     assert!(corrode_scanner::detectors::vulnerabilities::check_all(&[]).is_empty());
pub fn check_all(versions: &[TechnologyVersion]) -> Vec<Vulnerability> {
    wordpress::check_cves(versions)
}
