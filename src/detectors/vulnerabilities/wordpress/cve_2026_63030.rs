// Does:  Correlates WordPress version evidence with core advisories.
// Holds: Weak asset version hints do not produce advisory findings.

use crate::detectors::technologies::wordpress::{META_GENERATOR_METHOD, REST_GENERATOR_METHOD};
use crate::types::{
    AssessmentDisposition, EvidenceSource, FindingEvidence, TechnologyVersion, Vulnerability,
};

const SQLI_ADVISORY: &str =
    "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf";
const RCE_ADVISORY: &str =
    "https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u32, u32, u32);

/// Checks authoritative `WordPress` versions against supported core advisories.
///
///     assert!(corrode_scanner::detectors::vulnerabilities::wordpress::check_cves(&[]).is_empty());
pub fn check_cves(versions: &[TechnologyVersion]) -> Vec<Vulnerability> {
    assess(versions).ok().flatten().into_iter().collect()
}

pub(crate) fn assess(
    versions: &[TechnologyVersion],
) -> Result<Option<Vulnerability>, &'static str> {
    let Some(observed) = versions.iter().find(|version| {
        version.name.eq_ignore_ascii_case("WordPress")
            && is_authoritative_method(&version.detection_method)
    }) else {
        return Err("No usable WordPress generator version was observed.");
    };
    let Some(raw_version) = observed.version.as_deref() else {
        return Err("The generator did not supply a version.");
    };
    let Some(version) = parse_version(raw_version) else {
        return Err("The generator version could not be compared.");
    };

    let (source, location) = match observed.detection_method.as_str() {
        META_GENERATOR_METHOD => (EvidenceSource::Dom, "meta[name=\"generator\"]".to_owned()),
        REST_GENERATOR_METHOD => (
            EvidenceSource::Network,
            "naturally observed WordPress REST response".to_owned(),
        ),
        _ => return Err("Unknown generator source."),
    };
    let evidence = vec![FindingEvidence {
        source,
        location: Some(location),
        summary: format!("Observed WordPress {raw_version}"),
    }];

    if in_range(version, Version(6, 9, 0), Version(6, 9, 4))
        || in_range(version, Version(7, 0, 0), Version(7, 0, 1))
    {
        return Ok(Some(Vulnerability {
            vuln_type: "WordPress pre-authentication RCE chain (CVE-2026-60137/CVE-2026-63030)"
                .to_owned(),
            severity: "critical".to_owned(),
            description: format!(
                "The site advertises WordPress {raw_version}, in the affected range for the SQL injection \
                 prerequisite CVE-2026-60137 and the REST API batch-route confusion issue \
                 CVE-2026-63030, which can be chained for unauthenticated remote code \
                 execution (CVSS 3.1: 9.8 for the chain). Host exploitability is unverified. Advisories: {SQLI_ADVISORY} and {RCE_ADVISORY}."
            ),
            remediation:
                "Upgrade immediately to WordPress 6.9.5, 7.0.2, or a newer supported release."
                    .to_owned(),
            url: None,
            disposition: AssessmentDisposition::Lead,
            evidence,
            confidence: None,
        }));
    }

    Ok(None)
}

fn is_authoritative_method(method: &str) -> bool {
    matches!(method, META_GENERATOR_METHOD | REST_GENERATOR_METHOD)
}

fn in_range(version: Version, start: Version, end: Version) -> bool {
    version >= start && version <= end
}

fn parse_version(value: &str) -> Option<Version> {
    let parts: Vec<&str> = value.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    let major = parts.first()?.parse().ok()?;
    let minor = parts.get(1)?.parse().ok()?;
    let patch = parts.get(2).map_or(Some(0), |part| part.parse().ok())?;
    Some(Version(major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::technologies::wordpress::ASSET_CONSENSUS_METHOD;

    fn version(raw: &str, method: &str) -> TechnologyVersion {
        TechnologyVersion {
            name: "WordPress".to_owned(),
            version: Some(raw.to_owned()),
            detection_method: method.to_owned(),
        }
    }

    #[test]
    fn exact_advisory_boundaries() {
        for raw in ["6.9.0", "6.9.4", "7.0.0", "7.0.1"] {
            let findings = check_cves(&[version(raw, META_GENERATOR_METHOD)]);
            assert_eq!(findings.len(), 1, "{raw}");
            assert_eq!(findings[0].severity, "critical");
            assert!(findings[0].vuln_type.contains("CVE-2026-63030"));
        }

        for raw in [
            "6.8.0", "6.8.5", "6.8.6", "6.9.5", "7.0.2", "7.1.0", "8.0.0",
        ] {
            assert!(
                check_cves(&[version(raw, META_GENERATOR_METHOD)]).is_empty(),
                "{raw}"
            );
        }
    }

    #[test]
    fn weak_asset_version_never_emits_a_cve() {
        assert!(check_cves(&[version("7.0.1", ASSET_CONSENSUS_METHOD)]).is_empty());
    }

    #[test]
    fn malformed_and_prerelease_versions_are_ignored() {
        for raw in ["", "7", "7.0.1-alpha", "7.0.1+build", "latest"] {
            assert!(
                check_cves(&[version(raw, META_GENERATOR_METHOD)]).is_empty(),
                "{raw}"
            );
        }
    }
}
