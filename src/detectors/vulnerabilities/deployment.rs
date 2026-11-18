// Does:  Matches owner-supplied installed components to advisories for one deployment.
// Holds: A record applies only when the requested URL and the final document both match its key.

use std::{collections::BTreeMap, fmt};

use serde::Deserialize;
use url::Url;

use super::{nginx, php, react, vite};
use crate::types::{
    AdvisoryCheck, AdvisoryOutcome, AssessmentDisposition, EvidenceSource, FindingEvidence,
    Vulnerability,
};

/// Owner-supplied deployment records keyed by exact HTTP(S) URL.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(try_from = "BTreeMap<String, Deployment>")]
pub struct Deployments(BTreeMap<Url, Deployment>);

impl TryFrom<BTreeMap<String, Deployment>> for Deployments {
    type Error = String;

    fn try_from(records: BTreeMap<String, Deployment>) -> Result<Self, String> {
        let mut by_url = BTreeMap::new();
        for (key, record) in records {
            let url = Url::parse(&key).map_err(|_| format!("Invalid deployment URL: {key}"))?;
            if !matches!(url.scheme(), "http" | "https")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(format!(
                    "Deployment URL must be HTTP(S) without credentials or a fragment: {key}"
                ));
            }
            if by_url.insert(url, record).is_some() {
                return Err(format!("Duplicate deployment URL: {key}"));
            }
        }
        Ok(Self(by_url))
    }
}

impl Deployments {
    /// Assesses installed upstream releases and their declared configuration for a matching document.
    /// ```
    /// # use corrode_scanner::detectors::vulnerabilities::Deployments;
    /// # let site = "https://example.test/".parse().unwrap();
    /// assert!(Deployments::default().findings(&site, &site).is_empty());
    /// ```
    pub fn findings(&self, requested: &Url, document: &Url) -> Vec<Vulnerability> {
        self.assess(Ok((requested, document)))
            .into_iter()
            .filter_map(|check| match check.outcome {
                AdvisoryOutcome::Matched { details } => Some(details),
                _ => None,
            })
            .collect()
    }

    pub(super) fn assess(&self, urls: Result<(&Url, &Url), &'static str>) -> Vec<AdvisoryCheck> {
        let record = urls.and_then(|(requested, document)| {
            if requested != document {
                return Err("The final document URL differs from the requested URL.");
            }
            self.0
                .get(document)
                .ok_or("No owner deployment record for this URL.")
        });
        let document = urls.ok().map(|(_, document)| document);
        let check = |name, result: Result<Option<Advisory>, &str>| {
            AdvisoryCheck::from_evidence(
                name,
                "Owner deployment record",
                result.map(|advisory| advisory.and_then(|a| a.finding(document?))),
                "The reported release or configuration falls outside this rule’s criteria.",
            )
        };
        let react = record.and_then(|r| {
            r.react
                .as_ref()
                .ok_or("Missing React server deployment record.")
        });
        let php = record.and_then(|r| r.php.as_ref().ok_or("Missing PHP deployment record."));
        let nginx = record.and_then(|r| {
            r.nginx_open_source
                .as_ref()
                .ok_or("Missing NGINX deployment record.")
        });
        let vite = record.and_then(|r| r.vite.as_ref().ok_or("Missing Vite deployment record."));
        vec![
            check(
                "React2Shell CVE-2025-55182",
                react.map(react::react2shell::check),
            ),
            check(
                "PHP2Shell CVE-2026-109618 / CVE-2026-109619",
                php.and_then(php::php2shell::check),
            ),
            check(
                "NGINX CVE-2026-123007",
                nginx.map(nginx::cve_2026_123007::check),
            ),
            check(
                "NGINX CVE-2026-123633",
                nginx.and_then(nginx::cve_2026_123633::check),
            ),
            check(
                "Vite GHSA-p4f5-76q4-ffq7",
                vite.map(vite::dev_server_rce::check),
            ),
        ]
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    react: Option<React>,
    php: Option<Php>,
    nginx_open_source: Option<Nginx>,
    vite: Option<Vite>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct React {
    pub package: String,
    pub unmodified_upstream_version: Version,
    pub serves_server_components: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Php {
    pub unmodified_upstream_version: Version,
    pub serves_web_requests: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Nginx {
    pub unmodified_upstream_version: Version,
    pub serves_http2: bool,
    pub proxies_to_backend: Option<bool>,
    pub low_worker_connections_observed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vite {
    pub unmodified_upstream_version: Version,
    pub dev_server_exposed_to_network: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Version(pub u32, pub u32, pub u32);

impl TryFrom<String> for Version {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, String> {
        let invalid = || format!("Expected an exact upstream release X.Y.Z, got {raw:?}");
        let mut parts = raw.split('.');
        let mut number = || {
            let s = parts.next().ok_or_else(invalid)?;
            if (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            s.parse().map_err(|_| invalid())
        };
        let version = Self(number()?, number()?, number()?);
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(version)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

pub(super) struct Advisory {
    pub title: &'static str,
    pub cvss_version: &'static str,
    pub cvss_tenths: u8,
    pub observed: String,
    pub source: &'static str,
    pub remediation: &'static str,
}

impl Advisory {
    fn finding(self, document: &Url) -> Option<Vulnerability> {
        let severity = match self.cvss_tenths {
            80..=89 => "high",
            90..=100 => "critical",
            _ => return None,
        };
        Some(Vulnerability {
            vuln_type: self.title.to_owned(),
            severity: severity.to_owned(),
            description: format!(
                "Owner-reported deployment matches the affected configuration: {}. Host exploitability is unverified. Advisory CVSS {}: {}.{}. Advisory: {}",
                self.observed, self.cvss_version, self.cvss_tenths / 10, self.cvss_tenths % 10, self.source
            ),
            remediation: self.remediation.to_owned(),
            url: Some(document.to_string()),
            disposition: AssessmentDisposition::Lead,
            evidence: vec![FindingEvidence {
                source: EvidenceSource::Deployment,
                location: Some(document.to_string()),
                summary: self.observed,
            }],
            confidence: None,
        })
    }
}
