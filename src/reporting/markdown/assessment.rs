// Does:  Classifies findings and derives assessment leads.
// Holds: Explicit vulnerability dispositions are retained.

use crate::types::{
    AdvisoryOutcome, AssessmentDisposition, ConfidenceLevel, ScanResult, SecretFinding,
    Vulnerability,
};

use super::summary::secret_severity;

pub(crate) fn render_advisory_checks(result: &ScanResult) -> Vec<String> {
    let mut lines = vec!["---\n## Advisory comparisons\n".to_owned()];
    if result.advisory_checks.is_empty() {
        lines.push(
            "This result has no recorded advisory coverage. Host exposure is unknown.\n".to_owned(),
        );
        return lines;
    }
    lines.push("Corrode compares versions and settings with published advisories. Host exploitability is unverified.\n".to_owned());
    lines.push("| Advisory | Evidence used or required | Result |".to_owned());
    lines.push("|---|---|---|".to_owned());
    for check in &result.advisory_checks {
        let status = match &check.outcome {
            AdvisoryOutcome::Matched { .. } => "**Advisory match**".to_owned(),
            AdvisoryOutcome::NoMatch { reason } => format!("No match — {reason}"),
            AdvisoryOutcome::NotAssessed { reason } => format!("Not assessed — {reason}"),
        };
        lines.push(format!(
            "| {} | {} | {} |",
            check.advisory, check.method, status
        ));
    }
    for check in &result.advisory_checks {
        if let AdvisoryOutcome::Matched { details } = &check.outcome {
            lines.push(format!("\n### {}\n", details.vuln_type));
            lines.push(details.description.clone());
            lines.push(format!("\n**Recommended action**: {}", details.remediation));
        }
    }
    lines.push(String::new());
    lines
}

pub(crate) fn secret_disposition(
    pattern_name: &str,
    finding: &SecretFinding,
) -> AssessmentDisposition {
    if matches!(secret_severity(pattern_name), "LOW" | "INFO") {
        return AssessmentDisposition::Inventory;
    }
    match finding
        .confidence
        .as_ref()
        .map(|confidence| confidence.level)
    {
        Some(ConfidenceLevel::Low) => AssessmentDisposition::Lead,
        Some(ConfidenceLevel::Medium | ConfidenceLevel::High) | None => {
            AssessmentDisposition::Finding
        }
    }
}

pub(crate) fn vulnerability_disposition(vulnerability: &Vulnerability) -> AssessmentDisposition {
    vulnerability.disposition
}

pub(crate) fn wordpress_lead(result: &ScanResult) -> Option<String> {
    if !result
        .technologies
        .iter()
        .any(|technology| technology.eq_ignore_ascii_case("WordPress"))
    {
        return None;
    }

    let version = result
        .technology_versions
        .iter()
        .find(|version| version.name.eq_ignore_ascii_case("WordPress"));
    match version {
        Some(version)
            if version.detection_method
                == crate::detectors::technologies::wordpress::ASSET_CONSENSUS_METHOD =>
        {
            Some(format!(
                "WordPress {} is inferred from agreeing core-asset query strings. Verify the \
                 installed core version before applying CVE conclusions.",
                version.version.as_deref().unwrap_or("version")
            ))
        }
        None | Some(crate::types::TechnologyVersion { version: None, .. }) => Some(
            "WordPress was detected, but no authoritative core version was observed. Verify the \
             installed version against current WordPress security advisories."
                .to_owned(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, SecretFinding};

    fn secret(level: ConfidenceLevel) -> SecretFinding {
        SecretFinding {
            source: "HTML".to_owned(),
            matches: vec!["value".to_owned()],
            confidence: Some(Confidence {
                level,
                score: 50,
                factors: Vec::new(),
            }),
        }
    }

    #[test]
    fn low_confidence_secret_is_a_lead() {
        assert_eq!(
            secret_disposition("aws_key", &secret(ConfidenceLevel::Low)),
            AssessmentDisposition::Lead
        );
    }

    #[test]
    fn publishable_key_is_inventory() {
        assert_eq!(
            secret_disposition("stripe_publishable_key", &secret(ConfidenceLevel::High)),
            AssessmentDisposition::Inventory
        );
    }
}
