use std::cmp::Reverse;

use crate::types::{
    ApiTestResult, AssessmentDisposition, Confidence, JwtClaims, ScanResult, StorageAssessment,
    StorageRiskClass,
};

use super::assessment::{secret_disposition, vulnerability_disposition};
use super::summary::{
    confidence_sort_key, redact_value, secret_severity, severity_confidence, severity_rank,
    truncate_middle,
};

/// Unified finding for sorting across secrets and vulnerabilities.
struct Finding {
    severity: String,
    title: String,
    finding_type: String,
    source: String,
    value: Option<String>,
    context: String,
    location: Option<String>,
    remediation: Option<String>,
    confidence: Option<Confidence>,
    evidence_basis: Option<String>,
}

/// Top factor note from a confidence breakdown, for the rendered "why" line.
fn confidence_why(confidence: Option<&Confidence>) -> Option<String> {
    let c = confidence?;
    let note = c.factors.iter().find(|f| !f.note.is_empty())?;
    Some(note.note.clone())
}

pub(crate) fn render_findings(result: &ScanResult) -> Vec<String> {
    render_assessments(
        result,
        Some(AssessmentDisposition::Finding),
        "Actionable Findings",
    )
}

pub(crate) fn render_evidence_findings(result: &ScanResult) -> Vec<String> {
    render_assessments(result, None, "All Finding Candidates")
}

pub(crate) fn render_lead_assessments(result: &ScanResult) -> Vec<String> {
    render_assessments(
        result,
        Some(AssessmentDisposition::Lead),
        "Manual Validation Leads",
    )
}

fn render_assessments(
    result: &ScanResult,
    disposition: Option<AssessmentDisposition>,
    title: &str,
) -> Vec<String> {
    let mut report = Vec::new();

    if result.secrets.is_empty()
        && result.vulnerabilities.is_empty()
        && result.storage_assessments.is_empty()
    {
        return report;
    }

    // Collect all findings into a flat list with severity
    let mut findings: Vec<Finding> = Vec::new();

    // Secrets -> findings
    for (pattern_name, secret_findings) in &result.secrets {
        let severity = secret_severity(pattern_name).to_owned();
        for sf in secret_findings {
            if !sf.matches.is_empty()
                && sf.matches.iter().all(|value| {
                    result
                        .storage_assessments
                        .iter()
                        .any(|assessment| assessment.value == *value)
                })
            {
                continue;
            }
            if disposition.is_some_and(|wanted| secret_disposition(pattern_name, sf) != wanted) {
                continue;
            }
            let value_display = format_secret_values(&sf.matches);
            findings.push(Finding {
                severity: severity.clone(),
                title: format_pattern_title(pattern_name),
                finding_type: "Exposed Secret".to_owned(),
                source: sf.source.clone(),
                value: Some(value_display),
                context: secret_context(pattern_name),
                location: None,
                remediation: Some(secret_remediation(pattern_name)),
                confidence: sf.confidence.clone(),
                evidence_basis: None,
            });
        }
    }

    collect_structured_assessments(result, disposition, &mut findings);

    if findings.is_empty() {
        return report;
    }

    report.push(format!("---\n## {title}\n"));

    // Sort by severity (critical first), then by confidence within each band.
    findings.sort_by_key(|f| {
        (
            Reverse(severity_rank(&f.severity)),
            Reverse(confidence_sort_key(f.confidence.as_ref())),
        )
    });

    // Render by severity section
    for sev in &["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let section_findings: Vec<&Finding> =
            findings.iter().filter(|f| f.severity == *sev).collect();

        if section_findings.is_empty() {
            continue;
        }

        let icon = severity_icon(sev);
        report.push(format!("### {icon} {sev} ({})\n", section_findings.len()));

        for (i, finding) in section_findings.iter().enumerate() {
            report.push(format!("#### {}. {}\n", i + 1, finding.title));
            report.push(format!("**Type**: {}", finding.finding_type));
            report.push(format!(
                "**Assessment**: {}",
                severity_confidence(sev, finding.confidence.as_ref())
            ));
            if let Some(why) = finding
                .evidence_basis
                .clone()
                .or_else(|| confidence_why(finding.confidence.as_ref()))
            {
                report.push(format!("**Confidence basis**: {why}"));
            }
            report.push(format!("**Source**: {}", finding.source));

            if let Some(value) = &finding.value {
                report.push(format!("**Value**: `{}`", truncate_middle(value, 100)));
            }

            report.push(format!("**Context**: {}", finding.context));

            if let Some(loc) = &finding.location {
                report.push(format!("**Location**: `{loc}`"));
            }

            if let Some(rem) = &finding.remediation {
                report.push(format!("**Remediation**: {rem}"));
            }

            report.push(String::new());
        }
    }

    report
}

fn collect_structured_assessments(
    result: &ScanResult,
    disposition: Option<AssessmentDisposition>,
    findings: &mut Vec<Finding>,
) {
    for vuln in &result.vulnerabilities {
        if disposition.is_some_and(|wanted| vulnerability_disposition(vuln) != wanted) {
            continue;
        }
        findings.push(Finding {
            severity: vuln.severity.to_uppercase(),
            title: vuln.vuln_type.clone(),
            finding_type: "Vulnerability".to_owned(),
            source: vuln
                .evidence
                .first()
                .and_then(|evidence| evidence.location.as_deref())
                .or(vuln.url.as_deref())
                .unwrap_or("Scan target")
                .to_owned(),
            value: None,
            context: vuln.description.clone(),
            location: vuln.url.clone(),
            remediation: Some(vuln.remediation.clone()),
            confidence: vuln.confidence.clone(),
            evidence_basis: vuln
                .evidence
                .first()
                .map(|evidence| format!("{:?}: {}", evidence.source, evidence.summary)),
        });
    }

    for assessment in &result.storage_assessments {
        if disposition.is_some_and(|wanted| assessment.disposition != wanted) {
            continue;
        }
        findings.push(storage_finding(assessment));
    }
}

fn storage_finding(assessment: &StorageAssessment) -> Finding {
    Finding {
        severity: assessment.severity.to_uppercase(),
        title: storage_title(assessment.classification).to_owned(),
        finding_type: "Stored Session Material".to_owned(),
        source: assessment
            .evidence
            .first()
            .and_then(|evidence| evidence.location.as_deref())
            .unwrap_or("Browser-observed state")
            .to_owned(),
        value: Some(redact_value(&assessment.value)),
        context: storage_context(assessment),
        location: None,
        remediation: Some(storage_remediation(assessment.classification).to_owned()),
        confidence: assessment.confidence.clone(),
        evidence_basis: assessment
            .evidence
            .first()
            .map(|evidence| format!("{:?}: {}", evidence.source, evidence.summary)),
    }
}

pub(crate) fn storage_title(classification: StorageRiskClass) -> &'static str {
    match classification {
        StorageRiskClass::PrivilegedJwt => "Privileged JWT in Browser-Visible State",
        StorageRiskClass::AccessToken => "Access Token in Browser-Visible State",
        StorageRiskClass::RefreshToken => "Refresh Token in Browser-Visible State",
        StorageRiskClass::PersistedSession => "Persisted Session Material",
        StorageRiskClass::PublicConfiguration => "Public Client Configuration",
        StorageRiskClass::AmbiguousSensitiveName => "Sensitive Session-Related Name",
    }
}

fn storage_context(assessment: &StorageAssessment) -> String {
    let mut context = match assessment.classification {
        StorageRiskClass::PrivilegedJwt => {
            "A JWT with privileged role or scope claims was directly observed in state available to the browser."
        }
        StorageRiskClass::AccessToken => {
            "Access-token material was directly observed in browser-visible state."
        }
        StorageRiskClass::RefreshToken => {
            "Refresh-token material was directly observed in browser-visible state and may extend session access."
        }
        StorageRiskClass::PersistedSession => {
            "Opaque session material was directly observed in browser-visible state."
        }
        StorageRiskClass::PublicConfiguration => {
            "The observed value is public-by-design, anonymous, or already expired and is retained as inventory."
        }
        StorageRiskClass::AmbiguousSensitiveName => {
            "A session-related name was observed, but its value was not credential-shaped; manual validation is required."
        }
    }
    .to_owned();

    if let Some(claims) = &assessment.jwt_claims {
        let rendered = render_claims(claims);
        if !rendered.is_empty() {
            context.push_str(" Decoded claims: ");
            context.push_str(&rendered);
            context.push('.');
        }
    }
    context
}

fn render_claims(claims: &JwtClaims) -> String {
    let mut parts = Vec::new();
    if let Some(issuer) = &claims.issuer {
        parts.push(format!("issuer `{issuer}`"));
    }
    if !claims.audience.is_empty() {
        parts.push(format!("audience `{}`", claims.audience.join(", ")));
    }
    if let Some(expiry) = claims.expires_at {
        let state = if claims.expired == Some(true) {
            "expired"
        } else {
            "not expired at scan time"
        };
        parts.push(format!("expiry `{expiry}` ({state})"));
    }
    if !claims.roles.is_empty() {
        parts.push(format!("roles `{}`", claims.roles.join(", ")));
    }
    if !claims.scopes.is_empty() {
        parts.push(format!("scopes `{}`", claims.scopes.join(", ")));
    }
    if !claims.tenants.is_empty() {
        parts.push(format!("tenants `{}`", claims.tenants.join(", ")));
    }
    if !claims.accounts.is_empty() {
        parts.push(format!("accounts `{}`", claims.accounts.join(", ")));
    }
    parts.join("; ")
}

fn storage_remediation(classification: StorageRiskClass) -> &'static str {
    match classification {
        StorageRiskClass::PrivilegedJwt => {
            "Revoke the token, remove privileged credentials from browser-delivered state, and move privileged operations server-side."
        }
        StorageRiskClass::AccessToken => {
            "Minimize token lifetime and browser persistence; prefer HttpOnly, Secure, SameSite session cookies where the architecture permits."
        }
        StorageRiskClass::RefreshToken => {
            "Rotate the refresh token and avoid persisting long-lived refresh credentials in script-readable storage."
        }
        StorageRiskClass::PersistedSession => {
            "Review whether persistent browser storage is necessary and apply short expiry, rotation, and secure cookie controls."
        }
        StorageRiskClass::PublicConfiguration => {
            "No credential rotation is indicated; confirm the value is intentionally public and least-privileged."
        }
        StorageRiskClass::AmbiguousSensitiveName => {
            "Verify the value's purpose and sensitivity before treating it as a credential."
        }
    }
}

fn push_api_test(report: &mut Vec<String>, test: &ApiTestResult) {
    report.push(format!("#### {}", test.test_type));
    report.push(format!("**Endpoint**: `{}`", test.endpoint));
    report.push(format!("**Evidence**: {}", test.evidence));
    report.push(format!("**Details**: {}\n", test.details));
}

pub(crate) fn render_api_tests(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if result.api_tests.is_empty() {
        return report;
    }

    report.push("---\n## API Security Tests\n".to_owned());

    let critical_api: Vec<&ApiTestResult> = result
        .api_tests
        .iter()
        .filter(|t| t.severity == "CRITICAL" && t.vulnerable)
        .collect();
    let high_api: Vec<&ApiTestResult> = result
        .api_tests
        .iter()
        .filter(|t| t.severity == "HIGH" && t.vulnerable)
        .collect();
    let medium_api: Vec<&ApiTestResult> = result
        .api_tests
        .iter()
        .filter(|t| t.severity == "MEDIUM" && t.vulnerable)
        .collect();

    report.push(format!(
        "**Found {} vulnerable API endpoints**\n",
        result.api_tests.len()
    ));

    if !critical_api.is_empty() {
        report.push(format!(
            "### [!!] CRITICAL Issues ({})\n",
            critical_api.len()
        ));
        for test in &critical_api {
            push_api_test(&mut report, test);
        }
    }

    if !high_api.is_empty() {
        report.push(format!("### [!] HIGH Issues ({})\n", high_api.len()));
        for test in &high_api {
            push_api_test(&mut report, test);
        }
    }

    if !medium_api.is_empty() {
        report.push(format!("### [~] MEDIUM Issues ({})\n", medium_api.len()));
        for test in &medium_api {
            push_api_test(&mut report, test);
        }
    }

    report
}

fn severity_icon(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" => "[!!]",
        "HIGH" => "[!]",
        "MEDIUM" => "[~]",
        "LOW" => "[-]",
        "INFO" => "[.]",
        _ => "[?]",
    }
}

/// Format a list of secret match values for display.
fn format_secret_values(matches: &[String]) -> String {
    if matches.is_empty() {
        return String::new();
    }
    if let Some(first) = matches.first() {
        let display = redact_value(first);
        if matches.len() > 1 {
            format!("{display} (+{} more)", matches.len() - 1)
        } else {
            display
        }
    } else {
        String::new()
    }
}

/// Convert a pattern name like `aws_secret` to a readable title like `AWS Secret`.
fn format_pattern_title(pattern_name: &str) -> String {
    pattern_name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    format!("{upper}{}", chars.as_str())
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate context description for why a secret finding matters.
fn secret_context(pattern_name: &str) -> String {
    match pattern_name {
        "supabase_service_role" => "Service role key grants full database access bypassing RLS. An attacker can read, write, and delete all data.".to_owned(),
        "supabase_secret" => "Supabase secret key provides administrative access to the project.".to_owned(),
        "aws_key" | "aws_secret" => "AWS credentials could allow unauthorized access to cloud resources, data exfiltration, or resource abuse.".to_owned(),
        "stripe_secret_key" => "Stripe secret key allows creating charges, refunds, and accessing customer payment data.".to_owned(),
        "stripe_publishable_key" => "Publishable key is intended for client-side use but confirms Stripe integration.".to_owned(),
        "private_key" => "Private key material exposed in client-side code. Could enable impersonation or decryption.".to_owned(),
        "jwt" | "jwt_in_url" => "JSON Web Token found. May contain user identity, roles, or session data.".to_owned(),
        "github" | "github_fine" => "GitHub token could allow repository access, code modification, or org enumeration.".to_owned(),
        "gitlab" => "GitLab token could allow repository access and CI/CD pipeline manipulation.".to_owned(),
        "slack" | "slack_webhook" => "Slack token could allow message posting, channel enumeration, or workspace data access.".to_owned(),
        "firebase" => "Firebase API key confirms Firebase integration and may allow data access if security rules are misconfigured.".to_owned(),
        "sendgrid" => "SendGrid API key allows sending emails, potentially enabling phishing from the organization's domain.".to_owned(),
        "openai_api_key" => "OpenAI API key allows making API calls billed to the key owner's account.".to_owned(),
        "anthropic_api_key" => "Anthropic API key allows making API calls billed to the key owner's account.".to_owned(),
        "postgres_url" | "mongodb_url" | "mysql_url" | "redis_url" => "Database connection string with credentials exposed. Direct database access may be possible.".to_owned(),
        _ => "Exposed credential or sensitive value detected in client-side code.".to_owned(),
    }
}

/// Generate remediation advice for a secret pattern.
fn secret_remediation(pattern_name: &str) -> String {
    match pattern_name {
        "supabase_service_role" | "supabase_secret" => "Rotate the key immediately in the Supabase dashboard. Use server-side code for service role operations.".to_owned(),
        "aws_key" | "aws_secret" => "Rotate AWS credentials via IAM console. Use server-side proxies or signed URLs for client access.".to_owned(),
        "stripe_secret_key" | "stripe_restricted" => "Rotate the key in the Stripe dashboard. Never expose secret keys in client-side code.".to_owned(),
        "private_key" => "Remove the private key from client-side code immediately. Rotate the key pair.".to_owned(),
        "github" | "github_fine" | "gitlab" => "Revoke the token and generate a new one with minimum required scopes.".to_owned(),
        "postgres_url" | "mongodb_url" | "mysql_url" | "redis_url" => "Change database credentials immediately. Use server-side API proxies.".to_owned(),
        _ => "Rotate the exposed credential and ensure it is only used server-side.".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EvidenceSource, FindingEvidence, StorageAssessment};

    #[test]
    fn storage_values_are_redacted_but_claims_and_provenance_render() {
        let token = "session-secret-material-1234567890";
        let mut result = ScanResult::default();
        result.storage_assessments.push(StorageAssessment {
            classification: StorageRiskClass::RefreshToken,
            keys: vec!["refresh_token".to_owned()],
            value: token.to_owned(),
            severity: "high".to_owned(),
            disposition: AssessmentDisposition::Finding,
            evidence: vec![FindingEvidence {
                source: EvidenceSource::Runtime,
                location: Some("localStorage `refresh_token`".to_owned()),
                summary: "Refresh-token material observed".to_owned(),
            }],
            jwt_claims: None,
            confidence: None,
        });

        let markdown = render_findings(&result).join("\n");
        assert!(markdown.contains("Refresh Token in Browser-Visible State"));
        assert!(markdown.contains("localStorage `refresh_token`"));
        assert!(!markdown.contains(token));
    }
}
