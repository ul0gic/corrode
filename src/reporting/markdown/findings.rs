use std::cmp::Reverse;

use crate::types::{ApiTestResult, ScanResult};

use super::summary::{redact_value, secret_severity, severity_rank, truncate_middle};

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
}

pub(crate) fn render_secrets(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if result.secrets.is_empty() && result.vulnerabilities.is_empty() {
        return report;
    }

    report.push("---\n## Findings\n".to_owned());

    // Collect all findings into a flat list with severity
    let mut findings: Vec<Finding> = Vec::new();

    // Secrets -> findings
    for (pattern_name, secret_findings) in &result.secrets {
        let severity = secret_severity(pattern_name).to_owned();
        for sf in secret_findings {
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
            });
        }
    }

    // Vulnerabilities -> findings
    for vuln in &result.vulnerabilities {
        findings.push(Finding {
            severity: vuln.severity.to_uppercase(),
            title: vuln.vuln_type.clone(),
            finding_type: "Vulnerability".to_owned(),
            source: vuln.url.as_deref().unwrap_or("Scan target").to_owned(),
            value: None,
            context: vuln.description.clone(),
            location: vuln.url.clone(),
            remediation: Some(vuln.remediation.clone()),
        });
    }

    // Sort by severity (critical first)
    findings.sort_by_key(|f| Reverse(severity_rank(&f.severity)));

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
