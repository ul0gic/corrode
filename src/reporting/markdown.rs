use anyhow::Result;
use serde_json;
use std::fs;
use std::path::Path;

use crate::types::{ApiTestResult, ScanResult, Vulnerability};

pub fn write(result: &ScanResult, base_output_dir: &Path) -> Result<()> {
    let mut report = Vec::new();

    report.push("# 🦀 Corrode Security Scan Report\n".to_string());
    report.push(format!("**Target**: {}", result.url));
    report.push(format!("**Scan Date**: {}", result.timestamp));
    report.push("**Scanner**: Corrode v0.1.0\n".to_string());

    report.push("---\n## Executive Summary\n".to_string());

    let critical_vulns = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == "critical")
        .count();
    let high_vulns = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == "high")
        .count();
    let medium_vulns = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == "medium")
        .count();
    let low_vulns = result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity == "low")
        .count();
    let secret_count = result.secrets.len();

    let risk_level = if critical_vulns > 0 {
        "🔴 CRITICAL"
    } else if high_vulns > 0 {
        "🟠 HIGH"
    } else if medium_vulns > 0 {
        "🟡 MEDIUM"
    } else {
        "🟢 LOW"
    };

    report.push(format!("**Risk Level**: {}\n", risk_level));
    report.push(format!("- Critical Vulnerabilities: {}", critical_vulns));
    report.push(format!("- High Vulnerabilities: {}", high_vulns));
    report.push(format!("- Medium Vulnerabilities: {}", medium_vulns));
    report.push(format!("- Low Vulnerabilities: {}", low_vulns));
    report.push(format!("- Secret Types Found: {}", secret_count));
    report.push(format!(
        "- Technologies Detected: {}\n",
        result.technologies.len()
    ));

    if !result.secrets.is_empty() {
        report.push("---\n## 🔑 Secrets & Credentials Found\n".to_string());
        report.push(
            "⚠️ **CRITICAL**: The following secrets were exposed in the application\n".to_string(),
        );

        for (secret_type, findings) in &result.secrets {
            let total_matches: usize = findings.iter().map(|f| f.matches.len()).sum();
            report.push(format!("### {} ({} matches)", secret_type, total_matches));

            for finding in findings {
                report.push(format!("**Source**: {}", finding.source));
                report.push(format!("**Matches**: {}", finding.matches.len()));
                for m in finding.matches.iter().take(3) {
                    let display = if m.len() > 60 {
                        format!("{}...", &m[..60])
                    } else {
                        m.clone()
                    };
                    report.push(format!("- `{}`", display));
                }
                report.push(String::new());
            }
        }
    }

    if !result.vulnerabilities.is_empty() {
        report.push("---\n## 🚨 Vulnerabilities\n".to_string());

        for severity in &["critical", "high", "medium", "low"] {
            let vulns: Vec<&Vulnerability> = result
                .vulnerabilities
                .iter()
                .filter(|v| v.severity == *severity)
                .collect();

            if !vulns.is_empty() {
                let icon = match *severity {
                    "critical" => "🔴",
                    "high" => "🟠",
                    "medium" => "🟡",
                    _ => "🟢",
                };
                report.push(format!(
                    "### {} {} ({})\n",
                    icon,
                    severity.to_uppercase(),
                    vulns.len()
                ));

                for (i, vuln) in vulns.iter().enumerate() {
                    report.push(format!("#### {}. {}", i + 1, vuln.vuln_type));
                    report.push(format!("**Description**: {}", vuln.description));
                    if let Some(url) = &vuln.url {
                        report.push(format!("**URL**: `{}`", url));
                    }
                    report.push(format!("**Remediation**: {}\n", vuln.remediation));
                }
            }
        }
    }

    if !result.api_tests.is_empty() {
        report.push("---\n## 🎯 API Security Tests\n".to_string());

        let critical_api = result
            .api_tests
            .iter()
            .filter(|t| t.severity == "CRITICAL" && t.vulnerable)
            .count();
        let high_api = result
            .api_tests
            .iter()
            .filter(|t| t.severity == "HIGH" && t.vulnerable)
            .count();
        let medium_api = result
            .api_tests
            .iter()
            .filter(|t| t.severity == "MEDIUM" && t.vulnerable)
            .count();

        report.push(format!(
            "**Found {} vulnerable API endpoints**\n",
            result.api_tests.len()
        ));

        if critical_api > 0 {
            report.push(format!("### 🔴 CRITICAL Issues ({})\n", critical_api));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "CRITICAL" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }

        if high_api > 0 {
            report.push(format!("### 🟠 HIGH Issues ({})\n", high_api));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "HIGH" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }

        if medium_api > 0 {
            report.push(format!("### 🟡 MEDIUM Issues ({})\n", medium_api));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "MEDIUM" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }
    }

    if !result.comments.is_empty() {
        report.push("---\n## 💬 JavaScript Comments\n".to_string());
        for comment in &result.comments {
            report.push(format!(
                "### {} comment in {}",
                comment.comment_type, comment.source
            ));
            report.push(format!("```\n{}\n```\n", comment.content));
        }
    }

    report.push("---\n## 📡 Network Insights\n".to_string());
    report.push(format!(
        "- Total Requests: {}",
        result.network.total_requests
    ));
    report.push(format!(
        "- Third-party Requests: {}",
        result.network.third_party.len()
    ));
    report.push(format!(
        "- WebSockets: {}\n",
        result.network.websockets.len()
    ));

    if !result.javascript.source_maps.is_empty() {
        report.push("---\n## 🗺 Source Maps\n".to_string());
        for map in &result.javascript.source_maps {
            report.push(format!("- {}", map));
        }
    }

    report.push("---\n## 🧾 DOM Insights\n".to_string());
    report.push(format!("- Scripts: {}", result.dom.scripts));
    report.push(format!("- Forms: {}", result.dom.forms.len()));
    report.push(format!(
        "- Hidden Inputs: {}",
        result.dom.hidden_inputs.len()
    ));
    report.push(format!("- iframes: {}", result.dom.iframes.len()));

    if !result.dom.data_attributes.is_empty() {
        report.push("### Data Attributes\n".to_string());
        for attr in &result.dom.data_attributes {
            report.push(format!(
                "- {}: {}",
                attr.tag,
                serde_json::to_string_pretty(&attr.attributes)?
            ));
        }
    }

    if !result.technologies.is_empty() {
        report.push("---\n## 🛠️ Technology Stack\n".to_string());
        for tech in &result.technologies {
            report.push(format!("- {}", tech));
        }
        report.push(String::new());
    }

    report.push("---\n## 💡 Recommendations\n".to_string());
    report.push("1. **Immediately rotate** any exposed secrets and credentials".to_string());
    report.push("2. Remove or restrict access to source maps in production".to_string());
    report.push("3. Implement proper security headers (CSP, HSTS, etc.)".to_string());
    report.push("4. Review and fix all HIGH and CRITICAL vulnerabilities".to_string());
    report.push("5. Disable debug mode in production".to_string());
    report.push("6. Use HttpOnly, Secure, and SameSite flags on cookies\n".to_string());

    let domain = url::Url::parse(&result.url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
        .replace('.', "-");

    let site_dir = base_output_dir.join(&domain);
    fs::create_dir_all(&site_dir)?;

    let report_path = site_dir.join("REPORT.md");
    fs::write(report_path, report.join("\n"))?;

    Ok(())
}

fn push_api_test(report: &mut Vec<String>, test: &ApiTestResult) {
    report.push(format!("#### {}", test.test_type));
    report.push(format!("**Endpoint**: `{}`", test.endpoint));
    report.push(format!("**Evidence**: {}", test.evidence));
    report.push(format!("**Details**: {}\n", test.details));
}
