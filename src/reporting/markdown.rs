use anyhow::Result;
use serde_json;
use std::fs;
use std::path::Path;

use crate::types::{ApiTestResult, ScanResult, Vulnerability};

fn severity_rank(label: &str) -> u8 {
    match label.to_lowercase().as_str() {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn wrap_value_chunks(value: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return vec![value.to_string()];
    }
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let end = (start + max).min(bytes.len());
        out.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
        start = end;
    }
    out
}

fn wrap_entry(label: &str, value: &str, max_line: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let first_room = max_line.saturating_sub(label.len() + 2).max(8); // reserve space for value on first line
    let mut remaining = value.to_string();

    if !remaining.is_empty() {
        let chunks = wrap_value_chunks(&remaining, first_room);
        if let Some((first, rest)) = chunks.split_first() {
            lines.push(format!("{label}: {first}"));
            if !rest.is_empty() {
                remaining = rest.join("");
            } else {
                remaining.clear();
            }
        }
    } else {
        lines.push(format!("{label}:"));
    }

    let cont_room = max_line.saturating_sub(2).max(8);
    while !remaining.is_empty() {
        let chunks = wrap_value_chunks(&remaining, cont_room);
        if let Some((first, tail)) = chunks.split_first() {
            lines.push(format!("  {first}"));
            remaining = tail.join("");
        } else {
            break;
        }
    }

    lines
}

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

    let api_critical = result
        .api_tests
        .iter()
        .filter(|t| t.vulnerable && t.severity.eq_ignore_ascii_case("critical"))
        .count();
    let api_high = result
        .api_tests
        .iter()
        .filter(|t| t.vulnerable && t.severity.eq_ignore_ascii_case("high"))
        .count();
    let api_medium = result
        .api_tests
        .iter()
        .filter(|t| t.vulnerable && t.severity.eq_ignore_ascii_case("medium"))
        .count();

    let secret_count = result.secrets.len();

    let secret_has_service_role = result.secrets.contains_key("supabase_service_role");

    let mut highest = 0;
    if secret_has_service_role {
        highest = highest.max(3);
    }
    for v in &result.vulnerabilities {
        highest = highest.max(severity_rank(&v.severity));
    }
    for test in result.api_tests.iter().filter(|t| t.vulnerable) {
        highest = highest.max(severity_rank(&test.severity));
    }

    let risk_level = match highest {
        3 => "🔴 CRITICAL",
        2 => "🟠 HIGH",
        1 => "🟡 MEDIUM",
        _ => "🟢 LOW",
    };

    report.push(format!("**Risk Level**: {}\n", risk_level));
    report.push(format!("- Critical Vulnerabilities: {}", critical_vulns));
    report.push(format!("- High Vulnerabilities: {}", high_vulns));
    report.push(format!("- Medium Vulnerabilities: {}", medium_vulns));
    report.push(format!("- Low Vulnerabilities: {}", low_vulns));
    report.push(format!("- Critical API Findings: {}", api_critical));
    report.push(format!("- High API Findings: {}", api_high));
    report.push(format!("- Medium API Findings: {}", api_medium));
    report.push(format!("- Secret Types Found: {}", secret_count));
    report.push(format!(
        "- Technologies Detected: {}\n",
        result.technologies.len()
    ));

    // Key summary box: show one value for every detected secret type
    let max_line_width = 96;
    let mut key_lines: Vec<String> = Vec::new();
    for (secret_type, findings) in &result.secrets {
        if let Some(first) = findings.first() {
            if let Some(value) = first.matches.first() {
                for line in wrap_entry(secret_type, value, max_line_width) {
                    key_lines.push(line);
                }
            }
        }
    }

    if !key_lines.is_empty() {
        let content_width = key_lines
            .iter()
            .map(|l| l.len())
            .max()
            .unwrap_or(20)
            .max(20)
            .min(max_line_width);
        let border = format!("+{}+", "-".repeat(content_width + 2));
        report.push("```\n".to_string());
        report.push(border.clone());
        let title = "Keys Identified";
        let title_pad = content_width.saturating_sub(title.len());
        report.push(format!("| {}{} |", title, " ".repeat(title_pad)));
        report.push(border.clone());
        for line in key_lines {
            let pad = content_width.saturating_sub(line.len());
            report.push(format!("| {}{} |", line, " ".repeat(pad)));
        }
        report.push(border);
        report.push("```\n".to_string());
    }

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

    if !result.javascript.ast_findings.is_empty() {
        report.push("---\n## 🧠 JavaScript AST Findings\n".to_string());
        for finding in &result.javascript.ast_findings {
            report.push(format!("### {} @ {}", finding.kind, finding.location));
            report.push(format!("**Value**: `{}`", finding.value));
            report.push(format!("**Context**: {}\n", finding.context));
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
