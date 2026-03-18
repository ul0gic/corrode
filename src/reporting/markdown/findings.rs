use crate::types::{ApiTestResult, ScanResult, Vulnerability};

pub(crate) fn render_secrets(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if !result.secrets.is_empty() {
        report.push("---\n## 🔑 Secrets & Credentials Found\n".to_owned());
        report.push(
            "⚠️ **CRITICAL**: The following secrets were exposed in the application\n".to_owned(),
        );

        for (secret_type, findings) in &result.secrets {
            let total_matches: usize = findings.iter().map(|f| f.matches.len()).sum();
            report.push(format!("### {secret_type} ({total_matches} matches)"));

            for finding in findings {
                report.push(format!("**Source**: {}", finding.source));
                report.push(format!("**Matches**: {}", finding.matches.len()));
                for m in finding.matches.iter().take(3) {
                    let display = if m.len() > 60 {
                        format!("{}...", &m[..60])
                    } else {
                        m.clone()
                    };
                    report.push(format!("- `{display}`"));
                }
                report.push(String::new());
            }
        }
    }

    report
}

pub(crate) fn render_vulnerabilities(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if !result.vulnerabilities.is_empty() {
        report.push("---\n## 🚨 Vulnerabilities\n".to_owned());

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
                        report.push(format!("**URL**: `{url}`"));
                    }
                    report.push(format!("**Remediation**: {}\n", vuln.remediation));
                }
            }
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

    if !result.api_tests.is_empty() {
        report.push("---\n## 🎯 API Security Tests\n".to_owned());

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
            report.push(format!("### 🔴 CRITICAL Issues ({critical_api})\n"));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "CRITICAL" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }

        if high_api > 0 {
            report.push(format!("### 🟠 HIGH Issues ({high_api})\n"));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "HIGH" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }

        if medium_api > 0 {
            report.push(format!("### 🟡 MEDIUM Issues ({medium_api})\n"));
            for test in result
                .api_tests
                .iter()
                .filter(|t| t.severity == "MEDIUM" && t.vulnerable)
            {
                push_api_test(&mut report, test);
            }
        }
    }

    report
}
