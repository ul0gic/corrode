use crate::types::ScanResult;

pub(crate) fn severity_rank(label: &str) -> u8 {
    match label.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub(super) fn truncate_middle(value: &str, max_len: usize) -> String {
    if value.len() <= max_len || max_len < 8 {
        return value.to_owned();
    }
    let head = max_len / 2 - 2;
    let tail = max_len - head - 3;
    let start: String = value.chars().take(head).collect();
    let end: String = {
        let chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total > tail {
            chars.into_iter().skip(total - tail).collect()
        } else {
            value.to_owned()
        }
    };
    format!("{start}...{end}")
}

/// Redact a secret value, showing only the first and last 4 characters.
pub(super) fn redact_value(value: &str) -> String {
    if value.len() <= 12 {
        return "*".repeat(value.len());
    }
    let prefix: String = value.chars().take(4).collect();
    let suffix: String = {
        let chars: Vec<char> = value.chars().collect();
        let total = chars.len();
        if total > 4 {
            chars.into_iter().skip(total - 4).collect()
        } else {
            value.to_owned()
        }
    };
    let hidden = value.len().saturating_sub(8);
    format!("{prefix}{}...{suffix}", "*".repeat(hidden.min(20)))
}

/// Map a secret pattern name to a severity label.
pub(crate) fn secret_severity(pattern_name: &str) -> &'static str {
    match pattern_name {
        // Critical
        "supabase_service_role"
        | "supabase_secret"
        | "aws_secret"
        | "private_key"
        | "stripe_secret_key"
        | "postgres_url"
        | "mongodb_url"
        | "mysql_url"
        | "redis_url"
        | "digitalocean_token"
        | "azure_storage"
        | "azure_sas_token"
        | "anthropic_api_key"
        | "plaid_secret" => "CRITICAL",

        // High
        "aws_key"
        | "github"
        | "github_fine"
        | "gitlab"
        | "stripe_restricted"
        | "slack"
        | "slack_webhook"
        | "discord_token"
        | "sendgrid"
        | "twilio"
        | "bearer_token"
        | "basic_auth"
        | "google_oauth"
        | "openai_api_key"
        | "vercel_token"
        | "azure_ad_client_secret"
        | "cloudflare_origin_ca"
        | "sentry_auth_token"
        | "datadog_api_key"
        | "datadog_app_key"
        | "pagerduty"
        | "linear_api_key"
        | "notion_api_key"
        | "postmark"
        | "mapbox_sk" => "HIGH",

        // Low
        "supabase_publishable"
        | "supabase_url"
        | "supabase_anon_jwt"
        | "stripe_publishable_key"
        | "sentry_dsn"
        | "mapbox_pk" => "LOW",

        // Info
        "internal_ip" | "aws_arn" | "gcp_service_account" | "env_var_reference" => "INFO",

        // Default for unknown (custom patterns)
        _ => "MEDIUM",
    }
}

/// Severity counts for the summary section.
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
    security_issues: usize,
}

fn count_findings(result: &ScanResult) -> SeverityCounts {
    let mut counts = SeverityCounts {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        security_issues: result.security.missing_headers.len()
            + result.security.cors_issues.len()
            + result.security.insecure_cookies.len()
            + result.security.mixed_content.len(),
    };

    for pattern_name in result.secrets.keys() {
        match secret_severity(pattern_name) {
            "CRITICAL" => counts.critical += 1,
            "HIGH" => counts.high += 1,
            "LOW" => counts.low += 1,
            "INFO" => counts.info += 1,
            _ => counts.medium += 1,
        }
    }

    for vuln in &result.vulnerabilities {
        match vuln.severity.to_lowercase().as_str() {
            "critical" => counts.critical += 1,
            "high" => counts.high += 1,
            "low" => counts.low += 1,
            "info" => counts.info += 1,
            _ => counts.medium += 1,
        }
    }

    counts
}

fn render_risk_and_metrics(report: &mut Vec<String>, result: &ScanResult, counts: &SeverityCounts) {
    let risk_level = if counts.critical > 0 {
        "CRITICAL"
    } else if counts.high > 0 {
        "HIGH"
    } else if counts.medium > 0 {
        "MEDIUM"
    } else if counts.low > 0 {
        "LOW"
    } else {
        "INFO"
    };

    let risk_icon = match risk_level {
        "CRITICAL" => "!!",
        "HIGH" => "!",
        "MEDIUM" => "~",
        "LOW" => "-",
        _ => ".",
    };

    report.push(format!("**Risk Level**: [{risk_icon}] {risk_level}\n"));

    report.push("| Metric | Count |".to_owned());
    report.push("|--------|-------|".to_owned());
    report.push(format!("| CRITICAL findings | {} |", counts.critical));
    report.push(format!("| HIGH findings | {} |", counts.high));
    report.push(format!("| MEDIUM findings | {} |", counts.medium));
    report.push(format!("| LOW findings | {} |", counts.low));
    report.push(format!("| INFO findings | {} |", counts.info));
    report.push(format!("| Secret types found | {} |", result.secrets.len()));
    report.push(format!(
        "| Technologies detected | {} |",
        result.technologies.len()
    ));
    report.push(format!(
        "| Network requests captured | {} |",
        result.network.total_requests
    ));
    report.push(format!("| Security issues | {} |", counts.security_issues));
    report.push(String::new());

    let total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
    if total == 0 && counts.security_issues == 0 {
        report.push(
            "No secrets, vulnerabilities, or security issues were detected during this scan."
                .to_owned(),
        );
    } else {
        let mut parts = Vec::new();
        if counts.critical > 0 {
            parts.push(format!(
                "{} CRITICAL finding(s) requiring immediate attention",
                counts.critical
            ));
        }
        if counts.high > 0 {
            parts.push(format!("{} HIGH severity finding(s)", counts.high));
        }
        if !result.secrets.is_empty() {
            let total_matches: usize = result
                .secrets
                .values()
                .flat_map(|findings| findings.iter().map(|f| f.matches.len()))
                .sum();
            parts.push(format!(
                "{} secret type(s) detected with {} total match(es)",
                result.secrets.len(),
                total_matches
            ));
        }
        if counts.security_issues > 0 {
            parts.push(format!(
                "{} security configuration issue(s)",
                counts.security_issues
            ));
        }
        report.push(format!("This scan identified: {}.\n", parts.join("; ")));
    }
}

pub(crate) fn render_summary(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();
    report.push("---\n## Executive Summary\n".to_owned());

    let counts = count_findings(result);

    render_risk_and_metrics(&mut report, result, &counts);

    // Technologies detected (brief inline)
    if !result.technologies.is_empty() {
        let tech_list: String = result
            .technologies
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if result.technologies.len() > 10 {
            format!(" (+{} more)", result.technologies.len() - 10)
        } else {
            String::new()
        };
        report.push(format!("**Technologies**: {tech_list}{suffix}\n"));
    }

    report
}
