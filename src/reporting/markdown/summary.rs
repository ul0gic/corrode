use crate::types::ScanResult;

pub(crate) fn severity_rank(label: &str) -> u8 {
    match label.to_lowercase().as_str() {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

pub(super) fn wrap_value_chunks(value: &str, max: usize) -> Vec<String> {
    if max == 0 {
        return vec![value.to_owned()];
    }
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let end = (start + max).min(bytes.len());
        if let Some(slice) = bytes.get(start..end) {
            out.push(String::from_utf8_lossy(slice).to_string());
        }
        start = end;
    }
    out
}

pub(super) fn wrap_entry(label: &str, value: &str, max_line: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let first_room = max_line.saturating_sub(label.len() + 2).max(8); // reserve space for value on first line
    let mut remaining = value.to_owned();

    if remaining.is_empty() {
        lines.push(format!("{label}:"));
    } else {
        let chunks = wrap_value_chunks(&remaining, first_room);
        if let Some((first, rest)) = chunks.split_first() {
            lines.push(format!("{label}: {first}"));
            if rest.is_empty() {
                remaining.clear();
            } else {
                remaining = rest.join("");
            }
        }
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

pub(super) fn truncate_middle(value: &str, max_len: usize) -> String {
    if value.len() <= max_len || max_len < 8 {
        return value.to_owned();
    }
    let head = max_len / 2 - 2;
    let tail = max_len - head - 3;
    format!("{}...{}", &value[..head], &value[value.len() - tail..])
}

pub(crate) fn render_summary(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    report.push("---\n## Executive Summary\n".to_owned());

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

    let secret_has_service_role = result.secrets.contains_key("supabase_service_role");

    let mut highest = 0;
    if secret_has_service_role {
        highest = highest.max(3);
    }
    for v in &result.vulnerabilities {
        highest = highest.max(severity_rank(&v.severity));
    }

    let risk_level = match highest {
        3 => "🔴 CRITICAL",
        2 => "🟠 HIGH",
        1 => "🟡 MEDIUM",
        _ => "🟢 LOW",
    };

    report.push(format!("**Risk Level**: {risk_level}\n"));
    report.push(format!("- Critical Vulnerabilities: {critical_vulns}"));
    report.push(format!("- High Vulnerabilities: {high_vulns}"));
    report.push(format!("- Medium Vulnerabilities: {medium_vulns}"));
    report.push(format!("- Low Vulnerabilities: {low_vulns}"));
    report.push(format!("- Secret Types Found: {secret_count}"));
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
            .map(std::string::String::len)
            .max()
            .unwrap_or(20)
            .max(20)
            .min(max_line_width);
        let border = format!("+{}+", "-".repeat(content_width + 2));
        report.push("```\n".to_owned());
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
        report.push("```\n".to_owned());
    }

    report
}
