use crate::types::{ApiCall, ScanResult};

use super::summary::truncate_middle;

fn header_hints(headers: &std::collections::HashMap<String, String>) -> String {
    let mut hits = Vec::new();
    for key in [
        "authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-client-id",
    ] {
        if headers.keys().any(|k| k.eq_ignore_ascii_case(key)) {
            hits.push(key.replace('-', " ").to_uppercase());
        }
    }
    if hits.is_empty() {
        "-".to_owned()
    } else {
        hits.join(", ")
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_api_like(url: &str) -> bool {
    url.contains("/api/")
        || url.contains("/graphql")
        || url.contains("/v1/")
        || url.contains("/v2/")
        || url.contains("/v3/")
        || url.ends_with(".json")
}

fn format_calls_table(calls: &[ApiCall]) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("```".to_owned());
    lines.push(format!(
        "{:<6} {:<6} {:<18} {:<60} {}",
        "METHOD", "CODE", "CT", "URL", "AUTH"
    ));
    for call in calls {
        let method = if call.method.is_empty() {
            "GET".to_owned()
        } else {
            call.method.clone()
        };
        let status = if call.status == 0 {
            "-".to_owned()
        } else {
            call.status.to_string()
        };
        let url = truncate_middle(&call.url, 60);
        let hints = header_hints(&call.request_headers);
        let ct = content_type_for_call(call).unwrap_or("-".to_owned());
        lines.push(format!(
            "{:<6} {:<6} {:<18} {:<60} {}",
            method,
            status,
            truncate_middle(&ct, 18),
            url,
            hints
        ));
    }
    lines.push("```".to_owned());
    lines
}

fn content_type_for_call(call: &ApiCall) -> Option<String> {
    if let Some(ct) = &call.response_content_type {
        return Some(ct.clone());
    }
    header_value(&call.response_headers, "content-type")
        .or_else(|| header_value(&call.request_headers, "content-type"))
        .map(std::borrow::ToOwned::to_owned)
}

fn header_value<'a>(
    headers: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

pub(crate) fn render_network(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if result.network.total_requests > 0 || !result.network.calls.is_empty() {
        report.push("---\n## 🌐 Network Activity\n".to_owned());
        report.push(format!(
            "- Total Requests: {}",
            result.network.total_requests
        ));
        report.push(format!(
            "- API-like Requests: {}",
            result.network.api_calls.len()
        ));
        report.push(format!(
            "- Third-Party Requests: {}",
            result.network.third_party.len()
        ));

        let mut calls = result
            .network
            .calls
            .iter()
            .filter(|c| is_api_like(&c.url))
            .take(10)
            .cloned()
            .collect::<Vec<ApiCall>>();

        if calls.is_empty() {
            calls = result.network.calls.iter().take(10).cloned().collect();
        }

        if !calls.is_empty() {
            report.push("Key Requests (method, status, auth hints):".to_owned());
            report.extend(format_calls_table(&calls));
            report.push(String::new());
        }
    }

    report
}
