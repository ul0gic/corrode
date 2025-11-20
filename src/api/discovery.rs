use crate::types::DiscoveredEndpoint;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    // Patterns to find API endpoints in JavaScript
    static ref API_PATTERNS: Vec<Regex> = vec![
        // fetch() calls
        Regex::new(r#"fetch\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"fetch\s*\(\s*`([^`]+)`"#).unwrap(),

        // axios calls
        Regex::new(r#"axios\.(get|post|put|delete|patch)\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"axios\s*\(\s*\{\s*url\s*:\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),

        // XMLHttpRequest
        Regex::new(r#"\.open\s*\(\s*[`'"](\w+)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),

        // jQuery ajax
        Regex::new(r#"\$\.ajax\s*\(\s*\{\s*url\s*:\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"\$\.(get|post)\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),

        // API base URLs and endpoints
        Regex::new(r#"[`'"]https?://[^`'"]+/api/[^`'"]+[`'"]"#).unwrap(),
        Regex::new(r#"/api/[a-zA-Z0-9/_\-\{\}]+"#).unwrap(),
        Regex::new(r#"/v\d+/[a-zA-Z0-9/_\-\{\}]+"#).unwrap(),

        // GraphQL
        Regex::new(r#"[`'"]https?://[^`'"]+/graphql[`'"]"#).unwrap(),

        // Common REST patterns
        Regex::new(r#"[`'"]/users/\{?[a-zA-Z0-9_]+\}?[`'"]"#).unwrap(),
        Regex::new(r#"[`'"]/api/\w+/\{?[a-zA-Z0-9_]+\}?[`'"]"#).unwrap(),
    ];

    // Patterns to find URL parameters
    static ref PARAM_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"\{(\w+)\}"#).unwrap(),
        Regex::new(r#"\$\{(\w+)\}"#).unwrap(),
        Regex::new(r#":(\w+)"#).unwrap(),
    ];
}

pub fn extract_api_endpoints(code: &str, source: &str) -> Vec<DiscoveredEndpoint> {
    let mut endpoints = HashSet::new();
    let mut results = Vec::new();

    for pattern in API_PATTERNS.iter() {
        for cap in pattern.captures_iter(code) {
            // Try to extract URL from different capture groups
            let url = if let Some(url) = cap.get(1) {
                url.as_str()
            } else if let Some(url) = cap.get(2) {
                url.as_str()
            } else {
                continue;
            };

            // Skip if not an endpoint-like string
            if url.len() < 4 || (!url.starts_with('/') && !url.starts_with("http")) {
                continue;
            }

            // Deduplicate
            if endpoints.contains(url) {
                continue;
            }
            endpoints.insert(url.to_string());

            // Extract HTTP method if present
            let method = if let Some(method_cap) = cap.get(0) {
                let text = method_cap.as_str().to_lowercase();
                if text.contains("post") {
                    "POST"
                } else if text.contains("put") {
                    "PUT"
                } else if text.contains("delete") {
                    "DELETE"
                } else if text.contains("patch") {
                    "PATCH"
                } else {
                    "GET"
                }
            } else {
                "GET"
            };

            // Extract parameters
            let mut parameters = Vec::new();
            for param_pattern in PARAM_PATTERNS.iter() {
                for param_cap in param_pattern.captures_iter(url) {
                    if let Some(param) = param_cap.get(1) {
                        parameters.push(param.as_str().to_string());
                    }
                }
            }

            results.push(DiscoveredEndpoint {
                url: url.to_string(),
                method: method.to_string(),
                source: source.to_string(),
                auth_required: None,
                parameters,
            });
        }
    }

    results
}

pub fn normalize_endpoint(url: &str, base_url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else if url.starts_with('/') {
        // Extract base from base_url
        if let Ok(parsed) = reqwest::Url::parse(base_url) {
            format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                url
            )
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    }
}

pub fn find_graphql_schema(code: &str) -> Option<String> {
    let schema_pattern = Regex::new(r#"(?s)type\s+Query\s*\{[^\}]+\}"#).unwrap();
    schema_pattern.find(code).map(|m| m.as_str().to_string())
}
