// Does:  Finds endpoint candidates in JavaScript text.
// Holds: A candidate URL appears at most once per extraction.

// Why: Literal regex patterns are compiled with unwrap.
#![allow(clippy::unwrap_used)]
// Why: Regex collections use the lazy_static macro.
#![allow(clippy::non_std_lazy_statics)]

use crate::types::DiscoveredEndpoint;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashSet;

lazy_static! {
    static ref API_PATTERNS: Vec<Regex> = vec![
        Regex::new(r#"fetch\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r"fetch\s*\(\s*`([^`]+)`").unwrap(),
        Regex::new(r#"axios\.(get|post|put|delete|patch)\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"axios\s*\(\s*\{\s*url\s*:\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"\.open\s*\(\s*[`'"](\w+)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"\$\.ajax\s*\(\s*\{\s*url\s*:\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"\$\.(get|post)\s*\(\s*[`'"]([^`'"]+)[`'"]"#).unwrap(),
        Regex::new(r#"[`'"]https?://[^`'"]+/api/[^`'"]+[`'"]"#).unwrap(),
        Regex::new(r"/api/[a-zA-Z0-9/_\-\{\}]+").unwrap(),
        Regex::new(r"/v\d+/[a-zA-Z0-9/_\-\{\}]+").unwrap(),
        Regex::new(r#"[`'"]https?://[^`'"]+/graphql[`'"]"#).unwrap(),
        Regex::new(r#"[`'"]/users/\{?[a-zA-Z0-9_]+\}?[`'"]"#).unwrap(),
        Regex::new(r#"[`'"]/api/\w+/\{?[a-zA-Z0-9_]+\}?[`'"]"#).unwrap(),
    ];
    static ref PARAM_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"\{(\w+)\}").unwrap(),
        Regex::new(r"\$\{(\w+)\}").unwrap(),
        Regex::new(r":(\w+)").unwrap(),
    ];
}

/// Extracts distinct endpoint candidates from JavaScript using pattern matches.
///
/// ```
/// # use corrode_scanner::detectors::endpoints::extract_api_endpoints;
/// assert_eq!(extract_api_endpoints("fetch('/api/users')", "app.js")[0].url, "/api/users");
/// ```
pub fn extract_api_endpoints(code: &str, source: &str) -> Vec<DiscoveredEndpoint> {
    let mut endpoints = HashSet::new();
    let mut results = Vec::new();

    for pattern in API_PATTERNS.iter() {
        for cap in pattern.captures_iter(code) {
            let url = if let Some(url) = cap.get(1) {
                url.as_str()
            } else if let Some(url) = cap.get(2) {
                url.as_str()
            } else {
                continue;
            };

            if url.len() < 4 || (!url.starts_with('/') && !url.starts_with("http")) {
                continue;
            }

            if endpoints.contains(url) {
                continue;
            }
            endpoints.insert(url.to_owned());

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

            let mut parameters = Vec::new();
            for param_pattern in PARAM_PATTERNS.iter() {
                for param_cap in param_pattern.captures_iter(url) {
                    if let Some(param) = param_cap.get(1) {
                        parameters.push(param.as_str().to_owned());
                    }
                }
            }

            results.push(DiscoveredEndpoint {
                url: url.to_owned(),
                method: method.to_owned(),
                source: source.to_owned(),
                auth_required: None,
                parameters,
            });
        }
    }

    results
}
