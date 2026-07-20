use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::types::{ApiCall, MetaTag, TechnologyVersion};

pub const META_GENERATOR_METHOD: &str = "wordpress_generator_meta";
pub const REST_GENERATOR_METHOD: &str = "wordpress_observed_rest_generator";
pub const ASSET_CONSENSUS_METHOD: &str = "wordpress_asset_version_consensus";

#[derive(Debug, Default)]
pub struct WordPressFingerprint {
    pub detected: bool,
    pub version: Option<TechnologyVersion>,
}

/// Fingerprint `WordPress` and recover the best version hint from data already
/// captured during the normal browser scan. This function performs no I/O.
pub fn detect(calls: &[ApiCall], meta_tags: &[MetaTag], scripts: &[Value]) -> WordPressFingerprint {
    if let Some(version) = version_from_meta(meta_tags) {
        return WordPressFingerprint {
            detected: true,
            version: Some(TechnologyVersion {
                name: "WordPress".to_owned(),
                version: Some(version),
                detection_method: META_GENERATOR_METHOD.to_owned(),
            }),
        };
    }

    if let Some(version) = version_from_observed_rest(calls) {
        return WordPressFingerprint {
            detected: true,
            version: Some(TechnologyVersion {
                name: "WordPress".to_owned(),
                version: Some(version),
                detection_method: REST_GENERATOR_METHOD.to_owned(),
            }),
        };
    }

    let asset_version = version_from_asset_consensus(calls, scripts);
    let detected = asset_version.is_some()
        || calls.iter().any(|call| has_wordpress_marker(&call.url))
        || scripts
            .iter()
            .filter_map(|script| script.get("src").and_then(Value::as_str))
            .any(has_wordpress_marker)
        || meta_tags.iter().any(|tag| {
            tag.name.eq_ignore_ascii_case("generator")
                && tag.content.to_lowercase().contains("wordpress")
        });

    WordPressFingerprint {
        detected,
        version: asset_version.map(|version| TechnologyVersion {
            name: "WordPress".to_owned(),
            version: Some(version),
            detection_method: ASSET_CONSENSUS_METHOD.to_owned(),
        }),
    }
}

fn has_wordpress_marker(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.contains("/wp-content/")
        || lower.contains("/wp-includes/")
        || lower.contains("/wp-json/")
        || lower.contains("rest_route=/")
}

fn version_from_meta(meta_tags: &[MetaTag]) -> Option<String> {
    meta_tags
        .iter()
        .filter(|tag| tag.name.eq_ignore_ascii_case("generator"))
        .find_map(|tag| version_from_generator(&tag.content))
}

fn version_from_observed_rest(calls: &[ApiCall]) -> Option<String> {
    calls.iter().find_map(|call| {
        let lower = call.url.to_lowercase();
        if !lower.contains("/wp-json/") && !lower.contains("rest_route=/") {
            return None;
        }
        let body = call.response_body.as_deref()?;
        let body = serde_json::from_str::<Value>(body).ok()?;
        body.get("generator")
            .and_then(Value::as_str)
            .and_then(version_from_generator)
    })
}

fn version_from_asset_consensus(calls: &[ApiCall], scripts: &[Value]) -> Option<String> {
    let mut urls = HashSet::new();
    urls.extend(calls.iter().map(|call| call.url.as_str()));
    urls.extend(
        scripts
            .iter()
            .filter_map(|script| script.get("src").and_then(Value::as_str)),
    );

    let mut counts: HashMap<String, usize> = HashMap::new();
    for raw in urls {
        if !has_wordpress_marker(raw) {
            continue;
        }
        let Some(version) = url::Url::parse(raw).ok().and_then(|url| {
            url.query_pairs()
                .find(|(key, _)| key == "ver")
                .and_then(|(_, value)| normalize_version(&value))
        }) else {
            continue;
        };
        *counts.entry(version).or_default() += 1;
    }

    counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .max_by_key(|(_, count)| *count)
        .map(|(version, _)| version)
}

#[allow(clippy::unwrap_used)]
static WORDPRESS_VERSION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bwordpress\s+([0-9]+(?:\.[0-9]+){1,2})\b").unwrap());

fn version_from_generator(value: &str) -> Option<String> {
    if let Ok(url) = url::Url::parse(value) {
        if let Some(version) = url
            .query_pairs()
            .find(|(key, _)| key == "v")
            .and_then(|(_, value)| normalize_version(&value))
        {
            return Some(version);
        }
    }

    let captures = WORDPRESS_VERSION_RE.captures(value)?;
    let matched = captures.get(1)?;
    let suffix = value.get(matched.end()..).unwrap_or_default();
    if suffix.starts_with(['-', '+']) {
        return None;
    }
    normalize_version(matched.as_str())
}

fn normalize_version(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(url: &str, body: Option<&str>) -> ApiCall {
        ApiCall {
            url: url.to_owned(),
            method: "GET".to_owned(),
            status: 200,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            response_content_type: Some("application/json".to_owned()),
            request_body: None,
            response_body: body.map(str::to_owned),
            response_size: body.map_or(0, str::len),
        }
    }

    #[test]
    fn meta_generator_is_authoritative() {
        let meta = vec![MetaTag {
            name: "generator".to_owned(),
            content: "WordPress 7.0.1".to_owned(),
        }];
        let result = detect(&[], &meta, &[]);
        let version = result.version.expect("version");
        assert_eq!(version.version.as_deref(), Some("7.0.1"));
        assert_eq!(version.detection_method, META_GENERATOR_METHOD);
    }

    #[test]
    fn naturally_observed_rest_generator_is_authoritative() {
        let calls = vec![call(
            "https://example.test/wp-json/",
            Some(r#"{"generator":"https://wordpress.org/?v=6.9.4"}"#),
        )];
        let result = detect(&calls, &[], &[]);
        let version = result.version.expect("version");
        assert_eq!(version.version.as_deref(), Some("6.9.4"));
        assert_eq!(version.detection_method, REST_GENERATOR_METHOD);
    }

    #[test]
    fn asset_version_requires_two_consistent_urls() {
        let calls = vec![
            call("https://example.test/wp-includes/js/a.js?ver=6.9.4", None),
            call(
                "https://example.test/wp-content/plugins/x/b.js?ver=6.9.4",
                None,
            ),
        ];
        let result = detect(&calls, &[], &[]);
        assert_eq!(
            result.version.and_then(|v| v.version).as_deref(),
            Some("6.9.4")
        );

        let one = detect(&calls[..1], &[], &[]);
        assert!(one.detected);
        assert!(one.version.is_none());
    }

    #[test]
    fn marker_only_is_inventory() {
        let calls = vec![call(
            "https://example.test/wp-content/themes/site/style.css",
            None,
        )];
        let result = detect(&calls, &[], &[]);
        assert!(result.detected);
        assert!(result.version.is_none());
    }

    #[test]
    fn prerelease_and_malformed_versions_are_rejected() {
        for content in ["WordPress 7.0.1-alpha", "WordPress seven", "WordPress 7"] {
            let meta = vec![MetaTag {
                name: "generator".to_owned(),
                content: content.to_owned(),
            }];
            assert!(detect(&[], &meta, &[]).version.is_none(), "{content}");
        }
    }
}
