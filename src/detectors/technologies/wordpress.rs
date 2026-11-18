// Does:  Identifies WordPress and selects a captured version hint.
// Holds: Version selection prefers generator evidence over asset consensus.

use std::collections::{HashMap, HashSet};
use url::Url;

use serde_json::Value;

use crate::types::{ApiCall, MetaTag, TechnologyVersion};

/// Version derived from a generator meta tag.
pub const META_GENERATOR_METHOD: &str = "wordpress_generator_meta";
/// Version derived from an observed REST generator.
pub const REST_GENERATOR_METHOD: &str = "wordpress_observed_rest_generator";
/// Version derived from asset version consensus.
pub const ASSET_CONSENSUS_METHOD: &str = "wordpress_asset_version_consensus";

/// `WordPress` detection and selected version evidence.
#[derive(Debug, Default)]
pub struct WordPressFingerprint {
    /// Whether `WordPress` evidence was observed.
    pub detected: bool,
    /// Selected version hint, when available.
    pub version: Option<TechnologyVersion>,
}

/// Identifies `WordPress` from generator tags and asset URLs when no document origin is available.
///
///     assert!(!corrode_scanner::detectors::technologies::wordpress::detect(&[], &[], &[]).detected);
pub fn detect(calls: &[ApiCall], meta_tags: &[MetaTag], scripts: &[Value]) -> WordPressFingerprint {
    detect_for_page(calls, meta_tags, scripts, None)
}

/// Identifies `WordPress` using generator evidence scoped to the supplied document URL.
/// ```
/// # use corrode_scanner::detectors::technologies::wordpress::detect_for_page;
/// # let doc = url::Url::parse("https://example.test/").unwrap();
/// assert!(!detect_for_page(&[], &[], &[], Some(&doc)).detected);
/// ```
pub fn detect_for_page(
    calls: &[ApiCall],
    meta_tags: &[MetaTag],
    scripts: &[Value],
    document: Option<&Url>,
) -> WordPressFingerprint {
    let mut versions = meta_tags
        .iter()
        .filter(|tag| tag.name.eq_ignore_ascii_case("generator"))
        .filter_map(|tag| version_from_generator(&tag.content))
        .map(|v| (v, META_GENERATOR_METHOD))
        .chain(
            calls
                .iter()
                .filter_map(|call| rest_version(call, document?))
                .map(|v| (v, REST_GENERATOR_METHOD)),
        );
    if let Some((version, method)) = versions.next() {
        // Why: Conflicting release identifiers cannot establish which version serves this page.
        let consistent = versions.all(|(other, _)| other == version);
        return WordPressFingerprint {
            detected: true,
            version: consistent.then(|| TechnologyVersion {
                name: "WordPress".to_owned(),
                version: Some(version),
                detection_method: method.to_owned(),
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

fn rest_version(call: &ApiCall, document: &Url) -> Option<String> {
    let url = Url::parse(&call.url).ok()?;
    if url.origin() != document.origin() || call.status != 200 {
        return None;
    }
    let path = url.path().trim_end_matches('/');
    let installation = if let Some(base) = path.strip_suffix("/wp-json") {
        base
    } else if url
        .query_pairs()
        .any(|(key, value)| key == "rest_route" && value == "/")
    {
        path.strip_suffix("/index.php").unwrap_or(path)
    } else {
        return None;
    };
    // Why: Sibling sites on one origin can run different WordPress installations.
    if !document
        .path()
        .strip_prefix(installation)
        .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
    {
        return None;
    }
    let body = serde_json::from_str::<Value>(call.response_body.as_deref()?).ok()?;
    version_from_generator(body.get("generator")?.as_str()?)
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

fn version_from_generator(value: &str) -> Option<String> {
    if let Some((product, version)) = value.trim().split_once(' ') {
        return product
            .eq_ignore_ascii_case("WordPress")
            .then(|| normalize_version(version))
            .flatten();
    }
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || url.host_str() != Some("wordpress.org")
        || url.path() != "/"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let mut params = url.query_pairs();
    let (key, version) = params.next()?;
    if key != "v" || params.next().is_some() {
        return None;
    }
    normalize_version(&version)
}

fn normalize_version(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let parts: Vec<&str> = trimmed.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.chars().all(|c| c.is_ascii_digit())
        })
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
        let document = Url::parse("https://example.test/").unwrap();
        let result = detect_for_page(&calls, &[], &[], Some(&document));
        let version = result.version.expect("version");
        let other = Url::parse("https://unrelated.test/").unwrap();
        assert!(detect_for_page(&calls, &[], &[], Some(&other))
            .version
            .is_none());
        assert_eq!(version.version.as_deref(), Some("6.9.4"));
        assert_eq!(version.detection_method, REST_GENERATOR_METHOD);
    }

    #[test]
    fn a_sibling_installation_cannot_supply_the_page_version() {
        let api = [call(
            "https://example.test/shop/wp-json/",
            Some(r#"{"generator":"WordPress 6.9.4"}"#),
        )];
        for path in ["https://example.test/", "https://example.test/shopping/"] {
            let page = Url::parse(path).unwrap();
            assert!(detect_for_page(&api, &[], &[], Some(&page))
                .version
                .is_none());
        }
        let page = Url::parse("https://example.test/shop/cart").unwrap();
        assert!(detect_for_page(&api, &[], &[], Some(&page))
            .version
            .is_some());
    }

    #[test]
    fn conflicting_generator_versions_cannot_raise_an_advisory() {
        let page = Url::parse("https://example.test/").unwrap();
        let calls = [call(
            "https://example.test/wp-json/",
            Some(r#"{"generator":"https://wordpress.org/?v=6.9.4"}"#),
        )];
        let tags = [MetaTag {
            name: "generator".to_owned(),
            content: "WordPress 6.9.5".to_owned(),
        }];
        let fingerprint = detect_for_page(&calls, &tags, &[], Some(&page));
        assert!(fingerprint.detected);
        assert!(fingerprint.version.is_none());
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
        for content in [
            "WordPress 7.0.1-alpha",
            "WordPress seven",
            "WordPress 7",
            "https://other.test/?v=7.0.1",
            "WordPress 7.0.1.9",
        ] {
            let meta = vec![MetaTag {
                name: "generator".to_owned(),
                content: content.to_owned(),
            }];
            assert!(detect(&[], &meta, &[]).version.is_none(), "{content}");
        }
    }
}
