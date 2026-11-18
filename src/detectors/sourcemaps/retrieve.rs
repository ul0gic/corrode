// Does:  Resolves source-map references, checks their scope, and retrieves accepted maps.
// Holds: Classification completes without network access and rejects exhausted fetch budgets.

use tokio::time::{self, Duration};
use url::Url;

/// Maximum number of distinct map fetch attempts per analysis.
pub const MAX_MAPS: usize = 50;
/// Largest accepted source-map body in bytes.
pub const MAX_MAP_BYTES: u64 = 25 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Reason a reference was rejected or its body discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Inline data reference rejected before URL resolution.
    NonHttp,
    /// Resolved host outside the permitted host relationship.
    OffOrigin,
    /// Invalid base, unresolved reference, or unsupported URL scheme.
    Unresolvable,
    /// Map-attempt budget already exhausted.
    CountCapped,
    /// Declared length or decoded body exceeds the byte limit.
    TooLarge,
}

/// Resolves a reference against the referring document or script and accepts HTTP and HTTPS.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::retrieve::*;
/// let url = resolve_map_url("https://example.test/js/bundle.js", "bundle.js.map").unwrap();
/// # assert_eq!(url.path(), "/js/bundle.js.map");
/// ```
pub fn resolve_map_url(referrer: &str, map_ref: &str) -> Option<Url> {
    let base = Url::parse(referrer).ok()?;
    let resolved = base.join(map_ref).ok()?;
    match resolved.scheme() {
        "http" | "https" => Some(resolved),
        _ => None,
    }
}

/// Accepts matching hosts, their ancestors or subdomains, and any URL when the target is unknown.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::retrieve::*;
/// # let asset = "https://cdn.example.test/main.js.map".parse().unwrap();
/// assert!(is_in_scope(&asset, Some("example.test")));
/// ```
pub fn is_in_scope(url: &Url, target_host: Option<&str>) -> bool {
    let Some(target) = target_host else {
        return true;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case(target)
        || host
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", target.to_ascii_lowercase()))
        || target
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", host.to_ascii_lowercase()))
}

/// Checks the remaining fetch budget, resolves the reference, and checks its host before retrieval.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::retrieve::*;
/// assert_eq!(classify("https://example.test", "x.map", None, MAX_MAPS), Err(SkipReason::CountCapped));
/// ```
pub fn classify(
    referrer: &str,
    map_ref: &str,
    target_host: Option<&str>,
    already_fetched: usize,
) -> Result<Url, SkipReason> {
    if already_fetched >= MAX_MAPS {
        return Err(SkipReason::CountCapped);
    }
    // Why: Inline data references have a separate skip reason in the fetch log.
    if map_ref.trim_start().starts_with("data:") {
        return Err(SkipReason::NonHttp);
    }
    let url = resolve_map_url(referrer, map_ref).ok_or(SkipReason::Unresolvable)?;
    if !is_in_scope(&url, target_host) {
        return Err(SkipReason::OffOrigin);
    }
    Ok(url)
}

/// Fetches a previously classified URL. Discards oversized bodies and maps transport errors to `Ok(None)`.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::retrieve::*;
/// # let runtime = tokio::runtime::Runtime::new().unwrap();
/// # let unsupported = "data:,".parse().unwrap();
/// assert_eq!(runtime.block_on(fetch_map(&unsupported)), Ok(None));
/// ```
pub async fn fetch_map(url: &Url) -> Result<Option<String>, SkipReason> {
    let Ok(Ok(resp)) = time::timeout(FETCH_TIMEOUT, reqwest::get(url.clone())).await else {
        return Ok(None);
    };
    if let Some(len) = resp.content_length() {
        if len > MAX_MAP_BYTES {
            return Err(SkipReason::TooLarge);
        }
    }
    match resp.text().await {
        Ok(body) if body.len() as u64 <= MAX_MAP_BYTES => Ok(Some(body)),
        Ok(_) => Err(SkipReason::TooLarge),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_map_against_script_url() {
        let url = resolve_map_url(
            "https://app.example.com/_next/static/main.js",
            "main.js.map",
        )
        .expect("resolves");
        assert_eq!(
            url.as_str(),
            "https://app.example.com/_next/static/main.js.map"
        );
    }

    #[test]
    fn resolves_absolute_path_map() {
        let url = resolve_map_url("https://app.example.com/a/b.js", "/static/b.js.map")
            .expect("resolves");
        assert_eq!(url.as_str(), "https://app.example.com/static/b.js.map");
    }

    #[test]
    fn rejects_data_uri_scheme() {
        assert!(
            resolve_map_url("https://x.com/a.js", "data:application/json;base64,e30=").is_none()
        );
    }

    #[test]
    fn scope_allows_same_host_and_subdomains() {
        let t = Some("example.com");
        assert!(is_in_scope(
            &Url::parse("https://example.com/x.map").unwrap(),
            t
        ));
        assert!(is_in_scope(
            &Url::parse("https://cdn.example.com/x.map").unwrap(),
            t
        ));
    }

    #[test]
    fn scope_rejects_foreign_origin() {
        let t = Some("example.com");
        assert!(!is_in_scope(
            &Url::parse("https://evil.com/x.map").unwrap(),
            t
        ));
        assert!(!is_in_scope(
            &Url::parse("https://example.com.evil.com/x.map").unwrap(),
            t
        ));
    }

    #[test]
    fn scope_open_when_no_target_host() {
        assert!(is_in_scope(
            &Url::parse("https://anything.com/x.map").unwrap(),
            None
        ));
    }

    #[test]
    fn classify_blocks_off_origin() {
        let r = classify(
            "https://app.example.com/main.js",
            "https://evil.com/main.js.map",
            Some("example.com"),
            0,
        );
        assert_eq!(r, Err(SkipReason::OffOrigin));
    }

    #[test]
    fn classify_blocks_data_uri() {
        let r = classify(
            "https://app.example.com/main.js",
            "data:application/json;base64,e30=",
            Some("example.com"),
            0,
        );
        assert_eq!(r, Err(SkipReason::NonHttp));
    }

    #[test]
    fn classify_enforces_count_cap() {
        let r = classify(
            "https://app.example.com/main.js",
            "main.js.map",
            Some("example.com"),
            MAX_MAPS,
        );
        assert_eq!(r, Err(SkipReason::CountCapped));
    }

    #[test]
    fn classify_accepts_in_scope_relative() {
        let r = classify(
            "https://app.example.com/static/main.js",
            "main.js.map",
            Some("example.com"),
            0,
        )
        .expect("accepted");
        assert_eq!(r.as_str(), "https://app.example.com/static/main.js.map");
    }
}
