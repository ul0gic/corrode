//! Scoped, passive source-map retrieval (tasks 1.2 + 1.11 scope/safety).
//!
//! Strictly passive: we GET only `.map` URLs the page already referenced
//! (via `//# sourceMappingURL=` or a `.map` script src), resolved against the
//! referrer and confined to the target origin. No path guessing, no
//! enumeration, no off-origin follows. Count and size are capped, and every
//! fetch decision is reported so the caller can log it.

use tokio::time::{self, Duration};
use url::Url;

/// Maximum number of distinct maps fetched per scan.
pub const MAX_MAPS: usize = 50;
/// Maximum bytes accepted for a single map (declined if `Content-Length` exceeds).
pub const MAX_MAP_BYTES: u64 = 25 * 1024 * 1024;
/// Per-fetch network timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a candidate map URL was not fetched — surfaced for transparency logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// `data:` URI or other non-http(s) scheme — nothing to fetch over the network.
    NonHttp,
    /// Resolved to an origin other than the target.
    OffOrigin,
    /// Could not be resolved against its referrer.
    Unresolvable,
    /// The per-scan map count cap was reached.
    CountCapped,
    /// `Content-Length` exceeded `MAX_MAP_BYTES`.
    TooLarge,
}

/// Resolve a (possibly relative) `sourceMappingURL` against the URL of the
/// script or document that referenced it. Returns `None` for unparseable
/// results and for non-http(s) schemes such as `data:` inline maps.
pub fn resolve_map_url(referrer: &str, map_ref: &str) -> Option<Url> {
    let base = Url::parse(referrer).ok()?;
    let resolved = base.join(map_ref).ok()?;
    match resolved.scheme() {
        "http" | "https" => Some(resolved),
        _ => None,
    }
}

/// True when `url` belongs to the target origin: an exact host match, a
/// subdomain of the target, or the target being a subdomain of the host.
/// With no known target host we conservatively treat everything as in-scope
/// (matches the existing first-party heuristic in `collectors/javascript.rs`).
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

/// Classify a candidate before any network call. `Ok(url)` means "fetch this";
/// `Err(reason)` means skip and log why.
pub fn classify(
    referrer: &str,
    map_ref: &str,
    target_host: Option<&str>,
    already_fetched: usize,
) -> Result<Url, SkipReason> {
    if already_fetched >= MAX_MAPS {
        return Err(SkipReason::CountCapped);
    }
    // A bare `data:` ref never resolves to http(s); distinguish it for a clearer log.
    if map_ref.trim_start().starts_with("data:") {
        return Err(SkipReason::NonHttp);
    }
    let url = resolve_map_url(referrer, map_ref).ok_or(SkipReason::Unresolvable)?;
    if !is_in_scope(&url, target_host) {
        return Err(SkipReason::OffOrigin);
    }
    Ok(url)
}

/// GET a single in-scope map URL. Declines (returns `Err(TooLarge)`) when the
/// server advertises a `Content-Length` above the cap; returns `Ok(None)` on
/// any network/timeout/body error so a single bad map never aborts the scan.
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
