// Does:  Collects route, package, and embedded-source evidence from referenced maps.
// Holds: Each resolved map URL gets at most one fetch attempt per analysis.

/// Route and package-version inference from recovered paths.
pub mod intel;
/// Decoding of source paths and optional embedded text.
pub mod parse;
/// Reference resolution, scope checks, and HTTP retrieval.
pub mod retrieve;

use crate::types::{RouteSurface, SourceMapIntel, TechnologyVersion};

/// Evidence recovered from the candidate maps of one scan.
#[derive(Debug, Default)]
pub struct SourceMapReport {
    /// Successfully decoded maps and their referring scripts.
    pub intel: Vec<SourceMapIntel>,
    /// Route candidates inferred from file paths.
    pub routes: Vec<RouteSurface>,
    /// Distinct package names and versions found in dependency paths.
    pub versions: Vec<TechnologyVersion>,
    /// First-party `(path, text)` for the caller to run through the `SecretScanner`.
    pub recovered_sources: Vec<(String, String)>,
    /// Retrieval and parsing outcomes in candidate order.
    pub fetch_log: Vec<String>,
}

/// Analyzes observed (referrer, reference) pairs, skipping individual fetch or parse failures.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::analyze;
/// # let candidates = [("https://example.test/app.js".into(), "data:,".into())];
/// let report = futures::executor::block_on(analyze(&candidates, Some("example.test")));
/// # assert!(report.fetch_log[0].contains("NonHttp"));
/// ```
pub async fn analyze(
    candidates: &[(String, String)],
    target_host: Option<&str>,
) -> SourceMapReport {
    let mut report = SourceMapReport::default();
    let mut fetched_urls = std::collections::HashSet::new();

    for (referrer, map_ref) in candidates {
        let url = match retrieve::classify(referrer, map_ref, target_host, fetched_urls.len()) {
            Ok(url) => url,
            Err(reason) => {
                report
                    .fetch_log
                    .push(format!("skip {map_ref} (from {referrer}): {reason:?}"));
                continue;
            }
        };

        let url_str = url.to_string();
        if !fetched_urls.insert(url_str.clone()) {
            continue;
        }

        let body = match retrieve::fetch_map(&url).await {
            Ok(Some(body)) => body,
            Ok(None) => {
                report
                    .fetch_log
                    .push(format!("skip {url_str}: fetch failed"));
                continue;
            }
            Err(reason) => {
                report.fetch_log.push(format!("skip {url_str}: {reason:?}"));
                continue;
            }
        };

        let Ok(parsed) = parse::parse(&body) else {
            report
                .fetch_log
                .push(format!("skip {url_str}: unparseable source map"));
            continue;
        };

        let source_paths = parsed.source_paths();
        report
            .routes
            .extend(intel::extract_routes(&source_paths, &url_str));
        report
            .versions
            .extend(intel::extract_versions(&source_paths));
        for src in parsed.first_party_with_content() {
            if let Some(content) = &src.content {
                report
                    .recovered_sources
                    .push((src.path.clone(), content.clone()));
            }
        }

        report.fetch_log.push(format!(
            "fetched {url_str}: {} sources ({}sourcesContent)",
            source_paths.len(),
            if parsed.has_sources_content() {
                ""
            } else {
                "no "
            }
        ));
        report.intel.push(SourceMapIntel {
            map_url: url_str,
            script_url: referrer.clone(),
            recovered_sources: source_paths,
            has_sources_content: parsed.has_sources_content(),
            confidence: None,
        });
    }

    // Why: Different maps can reference the same package version in any order.
    let mut seen_versions = std::collections::HashSet::new();
    report
        .versions
        .retain(|v| seen_versions.insert((v.name.clone(), v.version.clone())));

    report
}
