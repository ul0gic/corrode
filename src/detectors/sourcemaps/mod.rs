//! Pillar 1 — source-map intelligence: recover routes, versions, and source
//! text from a page's exposed maps. Passive; see [`retrieve`] for the scoping.

// Complete but unwired until Gate 1; remove when `analyze` is called from the binary.
#![allow(dead_code)]

mod intel;
mod parse;
mod retrieve;

use crate::types::{RouteSurface, SourceMapIntel, TechnologyVersion};

#[derive(Debug, Default)]
pub struct SourceMapReport {
    pub intel: Vec<SourceMapIntel>,
    pub routes: Vec<RouteSurface>,
    pub versions: Vec<TechnologyVersion>,
    /// First-party `(path, text)` for the caller to run through the `SecretScanner`.
    pub recovered_sources: Vec<(String, String)>,
    pub fetch_log: Vec<String>,
}

/// `candidates` are `(referrer_url, map_ref)` pairs from the page's
/// `sourceMappingURL` references. A single bad map is logged and skipped.
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
            continue; // already fetched this exact map
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

    // Cross-map version dups aren't adjacent, so filter against a seen-set.
    let mut seen_versions = std::collections::HashSet::new();
    report
        .versions
        .retain(|v| seen_versions.insert((v.name.clone(), v.version.clone())));

    report
}
