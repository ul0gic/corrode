//! Pillar 1 — Source-map intelligence.
//!
//! Recovers attack-surface intelligence from exposed `JavaScript` source maps:
//! original filenames, embedded source text (for secret/comment scanning by the
//! caller), internal routes, and package versions. Strictly passive — GET-only
//! fetches of `.map` assets already referenced by the page, scoped to the
//! target origin (see [`retrieve`]).
//!
//! The orchestrator wiring (feeding the page's detected map refs in, and
//! running [`SourceMapReport::recovered_sources`] through the `SecretScanner`)
//! is added in `scanner/workflow.rs` at Gate 1. See `.project/enhance-plan.md`.

// Phase 1 builds this module ahead of its Gate-1 wiring into `workflow.rs`; the
// public entry points are exercised by unit tests but not yet called from the
// binary. The allow is removed when the gate wires `analyze` into the scan flow.
#![allow(dead_code)]

mod intel;
mod parse;
mod retrieve;

use crate::types::{RouteSurface, SourceMapIntel, TechnologyVersion};

/// Everything one scan recovered from source maps. The caller owns secret
/// scanning: it runs [`Self::recovered_sources`] through the `SecretScanner`,
/// tagging findings as `EvidenceSource::SourceMap` (task 1.4).
#[derive(Debug, Default)]
pub struct SourceMapReport {
    pub intel: Vec<SourceMapIntel>,
    pub routes: Vec<RouteSurface>,
    pub versions: Vec<TechnologyVersion>,
    /// `(source_path, source_text)` for every recovered first-party source that
    /// carried `sourcesContent`. Fed to the secret/comment scanners by the caller.
    pub recovered_sources: Vec<(String, String)>,
    /// Human-readable trail of fetch decisions (fetched / skipped + why), so the
    /// scan can log exactly which `.map` assets were touched (task 1.11).
    pub fetch_log: Vec<String>,
}

/// Retrieve and analyse the source maps referenced by a page.
///
/// `candidates` is a list of `(referrer_url, map_ref)` pairs — the referrer is
/// the script or document URL that carried the `sourceMappingURL`, and `map_ref`
/// is the (possibly relative) value of that reference. Resolution, origin
/// scoping, and count/size caps are enforced in [`retrieve`]; a single bad map
/// is logged and skipped, never fatal.
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

    // Collapse duplicate version findings recovered across multiple maps
    // (dups won't be adjacent, so filter against a seen-set rather than dedup).
    let mut seen_versions = std::collections::HashSet::new();
    report
        .versions
        .retain(|v| seen_versions.insert((v.name.clone(), v.version.clone())));

    report
}
