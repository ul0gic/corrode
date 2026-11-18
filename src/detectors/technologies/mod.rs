// Does:  Combines technology fingerprints from browser and captured evidence.
// Holds: Technology names are deduplicated before the fingerprint is returned.

/// Response-header signatures.
pub mod headers;
/// HTML meta signatures.
pub mod meta;
/// React Server Component inventory signals.
pub mod rsc;
/// Browser runtime signatures.
pub mod runtime;
/// Script and network URL signatures.
pub mod scripts;
/// `WordPress` fingerprints.
pub mod wordpress;

use chromiumoxide::Page;
use serde_json::Value;

use crate::types::{ApiCall, MetaTag, TechnologyVersion};

/// Technologies and versions detected during a scan.
pub struct TechFingerprint {
    /// Deduplicated detected technology names.
    pub technologies: Vec<String>,
    /// Detected technology versions.
    pub versions: Vec<TechnologyVersion>,
}

/// Combines technology detection results from captured data and browser runtime.
///
/// ```no_run
/// # use corrode_scanner::detectors::technologies::detect_all;
/// # async fn run(page: &chromiumoxide::Page) {
/// let fingerprint = detect_all(page, &[], &[], &[]).await;
/// # }
/// ```
pub async fn detect_all(
    page: &Page,
    calls: &[ApiCall],
    meta_tags: &[MetaTag],
    scripts: &[Value],
) -> TechFingerprint {
    let mut technologies = Vec::new();

    technologies.extend(runtime::detect(page).await);

    technologies.extend(headers::detect(calls));

    technologies.extend(meta::detect(meta_tags));

    technologies.extend(scripts::detect(scripts, calls));

    technologies.sort();
    technologies.dedup();

    let mut versions = runtime::extract_versions(page, scripts).await;

    let document = page
        .url()
        .await
        .ok()
        .flatten()
        .and_then(|s| url::Url::parse(&s).ok());
    let wordpress = wordpress::detect_for_page(calls, meta_tags, scripts, document.as_ref());
    if wordpress.detected && !technologies.iter().any(|tech| tech == "WordPress") {
        technologies.push("WordPress".to_owned());
        technologies.sort();
    }
    if let Some(version) = wordpress.version {
        versions.push(version);
    }

    TechFingerprint {
        technologies,
        versions,
    }
}
