pub mod headers;
pub mod meta;
pub mod runtime;
pub mod scripts;

use chromiumoxide::Page;
use serde_json::Value;

use crate::types::{ApiCall, MetaTag, TechnologyVersion};

/// All technology detection results from a single scan.
pub struct TechFingerprint {
    pub technologies: Vec<String>,
    pub versions: Vec<TechnologyVersion>,
}

/// Run all technology detection methods and return deduplicated results.
pub async fn detect_all(
    page: &Page,
    calls: &[ApiCall],
    meta_tags: &[MetaTag],
    scripts: &[Value],
) -> TechFingerprint {
    let mut technologies = Vec::new();

    // Runtime window object detection (requires live page)
    technologies.extend(runtime::detect(page).await);

    // HTTP response header detection
    technologies.extend(headers::detect(calls));

    // HTML meta tag detection
    technologies.extend(meta::detect(meta_tags));

    // Script URL/bundle pattern detection
    technologies.extend(scripts::detect(scripts));

    // Deduplicate
    technologies.sort();
    technologies.dedup();

    // Version extraction (React, Next.js)
    let versions = runtime::extract_versions(page, scripts).await;

    TechFingerprint {
        technologies,
        versions,
    }
}
