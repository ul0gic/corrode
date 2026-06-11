use anyhow::Result;
use chromiumoxide::Page;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::time::{self, Duration};
use url::Url;

use super::ast;
use crate::api::discovery::extract_api_endpoints;
use crate::detectors::secrets::SecretScanner;
use crate::scanner::page_utils;
use crate::types::{AstFinding, DiscoveredEndpoint};

pub struct ScriptArtifacts {
    pub script_count: usize,
    pub scripts_array: Vec<Value>,
    pub source_maps: Vec<String>,
    /// `(referrer, map_ref)` pairs — referrer is the base relative map URLs resolve against.
    pub source_map_candidates: Vec<(String, String)>,
    /// `(text, source)` script bodies retained so the RSC detector grades the corpus without re-fetching.
    pub script_bodies: Vec<(String, String)>,
    pub chunk_names: Vec<String>,
    /// Astro has no `window` global, so islands are the only client-side signal of its route surface.
    pub astro_islands: Vec<String>,
    pub window_objects: HashMap<String, String>,
    pub debug_flags: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub ast_findings: Vec<AstFinding>,
}

#[allow(clippy::too_many_lines)]
pub async fn collect(
    page: &Page,
    scanner: &SecretScanner,
    target_host: Option<&str>,
    page_url: &str,
) -> Result<ScriptArtifacts> {
    let scripts = match page
        .evaluate("Array.from(document.scripts).map(s => ({ src: s.src, inline: !s.src, content: s.src ? null : s.textContent.substring(0, 5000) }))")
        .await
    {
        Ok(result) => result.into_value().unwrap_or_else(|_| serde_json::json!([])),
        Err(_) => serde_json::json!([]),
    };

    let scripts_array: Vec<Value> = serde_json::from_value(scripts).unwrap_or_default();
    let mut source_maps = Vec::new();
    let mut source_map_candidates = Vec::new();
    let mut api_endpoints = Vec::new();
    let mut ast_findings = Vec::new();
    let mut script_bodies: Vec<(String, String)> = Vec::new();

    for (idx, script) in scripts_array.iter().enumerate() {
        if let Some(content) = script.get("content").and_then(|v| v.as_str()) {
            let label = format!("inline-script-{idx}");
            scanner.scan_text(content, "Inline Script").await;
            scanner.extract_comments(content, "Inline Script").await;
            api_endpoints.extend(extract_api_endpoints(content, &label));
            if should_analyze_ast(None, target_host) {
                ast_findings.extend(ast::analyze_script(content, &label));
            }
            // Retain only; per-script RSC grading would double-emit findings `rsc::detect` already covers.
            script_bodies.push((content.to_owned(), label));
            // Maps referenced by an inline script resolve against the page URL.
            for map_ref in detect_source_map_urls(content) {
                source_map_candidates.push((page_url.to_owned(), map_ref.clone()));
                source_maps.push(map_ref);
            }
        }

        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                let src_lower = src.to_ascii_lowercase();
                #[allow(clippy::case_sensitive_file_extension_comparisons)]
                if src_lower.ends_with(".map") || src_lower.contains(".js.map") {
                    // A `.map` script src is itself the map; resolve against the page URL.
                    source_map_candidates.push((page_url.to_owned(), src.to_owned()));
                    source_maps.push(src.to_owned());
                }

                let mut fetched = None;

                // Only fetch http/https scripts — never file:// (SEC-005)
                if src.starts_with("http://") || src.starts_with("https://") {
                    if let Ok(Ok(resp)) =
                        time::timeout(Duration::from_secs(10), reqwest::get(src)).await
                    {
                        if let Ok(text) = resp.text().await {
                            fetched = Some(text);
                        }
                    }
                }

                if let Some(text) = fetched {
                    let first_party = is_first_party_url(src, target_host);
                    if first_party {
                        scanner.scan_text(&text, &format!("Script: {src}")).await;
                        scanner
                            .extract_comments(&text, &format!("Script: {src}"))
                            .await;
                        api_endpoints.extend(extract_api_endpoints(
                            &text,
                            &format!("external-script-{idx}"),
                        ));
                        if should_analyze_ast(Some(src), target_host) {
                            ast_findings.extend(ast::analyze_script(&text, src));
                        }
                        // Maps referenced inside an external script resolve against that script.
                        for map_ref in detect_source_map_urls(&text) {
                            source_map_candidates.push((src.to_owned(), map_ref.clone()));
                            source_maps.push(map_ref);
                        }
                        script_bodies.push((text, src.to_owned()));
                    }
                }
            }
        }
    }

    let chunk_names = collect_chunk_names(page, &scripts_array).await;
    let astro_islands = collect_astro_islands(page).await;

    let window_objects = page_utils::extract_json::<HashMap<String, String>>(
        page,
        r"
        (() => {
            const results = {};
            // Manifest/Flight globals exceed the 10k default; downstream parsers degrade on truncation.
            const LARGE = 200000;
            const keys = [
                '__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', 'env', 'ENV',
                '__APOLLO_STATE__', '__APOLLO_CLIENT__', 'APOLLO_STATE',
                '__remixContext', '__NUXT_DATA__',
                '__pinia', '__sveltekit_data', '_$HY',
                '__RELAY_STORE__', '__REACT_QUERY_STATE__',
                '__REDWOOD__API_PROXY_PATH', '__PAYLOAD_CONFIG__'
            ];
            const largeKeys = [
                '__BUILD_MANIFEST', '__SSG_MANIFEST', '__next_f', '__remixManifest'
            ];
            keys.forEach(key => {
                if (window[key]) {
                    try {
                        results[key] = JSON.stringify(window[key]).substring(0, 10000);
                    } catch (e) {
                        results[key] = '[object Object]';
                    }
                }
            });
            largeKeys.forEach(key => {
                const val = window[key];
                if (!val) return;
                try {
                    // __SSG_MANIFEST is a Set; JSON.stringify yields {} for Sets,
                    // so spread it into an array first.
                    const norm = (val instanceof Set) ? Array.from(val) : val;
                    results[key] = JSON.stringify(norm).substring(0, LARGE);
                } catch (e) {
                    results[key] = '[object Object]';
                }
            });
            return results;
        })()
    ",
    )
    .await;

    // Scan window object values through the secret scanner
    for (key, value) in &window_objects {
        scanner
            .scan_text(value, &format!("Window Object: {key}"))
            .await;
    }

    let debug_mode = page_utils::extract_json::<Vec<String>>(page, r"
        (() => {
            const flags = [];
            if (window.__DEBUG__) flags.push('window.__DEBUG__');
            if (window.DEBUG) flags.push('window.DEBUG');
            if (window.__DEV__) flags.push('window.__DEV__');
            if (window.__NEXT_DATA__ && window.__NEXT_DATA__.buildId === 'development') flags.push('Next.js dev buildId');
            try {
                if (typeof __DEV__ !== 'undefined' && __DEV__ === true) flags.push('__DEV__=true');
            } catch(e) {}
            if (document.getElementById('react-error-overlay')) flags.push('react-error-overlay');
            try {
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers) {
                    for (const [, renderer] of window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers) {
                        if (renderer.bundleType === 1) flags.push('react_dev_bundle');
                    }
                }
            } catch(e) {}
            try {
                if (window.Vue && window.Vue.config && window.Vue.config.devtools) flags.push('vue_devtools_enabled');
                if (window.__VUE_PROD_DEVTOOLS__) flags.push('vue_prod_devtools');
            } catch(e) {}
            try {
                if (window.ng && typeof window.ng.probe === 'function') flags.push('angular_debug_mode');
                if (document.querySelector('[ng-version]')) flags.push('angular_ng_version_attr');
            } catch(e) {}
            return flags;
        })()
    ").await;

    Ok(ScriptArtifacts {
        script_count: scripts_array.len(),
        scripts_array,
        source_maps,
        source_map_candidates,
        script_bodies,
        chunk_names,
        astro_islands,
        window_objects,
        debug_flags: debug_mode,
        api_endpoints,
        ast_findings,
    })
}

/// Combines `<script src>` URLs with `<link rel="modulepreload">` hrefs; returns raw URLs, not stems.
async fn collect_chunk_names(page: &Page, scripts_array: &[Value]) -> Vec<String> {
    let mut chunks: Vec<String> = scripts_array
        .iter()
        .filter_map(|s| s.get("src").and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    let preloads = page_utils::extract_json::<Vec<String>>(
        page,
        r#"
        Array.from(document.querySelectorAll('link[rel="modulepreload"], link[rel="preload"][as="script"]'))
            .map(l => l.href)
            .filter(Boolean)
    "#,
    )
    .await;
    chunks.extend(preloads);
    chunks
}

/// Astro exposes no `window` route global, so `<astro-island>` attributes are the only client signal.
async fn collect_astro_islands(page: &Page) -> Vec<String> {
    page_utils::extract_json::<Vec<String>>(
        page,
        r"
        Array.from(document.querySelectorAll('astro-island')).map(el => {
            const attrs = {};
            for (const a of el.attributes) { attrs[a.name] = a.value; }
            return JSON.stringify(attrs);
        })
    ",
    )
    .await
}

fn should_analyze_ast(origin: Option<&str>, target_host: Option<&str>) -> bool {
    let Some(target) = target_host else {
        return true;
    };

    if let Some(orig) = origin {
        if let Ok(url) = Url::parse(orig) {
            if let Some(host) = url.host_str() {
                return host.eq_ignore_ascii_case(target);
            }
        }
    }

    true
}

fn is_first_party_url(url: &str, target_host: Option<&str>) -> bool {
    let Some(target) = target_host else {
        return true;
    };

    if let Ok(parsed) = Url::parse(url) {
        if let Some(host) = parsed.host_str() {
            return host.eq_ignore_ascii_case(target)
                || host.ends_with(&format!(".{target}"))
                || target.ends_with(&format!(".{host}"));
        }
    }

    true
}

/// Detect `sourceMappingURL` comments in script content.
#[allow(clippy::unwrap_used)]
static SOURCE_MAP_URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*(\S+\.map)\b").unwrap()
});

fn detect_source_map_urls(content: &str) -> Vec<String> {
    SOURCE_MAP_URL_RE
        .captures_iter(content)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_line_and_block_source_mapping_urls() {
        let line = "console.log(1);\n//# sourceMappingURL=app.js.map";
        assert_eq!(detect_source_map_urls(line), vec!["app.js.map".to_owned()]);

        let block = "code;/*# sourceMappingURL=vendor.js.map */";
        assert_eq!(
            detect_source_map_urls(block),
            vec!["vendor.js.map".to_owned()]
        );
    }

    #[test]
    fn ignores_scripts_with_no_map_reference() {
        assert!(detect_source_map_urls("const x = 1; // just a comment").is_empty());
    }

    // Asserts the referrer-assignment contract `collect` uses: inline maps resolve against
    // the page URL, external maps against the script `src`.
    #[test]
    fn referrer_assignment_matches_collect_contract() {
        let page_url = "https://example.com/app";
        let inline = "//# sourceMappingURL=inline.js.map";
        let inline_candidates: Vec<(String, String)> = detect_source_map_urls(inline)
            .into_iter()
            .map(|m| (page_url.to_owned(), m))
            .collect();
        assert_eq!(
            inline_candidates,
            vec![(page_url.to_owned(), "inline.js.map".to_owned())]
        );

        let script_src = "https://cdn.example.com/static/main.js";
        let external = "//# sourceMappingURL=main.js.map";
        let external_candidates: Vec<(String, String)> = detect_source_map_urls(external)
            .into_iter()
            .map(|m| (script_src.to_owned(), m))
            .collect();
        assert_eq!(
            external_candidates,
            vec![(script_src.to_owned(), "main.js.map".to_owned())]
        );
    }
}
