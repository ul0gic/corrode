use anyhow::Result;
use chromiumoxide::Page;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::time::{self, Duration};
use url::Url;

use crate::api::discovery::extract_api_endpoints;
use super::ast;
use crate::detectors::{secrets::SecretScanner, vulnerabilities};
use crate::scanner::page_utils;
use crate::types::{AstFinding, DiscoveredEndpoint, Vulnerability};

pub struct ScriptArtifacts {
    pub script_count: usize,
    pub scripts_array: Vec<Value>,
    pub source_maps: Vec<String>,
    pub window_objects: HashMap<String, String>,
    pub debug_flags: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub ast_findings: Vec<AstFinding>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[allow(clippy::too_many_lines)]
pub async fn collect(
    page: &Page,
    scanner: &SecretScanner,
    target_host: Option<&str>,
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
    let mut api_endpoints = Vec::new();
    let mut ast_findings = Vec::new();
    let mut vulnerabilities = Vec::new();

    for (idx, script) in scripts_array.iter().enumerate() {
        if let Some(content) = script.get("content").and_then(|v| v.as_str()) {
            scanner.scan_text(content, "Inline Script").await;
            scanner.extract_comments(content, "Inline Script").await;
            api_endpoints.extend(extract_api_endpoints(
                content,
                &format!("inline-script-{idx}"),
            ));
            if should_analyze_ast(None, target_host) {
                ast_findings.extend(ast::analyze_script(
                    content,
                    &format!("inline-script-{idx}"),
                ));
            }
            vulnerabilities.extend(vulnerabilities::react::detect_rsc_vulns(
                content,
                &format!("inline-script-{idx}"),
            ));
            source_maps.extend(detect_source_map_urls(content));
        }

        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                let src_lower = src.to_ascii_lowercase();
                #[allow(clippy::case_sensitive_file_extension_comparisons)]
                if src_lower.ends_with(".map") || src_lower.contains(".js.map") {
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
                        vulnerabilities
                            .extend(vulnerabilities::react::detect_rsc_vulns(&text, src));
                        source_maps.extend(detect_source_map_urls(&text));
                    }
                }
            }
        }
    }

    let window_objects = page_utils::extract_json::<HashMap<String, String>>(
        page,
        r"
        (() => {
            const results = {};
            const keys = [
                '__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', 'env', 'ENV',
                '__APOLLO_STATE__', '__APOLLO_CLIENT__', 'APOLLO_STATE',
                '__remixContext', '__NUXT_DATA__',
                '__pinia', '__sveltekit_data', '_$HY',
                '__RELAY_STORE__', '__REACT_QUERY_STATE__',
                '__REDWOOD__API_PROXY_PATH', '__PAYLOAD_CONFIG__'
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
        window_objects,
        debug_flags: debug_mode,
        api_endpoints,
        ast_findings,
        vulnerabilities,
    })
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
