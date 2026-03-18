use anyhow::Result;
use chromiumoxide::Page;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::sync::LazyLock;
use tokio::time::{self, Duration};
use url::Url;

use crate::api::discovery::extract_api_endpoints;
use crate::detectors::{ast, secrets::SecretScanner};
use crate::scanner::page_utils;
use crate::types::{AstFinding, DiscoveredEndpoint, TechnologyVersion, Vulnerability};

pub struct ScriptArtifacts {
    pub script_count: usize,
    pub source_maps: Vec<String>,
    pub window_objects: HashMap<String, String>,
    pub debug_flags: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub technologies: Vec<String>,
    pub technology_versions: Vec<TechnologyVersion>,
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
            vulnerabilities.extend(detect_rsc_vuln(content, &format!("inline-script-{idx}")));

            // Check inline script content for source map references
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

                if let Ok(url) = Url::parse(src) {
                    if url.scheme() == "file" {
                        if let Ok(path) = url.to_file_path() {
                            if let Ok(text) = fs::read_to_string(&path) {
                                fetched = Some(text);
                            }
                        }
                    }
                }

                if fetched.is_none() {
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
                        vulnerabilities.extend(detect_rsc_vuln(&text, src));

                        // Check fetched script content for source map references
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

    // Scan window object values through the secret scanner (critical gap fix).
    // Values like __NEXT_DATA__, __NUXT__, etc. may contain embedded secrets.
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

    let technologies = page_utils::extract_json::<Vec<String>>(
        page,
        r"
        (() => {
            const detected = [];
            const checks = [
                { name: 'React', test: () => !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__ },
                { name: 'Vue.js', test: () => !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__ },
                { name: 'Angular', test: () => !!window.ng },
                { name: 'Next.js', test: () => !!window.__NEXT_DATA__ },
                { name: 'Nuxt.js', test: () => !!window.__NUXT__ },
                { name: 'Firebase', test: () => !!window.firebase },
                { name: 'Stripe', test: () => !!window.Stripe },
                { name: 'Supabase', test: () => !!window.__supabase },
                { name: 'Auth0', test: () => !!window.auth0 },
                { name: 'AWS Amplify', test: () => !!window.Amplify },
                { name: 'GTM', test: () => !!window.dataLayer },
                { name: 'Segment', test: () => !!window.analytics },
                { name: 'Intercom', test: () => !!window.Intercom },
                { name: 'Hotjar', test: () => !!window.hj },
            ];
            checks.forEach(check => {
                try {
                    if (check.test()) detected.push(check.name);
                } catch (e) {}
            });
            return detected;
        })()
    ",
    )
    .await;

    // Extract technology versions (React, Next.js enrichment)
    let technology_versions = extract_technology_versions(page, &scripts_array).await;

    Ok(ScriptArtifacts {
        script_count: scripts_array.len(),
        source_maps,
        window_objects,
        debug_flags: debug_mode,
        api_endpoints,
        technologies,
        technology_versions,
        ast_findings,
        vulnerabilities,
    })
}

/// Extract React version using multiple detection methods.
/// Method 1: `DevTools` hook renderers (most reliable, works in production).
/// Method 2: window.React.version (CDN/UMD builds only).
async fn extract_react_version(page: &Page) -> Option<TechnologyVersion> {
    let version_result: Option<String> = page_utils::extract_json(
        page,
        r"
        (() => {
            try {
                if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__ && window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers) {
                    const renderers = window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers;
                    if (renderers.size > 0) {
                        const first = renderers.values().next().value;
                        if (first && first.version) return first.version;
                    }
                }
                if (window.React && window.React.version) return window.React.version;
                return null;
            } catch(e) { return null; }
        })()
        ",
    )
    .await;

    version_result.map(|version| TechnologyVersion {
        name: "React".to_owned(),
        version: Some(version),
        detection_method: "runtime_devtools_hook".to_owned(),
    })
}

/// Extract Next.js metadata: router type, buildId, runtimeConfig.
async fn extract_nextjs_metadata(page: &Page) -> Option<TechnologyVersion> {
    let next_data: Option<HashMap<String, Value>> = page_utils::extract_json(
        page,
        r"
        (() => {
            if (!window.__NEXT_DATA__) return null;
            const nd = window.__NEXT_DATA__;
            return {
                buildId: nd.buildId || null,
                page: nd.page || null,
                nextExport: nd.nextExport || false,
                hasRuntimeConfig: !!(nd.runtimeConfig && Object.keys(nd.runtimeConfig).length > 0)
            };
        })()
        ",
    )
    .await;

    next_data.map(|data| {
        let build_id = data
            .get("buildId")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let is_dev = build_id == "development";
        let method = if is_dev {
            "nextdata_dev_build"
        } else {
            "nextdata_script"
        };

        TechnologyVersion {
            name: "Next.js (Pages Router)".to_owned(),
            version: None,
            detection_method: method.to_owned(),
        }
    })
}

/// Detect Next.js App Router vs Pages Router from script URLs.
fn detect_nextjs_router(scripts: &[Value]) -> Option<TechnologyVersion> {
    let mut has_app_router = false;
    let mut has_pages_router = false;

    for script in scripts {
        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if src.contains("/_next/static/chunks/app/") {
                has_app_router = true;
            }
            if src.contains("/_next/static/chunks/pages/") {
                has_pages_router = true;
            }
        }
    }

    if has_app_router {
        Some(TechnologyVersion {
            name: "Next.js (App Router)".to_owned(),
            version: None,
            detection_method: "script_url_pattern".to_owned(),
        })
    } else if has_pages_router {
        Some(TechnologyVersion {
            name: "Next.js (Pages Router)".to_owned(),
            version: None,
            detection_method: "script_url_pattern".to_owned(),
        })
    } else {
        None
    }
}

/// Extract React version from CDN URLs in script sources.
fn extract_react_version_from_cdn(scripts: &[Value]) -> Option<TechnologyVersion> {
    #[allow(clippy::unwrap_used)]
    static CDN_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)/(?:npm/)?react(?:-dom)?@(\d+\.\d+\.\d+)",
        )
        .unwrap()
    });

    for script in scripts {
        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if let Some(caps) = CDN_VERSION_RE.captures(src) {
                if let Some(version) = caps.get(1) {
                    return Some(TechnologyVersion {
                        name: "React".to_owned(),
                        version: Some(version.as_str().to_owned()),
                        detection_method: "cdn_url_version".to_owned(),
                    });
                }
            }
        }
    }
    None
}

/// Collect all technology versions from multiple detection methods.
async fn extract_technology_versions(page: &Page, scripts: &[Value]) -> Vec<TechnologyVersion> {
    let mut versions = Vec::new();

    // React version extraction
    if let Some(react_ver) = extract_react_version(page).await {
        versions.push(react_ver);
    } else if let Some(cdn_ver) = extract_react_version_from_cdn(scripts) {
        versions.push(cdn_ver);
    }

    // Next.js metadata extraction
    if let Some(next_meta) = extract_nextjs_metadata(page).await {
        versions.push(next_meta);
    }

    // Next.js router type detection from script URLs
    if let Some(router_info) = detect_nextjs_router(scripts) {
        versions.push(router_info);
    }

    versions
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

// Widened separator from {0,6} to {0,15} for minified bundle compatibility
#[allow(clippy::unwrap_used)]
static RSC_VULN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(react-server-dom-(?:webpack|parcel|turbopack))[^0-9]{0,15}(19\.0(?:\.0)?|19\.1\.0|19\.1\.1|19\.2\.0)",
    )
    .unwrap()
});

// CVE-2025-55183 (Source Code Exposure) + CVE-2025-55184/CVE-2025-67779 (DoS)
// Affected: 19.0.0-19.2.2
#[allow(clippy::unwrap_used)]
static RSC_SOURCE_EXPOSURE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"react-server-dom-(?:webpack|parcel|turbopack)[^0-9]{0,15}(19\.(?:0\.[0-2]|1\.[0-3]|2\.[0-2]))\b",
    )
    .unwrap()
});

// CVE-2026-23864 (DoS — latest, January 2026)
// Affected: 19.0.0-19.2.3
#[allow(clippy::unwrap_used)]
static RSC_DOS_2026_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"react-server-dom-(?:webpack|parcel|turbopack)[^0-9]{0,15}(19\.(?:0\.[0-3]|1\.[0-4]|2\.[0-3]))\b",
    )
    .unwrap()
});

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

fn detect_rsc_vuln(text: &str, source: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();

    // CVE-2025-55182 — RCE (Critical)
    for cap in RSC_VULN_REGEX.captures_iter(text) {
        let pkg = cap.get(1).map_or("react-server-dom", |m| m.as_str());
        let ver = cap.get(2).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC RCE (CVE-2025-55182)".to_owned(),
            severity: "critical".to_owned(),
            description: format!(
                "Vulnerable {pkg} detected ({ver}). CVE-2025-55182 allows unauthenticated RCE in React Server Components/Functions."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.1/19.1.2/19.2.1 or framework patched versions (Next.js 15.x/16.x etc.).".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2025-55183 — Source Code Exposure (Medium)
    for cap in RSC_SOURCE_EXPOSURE_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC Source Code Exposure (CVE-2025-55183)".to_owned(),
            severity: "medium".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to source code exposure via Server Function .toString(). Hardcoded secrets, API keys, and database credentials in Server Functions may be exposed."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.3/19.1.4/19.2.3.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2025-55184 / CVE-2025-67779 — DoS (High), same version range as 55183
    for cap in RSC_SOURCE_EXPOSURE_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC DoS (CVE-2025-55184/CVE-2025-67779)".to_owned(),
            severity: "high".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to denial of service. Crafted HTTP requests can trigger infinite processing loops, hanging the server."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.3/19.1.4/19.2.3.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    // CVE-2026-23864 — DoS (High), wider version range
    for cap in RSC_DOS_2026_REGEX.captures_iter(text) {
        let ver = cap.get(1).map_or("unknown", |m| m.as_str());
        vulns.push(Vulnerability {
            vuln_type: "React RSC DoS (CVE-2026-23864)".to_owned(),
            severity: "high".to_owned(),
            description: format!(
                "react-server-dom version {ver} is vulnerable to multiple DoS vectors (CVE-2026-23864) causing server crashes, OOM, or excessive CPU."
            ),
            remediation: "Upgrade react-server-dom-* to 19.0.4/19.1.5/19.2.4.".to_owned(),
            url: Some(source.to_owned()),
        });
    }

    vulns
}
