use anyhow::Result;
use chromiumoxide::Page;
use regex::Regex;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use tokio::time::{self, Duration};
use url::Url;

use crate::api::discovery::extract_api_endpoints;
use crate::detectors::{ast, secrets::SecretScanner};
use crate::scanner::page_utils;
use crate::types::{AstFinding, DiscoveredEndpoint, Vulnerability};

pub struct ScriptArtifacts {
    pub script_count: usize,
    pub source_maps: Vec<String>,
    pub window_objects: HashMap<String, String>,
    pub debug_flags: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub technologies: Vec<String>,
    pub ast_findings: Vec<AstFinding>,
    pub vulnerabilities: Vec<Vulnerability>,
}

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
                &format!("inline-script-{}", idx),
            ));
            if should_analyze_ast(None, target_host) {
                ast_findings.extend(ast::analyze_script(
                    content,
                    &format!("inline-script-{}", idx),
                ));
            }
            vulnerabilities.extend(detect_rsc_vuln(content, &format!("inline-script-{}", idx)));
        }

        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                if src.ends_with(".map") || src.contains(".js.map") {
                    source_maps.push(src.to_string());
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
                        scanner.scan_text(&text, &format!("Script: {}", src)).await;
                        scanner
                            .extract_comments(&text, &format!("Script: {}", src))
                            .await;
                        api_endpoints.extend(extract_api_endpoints(
                            &text,
                            &format!("external-script-{}", idx),
                        ));
                        if should_analyze_ast(Some(src), target_host) {
                            ast_findings.extend(ast::analyze_script(&text, src));
                        }
                        vulnerabilities.extend(detect_rsc_vuln(&text, src));
                    }
                }
            }
        }
    }

    let window_objects = page_utils::extract_json::<HashMap<String, String>>(
        page,
        r#"
        (() => {
            const results = {};
            const keys = ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', 'env', 'ENV'];
            keys.forEach(key => {
                if (window[key]) {
                    try {
                        results[key] = JSON.stringify(window[key]).substring(0, 1000);
                    } catch (e) {
                        results[key] = '[object Object]';
                    }
                }
            });
            return results;
        })()
    "#,
    )
    .await;

    let debug_mode = page_utils::extract_json::<Vec<String>>(page, r#"
        (() => {
            const flags = [];
            if (window.__DEBUG__) flags.push('window.__DEBUG__');
            if (window.DEBUG) flags.push('window.DEBUG');
            if (window.__DEV__) flags.push('window.__DEV__');
            if (window.__NEXT_DATA__ && window.__NEXT_DATA__.buildId?.includes('dev')) flags.push('Next.js dev buildId');
            return flags;
        })()
    "#).await;

    let technologies = page_utils::extract_json::<Vec<String>>(
        page,
        r#"
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
    "#,
    )
    .await;

    Ok(ScriptArtifacts {
        script_count: scripts_array.len(),
        source_maps,
        window_objects,
        debug_flags: debug_mode,
        api_endpoints,
        technologies,
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
                || host.ends_with(&format!(".{}", target))
                || target.ends_with(&format!(".{}", host));
        }
    }

    true
}

fn detect_rsc_vuln(text: &str, source: &str) -> Vec<Vulnerability> {
    // Detect vulnerable react-server-dom-* versions (CVE-2025-55182)
    // Affected: 19.0, 19.1.0, 19.1.1, 19.2.0
    let mut vulns = Vec::new();
    let re = Regex::new(
        r"(react-server-dom-(?:webpack|parcel|turbopack))[^0-9]{0,6}(19\.0(?:\.0)?|19\.1\.0|19\.1\.1|19\.2\.0)",
    )
    .unwrap();

    for cap in re.captures_iter(text) {
        let pkg = cap.get(1).map(|m| m.as_str()).unwrap_or("react-server-dom");
        let ver = cap.get(2).map(|m| m.as_str()).unwrap_or("unknown");
        let desc = format!(
            "Vulnerable {} detected ({}). CVE-2025-55182 allows unauthenticated RCE in React Server Components/Functions.",
            pkg, ver
        );
        vulns.push(Vulnerability {
            vuln_type: "React RSC RCE (CVE-2025-55182)".to_string(),
            severity: "critical".to_string(),
            description: desc,
            remediation: "Upgrade react-server-dom-* to 19.0.1/19.1.2/19.2.1 or framework patched versions (Next.js 15.x/16.x etc.)."
                .to_string(),
            url: Some(source.to_string()),
        });
    }

    vulns
}
