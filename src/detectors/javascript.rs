use anyhow::Result;
use chromiumoxide::Page;
use reqwest;
use serde_json::Value;
use std::collections::HashMap;
use tokio::time::{self, Duration};

use crate::api::discovery::extract_api_endpoints;
use crate::detectors::secrets::SecretScanner;
use crate::scanner::page_utils;
use crate::types::DiscoveredEndpoint;

pub struct ScriptArtifacts {
    pub script_count: usize,
    pub source_maps: Vec<String>,
    pub window_objects: HashMap<String, String>,
    pub debug_flags: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub technologies: Vec<String>,
}

pub async fn collect(page: &Page, scanner: &SecretScanner) -> Result<ScriptArtifacts> {
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

    for (idx, script) in scripts_array.iter().enumerate() {
        if let Some(content) = script.get("content").and_then(|v| v.as_str()) {
            scanner.scan_text(content, "Inline Script").await;
            scanner.extract_comments(content, "Inline Script").await;
            api_endpoints.extend(extract_api_endpoints(
                content,
                &format!("inline-script-{}", idx),
            ));
        }

        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                if src.ends_with(".map") || src.contains(".js.map") {
                    source_maps.push(src.to_string());
                }

                if let Ok(Ok(resp)) =
                    time::timeout(Duration::from_secs(10), reqwest::get(src)).await
                {
                    if let Ok(text) = resp.text().await {
                        scanner.scan_text(&text, &format!("Script: {}", src)).await;
                        scanner
                            .extract_comments(&text, &format!("Script: {}", src))
                            .await;
                        api_endpoints.extend(extract_api_endpoints(
                            &text,
                            &format!("external-script-{}", idx),
                        ));
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
    })
}
