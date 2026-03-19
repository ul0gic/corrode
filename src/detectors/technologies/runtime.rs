use chromiumoxide::Page;
use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use crate::scanner::page_utils;
use crate::types::TechnologyVersion;

/// Detect technologies from browser runtime window objects.
pub async fn detect(page: &Page) -> Vec<String> {
    page_utils::extract_json::<Vec<String>>(
        page,
        r"
        (() => {
            const detected = [];
            const checks = [
                { name: 'React', test: () => !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__ },
                { name: 'Vue.js', test: () => !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__ },
                { name: 'Angular', test: () => !!window.ng },
                { name: 'Svelte', test: () => !!window.__svelte },
                { name: 'Next.js', test: () => !!window.__NEXT_DATA__ },
                { name: 'Nuxt.js', test: () => !!window.__NUXT__ },
                { name: 'SvelteKit', test: () => !!window.__sveltekit_data },
                { name: 'Remix', test: () => !!window.__remixContext },
                { name: 'Solid.js', test: () => !!window._$HY },
                { name: 'Firebase', test: () => !!window.firebase },
                { name: 'Stripe', test: () => !!window.Stripe },
                { name: 'Supabase', test: () => !!window.__supabase },
                { name: 'Auth0', test: () => !!window.auth0 },
                { name: 'Clerk', test: () => !!window.Clerk || !!window.__clerk_frontend_api },
                { name: 'AWS Amplify', test: () => !!window.Amplify },
                { name: 'GTM', test: () => !!window.dataLayer },
                { name: 'Google Analytics', test: () => !!window.gtag || !!window.ga },
                { name: 'Segment', test: () => !!window.analytics && !!window.analytics.track },
                { name: 'Intercom', test: () => !!window.Intercom },
                { name: 'Hotjar', test: () => !!window.hj },
                { name: 'Mixpanel', test: () => !!window.mixpanel },
                { name: 'Redux', test: () => !!window.__REDUX_DEVTOOLS_EXTENSION__ },
                { name: 'Apollo Client', test: () => !!window.__APOLLO_STATE__ || !!window.__APOLLO_CLIENT__ },
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
    .await
}

/// Extract technology versions from runtime APIs and script sources.
pub async fn extract_versions(page: &Page, scripts: &[Value]) -> Vec<TechnologyVersion> {
    let mut versions = Vec::new();

    if let Some(react_ver) = extract_react_version(page).await {
        versions.push(react_ver);
    } else if let Some(cdn_ver) = extract_react_version_from_cdn(scripts) {
        versions.push(cdn_ver);
    }

    if let Some(next_meta) = extract_nextjs_metadata(page).await {
        versions.push(next_meta);
    }

    if let Some(router_info) = detect_nextjs_router(scripts) {
        versions.push(router_info);
    }

    versions
}

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

async fn extract_nextjs_metadata(page: &Page) -> Option<TechnologyVersion> {
    let next_data: Option<std::collections::HashMap<String, Value>> = page_utils::extract_json(
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

#[allow(clippy::unwrap_used)]
static CDN_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)/(?:npm/)?react(?:-dom)?@(\d+\.\d+\.\d+)",
    )
    .unwrap()
});

fn extract_react_version_from_cdn(scripts: &[Value]) -> Option<TechnologyVersion> {
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
