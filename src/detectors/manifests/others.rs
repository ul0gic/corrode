//! Nuxt (§3), `SvelteKit` (§5), Astro (§4), and Vite/webpack chunk graphs (§6/§7).
//! Tier A only. None ship a full client route table inline the way Next/Remix do,
//! so these recover the current route, build fingerprint, and component surface;
//! full route enumeration is left to source-map / chunk recovery (Tier B at the gate).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::routes::RouteSet;
use crate::types::FrameworkManifest;

#[derive(Default)]
pub struct OtherResult {
    pub manifests: Vec<FrameworkManifest>,
    pub routes: RouteSet,
}

impl OtherResult {
    fn extend(&mut self, other: OtherResult) {
        self.manifests.extend(other.manifests);
        for r in other.routes.into_vec() {
            self.routes.push(&r.path, &r.kind, &r.source);
        }
    }
}

/// `nuxt` / `sveltekit` are the JSON strings of `window.__NUXT__` and a
/// `window.__sveltekit_*` global; `chunk_names` are already-referenced asset
/// stems (modulepreload hrefs, `<script src>`); `astro_islands` are the JSON
/// attribute maps of any `<astro-island>` DOM elements. All optional.
pub fn parse(
    nuxt: Option<&str>,
    sveltekit: Option<&str>,
    chunk_names: &[String],
    astro_islands: &[String],
) -> OtherResult {
    let mut out = OtherResult::default();
    out.extend(parse_nuxt(nuxt));
    out.extend(parse_sveltekit(sveltekit));
    out.extend(parse_astro(astro_islands));
    out.extend(parse_chunks(chunk_names));
    out
}

fn parse_nuxt(nuxt: Option<&str>) -> OtherResult {
    let mut out = OtherResult::default();
    let Some(value) = nuxt.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
        return out;
    };

    if let Some(path) = value
        .get("path")
        .or_else(|| value.get("routePath"))
        .and_then(Value::as_str)
    {
        if path.starts_with('/') {
            out.routes.push(path, "route", "nuxt:payload");
        }
    }

    // `data` keys are useFetch/useAsyncData cache keys — frequently literal API URLs.
    if let Some(data) = value.get("data").and_then(Value::as_object) {
        for key in data.keys() {
            if key.starts_with('/') {
                out.routes.push(key, "api", "nuxt:data-keys");
            }
        }
    }

    let build_id = value
        .get("config")
        .and_then(|c| c.get("app"))
        .and_then(|a| a.get("buildId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    out.manifests.push(FrameworkManifest {
        framework: "Nuxt".to_owned(),
        manifest_type: "nuxt-payload".to_owned(),
        routes: out.routes.clone_paths(),
        build_id,
        confidence: None,
    });
    out
}

fn parse_sveltekit(sveltekit: Option<&str>) -> OtherResult {
    let mut out = OtherResult::default();
    let Some(value) = sveltekit.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
        return out;
    };

    // `route.id` is SvelteKit's template form (`/blog/[slug]`, `/(app)/dashboard`).
    if let Some(id) = value
        .get("route")
        .and_then(|r| r.get("id"))
        .and_then(Value::as_str)
    {
        let path = strip_groups(id);
        if path.starts_with('/') {
            out.routes.push(&path, "route", "sveltekit:start");
        }
    }

    out.manifests.push(FrameworkManifest {
        framework: "SvelteKit".to_owned(),
        manifest_type: "sveltekit-start".to_owned(),
        routes: out.routes.clone_paths(),
        build_id: None,
        confidence: None,
    });
    out
}

fn parse_astro(islands: &[String]) -> OtherResult {
    let mut out = OtherResult::default();
    if islands.is_empty() {
        return out;
    }
    for attrs in islands {
        let Ok(value) = serde_json::from_str::<Value>(attrs) else {
            continue;
        };
        if let Some(url) = value.get("component-url").and_then(Value::as_str) {
            if let Some(name) = chunk_stem(url) {
                out.routes.push(&name, "component", "astro:island");
            }
        }
    }
    // Astro ships no client route manifest; routes stay empty by design.
    out.manifests.push(FrameworkManifest {
        framework: "Astro".to_owned(),
        manifest_type: "astro-islands".to_owned(),
        routes: Vec::new(),
        build_id: None,
        confidence: None,
    });
    out
}

fn parse_chunks(chunk_names: &[String]) -> OtherResult {
    let mut out = OtherResult::default();
    let mut emitted = false;
    for raw in chunk_names {
        let Some(stem) = chunk_stem(raw) else {
            continue;
        };
        // Numeric-only / hash-only chunk names carry no semantic value.
        if stem.is_empty() || stem.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        out.routes.push(&stem, "component", "chunk-graph");
        emitted = true;
    }
    if emitted {
        out.manifests.push(FrameworkManifest {
            framework: "Vite/webpack".to_owned(),
            manifest_type: "chunk-graph".to_owned(),
            routes: Vec::new(),
            build_id: None,
            confidence: None,
        });
    }
    out
}

/// Drop `SvelteKit` route-group segments `(group)`, which are URL-transparent.
fn strip_groups(id: &str) -> String {
    let kept: Vec<&str> = id
        .split('/')
        .filter(|seg| !(seg.starts_with('(') && seg.ends_with(')')))
        .collect();
    let joined = kept.join("/");
    if joined.is_empty() {
        "/".to_owned()
    } else {
        joined
    }
}

// `assets/UserProfile-a1b2c3d4.js` -> `UserProfile`; hash suffix and extension dropped.
#[allow(clippy::unwrap_used)]
static CHUNK_STEM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_.\[\]-]+?)(?:[-.][0-9a-f]{6,})?\.[cm]?js$").unwrap());

fn chunk_stem(url: &str) -> Option<String> {
    let file = url.rsplit('/').next().unwrap_or(url);
    let caps = CHUNK_STEM_RE.captures(file)?;
    Some(caps[1].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nuxt_extracts_current_route_build_id_and_data_keys() {
        let raw = r#"{
            "path":"/dashboard",
            "data":{"/api/user":{"id":1},"counter":5},
            "config":{"app":{"buildId":"nuxt-build-9"}}
        }"#;
        let out = parse(Some(raw), None, &[], &[]);
        let routes = out.routes.clone_routes();
        assert!(routes
            .iter()
            .any(|r| r.path == "/dashboard" && r.kind == "route"));
        assert!(routes
            .iter()
            .any(|r| r.path == "/api/user" && r.kind == "api"));
        assert_eq!(out.manifests[0].build_id.as_deref(), Some("nuxt-build-9"));
    }

    #[test]
    fn sveltekit_route_id_template_with_groups_stripped() {
        let raw = r#"{"route":{"id":"/(app)/blog/[slug]"}}"#;
        let out = parse(None, Some(raw), &[], &[]);
        let r = out.routes.clone_routes();
        assert!(r.iter().any(|x| x.path == "/blog/[slug]" && x.dynamic));
    }

    #[test]
    fn astro_island_recovers_component_name_no_routes() {
        let island = r#"{"component-url":"/_astro/Counter.a1b2c3d4.js","client":"load"}"#;
        let out = parse(None, None, &[], &[island.to_owned()]);
        let r = out.routes.clone_routes();
        assert!(r
            .iter()
            .any(|x| x.path == "Counter" && x.kind == "component"));
        assert!(out.manifests[0].routes.is_empty());
    }

    #[test]
    fn chunk_graph_recovers_named_chunks_skips_numeric() {
        let chunks = vec![
            "https://x.com/assets/UserProfile-a1b2c3d4.js".to_owned(),
            "/assets/4821.f00dface.js".to_owned(),
            "/_app/immutable/nodes/Dashboard-deadbeef.js".to_owned(),
        ];
        let out = parse(None, None, &chunks, &[]);
        let names: Vec<String> = out.routes.clone_paths();
        assert!(names.contains(&"UserProfile".to_owned()));
        assert!(names.contains(&"Dashboard".to_owned()));
        assert!(!names.iter().any(|n| n.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn absent_or_unparseable_inputs_yield_nothing() {
        let out = parse(Some("{bad"), Some("nope"), &[], &["{also bad".to_owned()]);
        assert!(out.routes.into_vec().is_empty());
        // Astro still emits its (empty-route) manifest on island presence; here
        // the island was unparseable so no component surfaced.
        assert!(out.manifests.iter().all(|m| m.routes.is_empty()));
    }

    #[test]
    fn empty_inputs_produce_no_manifests() {
        let out = parse(None, None, &[], &[]);
        assert!(out.manifests.is_empty());
    }
}
