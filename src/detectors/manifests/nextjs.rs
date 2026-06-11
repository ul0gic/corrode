//! Next.js manifest parsing (brief §1): `__NEXT_DATA__` (Pages Router),
//! `__BUILD_MANIFEST`, `__SSG_MANIFEST`, and the App Router `__next_f` Flight
//! stream. Tier A only — every value is read from already-captured in-page state.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::routes::{is_framework_internal, RouteSet};
use crate::types::FrameworkManifest;

#[derive(Default)]
pub struct NextResult {
    pub manifests: Vec<FrameworkManifest>,
    pub routes: RouteSet,
}

/// Parses whatever Next.js globals are present. Each value is the JSON string
/// captured by the collector (`JSON.stringify(window[key])`). Absent, truncated,
/// or unparseable values are skipped, never panicked on.
pub fn parse(
    next_data: Option<&str>,
    build_manifest: Option<&str>,
    ssg_manifest: Option<&str>,
    next_flight: Option<&str>,
) -> NextResult {
    let mut out = NextResult::default();

    if let Some(raw) = next_data {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            parse_next_data(&value, &mut out);
        }
    }
    if let Some(raw) = build_manifest {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            parse_build_manifest(&value, &mut out);
        }
    }
    if let Some(raw) = ssg_manifest {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            parse_ssg_manifest(&value, &mut out);
        }
    }
    if let Some(raw) = next_flight {
        parse_flight(raw, &mut out);
    }

    out
}

fn parse_next_data(value: &Value, out: &mut NextResult) {
    let build_id = value
        .get("buildId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    if let Some(page) = value.get("page").and_then(Value::as_str) {
        if !is_framework_internal(page) {
            out.routes.push(page, "route", "next:next-data");
        }
    }

    out.manifests.push(FrameworkManifest {
        framework: "Next.js".to_owned(),
        manifest_type: "next-data".to_owned(),
        routes: out
            .routes
            .clone_paths()
            .into_iter()
            .filter(|p| !is_framework_internal(p))
            .collect(),
        build_id,
        confidence: None,
    });
}

fn parse_build_manifest(value: &Value, out: &mut NextResult) {
    let Some(obj) = value.as_object() else {
        return;
    };

    let mut routes = Vec::new();

    // Object keys that look like paths are route templates.
    for key in obj.keys() {
        if key.starts_with('/') && !is_framework_internal(key) {
            out.routes.push(key, "route", "next:build-manifest");
            routes.push(key.clone());
        }
    }

    // `sortedPages` is the authoritative list; framework internals filtered.
    if let Some(pages) = obj.get("sortedPages").and_then(Value::as_array) {
        for page in pages.iter().filter_map(Value::as_str) {
            if page.starts_with('/') && !is_framework_internal(page) {
                out.routes.push(page, "route", "next:build-manifest");
                if !routes.iter().any(|r| r == page) {
                    routes.push(page.to_owned());
                }
            }
        }
    }

    // `__rewrites` destinations are hidden-path leads.
    if let Some(rewrites) = obj.get("__rewrites").and_then(Value::as_object) {
        for group in ["beforeFiles", "afterFiles", "fallback"] {
            let Some(rules) = rewrites.get(group).and_then(Value::as_array) else {
                continue;
            };
            for dest in rules
                .iter()
                .filter_map(|r| r.get("destination").and_then(Value::as_str))
            {
                if dest.starts_with('/') {
                    out.routes.push(dest, "route", "next:rewrite");
                }
            }
        }
    }

    out.manifests.push(FrameworkManifest {
        framework: "Next.js".to_owned(),
        manifest_type: "build-manifest".to_owned(),
        routes,
        build_id: None,
        confidence: None,
    });
}

fn parse_ssg_manifest(value: &Value, out: &mut NextResult) {
    // The collector probe converts the `Set` to an array before stringifying.
    let Some(arr) = value.as_array() else {
        return;
    };
    let mut routes = Vec::new();
    for path in arr.iter().filter_map(Value::as_str) {
        if path.starts_with('/') {
            out.routes.push(path, "route", "next:ssg-manifest");
            routes.push(path.to_owned());
        }
    }
    out.manifests.push(FrameworkManifest {
        framework: "Next.js".to_owned(),
        manifest_type: "ssg-manifest".to_owned(),
        routes,
        build_id: None,
        confidence: None,
    });
}

// Conservative path-shaped match over decoded Flight strings; the Flight grammar
// is unstable across Next versions, so we never attempt a full parse (brief §1d).
#[allow(clippy::unwrap_used)]
static APP_SEGMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"app/([A-Za-z0-9_./()\[\]@.-]*?)/(page|layout|route)\b").unwrap());

fn parse_flight(raw: &str, out: &mut NextResult) {
    // The collector stringifies `__next_f` (array of `[type, payload]` tuples).
    // Parse loosely: scan the whole serialized blob for `app/.../page|route`.
    let mut emitted = false;
    for cap in APP_SEGMENT_RE.captures_iter(raw) {
        let segments = &cap[1];
        let kind = if &cap[2] == "route" { "api" } else { "route" };
        let path = flight_segments_to_path(segments);
        if !path.is_empty() && !is_framework_internal(&path) {
            out.routes.push(&path, kind, "next:flight");
            emitted = true;
        }
    }
    if emitted {
        out.manifests.push(FrameworkManifest {
            framework: "Next.js".to_owned(),
            manifest_type: "next-flight".to_owned(),
            routes: Vec::new(),
            build_id: None,
            confidence: None,
        });
    }
}

/// Turn `app/(marketing)/about` segment text into `/about`: route groups
/// `(group)` and parallel slots `@slot` are URL-transparent and dropped.
fn flight_segments_to_path(segments: &str) -> String {
    let kept: Vec<&str> = segments
        .split('/')
        .filter(|seg| {
            !(seg.is_empty()
                || (seg.starts_with('(') && seg.ends_with(')'))
                || seg.starts_with('@'))
        })
        .collect();
    if kept.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", kept.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(out: &NextResult) -> Vec<String> {
        out.routes.clone_paths()
    }

    #[test]
    fn next_data_extracts_build_id_and_current_route() {
        let raw = r#"{"buildId":"abc123","page":"/posts/[id]","query":{"id":"5"}}"#;
        let out = parse(Some(raw), None, None, None);
        assert_eq!(out.manifests.len(), 1);
        assert_eq!(out.manifests[0].build_id.as_deref(), Some("abc123"));
        assert!(paths(&out).contains(&"/posts/[id]".to_owned()));
    }

    #[test]
    fn build_manifest_keys_become_routes_with_dynamic_flag() {
        let raw = r#"{
            "/": ["static/chunks/pages/index-a.js"],
            "/about": ["static/chunks/pages/about-b.js"],
            "/posts/[id]": ["static/chunks/pages/posts/[id]-c.js"],
            "/blog/[...slug]": ["static/chunks/pages/blog/[...slug]-d.js"],
            "__rewrites": {"beforeFiles":[],"afterFiles":[{"source":"/old","destination":"/new"}],"fallback":[]},
            "sortedPages": ["/", "/about", "/posts/[id]", "/_app", "/_error"]
        }"#;
        let out = parse(None, Some(raw), None, None);
        let p = paths(&out);
        assert!(p.contains(&"/".to_owned()));
        assert!(p.contains(&"/posts/[id]".to_owned()));
        assert!(p.contains(&"/new".to_owned())); // rewrite destination
        assert!(!p.contains(&"/_app".to_owned())); // framework internal filtered
        let dyn_route = out
            .routes
            .clone_routes()
            .into_iter()
            .find(|r| r.path == "/blog/[...slug]")
            .unwrap();
        assert!(dyn_route.dynamic);
    }

    #[test]
    fn ssg_manifest_array_members_are_static_routes() {
        let raw = r#"["/posts/1","/posts/2","/about"]"#;
        let out = parse(None, None, Some(raw), None);
        let p = paths(&out);
        assert!(p.contains(&"/about".to_owned()));
        assert_eq!(out.manifests[0].manifest_type, "ssg-manifest");
    }

    #[test]
    fn flight_stream_recovers_app_router_routes_and_handlers() {
        // Serialized `__next_f` blob with App Router segment references.
        let raw = r#"[[1,"2:[\"$\",\"div\"]"],[1,"app/dashboard/page app/(marketing)/about/page app/users/[id]/page app/health/route"]]"#;
        let out = parse(None, None, None, Some(raw));
        let p = paths(&out);
        assert!(p.contains(&"/dashboard".to_owned()));
        assert!(p.contains(&"/about".to_owned())); // route group dropped
        assert!(p.contains(&"/users/[id]".to_owned()));
        let api = out
            .routes
            .clone_routes()
            .into_iter()
            .find(|r| r.path == "/health")
            .unwrap();
        assert_eq!(api.kind, "api"); // `/route` suffix => route handler
    }

    #[test]
    fn dev_build_id_is_surfaced() {
        let raw = r#"{"buildId":"development","page":"/"}"#;
        let out = parse(Some(raw), None, None, None);
        assert_eq!(out.manifests[0].build_id.as_deref(), Some("development"));
    }

    #[test]
    fn unparseable_or_absent_globals_yield_nothing() {
        let out = parse(Some("not json {"), Some("]["), None, None);
        assert!(out.manifests.is_empty());
        assert!(paths(&out).is_empty());
    }

    #[test]
    fn truncated_build_manifest_degrades_without_panic() {
        // A value clipped at 10000 chars is invalid JSON; must be skipped.
        let raw = r#"{"/": ["chunk.js"], "/about": ["#;
        let out = parse(None, Some(raw), None, None);
        assert!(out.manifests.is_empty());
    }
}
