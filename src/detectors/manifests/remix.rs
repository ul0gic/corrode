//! Remix manifest parsing (brief §2). Tier A: `window.__remixManifest` (or
//! `__remixContext.manifest`) is captured in-page. Routes are reconstructed by
//! walking the `parentId` chain; `$param`/splat segments become `:param`/`*`.

use serde_json::Value;

use super::routes::RouteSet;
use crate::types::FrameworkManifest;

#[derive(Default)]
pub struct RemixResult {
    pub manifests: Vec<FrameworkManifest>,
    pub routes: RouteSet,
}

/// `manifest` is the JSON string of `__remixManifest` (or the `.manifest` field
/// of `__remixContext`). Unparseable input yields an empty result.
pub fn parse(manifest: Option<&str>) -> RemixResult {
    let mut out = RemixResult::default();
    let Some(raw) = manifest else {
        return out;
    };
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return out;
    };

    // Accept either the manifest directly or a wrapper exposing `.manifest`.
    let manifest = value.get("manifest").unwrap_or(&value);
    let Some(routes) = manifest.get("routes").and_then(Value::as_object) else {
        return out;
    };

    let build_id = manifest
        .get("version")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let mut flat = Vec::new();
    for id in routes.keys() {
        let Some(path) = full_path(id, routes) else {
            continue;
        };
        if path.is_empty() {
            continue; // pathless layout / root
        }
        let entry = &routes[id];
        let has_action = entry.get("hasAction").and_then(Value::as_bool) == Some(true);
        let is_api = path.starts_with("/api/")
            || path == "/api"
            || id.contains("api.")
            || (has_action && id.contains('.'));
        let kind = if is_api { "api" } else { "route" };
        out.routes.push(&path, kind, "remix:manifest");
        flat.push(path);
    }

    out.manifests.push(FrameworkManifest {
        framework: "Remix".to_owned(),
        manifest_type: "remix-manifest".to_owned(),
        routes: flat,
        build_id,
        confidence: None,
    });
    out
}

/// Walk `parentId` to the root, joining each segment's `path` and normalizing
/// Remix dynamic markers. Returns `None` if the chain is malformed.
fn full_path(id: &str, routes: &serde_json::Map<String, Value>) -> Option<String> {
    let mut segments = Vec::new();
    let mut current = Some(id.to_owned());
    let mut guard = 0;

    while let Some(cur) = current {
        guard += 1;
        if guard > 64 {
            return None; // cycle guard
        }
        let entry = routes.get(&cur)?;
        if let Some(seg) = entry.get("path").and_then(Value::as_str) {
            if !seg.is_empty() {
                segments.push(normalize_segment(seg));
            }
        }
        current = entry
            .get("parentId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
    }

    segments.reverse();
    Some(format!("/{}", segments.join("/")).replace("//", "/"))
}

/// Remix path segments already use `:param`; normalize a bare `$`/`$param`
/// (older filename-derived forms) and splats to the canonical template form.
fn normalize_segment(seg: &str) -> String {
    seg.split('/')
        .map(|part| {
            if part == "$" {
                "*".to_owned()
            } else if let Some(rest) = part.strip_prefix('$') {
                format!(":{rest}")
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(out: &RemixResult) -> Vec<String> {
        out.routes.clone_paths()
    }

    #[test]
    fn reconstructs_nested_paths_via_parent_chain() {
        let raw = r#"{
            "routes": {
                "root": {"id":"root","path":"","parentId":null},
                "routes/users": {"id":"routes/users","path":"users","parentId":"root"},
                "routes/users.$id": {"id":"routes/users.$id","path":":id","parentId":"routes/users","hasLoader":true}
            },
            "version": "v-hash-1"
        }"#;
        let out = parse(Some(raw));
        let p = paths(&out);
        assert!(p.contains(&"/users/:id".to_owned()));
        assert_eq!(out.manifests[0].build_id.as_deref(), Some("v-hash-1"));
        let dyn_route = out
            .routes
            .clone_routes()
            .into_iter()
            .find(|r| r.path == "/users/:id")
            .unwrap();
        assert!(dyn_route.dynamic);
    }

    #[test]
    fn api_routes_classified_as_api() {
        let raw = r#"{
            "routes": {
                "root": {"id":"root","path":"","parentId":null},
                "routes/api.health": {"id":"routes/api.health","path":"api/health","parentId":"root","hasLoader":true}
            }
        }"#;
        let out = parse(Some(raw));
        let r = out
            .routes
            .clone_routes()
            .into_iter()
            .find(|r| r.path == "/api/health")
            .unwrap();
        assert_eq!(r.kind, "api");
    }

    #[test]
    fn splat_segment_becomes_catch_all() {
        let raw = r#"{
            "routes": {
                "root": {"id":"root","path":"","parentId":null},
                "routes/files.$": {"id":"routes/files.$","path":"files/$","parentId":"root"}
            }
        }"#;
        let out = parse(Some(raw));
        assert!(paths(&out).iter().any(|p| p.contains('*')));
    }

    #[test]
    fn accepts_context_wrapper_with_manifest_field() {
        let raw =
            r#"{"manifest":{"routes":{"root":{"id":"root","path":"about","parentId":null}}}}"#;
        let out = parse(Some(raw));
        assert!(paths(&out).contains(&"/about".to_owned()));
    }

    #[test]
    fn unparseable_input_yields_nothing() {
        let out = parse(Some("{nope"));
        assert!(out.manifests.is_empty());
        assert!(parse(None).manifests.is_empty());
    }
}
