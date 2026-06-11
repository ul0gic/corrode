//! Intelligence extracted from recovered source (tasks 1.5 + 1.6).
//!
//! Pure functions over the paths and text a source map recovers: internal
//! routes/controllers/API handlers (→ `RouteSurface`) and package versions
//! embedded in dependency paths (→ `TechnologyVersion`). Secret scanning and
//! comment extraction reuse the existing `SecretScanner` at wiring time
//! (task 1.4) rather than being re-implemented here.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{RouteSurface, TechnologyVersion};

/// Directory segments that mark the start of a framework's routing tree.
const ROUTE_DIRS: &[&str] = &["pages", "app", "routes", "views"];

/// Strip a virtual-source scheme prefix (`webpack://app/`, `rsbuild://`, …) and
/// any leading `./`, leaving a repo-relative path.
fn normalize_path(path: &str) -> String {
    let after_scheme = match path.split_once("://") {
        Some((_, rest)) => {
            // Drop a leading namespace segment like `_N_E/` or `app/` that
            // webpack inserts after the scheme.
            rest.trim_start_matches('/')
        }
        None => path,
    };
    after_scheme.trim_start_matches("./").to_owned()
}

/// True for paths we never want to surface as first-party routes.
fn is_vendor(path: &str) -> bool {
    path.contains("node_modules")
        || path.contains("/vendor/")
        || path.starts_with("vendor/")
        || path.contains("/.pnpm/")
}

/// Convert a framework route-file path into a URL path, preserving dynamic
/// segment syntax (`[id]`, `[...slug]`). Returns the URL path and whether it is
/// dynamic.
fn file_to_route(rel_after_dir: &str) -> (String, bool) {
    // Drop the file extension.
    let no_ext = rel_after_dir
        .rsplit_once('.')
        .map_or(rel_after_dir, |(stem, _ext)| stem);
    // `index` files map to their containing directory.
    let trimmed = no_ext
        .strip_suffix("/index")
        .or_else(|| (no_ext == "index").then_some(""))
        .unwrap_or(no_ext);
    let route = if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    };
    let dynamic = route.contains('[') || route.contains(':');
    (route, dynamic)
}

/// Recover internal routes, API handlers, and controllers from recovered source
/// file paths. De-duplicated; vendored/ignored code is excluded.
pub fn extract_routes(source_paths: &[String], map_url: &str) -> Vec<RouteSurface> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for raw in source_paths {
        let path = normalize_path(raw);
        if is_vendor(&path) {
            continue;
        }
        let lower = path.to_ascii_lowercase();

        // Find the routing-tree root, if any.
        let segments: Vec<&str> = path.split('/').collect();
        // Use the *last* route-dir segment: a webpack namespace prefix can itself
        // be named like a route dir (e.g. `webpack://app/./pages/...`), and the
        // real routing root is the deepest such segment.
        let route_dir_idx = segments
            .iter()
            .rposition(|seg| ROUTE_DIRS.contains(&seg.to_ascii_lowercase().as_str()));

        let (kind, route_path, dynamic) = if lower.contains("controller") {
            ("controller", path.clone(), false)
        } else if let Some(idx) = route_dir_idx {
            let rel: String = segments.get(idx + 1..).unwrap_or(&[]).join("/");
            if rel.is_empty() {
                continue;
            }
            let (route, dynamic) = file_to_route(&rel);
            let is_api = route.starts_with("/api/") || route == "/api";
            (if is_api { "api" } else { "route" }, route, dynamic)
        } else {
            continue;
        };

        if seen.insert((kind, route_path.clone())) {
            out.push(RouteSurface {
                path: route_path,
                kind: kind.to_owned(),
                source: map_url.to_owned(),
                dynamic,
                confidence: None,
            });
        }
    }

    out
}

/// `name@1.2.3` as embedded in dependency paths. Captures an optional `@scope/`
/// prefix and a semver-ish version. pnpm encodes scoped packages as
/// `@scope+name@1.2.3`, which this also accepts.
#[allow(clippy::unwrap_used)]
static PKG_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    // The name is a single path component (no `/`) so the parent dir (`.pnpm/`,
    // `node_modules/`) is never swallowed. pnpm scoped names use `+` as the scope
    // separator (`@babel+core@7.0.0`), normalized back to `/` below.
    Regex::new(r"(@?[a-z0-9][a-z0-9._+-]*)@(\d+\.\d+\.\d+[A-Za-z0-9.+-]*)").unwrap()
});

/// Recover package versions embedded in recovered dependency paths
/// (e.g. `node_modules/.pnpm/next@14.2.3/...`). De-duplicated by name+version.
pub fn extract_versions(source_paths: &[String]) -> Vec<TechnologyVersion> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for raw in source_paths {
        let path = normalize_path(raw);
        // Versions only live in dependency paths; first-party files won't carry them.
        if !path.contains("node_modules") && !path.contains("/.pnpm/") {
            continue;
        }
        for cap in PKG_VERSION_RE.captures_iter(&path) {
            let name = cap[1].trim_start_matches('@').replace('+', "/");
            let version = cap[2].to_owned();
            if name.is_empty() {
                continue;
            }
            if seen.insert((name.clone(), version.clone())) {
                out.push(TechnologyVersion {
                    name,
                    version: Some(version),
                    detection_method: "source-map dependency path".to_owned(),
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_next_pages_routes_with_dynamic_segments() {
        let paths = vec![
            "webpack://_N_E/./pages/index.tsx".to_owned(),
            "webpack://_N_E/./pages/admin/billing.tsx".to_owned(),
            "webpack://_N_E/./pages/users/[id].tsx".to_owned(),
        ];
        let routes = extract_routes(&paths, "https://x.com/main.js.map");
        let by_path: std::collections::HashMap<_, _> =
            routes.iter().map(|r| (r.path.as_str(), r)).collect();
        assert_eq!(by_path["/"].kind, "route");
        assert_eq!(by_path["/admin/billing"].kind, "route");
        assert!(by_path["/users/[id]"].dynamic);
    }

    #[test]
    fn classifies_api_handlers() {
        let paths = vec!["webpack://app/./pages/api/login.ts".to_owned()];
        let routes = extract_routes(&paths, "m");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].kind, "api");
        assert_eq!(routes[0].path, "/api/login");
    }

    #[test]
    fn classifies_controllers() {
        let paths = vec!["src/controllers/UserController.ts".to_owned()];
        let routes = extract_routes(&paths, "m");
        assert_eq!(routes[0].kind, "controller");
    }

    #[test]
    fn excludes_vendor_code() {
        let paths = vec![
            "webpack://app/node_modules/next/dist/pages/_app.js".to_owned(),
            "node_modules/react-router/routes/x.js".to_owned(),
        ];
        assert!(extract_routes(&paths, "m").is_empty());
    }

    #[test]
    fn ignores_files_outside_route_trees() {
        let paths = vec!["src/lib/format.ts".to_owned(), "src/utils.ts".to_owned()];
        assert!(extract_routes(&paths, "m").is_empty());
    }

    #[test]
    fn deduplicates_routes() {
        let paths = vec![
            "webpack://a/./pages/x.tsx".to_owned(),
            "webpack://a/./pages/x.tsx".to_owned(),
        ];
        assert_eq!(extract_routes(&paths, "m").len(), 1);
    }

    #[test]
    fn recovers_pnpm_package_versions() {
        let paths = vec![
            "webpack://_N_E/./node_modules/.pnpm/next@14.2.3/node_modules/next/dist/x.js"
                .to_owned(),
            "node_modules/react@18.2.0/index.js".to_owned(),
        ];
        let versions = extract_versions(&paths);
        let map: std::collections::HashMap<_, _> = versions
            .iter()
            .map(|v| (v.name.as_str(), v.version.as_deref().unwrap()))
            .collect();
        assert_eq!(map.get("next"), Some(&"14.2.3"));
        assert_eq!(map.get("react"), Some(&"18.2.0"));
    }

    #[test]
    fn no_versions_from_first_party_paths() {
        let paths = vec!["src/app@home.ts".to_owned()];
        assert!(extract_versions(&paths).is_empty());
    }
}
