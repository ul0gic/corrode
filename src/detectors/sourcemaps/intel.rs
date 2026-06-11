//! Routes and package versions extracted from recovered source paths. Secret
//! and comment scanning reuse the existing `SecretScanner` at wiring time.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::types::{RouteSurface, TechnologyVersion};

const ROUTE_DIRS: &[&str] = &["pages", "app", "routes", "views"];

fn normalize_path(path: &str) -> String {
    let after_scheme = match path.split_once("://") {
        Some((_, rest)) => rest.trim_start_matches('/'),
        None => path,
    };
    after_scheme.trim_start_matches("./").to_owned()
}

fn is_vendor(path: &str) -> bool {
    path.contains("node_modules")
        || path.contains("/vendor/")
        || path.starts_with("vendor/")
        || path.contains("/.pnpm/")
}

fn file_to_route(rel_after_dir: &str) -> (String, bool) {
    let no_ext = rel_after_dir
        .rsplit_once('.')
        .map_or(rel_after_dir, |(stem, _ext)| stem);
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

pub fn extract_routes(source_paths: &[String], map_url: &str) -> Vec<RouteSurface> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for raw in source_paths {
        let path = normalize_path(raw);
        if is_vendor(&path) {
            continue;
        }
        let lower = path.to_ascii_lowercase();

        let segments: Vec<&str> = path.split('/').collect();
        // Last match, not first: a webpack namespace prefix can be named like a
        // route dir (`webpack://app/./pages/...`); the real root is the deepest.
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

// Name is a single path component so the parent dir (`.pnpm/`) isn't swallowed.
// pnpm scoped names use `+` as the scope separator, normalized back to `/` below.
#[allow(clippy::unwrap_used)]
static PKG_VERSION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(@?[a-z0-9][a-z0-9._+-]*)@(\d+\.\d+\.\d+[A-Za-z0-9.+-]*)").unwrap()
});

pub fn extract_versions(source_paths: &[String]) -> Vec<TechnologyVersion> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for raw in source_paths {
        let path = normalize_path(raw);
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

    // --- Fixture-backed coverage (task 1.12) ---

    const FIXTURE_WITH_CONTENT: &str = r#"{
  "version": 3,
  "file": "main.js",
  "sourceRoot": "",
  "sources": [
    "webpack://_N_E/./src/app/page.tsx",
    "webpack://_N_E/./src/app/admin/[id]/route.ts",
    "webpack://_N_E/./src/utils/api.ts",
    "webpack://_N_E/./node_modules/.pnpm/next@14.1.0/dist/client.js"
  ],
  "sourcesContent": [
    "export default function Page() { return null; }",
    "export async function GET(req) { /* TODO: add authz check */ return Response.json({}); }",
    "export const API_BASE = '/api/internal';",
    "module.exports = {};"
  ],
  "names": ["Page", "GET", "API_BASE"],
  "x_google_ignoreList": [3]
}
"#;

    #[test]
    fn fixture_recovers_routes_and_versions_end_to_end() {
        let parsed = super::super::parse::parse(FIXTURE_WITH_CONTENT).expect("valid fixture map");
        let paths = parsed.source_paths();

        let routes = extract_routes(&paths, "https://app.example.com/main.js.map");
        let by_path: std::collections::HashMap<_, _> =
            routes.iter().map(|r| (r.path.as_str(), r)).collect();
        // src/app/page.tsx -> /page; src/app/admin/[id]/route.ts -> dynamic.
        assert_eq!(by_path["/page"].kind, "route");
        assert!(by_path["/admin/[id]/route"].dynamic);
        // src/utils/api.ts sits outside a route tree and must not appear.
        assert!(!routes.iter().any(|r| r.path.contains("utils")));

        // The pnpm vendor path yields a recovered package version.
        let versions = extract_versions(&paths);
        assert!(versions
            .iter()
            .any(|v| v.name == "next" && v.version.as_deref() == Some("14.1.0")));
    }
}
