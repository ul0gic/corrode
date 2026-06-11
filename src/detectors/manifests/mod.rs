//! Tier A only — pure and synchronous over already-captured in-page state; this
//! module never fetches.

mod nextjs;
mod others;
mod remix;
mod routes;

use std::collections::HashMap;

use crate::types::{FrameworkManifest, RouteSurface};

/// Window-object keys this module reads. Names match the `JSON.stringify`
/// capture in `collectors::javascript`.
const NEXT_DATA: &str = "__NEXT_DATA__";
const BUILD_MANIFEST: &str = "__BUILD_MANIFEST";
const SSG_MANIFEST: &str = "__SSG_MANIFEST";
const NEXT_FLIGHT: &str = "__next_f";
const REMIX_MANIFEST: &str = "__remixManifest";
const REMIX_CONTEXT: &str = "__remixContext";
const NUXT: &str = "__NUXT__";
const SVELTEKIT: &str = "__sveltekit_data";

#[derive(Debug, Default)]
pub struct ManifestReport {
    pub manifests: Vec<FrameworkManifest>,
    pub routes: Vec<RouteSurface>,
}

/// `technologies` gates each parser, so absent frameworks cost nothing; pass empty
/// `chunk_names`/`astro_islands` until the gate wires them.
pub fn analyze(
    window_objects: &HashMap<String, String>,
    technologies: &[String],
    chunk_names: &[String],
    astro_islands: &[String],
) -> ManifestReport {
    let mut report = ManifestReport::default();
    let get = |key: &str| window_objects.get(key).map(String::as_str);

    let next_global = [NEXT_DATA, BUILD_MANIFEST, SSG_MANIFEST, NEXT_FLIGHT]
        .iter()
        .any(|k| get(k).is_some());
    if tech_matches(technologies, "next.js") || next_global {
        let result = nextjs::parse(
            get(NEXT_DATA),
            get(BUILD_MANIFEST),
            get(SSG_MANIFEST),
            get(NEXT_FLIGHT),
        );
        report.manifests.extend(result.manifests);
        report.routes.extend(result.routes.into_vec());
    }

    if tech_matches(technologies, "remix") || get(REMIX_CONTEXT).is_some() {
        // Prefer the standalone manifest; fall back to `__remixContext` (`.manifest`).
        let manifest = get(REMIX_MANIFEST).or_else(|| get(REMIX_CONTEXT));
        let result = remix::parse(manifest);
        report.manifests.extend(result.manifests);
        report.routes.extend(result.routes.into_vec());
    }

    // Astro has no window global, so it is gated on island presence / tech alone.
    let astro_present = tech_matches(technologies, "astro") || !astro_islands.is_empty();
    let nuxt = (tech_matches(technologies, "nuxt") || get(NUXT).is_some()).then(|| get(NUXT));
    let svelte = (tech_matches(technologies, "sveltekit") || get(SVELTEKIT).is_some())
        .then(|| get(SVELTEKIT));

    if nuxt.is_some() || svelte.is_some() || astro_present || !chunk_names.is_empty() {
        let result = others::parse(
            nuxt.flatten(),
            svelte.flatten(),
            chunk_names,
            if astro_present { astro_islands } else { &[] },
        );
        report.manifests.extend(result.manifests);
        report.routes.extend(result.routes.into_vec());
    }

    report
}

/// Case-insensitive substring match against the detected technology list, so
/// `Next.js (App Router)` matches the `next.js` gate.
fn tech_matches(technologies: &[String], needle: &str) -> bool {
    technologies
        .iter()
        .any(|t| t.to_ascii_lowercase().contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn next_gate_off_without_tech_or_global() {
        let report = analyze(&HashMap::new(), &["React".to_owned()], &[], &[]);
        assert!(report.manifests.is_empty());
        assert!(report.routes.is_empty());
    }

    #[test]
    fn next_app_router_tech_variant_triggers_parser() {
        let w = windows(&[(NEXT_DATA, r#"{"buildId":"b1","page":"/home"}"#)]);
        let report = analyze(&w, &["Next.js (App Router)".to_owned()], &[], &[]);
        assert!(report.routes.iter().any(|r| r.path == "/home"));
        assert!(report
            .manifests
            .iter()
            .any(|m| m.build_id.as_deref() == Some("b1")));
    }

    #[test]
    fn next_parses_even_when_only_global_present() {
        let w = windows(&[(BUILD_MANIFEST, r#"{"/":["c.js"],"/about":["d.js"]}"#)]);
        let report = analyze(&w, &[], &[], &[]);
        assert!(report.routes.iter().any(|r| r.path == "/about"));
    }

    #[test]
    fn remix_falls_back_to_context_manifest() {
        let ctx =
            r#"{"manifest":{"routes":{"root":{"id":"root","path":"about","parentId":null}}}}"#;
        let w = windows(&[(REMIX_CONTEXT, ctx)]);
        let report = analyze(&w, &["Remix".to_owned()], &[], &[]);
        assert!(report.routes.iter().any(|r| r.path == "/about"));
    }

    #[test]
    fn astro_gated_on_island_presence_without_window_global() {
        let island = r#"{"component-url":"/_astro/Widget.abcdef12.js"}"#;
        let report = analyze(&HashMap::new(), &[], &[], &[island.to_owned()]);
        assert!(report
            .routes
            .iter()
            .any(|r| r.path == "Widget" && r.kind == "component"));
    }

    #[test]
    fn chunk_names_alone_recover_component_surface() {
        let chunks = vec!["/assets/Dashboard-a1b2c3d4.js".to_owned()];
        let report = analyze(&HashMap::new(), &[], &chunks, &[]);
        assert!(report.routes.iter().any(|r| r.path == "Dashboard"));
    }

    #[test]
    fn multiple_frameworks_aggregate_without_panic() {
        let w = windows(&[
            (NEXT_DATA, r#"{"buildId":"b","page":"/n"}"#),
            (NUXT, r#"{"path":"/nuxt","config":{"app":{"buildId":"x"}}}"#),
        ]);
        let report = analyze(&w, &["Next.js".to_owned(), "Nuxt".to_owned()], &[], &[]);
        assert!(report.routes.iter().any(|r| r.path == "/n"));
        assert!(report.routes.iter().any(|r| r.path == "/nuxt"));
    }

    // --- Fixture-backed coverage (task 1.12) ---

    const FIXTURE_NEXT_BUILD: &str = r#"{
  "/": ["static/chunks/pages/index.js"],
  "/admin": ["static/chunks/pages/admin.js"],
  "/admin/billing": ["static/chunks/pages/admin/billing.js"],
  "/users/[id]": ["static/chunks/pages/users/[id].js"],
  "/api/login": ["static/chunks/pages/api/login.js"]
}
"#;
    const FIXTURE_REMIX_CONTEXT: &str = r#"{
  "manifest": {
    "routes": {
      "root": { "id": "root", "path": "", "parentId": null },
      "routes/login": { "id": "routes/login", "path": "login", "parentId": "root" },
      "routes/dashboard": { "id": "routes/dashboard", "path": "dashboard", "parentId": "root" },
      "routes/dashboard.settings": {
        "id": "routes/dashboard.settings",
        "path": "settings",
        "parentId": "routes/dashboard"
      }
    }
  }
}
"#;

    #[test]
    fn fixture_next_build_manifest_recovers_routes() {
        let w = windows(&[(BUILD_MANIFEST, FIXTURE_NEXT_BUILD)]);
        let report = analyze(&w, &["Next.js".to_owned()], &[], &[]);
        let paths: std::collections::HashSet<_> =
            report.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains("/admin"));
        assert!(paths.contains("/admin/billing"));
        // Dynamic + API classification survive the real-shaped manifest.
        assert!(report
            .routes
            .iter()
            .any(|r| r.path == "/users/[id]" && r.dynamic));
        // The build-manifest parser surfaces every key as a route template; it
        // does not sub-classify api paths (that distinction lives in source-map intel).
        assert!(paths.contains("/api/login"));
    }

    #[test]
    fn fixture_remix_context_recovers_nested_routes() {
        let w = windows(&[(REMIX_CONTEXT, FIXTURE_REMIX_CONTEXT)]);
        let report = analyze(&w, &["Remix".to_owned()], &[], &[]);
        let paths: std::collections::HashSet<_> =
            report.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains("/login"));
        // Nested parentId chain resolves to a full path.
        assert!(paths.contains("/dashboard/settings"));
    }

    #[test]
    fn fixture_unparseable_manifest_degrades_without_panic() {
        // A truncated/garbage global must yield no routes, never a panic.
        let w = windows(&[(BUILD_MANIFEST, r#"{"/admin": ["chunk.js"}"#)]);
        let report = analyze(&w, &["Next.js".to_owned()], &[], &[]);
        assert!(report.routes.is_empty());
        assert!(report.manifests.is_empty());
    }
}
