// Does:  Recovers route and component inventory from framework manifests.
// Holds: Analysis uses only the supplied observations.

mod nextjs;
mod others;
mod remix;
mod routes;

use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::types::{FrameworkManifest, RouteSurface};

const NEXT_DATA: &str = "__NEXT_DATA__";
const BUILD_MANIFEST: &str = "__BUILD_MANIFEST";
const SSG_MANIFEST: &str = "__SSG_MANIFEST";
const NEXT_FLIGHT: &str = "__next_f";
const REMIX_MANIFEST: &str = "__remixManifest";
const REMIX_CONTEXT: &str = "__remixContext";
const NUXT: &str = "__NUXT__";
const SVELTEKIT: &str = "__sveltekit_data";

#[derive(Debug, Default)]
/// Manifest and route observations inferred from captured page data.
pub struct ManifestReport {
    /// Recovered framework manifests.
    pub manifests: Vec<FrameworkManifest>,
    /// Route and component candidates.
    pub routes: Vec<RouteSurface>,
}

/// Extracts framework and route observations from captured values.
/// Framework globals and technology names gate their respective parsers.
///
/// ```
/// # use corrode_scanner::detectors::manifests::analyze;
/// # let windows = std::collections::HashMap::from([("__NEXT_DATA__".into(), r#"{"page":"/home"}"#.into())]);
/// let report = analyze(&windows, &[], &[], &[]);
/// ```
pub fn analyze<S: BuildHasher>(
    window_objects: &HashMap<String, String, S>,
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
        let manifest = get(REMIX_MANIFEST).or_else(|| get(REMIX_CONTEXT));
        let result = remix::parse(manifest);
        report.manifests.extend(result.manifests);
        report.routes.extend(result.routes.into_vec());
    }

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
}
