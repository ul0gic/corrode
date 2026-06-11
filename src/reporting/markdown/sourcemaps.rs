//! Pillar 1 — source-map & manifest intelligence section. Renders recovered
//! source maps, the client-side route surface, parsed framework manifests, and
//! package versions recovered from source-map dependency paths. Every item is a
//! manual-test lead with evidence, never a confirmed vulnerability.
//!
//! RSC findings are `Vulnerability`s rendered by the existing findings section,
//! so they are intentionally absent here.

use crate::types::{Confidence, ScanResult};

use super::summary::{confidence_label, confidence_sort_key};

/// Confidence cell for a table, e.g. `Medium`. Empty when unscored (back-compat).
fn confidence_cell(confidence: Option<&Confidence>) -> String {
    confidence.map_or_else(String::new, |c| {
        confidence_label(c.level)
            .trim_end_matches(" confidence")
            .to_owned()
    })
}

/// Versions recovered from source-map dependency paths carry this detection
/// method; the general technology section renders everything else, so matching
/// on it keeps the two sections from double-listing the same package.
const SOURCE_MAP_VERSION_METHOD: &str = "source-map dependency path";

pub(crate) fn render_sourcemap_intel(result: &ScanResult) -> Vec<String> {
    let recovered_versions: Vec<_> = result
        .technology_versions
        .iter()
        .filter(|tv| tv.detection_method == SOURCE_MAP_VERSION_METHOD)
        .collect();

    let nothing_to_report = result.source_maps_intel.is_empty()
        && result.route_surface.is_empty()
        && result.framework_manifests.is_empty()
        && recovered_versions.is_empty();
    if nothing_to_report {
        return Vec::new();
    }

    let mut report = vec!["---\n## Client-Side Attack Surface\n".to_owned()];
    report.push(
        "Reconstructed from passively-retrieved build artifacts. Treat each entry as a \
         manual-test lead, not a confirmed finding.\n"
            .to_owned(),
    );

    render_source_maps(&result.source_maps_intel, &mut report);
    render_manifests(&result.framework_manifests, &mut report);
    render_routes(&result.route_surface, &mut report);
    render_versions(&recovered_versions, &mut report);

    report
}

fn render_source_maps(maps: &[crate::types::SourceMapIntel], report: &mut Vec<String>) {
    if maps.is_empty() {
        return;
    }

    report.push("### Exposed Source Maps\n".to_owned());
    report.push("| Source Map | From Script | Sources | Source Text | Confidence |".to_owned());
    report.push("|------------|-------------|--------:|-------------|------------|".to_owned());
    for map in maps {
        report.push(format!(
            "| `{}` | `{}` | {} | {} | {} |",
            map.map_url,
            map.script_url,
            map.recovered_sources.len(),
            if map.has_sources_content {
                "recovered"
            } else {
                "filenames only"
            },
            confidence_cell(map.confidence.as_ref())
        ));
    }
    report.push(String::new());
}

fn render_manifests(manifests: &[crate::types::FrameworkManifest], report: &mut Vec<String>) {
    if manifests.is_empty() {
        return;
    }

    report.push("### Framework Manifests\n".to_owned());
    report.push("| Framework | Manifest | Routes | Build ID |".to_owned());
    report.push("|-----------|----------|-------:|----------|".to_owned());
    for manifest in manifests {
        report.push(format!(
            "| {} | {} | {} | {} |",
            manifest.framework,
            manifest.manifest_type,
            manifest.routes.len(),
            manifest.build_id.as_deref().unwrap_or("—")
        ));
    }
    report.push(String::new());
}

fn render_routes(routes: &[crate::types::RouteSurface], report: &mut Vec<String>) {
    if routes.is_empty() {
        return;
    }

    report.push("### Recovered Route Surface\n".to_owned());
    report.push("| Path | Kind | Dynamic | Source | Confidence |".to_owned());
    report.push("|------|------|:-------:|--------|------------|".to_owned());
    let mut ordered: Vec<&crate::types::RouteSurface> = routes.iter().collect();
    ordered.sort_by_key(|r| std::cmp::Reverse(confidence_sort_key(r.confidence.as_ref())));
    for route in ordered {
        report.push(format!(
            "| `{}` | {} | {} | `{}` | {} |",
            route.path,
            route.kind,
            if route.dynamic { "yes" } else { "no" },
            route.source,
            confidence_cell(route.confidence.as_ref())
        ));
    }
    report.push(String::new());
}

fn render_versions(versions: &[&crate::types::TechnologyVersion], report: &mut Vec<String>) {
    if versions.is_empty() {
        return;
    }

    report.push("### Package Versions Recovered from Source Maps\n".to_owned());
    for tv in versions {
        match &tv.version {
            Some(ver) => report.push(format!("- {} `{}`", tv.name, ver)),
            None => report.push(format!("- {}", tv.name)),
        }
    }
    report.push(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        FrameworkManifest, RouteSurface, ScanResult, SourceMapIntel, TechnologyVersion,
    };

    fn base() -> ScanResult {
        ScanResult::default()
    }

    #[test]
    fn empty_input_renders_nothing() {
        assert!(render_sourcemap_intel(&base()).is_empty());
    }

    #[test]
    fn technology_versions_from_other_methods_do_not_trigger_the_section() {
        let mut result = base();
        result.technology_versions.push(TechnologyVersion {
            name: "React".to_owned(),
            version: Some("18.2.0".to_owned()),
            detection_method: "runtime window object".to_owned(),
        });
        // Only a source-map-derived version (or other P1 data) should open the section.
        assert!(render_sourcemap_intel(&result).is_empty());
    }

    #[test]
    fn renders_source_map_table_with_content_state() {
        let mut result = base();
        result.source_maps_intel.push(SourceMapIntel {
            map_url: "https://app.example.com/main.js.map".to_owned(),
            script_url: "https://app.example.com/main.js".to_owned(),
            recovered_sources: vec!["src/a.ts".to_owned(), "src/b.ts".to_owned()],
            has_sources_content: true,
            confidence: None,
        });
        result.source_maps_intel.push(SourceMapIntel {
            map_url: "https://app.example.com/vendor.js.map".to_owned(),
            script_url: "https://app.example.com/vendor.js".to_owned(),
            recovered_sources: vec!["v.js".to_owned()],
            has_sources_content: false,
            confidence: None,
        });

        let md = render_sourcemap_intel(&result).join("\n");
        assert!(md.contains("## Client-Side Attack Surface"));
        assert!(md.contains("### Exposed Source Maps"));
        assert!(md.contains("`https://app.example.com/main.js.map`"));
        assert!(md.contains("recovered"));
        assert!(md.contains("filenames only"));
        // 2 sources counted for the first map.
        assert!(md.contains("| 2 |"));
    }

    #[test]
    fn renders_manifest_and_route_tables() {
        let mut result = base();
        result.framework_manifests.push(FrameworkManifest {
            framework: "Next.js".to_owned(),
            manifest_type: "__BUILD_MANIFEST".to_owned(),
            routes: vec!["/".to_owned(), "/admin".to_owned()],
            build_id: Some("abc123".to_owned()),
            confidence: None,
        });
        result.route_surface.push(RouteSurface {
            path: "/admin/[id]".to_owned(),
            kind: "route".to_owned(),
            source: "https://app.example.com/main.js.map".to_owned(),
            dynamic: true,
            confidence: None,
        });

        let md = render_sourcemap_intel(&result).join("\n");
        assert!(md.contains("### Framework Manifests"));
        assert!(md.contains("Next.js"));
        assert!(md.contains("abc123"));
        assert!(md.contains("### Recovered Route Surface"));
        assert!(md.contains("`/admin/[id]`"));
        // Dynamic flag rendered as yes.
        assert!(md.contains("| yes |"));
    }

    #[test]
    fn manifest_without_build_id_renders_dash() {
        let mut result = base();
        result.framework_manifests.push(FrameworkManifest {
            framework: "Remix".to_owned(),
            manifest_type: "__remixManifest".to_owned(),
            routes: vec!["/login".to_owned()],
            build_id: None,
            confidence: None,
        });
        let md = render_sourcemap_intel(&result).join("\n");
        assert!(md.contains("| — |"));
    }

    #[test]
    fn renders_only_source_map_recovered_versions() {
        let mut result = base();
        result.technology_versions.push(TechnologyVersion {
            name: "next".to_owned(),
            version: Some("14.1.0".to_owned()),
            detection_method: SOURCE_MAP_VERSION_METHOD.to_owned(),
        });
        result.technology_versions.push(TechnologyVersion {
            name: "react".to_owned(),
            version: Some("18.2.0".to_owned()),
            detection_method: "runtime window object".to_owned(),
        });

        let md = render_sourcemap_intel(&result).join("\n");
        assert!(md.contains("### Package Versions Recovered from Source Maps"));
        assert!(md.contains("next `14.1.0`"));
        // The runtime-derived version belongs to the technology section, not here.
        assert!(!md.contains("react `18.2.0`"));
    }

    #[test]
    fn version_without_a_number_renders_name_only() {
        let mut result = base();
        result.technology_versions.push(TechnologyVersion {
            name: "lodash".to_owned(),
            version: None,
            detection_method: SOURCE_MAP_VERSION_METHOD.to_owned(),
        });
        let md = render_sourcemap_intel(&result).join("\n");
        assert!(md.contains("- lodash"));
        assert!(!md.contains("lodash `"));
    }
}
