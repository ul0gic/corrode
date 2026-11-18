// Does:  Checks route and dependency recovery from captured source maps.
// Holds: Missing source text must stay distinguishable from recovered first-party code.

use corrode_scanner::detectors::sourcemaps::{intel, parse};

#[test]
fn with_content_map_recovers_first_party_source_text() {
    let map = parse::parse(include_str!("../fixtures/sourcemaps/with-content.js.map"))
        .expect("valid map");
    assert!(map.has_sources_content());

    let first_party: Vec<_> = map.first_party_with_content().collect();
    assert_eq!(first_party.len(), 3);
    assert!(
        first_party
            .iter()
            .all(|s| !s.path.contains(".pnpm") && !s.path.contains("node_modules")),
        "vendor path must be excluded: {first_party:?}"
    );
    assert!(
        first_party
            .iter()
            .any(|s| s.content.as_deref().is_some_and(|c| c.contains("TODO"))),
        "recovered source text must include the security-relevant TODO"
    );
}

#[test]
fn with_content_map_surfaces_internal_route_and_version() {
    let map = parse::parse(include_str!("../fixtures/sourcemaps/with-content.js.map"))
        .expect("valid map");
    let paths = map.source_paths();

    let routes = intel::extract_routes(&paths, "https://app.example.com/main.js.map");
    assert!(
        routes
            .iter()
            .any(|r| r.dynamic && r.path == "/admin/[id]/route"),
        "the internal admin/[id] route must be recovered: {routes:?}"
    );

    assert!(routes
        .iter()
        .any(|r| r.path == "/page" && r.kind == "route"));
    assert!(!routes.iter().any(|r| r.path.contains("utils")));
    let versions = intel::extract_versions(&paths);
    assert!(
        versions
            .iter()
            .any(|v| v.name == "next" && v.version.as_deref() == Some("14.1.0")),
        "next@14.1.0 must be recovered from the pnpm path: {versions:?}"
    );
}

#[test]
fn filenames_only_map_has_no_source_text() {
    let map = parse::parse(include_str!("../fixtures/sourcemaps/filenames-only.js.map"))
        .expect("valid map");
    assert!(!map.has_sources_content());
    assert_eq!(map.source_paths().len(), 2);
    assert!(map.sources.iter().all(|s| s.content.is_none()));
}

#[test]
fn truncated_map_fails_gracefully_without_panic() {
    assert!(parse::parse(include_str!("../fixtures/sourcemaps/truncated.js.map")).is_err());
}

#[test]
fn minimal_map_yields_no_sources_not_a_panic() {
    let map = parse::parse("{\"version\":3}").expect("minimal map parses");
    assert_eq!(map.source_paths(), Vec::<String>::new());
    assert!(!map.has_sources_content());
}
