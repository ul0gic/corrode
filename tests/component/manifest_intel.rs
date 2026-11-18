// Does:  Checks route recovery and advisory classification from framework artifacts.
// Holds: Flight markers alone establish a surface without confirming a vulnerable version.

use std::collections::HashMap;

use corrode_scanner::detectors::manifests;
use corrode_scanner::detectors::sourcemaps::retrieve;
use corrode_scanner::detectors::vulnerabilities::rsc;

fn windows(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn next_build_manifest_recovers_admin_api_and_dynamic_routes() {
    let w = windows(&[(
        "__BUILD_MANIFEST",
        include_str!("../fixtures/manifests/next-build-manifest.json"),
    )]);
    let report = manifests::analyze(&w, &["Next.js".to_owned()], &[], &[]);

    let paths: std::collections::HashSet<_> =
        report.routes.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains("/admin"), "{paths:?}");
    assert!(paths.contains("/admin/billing"), "{paths:?}");
    assert!(paths.contains("/api/login"), "{paths:?}");
    assert!(
        report
            .routes
            .iter()
            .any(|r| r.path == "/users/[id]" && r.dynamic),
        "dynamic route must be flagged: {:?}",
        report.routes
    );
}

#[test]
fn garbage_manifest_degrades_without_panic() {
    let w = windows(&[("__BUILD_MANIFEST", r#"{"/admin": ["chunk.js"}"#)]);
    let report = manifests::analyze(&w, &["Next.js".to_owned()], &[], &[]);
    assert!(report.routes.is_empty());
    assert!(report.manifests.is_empty());
}

#[test]
fn remix_context_recovers_nested_route_paths() {
    let w = windows(&[(
        "__remixContext",
        include_str!("../fixtures/manifests/remix-context.json"),
    )]);
    let report = manifests::analyze(&w, &["Remix".to_owned()], &[], &[]);

    let paths: std::collections::HashSet<_> =
        report.routes.iter().map(|r| r.path.as_str()).collect();
    assert!(paths.contains("/login"), "{paths:?}");
    assert!(paths.contains("/dashboard/settings"), "{paths:?}");
}

#[test]
fn flight_fixture_fingerprints_app_router_surface() {
    let js = include_str!("../fixtures/rsc/next-flight.js");
    let scripts = [(js, "https://app.example.com/page.js")];
    let surface = rsc::fingerprint(&scripts, &HashMap::new());

    assert!(surface.flight_markers);
    assert!(surface.app_router);
    assert!(surface.server_dom, "react-server-dom bridge referenced");
}

#[test]
fn flight_fixture_without_version_emits_inferred_advisory_only() {
    let js = include_str!("../fixtures/rsc/next-flight.js");
    let scripts = [(js, "https://app.example.com/page.js")];
    let vulns = rsc::detect(&scripts, &HashMap::new());

    assert_eq!(vulns.len(), 1, "{vulns:?}");
    let advisory = vulns.first().expect("inferred advisory");
    assert_eq!(advisory.severity, "info");
    assert!(advisory.description.starts_with("inferred:"));
}

#[test]
fn scope_allows_same_host_and_subdomains() {
    let referrer = "https://example.com/app.js";
    assert!(retrieve::classify(referrer, "app.js.map", Some("example.com"), 0).is_ok());

    let cdn = "https://cdn.example.com/app.js";
    assert!(retrieve::classify(cdn, "app.js.map", Some("example.com"), 0).is_ok());
}
