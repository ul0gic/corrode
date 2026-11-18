// Does:  Checks how script findings combine with origin checks and page policies.
// Holds: A nonce-bearing policy must suppress the permissive inline-script correlation.

use corrode_scanner::detectors::taint::{gadgets, postmessage, proto};

const URL: &str = "https://example.com/fixture.html";

#[test]
fn postmessage_fixture_recovers_handlers_across_origin_postures() {
    let scripts = super::scripts(
        include_str!("../fixtures/taint/postmessage-handlers.html"),
        URL,
    );
    let handlers = postmessage::detect(&scripts);

    assert!(!handlers.is_empty(), "fixture has message handlers");
    let postures: Vec<&str> = handlers.iter().map(|h| h.origin_check.as_str()).collect();
    assert!(
        postures.contains(&"none"),
        "missing-check handler: {postures:?}"
    );
    assert!(
        postures.contains(&"weak"),
        "substring/prefix check: {postures:?}"
    );
    assert!(
        postures.contains(&"strict"),
        "exact-match check: {postures:?}"
    );
}

#[test]
fn weak_and_missing_origin_handlers_reach_a_sink() {
    let scripts = super::scripts(
        include_str!("../fixtures/taint/postmessage-handlers.html"),
        URL,
    );
    let handlers = postmessage::detect(&scripts);
    assert!(
        handlers
            .iter()
            .any(|h| h.origin_check != "strict" && h.reaches_sink),
        "a weak/absent-origin handler must be recorded reaching a sink: {handlers:?}"
    );
}

#[test]
fn proto_fixture_recovers_pollution_surfaces_from_tainted_sources() {
    let scripts = super::scripts(include_str!("../fixtures/taint/proto-pollution.html"), URL);
    let findings = proto::detect(&scripts);
    assert!(
        !findings.is_empty(),
        "merge/deep-set helpers fed from URL sources must surface"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.source().contains("location") || f.source().contains("URLSearchParams")),
        "a pollution surface must originate at a URL-derived source: {:?}",
        findings
            .iter()
            .map(proto::ProtoFinding::source)
            .collect::<Vec<_>>()
    );
}

#[test]
fn dom_xss_fixture_yields_gadgets() {
    let scripts = super::scripts(include_str!("../fixtures/taint/dom-xss-flow.html"), URL);
    let gadgets = gadgets::inventory(&scripts, None);
    assert!(
        gadgets.iter().any(|g| g.category == "dom-xss"),
        "DOM-XSS gadget expected: {:?}",
        gadgets.iter().map(|g| &g.category).collect::<Vec<_>>()
    );
}

#[test]
fn permissive_csp_with_matching_sink_emits_a_bypass_gadget() {
    let scripts = super::scripts(include_str!("../fixtures/taint/csp-correlation.html"), URL);
    let policy = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:";
    let gadgets = gadgets::inventory(&scripts, Some(policy));
    assert!(
        gadgets.iter().any(|g| g.category == "csp-bypass"),
        "permissive CSP + HTML/code sink must correlate: {:?}",
        gadgets.iter().map(|g| &g.category).collect::<Vec<_>>()
    );
}

#[test]
fn nonce_csp_does_not_emit_a_bypass_gadget() {
    let scripts = super::scripts(include_str!("../fixtures/taint/csp-correlation.html"), URL);
    let policy = "script-src 'self' 'unsafe-inline' 'nonce-abc123'";
    let gadgets = gadgets::inventory(&scripts, Some(policy));
    assert!(
        !gadgets.iter().any(|g| g.category == "csp-bypass"),
        "nonce must neutralize the unsafe-inline correlation: {:?}",
        gadgets.iter().map(|g| &g.category).collect::<Vec<_>>()
    );
}
