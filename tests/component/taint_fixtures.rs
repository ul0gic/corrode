// Does:  Checks data flow through scripts in the component fixtures.
// Holds: Safe DOM writes and constant values must stay out of the taint findings.

use corrode_scanner::detectors::taint;

fn analyze(html: &str) -> Vec<corrode_scanner::types::TaintFlow> {
    let scripts = super::scripts(html, "https://example.com/fixture.html");
    taint::analyze(&scripts)
}

#[test]
fn dom_xss_fixture_pairs_sources_with_dangerous_sinks() {
    let flows = analyze(include_str!("../fixtures/taint/dom-xss-flow.html"));
    assert!(!flows.is_empty(), "fixture must produce taint flows");
    assert!(
        flows
            .iter()
            .any(|f| f.source.contains("location") || f.source.contains("localStorage")),
        "a recovered flow must originate at a URL/storage source"
    );
}

#[test]
fn dom_xss_fixture_covers_each_dangerous_sink_kind() {
    let flows = analyze(include_str!("../fixtures/taint/dom-xss-flow.html"));
    let sinks: Vec<&str> = flows.iter().map(|f| f.sink.as_str()).collect();

    assert!(sinks.iter().any(|s| s.contains("innerHTML")), "{sinks:?}");
    assert!(sinks.iter().any(|s| s.contains("eval")), "{sinks:?}");
    assert!(sinks.iter().any(|s| s.contains("srcdoc")), "{sinks:?}");
    assert!(
        sinks.iter().any(|s| s.contains("setAttribute")),
        "navigation sink: {sinks:?}"
    );
    assert!(
        sinks.iter().any(|s| s.contains("write")),
        "document.write sink: {sinks:?}"
    );
}

#[test]
fn dom_xss_fixture_suppresses_safe_and_constant_sinks() {
    let flows = analyze(include_str!("../fixtures/taint/dom-xss-flow.html"));
    assert!(
        !flows.iter().any(|f| f.sink.contains("textContent")),
        "safe sink must not be reported: {flows:?}"
    );
    let inner_html = flows
        .iter()
        .filter(|f| f.sink.contains("innerHTML"))
        .count();
    assert_eq!(
        inner_html, 1,
        "only the tainted innerHTML is a flow: {flows:?}"
    );
}
