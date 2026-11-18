// Does:  Checks benign and empty inputs across the page detectors.
// Holds: Ordinary scripts must not generate actionable findings.

use std::collections::HashMap;

use corrode_scanner::detectors::taint::{self, gadgets, postmessage, proto};
use corrode_scanner::detectors::{manifests, vulnerabilities::rsc};

const URL: &str = "https://example.com/benign.html";

#[test]
fn benign_page_yields_no_taint_findings() {
    let scripts = super::scripts(
        include_str!("../fixtures/taint/benign-no-findings.html"),
        URL,
    );

    assert!(taint::analyze(&scripts).is_empty());
    assert!(proto::detect(&scripts).is_empty());
    assert!(gadgets::inventory(&scripts, None).is_empty());
    assert!(postmessage::detect(&scripts).is_empty());
}

#[test]
fn benign_page_yields_no_manifest_or_rsc_surface() {
    let report = manifests::analyze(&HashMap::new(), &["React".to_owned()], &[], &[]);
    assert!(report.routes.is_empty());
    assert!(report.manifests.is_empty());

    let scripts = super::scripts(
        include_str!("../fixtures/taint/benign-no-findings.html"),
        URL,
    );
    let vulns = rsc::detect(&scripts, &HashMap::new());
    assert!(vulns.is_empty(), "{vulns:?}");
}

#[test]
fn empty_input_degrades_across_detectors_without_panic() {
    let empty: [(&str, &str); 0] = [];
    assert!(taint::analyze(&empty).is_empty());
    assert!(proto::detect(&empty).is_empty());
    assert!(postmessage::detect(&empty).is_empty());
    assert!(gadgets::inventory(&empty, None).is_empty());
    assert!(rsc::detect(&empty, &HashMap::new()).is_empty());
}
