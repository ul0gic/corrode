// Does:  Checks version boundaries for React Server Components advisories.
// Holds: A patch for one advisory can leave another advisory applicable.

use corrode_scanner::detectors::vulnerabilities::react::detect_rsc_vulns;

const SRC: &str = "https://app.example.com/_next/static/chunk.js";

fn vuln_types(text: &str) -> Vec<String> {
    detect_rsc_vulns(text, SRC)
        .into_iter()
        .map(|v| v.vuln_type)
        .collect()
}

fn flags_rce(text: &str) -> bool {
    vuln_types(text)
        .iter()
        .any(|t| t.contains("CVE-2025-55182"))
}

fn flags_source_exposure(text: &str) -> bool {
    vuln_types(text)
        .iter()
        .any(|t| t.contains("CVE-2025-55183"))
}

fn flags_dos_2026(text: &str) -> bool {
    vuln_types(text)
        .iter()
        .any(|t| t.contains("CVE-2026-23864"))
}

#[test]
fn rce_matches_each_affected_version() {
    assert!(flags_rce("react-server-dom-webpack@19.0.0"));
    assert!(flags_rce("react-server-dom-webpack version 19.1.0"));
    assert!(flags_rce("react-server-dom-parcel/19.1.1"));
    assert!(flags_rce("react-server-dom-turbopack@19.2.0"));
}

#[test]
fn rce_emits_critical_severity() {
    let vulns = detect_rsc_vulns("react-server-dom-webpack@19.0.0", SRC);
    let rce = vulns
        .iter()
        .find(|v| v.vuln_type.contains("CVE-2025-55182"))
        .expect("RCE finding present");
    assert_eq!(rce.severity, "critical");
    assert_eq!(rce.url.as_deref(), Some(SRC));
}

#[test]
fn rce_rejects_patched_versions() {
    assert!(!flags_rce("react-server-dom-webpack@19.0.1"));
    assert!(!flags_rce("react-server-dom-webpack@19.1.2"));
    assert!(!flags_rce("react-server-dom-webpack@19.2.1"));
}

#[test]
fn rce_rejects_pre_rsc_react_18() {
    assert!(!flags_rce("react-server-dom-webpack@18.2.0"));
}

#[test]
fn rce_tolerates_minified_separators() {
    assert!(flags_rce("react-server-dom-webpack/19.2.0"));
    assert!(flags_rce("react-server-dom-webpack 19.2.0"));
    assert!(flags_rce("react-server-dom-webpack:19.2.0"));
}

#[test]
fn rce_matches_all_bundlers() {
    assert!(flags_rce("react-server-dom-webpack@19.2.0"));
    assert!(flags_rce("react-server-dom-parcel@19.2.0"));
    assert!(flags_rce("react-server-dom-turbopack@19.2.0"));
}

#[test]
fn source_exposure_matches_affected_boundary_versions() {
    assert!(flags_source_exposure("react-server-dom-webpack@19.0.0"));
    assert!(flags_source_exposure("react-server-dom-webpack@19.0.2"));
    assert!(flags_source_exposure("react-server-dom-webpack@19.1.3"));
    assert!(flags_source_exposure("react-server-dom-webpack@19.2.2"));
}

#[test]
fn source_exposure_rejects_patched_versions() {
    assert!(!flags_source_exposure("react-server-dom-webpack@19.0.3"));
    assert!(!flags_source_exposure("react-server-dom-webpack@19.1.4"));
    assert!(!flags_source_exposure("react-server-dom-webpack@19.2.3"));
}

#[test]
fn source_exposure_rejects_pre_rsc_react_18() {
    assert!(!flags_source_exposure("react-server-dom-webpack@18.2.0"));
}

#[test]
fn source_exposure_matches_all_bundlers() {
    assert!(flags_source_exposure("react-server-dom-webpack@19.1.3"));
    assert!(flags_source_exposure("react-server-dom-parcel@19.1.3"));
    assert!(flags_source_exposure("react-server-dom-turbopack@19.1.3"));
}

#[test]
fn dos_2026_matches_affected_boundary_versions() {
    assert!(flags_dos_2026("react-server-dom-webpack@19.0.0"));
    assert!(flags_dos_2026("react-server-dom-webpack@19.0.3"));
    assert!(flags_dos_2026("react-server-dom-webpack@19.1.4"));
    assert!(flags_dos_2026("react-server-dom-webpack@19.2.3"));
}

#[test]
fn dos_2026_rejects_patched_versions() {
    assert!(!flags_dos_2026("react-server-dom-webpack@19.0.4"));
    assert!(!flags_dos_2026("react-server-dom-webpack@19.1.5"));
    assert!(!flags_dos_2026("react-server-dom-webpack@19.2.4"));
}

#[test]
fn dos_2026_rejects_pre_rsc_react_18() {
    assert!(!flags_dos_2026("react-server-dom-webpack@18.2.0"));
}

#[test]
fn dos_2026_matches_all_bundlers() {
    assert!(flags_dos_2026("react-server-dom-webpack@19.2.3"));
    assert!(flags_dos_2026("react-server-dom-parcel@19.2.3"));
    assert!(flags_dos_2026("react-server-dom-turbopack@19.2.3"));
}

#[test]
fn version_19_2_1_is_exposure_and_dos_but_not_rce() {
    let text = "react-server-dom-webpack@19.2.1";
    assert!(!flags_rce(text), "19.2.1 is patched for RCE");
    assert!(
        flags_source_exposure(text),
        "19.2.1 still has source exposure"
    );
}

#[test]
fn version_19_2_3_is_dos_2026_but_not_source_exposure() {
    let text = "react-server-dom-webpack@19.2.3";
    assert!(
        !flags_source_exposure(text),
        "19.2.3 patched for source exposure"
    );
    assert!(flags_dos_2026(text), "19.2.3 still has the 2026 DoS");
}

#[test]
fn version_19_2_4_is_patched_for_all_cves() {
    let text = "react-server-dom-webpack@19.2.4";
    assert!(!flags_rce(text));
    assert!(!flags_source_exposure(text));
    assert!(!flags_dos_2026(text));
    assert!(detect_rsc_vulns(text, SRC).is_empty());
}

#[test]
fn non_rsc_text_yields_no_findings() {
    assert!(detect_rsc_vulns("function render(){ return 1; }", SRC).is_empty());
    assert!(detect_rsc_vulns("", SRC).is_empty());
}
