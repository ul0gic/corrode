use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::LazyLock;

use regex::Regex;

use super::react::detect_rsc_vulns;
use crate::types::{AssessmentDisposition, EvidenceSource, FindingEvidence, Vulnerability};

// `self.__next_f.push(...)` / bare `__next_f` Flight-stream bootstrap, plus the
// `N:` row prefixes the Flight wire format emits. These are App-Router-only.
#[allow(clippy::unwrap_used)]
static FLIGHT_PUSH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:self\.)?__next_f\s*(?:\.push|\[)").unwrap());

// The RSC client/server bridge; its presence alone is RSC evidence, version graded by `react.rs`.
#[allow(clippy::unwrap_used)]
static SERVER_DOM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"react-server-dom-(?:webpack|parcel|turbopack)").unwrap());

// Server-action runtime markers. `createServerReference` / `callServer` are the
// client-side entry points; the `$$typeof` action sentinel appears in bundles.
#[allow(clippy::unwrap_used)]
static SERVER_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"createServerReference|callServerReference|\bcallServer\b|react\.server\.reference")
        .unwrap()
});

/// Independent RSC presence signals, not state-machine phases — any subset can co-occur,
/// so a flat bool struct is the honest shape.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RscSurface {
    pub flight_markers: bool,
    pub server_dom: bool,
    pub server_actions: bool,
    pub app_router: bool,
    pub pages_router: bool,
}

impl RscSurface {
    /// Corroborated RSC surface — Flight, server-dom, or server-action markers;
    /// a lone `_rsc=` query string is deliberately not enough (see [`detect`]).
    fn is_present(&self) -> bool {
        self.flight_markers || self.server_dom || self.server_actions
    }
}

/// Fingerprint the RSC surface from script text and captured window globals.
/// `scripts` are `(text, source_url)` slices, matching [`super::react`]'s shape.
pub fn fingerprint<S: BuildHasher>(
    scripts: &[(&str, &str)],
    window_objects: &HashMap<String, String, S>,
) -> RscSurface {
    let mut surface = RscSurface::default();

    // `__next_f` is the App Router Flight bootstrap; if the collector captured it
    // as a window global that alone establishes App Router + Flight.
    if window_objects.keys().any(|k| k == "__next_f") {
        surface.flight_markers = true;
        surface.app_router = true;
    }
    // `__NEXT_DATA__` without `__next_f` is the Pages Router shape.
    if window_objects.keys().any(|k| k == "__NEXT_DATA__") {
        surface.pages_router = true;
    }

    for (text, _) in scripts {
        if FLIGHT_PUSH_RE.is_match(text) {
            surface.flight_markers = true;
            surface.app_router = true;
        }
        if SERVER_DOM_RE.is_match(text) {
            surface.server_dom = true;
        }
        if SERVER_ACTION_RE.is_match(text) {
            surface.server_actions = true;
        }
    }

    surface
}

/// Two evidence tiers kept distinct in text and severity: observed (graded CVEs from
/// [`detect_rsc_vulns`]) vs inferred (a low-severity lead when the surface but no version is seen).
pub fn detect<S: BuildHasher>(
    scripts: &[(&str, &str)],
    window_objects: &HashMap<String, String, S>,
) -> Vec<Vulnerability> {
    let surface = fingerprint(scripts, window_objects);

    // Observed: reuse react.rs verbatim over each script. De-dupe identical
    // findings that recur across multiple scripts (same vuln_type + version text).
    let mut vulns: Vec<Vulnerability> = Vec::new();
    let mut observed_version = false;
    for (text, source) in scripts {
        for v in detect_rsc_vulns(text, source) {
            observed_version = true;
            if !vulns
                .iter()
                .any(|e| e.vuln_type == v.vuln_type && e.description == v.description)
            {
                vulns.push(v);
            }
        }
    }

    // Inferred advisory only when (a) no concrete version was observed, and
    // (b) we have a corroborated RSC surface — never on a bare `_rsc=` query.
    if !observed_version && surface.is_present() {
        vulns.push(inferred_advisory(&surface));
    }

    vulns
}

fn inferred_advisory(surface: &RscSurface) -> Vulnerability {
    let mut evidence_labels = Vec::new();
    if surface.app_router {
        evidence_labels.push("App Router");
    }
    if surface.flight_markers {
        evidence_labels.push("Flight stream (__next_f)");
    }
    if surface.server_dom {
        evidence_labels.push("react-server-dom-*");
    }
    if surface.server_actions {
        evidence_labels.push("server-action markers");
    }
    let evidence_summary = evidence_labels.join(", ");

    Vulnerability {
        vuln_type: "React RSC surface (advisory — version unknown)".to_owned(),
        // Inferred, version-unknown: advisory-only, intentionally low so it does
        // not inflate severity rollups alongside observed CVE findings.
        severity: "info".to_owned(),
        description: format!(
            "inferred: RSC/App Router surface detected ({evidence_summary}), version unknown — verify the \
             react-server-dom-* version against the CVE cluster CVE-2025-55182 (RCE), \
             CVE-2025-55183 (source exposure), CVE-2025-55184/CVE-2025-67779 and \
             CVE-2026-23864 (DoS). No vulnerable version was observed on this page."
        ),
        remediation: "Determine the react-server-dom-* version (build manifests, bundle, or \
                      framework release notes) and confirm it is patched to 19.0.4/19.1.5/19.2.4 \
                      or later."
            .to_owned(),
        url: None,
        disposition: AssessmentDisposition::Lead,
        evidence: vec![FindingEvidence {
            source: EvidenceSource::Ast,
            location: None,
            summary: evidence_summary,
        }],
        confidence: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_windows() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn observed_vulnerable_version_emits_concrete_cve_not_advisory() {
        let script = r#"import x from "react-server-dom-webpack@19.0.0/client";"#;
        let scripts = [(script, "https://app.example.com/_next/static/chunk.js")];
        let vulns = detect(&scripts, &no_windows());

        // The critical RCE finding from react.rs must be present...
        assert!(vulns
            .iter()
            .any(|v| v.vuln_type.contains("CVE-2025-55182") && v.severity == "critical"));
        // ...and no inferred advisory, because a version was observed.
        assert!(!vulns.iter().any(|v| v.severity == "info"));
    }

    #[test]
    fn inferred_app_router_surface_emits_low_severity_advisory_only() {
        let script = r#"self.__next_f.push([1,"app/dashboard/page"]);"#;
        let scripts = [(script, "https://app.example.com/page.js")];
        let vulns = detect(&scripts, &no_windows());

        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
        assert!(vulns[0].description.starts_with("inferred:"));
        assert!(vulns[0].description.contains("App Router"));
        assert!(vulns[0].description.contains("Flight stream"));
        assert!(vulns[0].url.is_none());
    }

    #[test]
    fn flight_global_alone_establishes_app_router_inferred_surface() {
        let mut windows = HashMap::new();
        windows.insert("__next_f".to_owned(), "[[1,\"...\"]]".to_owned());
        let vulns = detect(&[], &windows);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
    }

    #[test]
    fn server_dom_without_version_is_inferred_evidence() {
        // server-dom present but no parseable version => surface, not a CVE.
        let script = "var a = require('react-server-dom-turbopack/client.edge');";
        let scripts = [(script, "https://app.example.com/v.js")];
        let vulns = detect(&scripts, &no_windows());
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
        assert!(vulns[0].description.contains("react-server-dom-*"));
    }

    #[test]
    fn pages_router_only_is_a_negative() {
        // Classic Pages Router (__NEXT_DATA__, no Flight / server-dom / actions)
        // is not an RSC surface and must produce no findings.
        let mut windows = HashMap::new();
        windows.insert("__NEXT_DATA__".to_owned(), r#"{"buildId":"x"}"#.to_owned());
        let script = "function render(){ return React.createElement('div'); }";
        let scripts = [(script, "https://app.example.com/main.js")];
        let vulns = detect(&scripts, &windows);
        assert!(vulns.is_empty());

        let surface = fingerprint(&scripts, &windows);
        assert!(surface.pages_router);
        assert!(!surface.app_router);
        assert!(!surface.is_present());
    }

    #[test]
    fn bare_rsc_query_marker_is_not_enough() {
        // `?_rsc=` in a URL string with no Flight/server-dom/action corroboration
        // is too weak to assert an RSC surface — suppressed to avoid FPs.
        let script = r#"fetch("/dashboard?_rsc=abcd1234");"#;
        let scripts = [(script, "https://app.example.com/router.js")];
        let vulns = detect(&scripts, &no_windows());
        assert!(vulns.is_empty());
    }

    #[test]
    fn server_action_markers_alone_are_a_surface() {
        let script = "const ref = createServerReference('a1b2', callServer);";
        let scripts = [(script, "https://app.example.com/actions.js")];
        let vulns = detect(&scripts, &no_windows());
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
        assert!(vulns[0].description.contains("server-action markers"));
    }

    #[test]
    fn malformed_flight_payload_degrades_gracefully() {
        // Truncated/garbage Flight bootstrap: the push marker still fingerprints
        // the surface, and nothing panics on the unbalanced JSON-ish payload.
        let script = r#"self.__next_f.push([1,"2:[\"$\",\"div\",{"#;
        let scripts = [(script, "https://app.example.com/trunc.js")];
        let vulns = detect(&scripts, &no_windows());
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
    }

    #[test]
    fn duplicate_observed_findings_across_scripts_are_deduped() {
        let s = r"react-server-dom-webpack@19.0.0";
        let scripts = [
            (s, "https://app.example.com/a.js"),
            (s, "https://app.example.com/b.js"),
        ];
        let vulns = detect(&scripts, &no_windows());
        let rce = vulns
            .iter()
            .filter(|v| v.vuln_type.contains("CVE-2025-55182"))
            .count();
        assert_eq!(rce, 1, "identical RCE finding from two scripts must dedupe");
    }

    #[test]
    fn empty_inputs_yield_nothing() {
        let vulns = detect(&[], &no_windows());
        assert!(vulns.is_empty());
    }

    // --- Fixture-backed coverage (task 1.12) ---

    const FIXTURE_NEXT_FLIGHT: &str = r#"(self.__next_f = self.__next_f || []).push([1, "1:HL[\"/_next/static/css/app.css\",\"style\"]\n"]);
self.__next_f.push([1, "2:[[\"$\",\"html\",null,{\"children\":[\"$\",\"body\",null,{}]}]]\n"]);
self.__next_f.push([1, "3:I[\"react-server-dom-webpack/client\",[],\"\"]\n"]);
"#;

    #[test]
    fn fixture_flight_stream_fingerprints_app_router_surface() {
        let scripts = [(FIXTURE_NEXT_FLIGHT, "https://app.example.com/page.js")];
        let surface = fingerprint(&scripts, &no_windows());
        assert!(surface.flight_markers);
        assert!(surface.app_router);
        // The fixture references the server-dom bridge but pins no version.
        assert!(surface.server_dom);

        // Surface present, version unknown => exactly one inferred advisory.
        let vulns = detect(&scripts, &no_windows());
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].severity, "info");
        assert!(vulns[0].description.starts_with("inferred:"));
    }
}
