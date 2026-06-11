mod appendix;
mod findings;
mod network;
mod security;
mod sourcemaps;
pub mod summary;
mod taint;
mod technologies;

use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::ScanResult;

pub fn write(result: &ScanResult, base_output_dir: &Path) -> Result<()> {
    let mut report = Vec::new();

    // Report header
    report.push("# Corrode Security Scan Report\n".to_owned());
    report.push(format!("**Target**: {}", result.url));
    report.push(format!("**Scan Date**: {}", result.timestamp));
    report.push(format!(
        "**Scanner**: Corrode v{}\n",
        env!("CARGO_PKG_VERSION")
    ));

    // Sections (ordered for operator workflow)
    report.extend(summary::render_summary(result));
    report.extend(findings::render_secrets(result));
    report.extend(security::render_security_posture(result));
    report.extend(findings::render_api_tests(result));
    report.extend(technologies::render_technologies(result));
    report.extend(network::render_network(result));
    report.extend(technologies::render_dom(result)?);
    report.extend(sourcemaps::render_sourcemap_intel(result));
    report.extend(taint::render_taint(result));
    report.extend(appendix::render_appendix(result));
    report.extend(appendix::render_recommendations(result));

    // Write to file
    let domain = url::Url::parse(&result.url)
        .ok()
        .and_then(|u| u.host_str().map(std::borrow::ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
        .replace('.', "-");

    let site_dir = base_output_dir.join(&domain);
    fs::create_dir_all(&site_dir)?;

    let report_path = site_dir.join("REPORT.md");
    fs::write(report_path, report.join("\n"))?;

    Ok(())
}

#[cfg(test)]
mod e2e_tests {
    use crate::detectors::scoring::score_all;
    use crate::reporting::json;
    use crate::types::{
        Gadget, PostMessageHandler, RouteSurface, ScanResult, SecretFinding, SourceMapIntel,
        TaintFlow, Vulnerability,
    };

    /// A representative result spanning every scored finding type, used to
    /// exercise the full report render in the e2e tests.
    fn fixture() -> ScanResult {
        let mut result = ScanResult {
            url: "https://app.example.com".to_owned(),
            timestamp: "2026-06-11T00:00:00Z".to_owned(),
            ..ScanResult::default()
        };

        // Strong: service_role JWT seen in a window object, high-entropy value.
        let jwt = "eyJhbGciOiJIUzI1NiJ9.aGVsbG93b3JsZGZvb2JhcnF1eA.signaturepart";
        result.secrets.insert(
            "supabase_service_role".to_owned(),
            vec![SecretFinding {
                source: "Window Object: __SUPABASE__".to_owned(),
                matches: vec![jwt.to_owned()],
                confidence: None,
            }],
        );
        // Suppressed placeholder.
        result.secrets.insert(
            "aws_key".to_owned(),
            vec![SecretFinding {
                source: "HTML".to_owned(),
                matches: vec!["AKIAIOSFODNN7EXAMPLE".to_owned()],
                confidence: None,
            }],
        );

        result.vulnerabilities.push(Vulnerability {
            vuln_type: "Outdated Next.js".to_owned(),
            severity: "high".to_owned(),
            description: "Observed next 14.0.0".to_owned(),
            remediation: "upgrade".to_owned(),
            url: Some("https://app.example.com/_next/static/chunk.js".to_owned()),
            confidence: None,
        });

        result.source_maps_intel.push(SourceMapIntel {
            map_url: "https://app.example.com/main.js.map".to_owned(),
            script_url: "https://app.example.com/main.js".to_owned(),
            recovered_sources: vec!["src/a.ts".to_owned(), "src/b.ts".to_owned()],
            has_sources_content: true,
            confidence: None,
        });
        result.route_surface.push(RouteSurface {
            path: "/admin".to_owned(),
            kind: "route".to_owned(),
            source: "https://app.example.com/main.js.map".to_owned(),
            dynamic: false,
            confidence: None,
        });

        // Static taint flow (third-party, navigation-only) → low.
        result.taint_flows.push(TaintFlow {
            source: "location.search".to_owned(),
            sink: "location.assign(...)".to_owned(),
            path: vec![],
            script_url: "https://cdn.thirdparty.io/x.js".to_owned(),
            location: "x.js:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        });
        // Runtime-observed taint flow (first-party, HTML sink) → high.
        result.taint_flows.push(TaintFlow {
            source: "location.hash".to_owned(),
            sink: "innerHTML".to_owned(),
            path: vec!["redirect".to_owned()],
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "main.js:10:5".to_owned(),
            runtime_observed: true,
            confidence: None,
        });
        result.gadgets.push(Gadget {
            category: "dom-xss".to_owned(),
            description: "location.hash → innerHTML".to_owned(),
            script_url: "https://app.example.com/main.js".to_owned(),
            exploitability_hint: "CSP allows unsafe-inline near the sink".to_owned(),
            confidence: None,
        });
        // Strict-origin postMessage → low.
        result.post_message_handlers.push(PostMessageHandler {
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "main.js:3:1".to_owned(),
            origin_check: "strict".to_owned(),
            reaches_sink: false,
            confidence: None,
        });

        result
    }

    #[test]
    fn confidence_labels_render_in_markdown() {
        let mut result = fixture();
        score_all(&mut result, Some("example.com"));

        let mut md = Vec::new();
        md.extend(super::findings::render_secrets(&result));
        md.extend(super::sourcemaps::render_sourcemap_intel(&result));
        md.extend(super::taint::render_taint(&result));
        let md = md.join("\n");

        // Severity × confidence appears on findings.
        assert!(md.contains("severity / High confidence"));
        // Confidence columns appear in the taint and source-map tables.
        assert!(md.contains("| Confidence |"));
        // The high-confidence runtime flow outranks the low static one: its row
        // (innerHTML) must appear before the location.assign row.
        let high = md.find("innerHTML").expect("high flow present");
        let low = md.find("location.assign").expect("low flow present");
        assert!(high < low, "high-confidence flow should sort first");
    }

    #[test]
    fn confidence_serializes_in_json() {
        let mut result = fixture();
        score_all(&mut result, Some("example.com"));

        let dir = std::env::temp_dir().join("corrode_e2e_json");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("scan_result.json");
        json::write(&path, &result).expect("write json");

        let raw = std::fs::read_to_string(&path).expect("read json");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse json");

        assert_eq!(parsed["schema_version"], "0.4");
        // The strong secret scored High; the placeholder was suppressed to Low.
        assert_eq!(
            parsed["secrets"]["supabase_service_role"][0]["confidence"]["level"],
            "high"
        );
        assert_eq!(
            parsed["secrets"]["aws_key"][0]["confidence"]["level"],
            "low"
        );
        // Every collection carries a confidence object once scored.
        assert!(parsed["taint_flows"][0]["confidence"]["level"].is_string());
        assert!(parsed["post_message_handlers"][0]["confidence"]["level"].is_string());
    }
}
