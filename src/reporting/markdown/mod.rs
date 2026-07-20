mod appendix;
mod assessment;
mod findings;
mod inventory;
mod leads;
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
    let mut report = report_header(result, "Corrode Security Scan Report");

    // Decision-focused report: actionable work first, then leads and inventory.
    report.extend(summary::render_summary(result));
    report.extend(findings::render_findings(result));
    report.extend(findings::render_lead_assessments(result));
    report.extend(leads::render_additional_leads(result));
    report.extend(findings::render_api_tests(result));
    report.extend(inventory::render_inventory(result));
    report.extend(technologies::render_technologies(result));
    report.extend(appendix::render_recommendations(result));
    report.push(
        "---\nFull captured evidence, including raw AST, network, DOM, route, and static-analysis \
         records, is available in [`EVIDENCE.md`](EVIDENCE.md).\n"
            .to_owned(),
    );

    let mut evidence = report_header(result, "Corrode Scan Evidence");
    evidence.push(
        "This companion artifact contains exhaustive passive observations. Entries here are not \
         automatically confirmed vulnerabilities and do not independently determine headline risk.\n"
            .to_owned(),
    );
    evidence.extend(findings::render_evidence_findings(result));
    evidence.extend(security::render_security_posture(result));
    evidence.extend(findings::render_api_tests(result));
    evidence.extend(technologies::render_technologies(result));
    evidence.extend(network::render_network(result));
    evidence.extend(technologies::render_dom(result)?);
    evidence.extend(sourcemaps::render_sourcemap_intel(result));
    evidence.extend(taint::render_taint(result));
    evidence.extend(appendix::render_appendix(result));

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
    let evidence_path = site_dir.join("EVIDENCE.md");
    fs::write(evidence_path, evidence.join("\n"))?;

    Ok(())
}

fn report_header(result: &ScanResult, title: &str) -> Vec<String> {
    vec![
        format!("# {title}\n"),
        format!("**Target**: {}", result.url),
        format!("**Scan Date**: {}", result.timestamp),
        format!("**Scanner**: Corrode v{}\n", env!("CARGO_PKG_VERSION")),
    ]
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
            disposition: crate::types::AssessmentDisposition::Finding,
            evidence: Vec::new(),
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
        md.extend(super::findings::render_findings(&result));
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

        assert_eq!(parsed["schema_version"], "0.5");
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

    #[test]
    fn concise_report_and_exhaustive_evidence_are_split() {
        let mut result = fixture();
        result
            .javascript
            .ast_findings
            .push(crate::types::AstFinding {
                kind: "literal".to_owned(),
                value: "<svg class=\"font-sans\">".to_owned(),
                location: "main.js:1:1".to_owned(),
                context: "Tailwind/SVG literal".to_owned(),
            });
        result
            .security
            .cors_issues
            .push("https://app.example.com/public".to_owned());
        result.vulnerabilities.push(Vulnerability {
            vuln_type: "CORS Misconfiguration".to_owned(),
            severity: "medium".to_owned(),
            description: "Wildcard CORS requires context".to_owned(),
            remediation: "Validate whether credentials or sensitive data are exposed".to_owned(),
            url: None,
            disposition: crate::types::AssessmentDisposition::Lead,
            evidence: Vec::new(),
            confidence: None,
        });
        score_all(&mut result, Some("example.com"));

        let output = std::env::temp_dir().join("corrode_markdown_split");
        super::write(&result, &output).expect("write markdown");
        let site = output.join("app-example-com");
        let report = std::fs::read_to_string(site.join("REPORT.md")).expect("read report");
        let evidence = std::fs::read_to_string(site.join("EVIDENCE.md")).expect("read evidence");

        assert!(report.contains("## Actionable Findings"));
        assert!(report.contains("## Manual Validation Leads"));
        assert!(report.contains("EVIDENCE.md"));
        assert!(!report.contains("JavaScript AST Findings"));
        assert!(!report.contains("Tailwind/SVG literal"));
        assert!(evidence.contains("JavaScript AST Findings"));
        assert!(evidence.contains("Tailwind/SVG literal"));
    }
}
