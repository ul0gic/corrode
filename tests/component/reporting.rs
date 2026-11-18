// Does:  Checks how scored findings and captured evidence appear in written reports.
// Holds: Confidence survives JSON serialization and the Markdown evidence file retains raw observations.

use corrode_scanner::detectors::scoring::score_all;
use corrode_scanner::reporting::{json, markdown};
use corrode_scanner::types::{
    Gadget, PostMessageHandler, RouteSurface, ScanResult, SecretFinding, SourceMapIntel, TaintFlow,
    Vulnerability,
};

fn output_directory(case: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("corrode-reporting-{case}-{}", std::process::id()));
    std::fs::create_dir(&dir).expect("create isolated report directory");
    dir
}

fn read_markdown(result: &ScanResult, case: &str) -> (String, String) {
    let dir = output_directory(case);
    markdown::write(result, &dir).expect("write markdown");
    let site = dir.join("app-example-com");
    let report = std::fs::read_to_string(site.join("REPORT.md")).expect("read report");
    let evidence = std::fs::read_to_string(site.join("EVIDENCE.md")).expect("read evidence");
    std::fs::remove_dir_all(dir).expect("remove test output");
    (report, evidence)
}

fn fixture() -> ScanResult {
    let mut result = ScanResult {
        url: "https://app.example.com".to_owned(),
        timestamp: "2026-06-11T00:00:00Z".to_owned(),
        ..ScanResult::default()
    };

    let jwt = "eyJhbGciOiJIUzI1NiJ9.aGVsbG93b3JsZGZvb2JhcnF1eA.signaturepart";
    result.secrets.insert(
        "supabase_service_role".to_owned(),
        vec![SecretFinding {
            source: "Window Object: __SUPABASE__".to_owned(),
            matches: vec![jwt.to_owned()],
            confidence: None,
        }],
    );
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
        disposition: corrode_scanner::types::AssessmentDisposition::Finding,
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

    result.taint_flows.push(TaintFlow {
        source: "location.search".to_owned(),
        sink: "location.assign(...)".to_owned(),
        path: vec![],
        script_url: "https://cdn.thirdparty.io/x.js".to_owned(),
        location: "x.js:1:1".to_owned(),
        runtime_observed: false,
        confidence: None,
    });
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

    let (report, evidence) = read_markdown(&result, "confidence-labels");
    assert!(report.contains("severity / High confidence"));
    assert!(evidence.contains("| Source Map | From Script | Sources | Source Text | Confidence |"));
    let (_, flows) = evidence.split_once("### Taint Flows").expect("flow table");
    let high = flows.find("innerHTML").expect("high flow present");
    let low = flows.find("location.assign").expect("low flow present");
    assert!(high < low, "high-confidence flow should sort first");
}

#[test]
fn confidence_serializes_in_json() {
    let mut result = fixture();
    score_all(&mut result, Some("example.com"));

    let dir = output_directory("confidence-json");
    let path = dir.join("scan_result.json");
    json::write(&path, &result).expect("write json");

    let raw = std::fs::read_to_string(&path).expect("read json");
    std::fs::remove_dir_all(dir).expect("remove test output");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse json");

    let string_at = |path: &str| parsed.pointer(path).and_then(serde_json::Value::as_str);
    assert_eq!(string_at("/schema_version"), Some("0.6"));
    assert_eq!(
        string_at("/secrets/supabase_service_role/0/confidence/level"),
        Some("high")
    );
    assert_eq!(
        string_at("/secrets/aws_key/0/confidence/level"),
        Some("low")
    );
    assert!(string_at("/taint_flows/0/confidence/level").is_some());
    assert!(string_at("/post_message_handlers/0/confidence/level").is_some());
}

#[test]
fn concise_report_and_exhaustive_evidence_are_split() {
    let mut result = fixture();
    result
        .javascript
        .ast_findings
        .push(corrode_scanner::types::AstFinding {
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
        disposition: corrode_scanner::types::AssessmentDisposition::Lead,
        evidence: Vec::new(),
        confidence: None,
    });
    score_all(&mut result, Some("example.com"));

    let (report, evidence) = read_markdown(&result, "report-evidence");

    assert!(report.contains("## Actionable Findings"));
    assert!(report.contains("## Manual Validation Leads"));
    assert!(report.contains("EVIDENCE.md"));
    assert!(!report.contains("JavaScript AST Findings"));
    assert!(!report.contains("Tailwind/SVG literal"));
    assert!(evidence.contains("JavaScript AST Findings"));
    assert!(evidence.contains("Tailwind/SVG literal"));
}

#[test]
fn partial_deployment_reports_match_missing_and_out_of_range_separately() {
    use corrode_scanner::{config::ConfigFile, detectors::vulnerabilities::assess};
    let url = url::Url::parse("https://app.example.com/").unwrap();
    let config: ConfigFile = toml::from_str(
        r#"
        [deployments."https://app.example.com/".nginx_open_source]
        unmodified_upstream_version = "1.31.8"
        serves_http2 = true
        proxies_to_backend = true
        low_worker_connections_observed = false
        [deployments."https://app.example.com/".php]
        unmodified_upstream_version = "8.5.12"
        serves_web_requests = true
    "#,
    )
    .unwrap();
    let result = ScanResult {
        url: url.to_string(),
        advisory_checks: assess(&config.deployments, Some(&url), Some(&url), &[]),
        ..ScanResult::default()
    };
    let (report, evidence) = read_markdown(&result, "partial-deployment");
    for output in [&report, &evidence] {
        assert!(output.contains("Worker connection pressure is unverified"));
        assert!(output.contains("Host exploitability is unverified"));
    }
    assert!(report.contains("1 matched, 1 no match, 4 not assessed"));
    assert!(!report.contains("## Actionable Findings"));
    assert!(!report.contains("clean security posture"));

    let serialized = serde_json::to_value(&result).unwrap();
    let checks = serialized
        .get("advisory_checks")
        .unwrap()
        .as_array()
        .unwrap();
    let status_for = |id: &str| {
        checks
            .iter()
            .find(|c| c["advisory"].as_str().unwrap().contains(id))
            .unwrap()["status"]
            .as_str()
    };
    assert_eq!(status_for("123007"), Some("matched"));
    assert_eq!(status_for("123633"), Some("not_assessed"));
    assert_eq!(status_for("PHP"), Some("no_match"));
    assert_eq!(status_for("WordPress"), Some("not_assessed"));
    assert_eq!(
        serialized.get("vulnerabilities"),
        Some(&serde_json::json!([]))
    );
}
