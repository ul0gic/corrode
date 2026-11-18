// Does:  Checks high-impact advisories against installed releases, deployment roles, and target identity.
// Holds: Patched releases and look-alike deployments produce no advisory for the affected component.

use corrode_scanner::config::ConfigFile;
use corrode_scanner::detectors::vulnerabilities::check_all;
use corrode_scanner::types::{
    AssessmentDisposition, EvidenceSource, TechnologyVersion, Vulnerability,
};
use url::Url;

const TARGET: &str = "https://example.test/app";

fn assess(table: &str, version: &str, conditions: &str) -> Vec<Vulnerability> {
    let config: ConfigFile = toml::from_str(&format!(
        "[deployments.'{TARGET}'.{table}]\nunmodified_upstream_version='{version}'\n{conditions}"
    ))
    .expect("valid deployment");
    let url = Url::parse(TARGET).unwrap();
    config.deployments.findings(&url, &url)
}

#[test]
fn react2shell_requires_an_affected_deployed_server_renderer() {
    for package in [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack",
    ] {
        let settings = format!("package='{package}'\nserves_server_components=true");
        for v in ["19.0.0", "19.1.0", "19.1.1", "19.2.0"] {
            let results = assess("react", v, &settings);
            assert_eq!(results.len(), 1);
            let finding = results.first().expect("one React advisory");
            assert!(finding.vuln_type.contains("CVE-2025-55182"));
            assert_eq!(finding.disposition, AssessmentDisposition::Lead);
            assert_eq!(
                finding.evidence.first().unwrap().source,
                EvidenceSource::Deployment
            );
        }
        for v in ["19.0.1", "19.1.2", "19.2.1"] {
            assert!(assess("react", v, &settings).is_empty());
        }
    }
    for settings in [
        "package='react'\nserves_server_components=true",
        "package='react-server-dom-webpack'\nserves_server_components=false",
    ] {
        assert!(assess("react", "19.1.1", settings).is_empty());
    }
}

#[test]
fn php2shell_coalesces_both_ids_and_respects_branch_fixes_and_web_role() {
    for (last, fixed) in [
        ("8.2.34", "8.2.35"),
        ("8.3.35", "8.3.36"),
        ("8.4.26", "8.4.27"),
        ("8.5.11", "8.5.12"),
    ] {
        let results = assess("php", last, "serves_web_requests=true");
        assert_eq!(results.len(), 1);
        let title = &results.first().unwrap().vuln_type;
        assert!(title.contains("109618") && title.contains("109619"));
        assert!(assess("php", fixed, "serves_web_requests=true").is_empty());
        assert!(assess("php", last, "serves_web_requests=false").is_empty());
    }
    assert!(assess("php", "8.1.5", "serves_web_requests=true").is_empty());
}

#[test]
fn nginx_advisories_have_distinct_introductions_and_proxy_prerequisites() {
    let proxy = "serves_http2=true\nproxies_to_backend=true\nlow_worker_connections_observed=true";
    for (v, expected) in [
        ("1.9.4", 0),
        ("1.9.5", 1),
        ("1.19.6", 1),
        ("1.19.7", 2),
        ("1.30.6", 2),
        ("1.30.7", 0),
        ("1.31.8", 2),
        ("1.31.9", 0),
        ("1.32.0", 0),
    ] {
        assert_eq!(assess("nginx_open_source", v, proxy).len(), expected, "{v}");
    }
    for setup in [
        "serves_http2=true",
        "serves_http2=true\nproxies_to_backend=false\nlow_worker_connections_observed=true",
        "serves_http2=true\nproxies_to_backend=true\nlow_worker_connections_observed=false",
    ] {
        let findings = assess("nginx_open_source", "1.31.8", setup);
        assert_eq!(findings.len(), 1);
        assert!(findings.first().unwrap().vuln_type.contains("123007"));
    }
    assert!(assess("nginx_open_source", "1.31.8", "serves_http2=false").is_empty());
}

#[test]
fn vite_checks_each_patched_branch_and_requires_an_exposed_dev_server() {
    for (last, fixed) in [
        ("6.4.5", "6.4.6"),
        ("7.3.7", "7.3.8"),
        ("8.1.6", "8.1.7"),
        ("8.2.4", "8.2.5"),
        ("8.3.6", "8.3.7"),
    ] {
        assert_eq!(
            assess("vite", last, "dev_server_exposed_to_network=true").len(),
            1
        );
        assert!(assess("vite", fixed, "dev_server_exposed_to_network=true").is_empty());
        assert!(assess("vite", last, "dev_server_exposed_to_network=false").is_empty());
    }
}

#[test]
fn a_record_cannot_follow_a_redirect_or_leak_to_another_batch_target() {
    let config: ConfigFile = toml::from_str(&format!("[deployments.'{TARGET}'.php]\nunmodified_upstream_version='8.5.11'\nserves_web_requests=true")).unwrap();
    let site = Url::parse(TARGET).unwrap();
    for other in [
        "https://example.test/other",
        "http://example.test/app",
        "https://example.test:8443/app",
        "https://elsewhere.test/app",
    ] {
        let other = Url::parse(other).unwrap();
        assert!(config.deployments.findings(&site, &other).is_empty());
        assert!(config.deployments.findings(&other, &site).is_empty());
        assert!(config.deployments.findings(&other, &other).is_empty());
    }
    for v in [
        "8.5.11-1ubuntu1",
        "v8.5.11",
        "8.5.11-beta",
        "8.5",
        "8.05.11",
    ] {
        let config = format!("[deployments.'{TARGET}'.php]\nunmodified_upstream_version='{v}'\nserves_web_requests=true");
        assert!(toml::from_str::<ConfigFile>(&config).is_err(), "{v}");
    }
}

#[test]
fn product_names_and_client_versions_do_not_generate_server_advisories() {
    let versions = [
        "Next.js (App Router)",
        "react-server-dom-webpack",
        "PHP",
        "nginx",
        "Vite",
    ]
    .map(|name| TechnologyVersion {
        name: name.to_owned(),
        version: Some("19.0.0".to_owned()),
        detection_method: "script".to_owned(),
    });
    assert!(check_all(&versions).is_empty());
}
