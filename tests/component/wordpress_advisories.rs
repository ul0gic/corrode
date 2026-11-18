// Does:  Checks which WordPress observations justify reporting an advisory.
// Holds: A version inferred only from asset URLs cannot confirm an advisory.

use corrode_scanner::detectors::technologies::wordpress::{
    detect, ASSET_CONSENSUS_METHOD, META_GENERATOR_METHOD,
};
use corrode_scanner::detectors::vulnerabilities::wordpress::check_cves;
use corrode_scanner::types::{MetaTag, TechnologyVersion};

#[test]
fn advisory_fixture_exercises_production_boundaries() {
    let raw = include_str!("../fixtures/wordpress/advisory-cases.json");
    let cases: serde_json::Value = serde_json::from_str(raw).expect("fixture JSON");
    let cases = cases.as_array().expect("fixture array");

    for case in cases {
        let version = case["version"].as_str().expect("version");
        let expected = case["expected_severity"].as_str();
        let findings = check_cves(&[TechnologyVersion {
            name: "WordPress".to_owned(),
            version: Some(version.to_owned()),
            detection_method: META_GENERATOR_METHOD.to_owned(),
        }]);
        assert_eq!(
            findings.first().map(|finding| finding.severity.as_str()),
            expected,
            "{version}"
        );
    }
}

#[test]
fn fingerprinting_is_purely_over_supplied_observations() {
    let observed = detect(
        &[],
        &[MetaTag {
            name: "generator".to_owned(),
            content: "WordPress 7.0.1".to_owned(),
        }],
        &[],
    );
    let version = observed.version.expect("authoritative version");
    assert_eq!(version.detection_method, META_GENERATOR_METHOD);
    assert_eq!(check_cves(&[version]).len(), 1);

    let weak = TechnologyVersion {
        name: "WordPress".to_owned(),
        version: Some("7.0.1".to_owned()),
        detection_method: ASSET_CONSENSUS_METHOD.to_owned(),
    };
    assert!(check_cves(&[weak]).is_empty());
}
