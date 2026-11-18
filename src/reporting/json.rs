// Does:  Writes scan results as versioned JSON.
// Holds: The schema marker is added to the serialized object.

use anyhow::Result;
use std::fs;
use std::path::Path;

use crate::types::ScanResult;

const SCHEMA_VERSION: &str = "0.5";

/// Writes a versioned JSON report, returning serialization or filesystem errors.
///
/// ```no_run
/// # use corrode_scanner::{reporting::json, types::ScanResult};
/// # let result = ScanResult::default();
/// json::write(std::path::Path::new("scan_result.json"), &result).unwrap();
/// ```
pub fn write(path: &Path, result: &ScanResult) -> Result<()> {
    let mut value = serde_json::to_value(result)?;
    if let serde_json::Value::Object(map) = &mut value {
        map.insert(
            "schema_version".to_owned(),
            serde_json::Value::String(SCHEMA_VERSION.to_owned()),
        );
    }
    let contents = serde_json::to_string_pretty(&value)?;
    fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, ConfidenceLevel, ScanResult, SecretFinding};

    #[test]
    fn emits_schema_version_and_confidence() {
        let dir = std::env::temp_dir().join("corrode_json_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("scan_result.json");

        let mut result = ScanResult::default();
        result.secrets.insert(
            "aws_key".to_owned(),
            vec![SecretFinding {
                source: "HTML".to_owned(),
                matches: vec!["AKIAEXAMPLE".to_owned()],
                confidence: Some(Confidence {
                    level: ConfidenceLevel::High,
                    score: 90,
                    factors: vec![],
                }),
            }],
        );

        write(&path, &result).expect("write json");
        let raw = fs::read_to_string(&path).expect("read json");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse json");

        assert_eq!(parsed["schema_version"], "0.5");
        assert_eq!(
            parsed["secrets"]["aws_key"][0]["confidence"]["level"],
            "high"
        );
    }

    #[test]
    fn unscored_confidence_is_omitted() {
        let dir = std::env::temp_dir().join("corrode_json_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("scan_result_unscored.json");

        let mut result = ScanResult::default();
        result.secrets.insert(
            "aws_key".to_owned(),
            vec![SecretFinding {
                source: "HTML".to_owned(),
                matches: vec!["abc".to_owned()],
                confidence: None,
            }],
        );

        write(&path, &result).expect("write json");
        let raw = fs::read_to_string(&path).expect("read json");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("parse json");

        assert!(parsed["secrets"]["aws_key"][0].get("confidence").is_none());
    }
}
