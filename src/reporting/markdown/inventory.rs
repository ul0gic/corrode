use std::collections::BTreeSet;

use crate::types::{AssessmentDisposition, ScanResult};

use super::findings::storage_title;
use super::summary::redact_value;

const MAX_ENDPOINTS: usize = 15;
const MAX_ROUTES: usize = 20;

pub(crate) fn render_inventory(result: &ScanResult) -> Vec<String> {
    let mut report = vec!["---\n## Attack Surface Inventory\n".to_owned()];
    report.push("| Surface | Count |".to_owned());
    report.push("|---------|------:|".to_owned());
    report.push(format!(
        "| Technologies and recovered versions | {} |",
        result.technologies.len() + result.technology_versions.len()
    ));
    report.push(format!(
        "| Network requests observed | {} |",
        result.network.total_requests
    ));
    report.push(format!(
        "| API/endpoints discovered | {} |",
        result.javascript.api_endpoints.len()
    ));
    report.push(format!(
        "| Routes/components recovered | {} |",
        result.route_surface.len()
    ));
    report.push(format!(
        "| Source maps observed | {} |",
        result.source_maps_intel.len()
    ));
    report.push(format!(
        "| Storage/session items classified | {} |",
        result.storage_assessments.len()
    ));
    report.push(String::new());

    let storage_inventory: Vec<_> = result
        .storage_assessments
        .iter()
        .filter(|assessment| assessment.disposition == AssessmentDisposition::Inventory)
        .collect();
    if !storage_inventory.is_empty() {
        report.push("### Storage and Session Inventory\n".to_owned());
        report.push("| Classification | Key | Value |".to_owned());
        report.push("|----------------|-----|-------|".to_owned());
        for assessment in storage_inventory {
            report.push(format!(
                "| {} | `{}` | `{}` |",
                storage_title(assessment.classification),
                assessment.keys.join(", "),
                redact_value(&assessment.value)
            ));
        }
        report.push(String::new());
    }

    let endpoints: BTreeSet<&str> = result
        .javascript
        .api_endpoints
        .iter()
        .map(|endpoint| endpoint.url.as_str())
        .chain(result.network.api_calls.iter().map(String::as_str))
        .collect();
    if !endpoints.is_empty() {
        report.push("### Priority Endpoints\n".to_owned());
        for endpoint in endpoints.iter().take(MAX_ENDPOINTS) {
            report.push(format!("- `{endpoint}`"));
        }
        if endpoints.len() > MAX_ENDPOINTS {
            report.push(format!(
                "- … and {} more in `EVIDENCE.md`",
                endpoints.len() - MAX_ENDPOINTS
            ));
        }
        report.push(String::new());
    }

    if !result.route_surface.is_empty() {
        report.push("### Recovered Routes and Components\n".to_owned());
        for route in result.route_surface.iter().take(MAX_ROUTES) {
            report.push(format!("- `{}` ({})", route.path, route.kind));
        }
        if result.route_surface.len() > MAX_ROUTES {
            report.push(format!(
                "- … and {} more in `EVIDENCE.md`",
                result.route_surface.len() - MAX_ROUTES
            ));
        }
        report.push(String::new());
    }

    report
}
