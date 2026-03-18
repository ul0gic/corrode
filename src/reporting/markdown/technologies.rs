use anyhow::Result;

use crate::types::ScanResult;

pub(crate) fn render_technologies(result: &ScanResult) -> Vec<String> {
    let mut report = Vec::new();

    if !result.technologies.is_empty() {
        report.push("---\n## 🛠️ Technology Stack\n".to_owned());
        for tech in &result.technologies {
            report.push(format!("- {tech}"));
        }
        report.push(String::new());
    }

    report
}

pub(crate) fn render_dom(result: &ScanResult) -> Result<Vec<String>> {
    let mut report = Vec::new();

    report.push("---\n## 🧾 DOM Insights\n".to_owned());
    report.push(format!("- Scripts: {}", result.dom.scripts));
    report.push(format!("- Forms: {}", result.dom.forms.len()));
    report.push(format!(
        "- Hidden Inputs: {}",
        result.dom.hidden_inputs.len()
    ));
    report.push(format!("- iframes: {}", result.dom.iframes.len()));

    if !result.dom.data_attributes.is_empty() {
        report.push("### Data Attributes\n".to_owned());
        for attr in &result.dom.data_attributes {
            report.push(format!(
                "- {}: {}",
                attr.tag,
                serde_json::to_string_pretty(&attr.attributes)?
            ));
        }
    }

    Ok(report)
}
