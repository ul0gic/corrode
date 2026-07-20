use crate::types::{ConfidenceLevel, ScanResult};

use super::assessment::wordpress_lead;

const MAX_LEADS_PER_KIND: usize = 10;

pub(crate) fn render_additional_leads(result: &ScanResult) -> Vec<String> {
    let wordpress = wordpress_lead(result);
    let flows: Vec<_> = result
        .taint_flows
        .iter()
        .filter(|flow| {
            !matches!(
                flow.confidence.as_ref().map(|confidence| confidence.level),
                Some(ConfidenceLevel::Low)
            )
        })
        .take(MAX_LEADS_PER_KIND)
        .collect();
    let handlers: Vec<_> = result
        .post_message_handlers
        .iter()
        .filter(|handler| handler.reaches_sink)
        .take(MAX_LEADS_PER_KIND)
        .collect();

    if wordpress.is_none() && flows.is_empty() && handlers.is_empty() {
        return Vec::new();
    }

    let mut report = vec!["---\n## Additional Manual Validation Leads\n".to_owned()];
    if let Some(lead) = wordpress {
        report.push(format!("- **WordPress version validation:** {lead}"));
    }
    for flow in flows {
        report.push(format!(
            "- **Client-side flow:** `{}` → `{}` at `{}`",
            flow.source, flow.sink, flow.location
        ));
    }
    for handler in handlers {
        report.push(format!(
            "- **postMessage handler reaching a sink:** `{}`; origin check: {}",
            handler.location, handler.origin_check
        ));
    }
    report.push(
        "\nThese are hypotheses for manual validation, not confirmed vulnerabilities. Full \
         static-analysis evidence is in `EVIDENCE.md`."
            .to_owned(),
    );
    report
}
