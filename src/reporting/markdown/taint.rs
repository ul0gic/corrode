//! Pillar 2 — client-side taint & gadget section. Renders the static
//! source→sink flows, the classified gadget inventory, and the postMessage
//! handler surface. Every item is a manual-test lead with evidence, never a
//! confirmed or fired vulnerability.
//!
//! Self-contained and not yet wired into `write()` — the live wiring lands at
//! Gate 2. Mirrors `sourcemaps::render_sourcemap_intel`: `pub(crate)`, takes
//! `&ScanResult`, returns `Vec<String>`, and is empty when all three source
//! collections are empty.

use crate::types::ScanResult;

pub(crate) fn render_taint(result: &ScanResult) -> Vec<String> {
    let nothing_to_report = result.taint_flows.is_empty()
        && result.gadgets.is_empty()
        && result.post_message_handlers.is_empty();
    if nothing_to_report {
        return Vec::new();
    }

    let mut report = vec!["---\n## Client-Side Taint & Gadgets\n".to_owned()];
    report.push(
        "Static source→sink analysis of the page's JavaScript. Each entry is a \
         manual-test lead — Corrode reports the surface and fires nothing.\n"
            .to_owned(),
    );

    render_flows(&result.taint_flows, &mut report);
    render_gadgets(&result.gadgets, &mut report);
    render_handlers(&result.post_message_handlers, &mut report);

    report
}

fn render_flows(flows: &[crate::types::TaintFlow], report: &mut Vec<String>) {
    if flows.is_empty() {
        return;
    }

    report.push("### Taint Flows\n".to_owned());
    report.push("| Flow | Location | Runtime |".to_owned());
    report.push("|------|----------|:-------:|".to_owned());
    for flow in flows {
        report.push(format!(
            "| {} | `{}` | {} |",
            crate::detectors::taint::render_flow(flow),
            flow.location,
            if flow.runtime_observed {
                "observed"
            } else {
                "static"
            }
        ));
    }
    report.push(String::new());
}

fn render_gadgets(gadgets: &[crate::types::Gadget], report: &mut Vec<String>) {
    if gadgets.is_empty() {
        return;
    }

    report.push("### Gadget Inventory\n".to_owned());
    report.push("| Category | Description | Exploitability Hint |".to_owned());
    report.push("|----------|-------------|---------------------|".to_owned());
    for gadget in gadgets {
        report.push(format!(
            "| {} | {} | {} |",
            gadget.category, gadget.description, gadget.exploitability_hint
        ));
    }
    report.push(String::new());
}

fn render_handlers(handlers: &[crate::types::PostMessageHandler], report: &mut Vec<String>) {
    if handlers.is_empty() {
        return;
    }

    report.push("### postMessage Handlers\n".to_owned());
    report.push("| Location | Origin Check | Reaches Sink |".to_owned());
    report.push("|----------|--------------|:------------:|".to_owned());
    for handler in handlers {
        report.push(format!(
            "| `{}` | {} | {} |",
            handler.location,
            handler.origin_check,
            if handler.reaches_sink { "yes" } else { "no" }
        ));
    }
    report.push(String::new());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Gadget, PostMessageHandler, ScanResult, TaintFlow};

    fn base() -> ScanResult {
        ScanResult::default()
    }

    #[test]
    fn empty_input_renders_nothing() {
        assert!(render_taint(&base()).is_empty());
    }

    #[test]
    fn renders_taint_flow_table_with_runtime_state() {
        let mut result = base();
        result.taint_flows.push(TaintFlow {
            source: "location.hash".to_owned(),
            sink: "innerHTML".to_owned(),
            path: vec!["redirect".to_owned()],
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "https://app.example.com/main.js:10:5".to_owned(),
            runtime_observed: true,
            confidence: None,
        });

        let md = render_taint(&result).join("\n");
        assert!(md.contains("## Client-Side Taint & Gadgets"));
        assert!(md.contains("### Taint Flows"));
        assert!(md.contains("location.hash → redirect → innerHTML"));
        assert!(md.contains("observed"));
    }

    #[test]
    fn renders_gadget_inventory_table() {
        let mut result = base();
        result.gadgets.push(Gadget {
            category: "dom-xss".to_owned(),
            description: "location.hash → innerHTML".to_owned(),
            script_url: "https://app.example.com/main.js".to_owned(),
            exploitability_hint: "manually confirm the value is attacker-controlled".to_owned(),
            confidence: None,
        });

        let md = render_taint(&result).join("\n");
        assert!(md.contains("### Gadget Inventory"));
        assert!(md.contains("dom-xss"));
        assert!(md.contains("manually confirm the value is attacker-controlled"));
    }

    #[test]
    fn renders_post_message_handler_table() {
        let mut result = base();
        result.post_message_handlers.push(PostMessageHandler {
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "https://app.example.com/main.js:3:1".to_owned(),
            origin_check: "weak".to_owned(),
            reaches_sink: true,
            confidence: None,
        });

        let md = render_taint(&result).join("\n");
        assert!(md.contains("### postMessage Handlers"));
        assert!(md.contains("weak"));
        // reaches_sink true rendered as yes.
        assert!(md.contains("| yes |"));
    }

    #[test]
    fn flows_only_opens_the_section() {
        let mut result = base();
        result.taint_flows.push(TaintFlow {
            source: "location.search".to_owned(),
            sink: "eval(...)".to_owned(),
            path: vec![],
            script_url: "u".to_owned(),
            location: "u:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        });
        let md = render_taint(&result).join("\n");
        assert!(md.contains("### Taint Flows"));
        // No gadget or handler sub-sections when those collections are empty.
        assert!(!md.contains("### Gadget Inventory"));
        assert!(!md.contains("### postMessage Handlers"));
        // Static flow rendered as such.
        assert!(md.contains("static"));
    }
}
