//! Pillar 2 — client-side taint & gadget mapping. A static source→sink pass
//! over a page's JavaScript that reports DOM-XSS-shaped flows as manual-test
//! leads. **Reported, never fired** — Corrode constructs no payloads.
//!
//! ## Design for the fan-out
//!
//! Three sibling detectors build on this engine, each in its own file:
//! [`proto`] (prototype-pollution), [`postmessage`], [`csp`]. They consume the
//! shared `pub(crate)` surface and must not need edits here:
//!
//! - [`parse::parse_script`] / [`parse::ParsedModule`] — the shared SWC parse
//!   (ES-then-TS, JSX/TSX) and span→`file:line:col` resolution.
//! - [`sources`] — `classify_expr`, `classify_bare_ident`,
//!   `classify_message_data`, plus `SourceKind` / `SourceMatch`.
//! - [`sinks`] — `classify_call`, `classify_assign_target`,
//!   `classify_assign_ident`, `classify_new`, `classify_framework_hatch`,
//!   `is_safe_property`, `is_safe_attribute`, plus `SinkKind` / `SinkMatch`.
//! - [`visitor::run`] / [`visitor::RawFlow`] — the intra-function taint pass.
//!
//! Add a sibling by declaring `pub(crate) mod <name>;` below.
//!
//! ## Why intra-function, intra-script
//!
//! The taint environment is reset at every function boundary and never crosses
//! files. This is the primary false-positive control: a variable tainted in one
//! function is invisible in another, so we never invent a flow that the code
//! cannot actually realize in one scope. The cost is missed cross-function
//! flows — an acceptable trade for the plan's high-signal / low-FP stance.

// Unwired until Gate 2; mirrors `sourcemaps`/`manifests` during their build.
#![allow(dead_code)]

pub(crate) mod parse;
pub(crate) mod sinks;
pub(crate) mod sources;
pub(crate) mod visitor;

use crate::types::TaintFlow;

/// Analyze a corpus of scripts and return the source→sink flows found.
/// `scripts` is `(source_text, source_url)` — matching how `sourcemaps`/`rsc`
/// take script corpora. Unparseable scripts are skipped silently (no panic).
pub fn analyze(scripts: &[(&str, &str)]) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    for (text, url) in scripts {
        let Some(parsed) = parse::parse_script(text, url) else {
            continue;
        };
        for raw in visitor::run(&parsed, url) {
            flows.push(assemble(raw, url));
        }
    }

    dedupe(flows)
}

/// Lift an internal `RawFlow` into the public `TaintFlow`. `confidence` is left
/// `None` (Phase 3 scores) and `runtime_observed` is `false` (task 2.8 sets it).
fn assemble(raw: visitor::RawFlow, url: &str) -> TaintFlow {
    TaintFlow {
        source: raw.source_label,
        sink: raw.sink_label,
        path: raw.path,
        script_url: url.to_owned(),
        location: raw.location,
        runtime_observed: false,
        confidence: None,
    }
}

/// Collapse identical flows (same source, sink, and location) that the visitor
/// can emit when a value reaches the same sink by two read paths.
fn dedupe(mut flows: Vec<TaintFlow>) -> Vec<TaintFlow> {
    let mut seen = std::collections::HashSet::new();
    flows.retain(|f| seen.insert((f.source.clone(), f.sink.clone(), f.location.clone())));
    flows
}

/// Human-readable rendering of a flow as `source → …hops… → sink`. Used by the
/// reporting layer (wired at the gate); kept here so the format lives with the
/// type that produces it.
pub fn render_flow(flow: &TaintFlow) -> String {
    let mut parts = Vec::with_capacity(flow.path.len() + 2);
    parts.push(flow.source.clone());
    parts.extend(flow.path.iter().cloned());
    parts.push(flow.sink.clone());
    parts.join(" → ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_one(src: &str) -> Vec<TaintFlow> {
        analyze(&[(src, "https://example.com/app.js")])
    }

    #[test]
    fn classic_source_to_sink_flow() {
        let src = r#"
            const params = new URLSearchParams(location.search);
            const redirect = params.get("redirect");
            document.getElementById("out").innerHTML = redirect;
        "#;
        let flows = analyze_one(src);
        assert_eq!(flows.len(), 1, "expected exactly one flow: {flows:?}");
        let rendered = render_flow(&flows[0]);
        assert!(rendered.contains("innerHTML"), "rendered flow: {rendered}");
        assert!(
            flows[0].source.contains("URLSearchParams") || flows[0].source.contains("location")
        );
        assert!(!flows[0].runtime_observed);
        assert!(flows[0].confidence.is_none());
    }

    #[test]
    fn direct_location_into_eval() {
        let src = r#"eval(location.hash);"#;
        let flows = analyze_one(src);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].source, "location.hash");
        assert_eq!(flows[0].sink, "eval(...)");
    }

    #[test]
    fn safe_sink_text_content_is_not_flagged() {
        // Tainted value into textContent must produce no flow.
        let src = r#"
            const x = location.search;
            document.getElementById("o").textContent = x;
        "#;
        assert!(analyze_one(src).is_empty());
    }

    #[test]
    fn constant_only_assignment_is_not_flagged() {
        // A static, non-tainted RHS into a real sink must not be a flow.
        let src = r#"document.getElementById("o").innerHTML = "<b>static</b>";"#;
        assert!(analyze_one(src).is_empty());
    }

    #[test]
    fn unparseable_script_degrades_gracefully() {
        let flows = analyze(&[("function (((", "https://example.com/broken.js")]);
        assert!(flows.is_empty());
    }

    #[test]
    fn no_cross_function_false_flow() {
        // `tainted` is set in one function and a sink reads a *same-named* local
        // in another. Intra-function scoping must not connect them.
        let src = r#"
            function a() { const v = location.search; return v; }
            function b(v) { document.body.innerHTML = v; }
        "#;
        assert!(
            analyze_one(src).is_empty(),
            "must not link taint across functions"
        );
    }

    #[test]
    fn taint_survives_string_transform() {
        let src = r##"
            const raw = location.hash;
            const clean = raw.replace("#", "");
            document.body.innerHTML = clean;
        "##;
        let flows = analyze_one(src);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink, "innerHTML");
    }

    #[test]
    fn string_settimeout_is_flow_but_fn_ref_is_not() {
        let tainted_string = r#"
            const code = location.hash;
            setTimeout(code, 100);
        "#;
        assert_eq!(analyze_one(tainted_string).len(), 1);

        let fn_ref = r#"setTimeout(render, 100);"#;
        assert!(analyze_one(fn_ref).is_empty());
    }

    #[test]
    fn postmessage_data_into_sink() {
        let src = r#"
            window.addEventListener("message", function (e) {
                document.getElementById("x").innerHTML = e.data;
            });
        "#;
        let flows = analyze_one(src);
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert!(flows[0].source.contains("data"));
    }

    #[test]
    fn render_flow_joins_with_arrows() {
        let flow = TaintFlow {
            source: "location.search".to_owned(),
            sink: "innerHTML".to_owned(),
            path: vec!["params".to_owned(), "redirect".to_owned()],
            script_url: "u".to_owned(),
            location: "u:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        };
        assert_eq!(
            render_flow(&flow),
            "location.search → params → redirect → innerHTML"
        );
    }
}
