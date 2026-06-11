use crate::types::{Gadget, PostMessageHandler, TaintFlow};

use super::csp::Csp;
use super::proto::{self, ProtoFinding};
use super::{analyze, postmessage};

/// Bound on emitted gadgets per corpus, mirroring the engine's `MAX_FLOWS` and
/// each detector's `MAX_FINDINGS`. Truncation is logged, never silent (2.12).
const MAX_GADGETS: usize = 200;

/// `csp` is the page's `Content-Security-Policy` value, used for the bypass
/// correlation (2.7b); `scripts` is `(source_text, source_url)`.
pub(crate) fn inventory(scripts: &[(&str, &str)], csp: Option<&str>) -> Vec<Gadget> {
    let flows = analyze(scripts);
    let protos = proto::detect(scripts);
    let handlers = postmessage::detect(scripts);
    classify(&flows, &protos, &handlers, csp)
}

/// Pure classifier over already-computed detector output. Split from `inventory`
/// so it can be unit-tested without re-running every detector.
fn classify(
    flows: &[TaintFlow],
    protos: &[ProtoFinding],
    handlers: &[PostMessageHandler],
    csp: Option<&str>,
) -> Vec<Gadget> {
    let mut gadgets = Vec::new();

    for flow in flows {
        if let Some(g) = gadget_from_flow(flow) {
            gadgets.push(g);
        }
    }
    for finding in protos {
        gadgets.push(gadget_from_proto(finding));
    }
    for handler in handlers {
        if let Some(g) = gadget_from_handler(handler) {
            gadgets.push(g);
        }
    }
    if let Some(g) = csp_bypass_gadget(flows, csp) {
        gadgets.push(g);
    }

    if gadgets.len() > MAX_GADGETS {
        eprintln!(
            "[!] gadget inventory truncated from {} to cap {MAX_GADGETS}",
            gadgets.len()
        );
        gadgets.truncate(MAX_GADGETS);
    }
    gadgets
}

/// Ordered most- to least-specific so navigation/script/template are not
/// shadowed by the broad HTML/code match.
enum FlowSink {
    HtmlOrCode,
    Navigation,
    ScriptLoad,
    FrameworkHatch,
}

/// Recover the sink class from a `TaintFlow.sink` label. Mirrors the exact
/// labels `sinks.rs` emits; an unrecognized label yields `None` (no gadget).
fn flow_sink(label: &str) -> Option<FlowSink> {
    // Framework escape hatches — must precede the HTML match.
    if label == "dangerouslySetInnerHTML"
        || label == "v-html"
        || label.starts_with("bypassSecurityTrust")
    {
        return Some(FlowSink::FrameworkHatch);
    }
    // Navigation: `location`, `location.href`, `location.assign(...)`,
    // `location.replace(...)`, `form.action`.
    if label == "location"
        || label == "location.href"
        || label == "location.assign(...)"
        || label == "location.replace(...)"
        || label == "form.action"
    {
        return Some(FlowSink::Navigation);
    }
    // `.src` is matched as a plain string suffix, not a file extension.
    let is_script_src = matches!(label.strip_suffix(".src"), Some(obj) if obj.contains("script"));
    if label == "script.text" || is_script_src {
        return Some(FlowSink::ScriptLoad);
    }
    // HTML injection / code execution.
    if label == "innerHTML"
        || label == "outerHTML"
        || label == "insertAdjacentHTML(...)"
        || label.starts_with("document.write")
        || label == "eval(...)"
        || label == "Function(...)"
        || label == "new Function(...)"
        || label.ends_with("(string)")
    {
        return Some(FlowSink::HtmlOrCode);
    }
    None
}

fn gadget_from_flow(flow: &TaintFlow) -> Option<Gadget> {
    let (category, hint) = match flow_sink(&flow.sink)? {
        FlowSink::HtmlOrCode => (
            "dom-xss",
            "tainted source reaches an HTML/code sink — manually confirm the value is attacker-controlled and unescaped",
        ),
        FlowSink::Navigation => (
            "open-redirect",
            "tainted source reaches a navigation sink — manually confirm an external URL can be injected",
        ),
        // A URL-derived value steering a script load is the JSONP/script-
        // injection shape; non-URL sources fall through to dom-xss above.
        FlowSink::ScriptLoad => (
            "jsonp",
            "tainted source controls a script source — manually confirm an attacker URL can be loaded as code",
        ),
        FlowSink::FrameworkHatch => (
            "unsafe-template",
            "tainted source reaches a framework HTML-trust escape hatch — manually confirm the binding is attacker-controlled",
        ),
    };
    Some(Gadget {
        category: category.to_owned(),
        description: super::render_flow(flow),
        script_url: flow.script_url.clone(),
        exploitability_hint: hint.to_owned(),
        confidence: None,
    })
}

fn gadget_from_proto(finding: &ProtoFinding) -> Gadget {
    Gadget {
        category: "prototype-pollution".to_owned(),
        description: format!(
            "{} → {} ({})",
            finding.source(),
            finding.sink(),
            finding.location()
        ),
        script_url: finding.location().split(':').next().unwrap_or("").to_owned(),
        exploitability_hint:
            "tainted data reaches a prototype-pollution sink — manually confirm a `__proto__` key can be injected"
                .to_owned(),
        confidence: None,
    }
}

/// A gadget only when the handler trusts its origin weakly *and* reaches a sink;
/// either alone is reported by the detector but is not exploitable on its own.
fn gadget_from_handler(handler: &PostMessageHandler) -> Option<Gadget> {
    if handler.origin_check == "strict" || !handler.reaches_sink {
        return None;
    }
    Some(Gadget {
        category: "postmessage-trust".to_owned(),
        description: format!(
            "message handler with {} origin check reaches a sink ({})",
            handler.origin_check, handler.location
        ),
        script_url: handler.script_url.clone(),
        exploitability_hint:
            "weak/absent origin validation on a handler that reaches a sink — manually confirm a cross-origin frame can drive it"
                .to_owned(),
        confidence: None,
    })
}

/// CSP-bypass correlation (2.7b): emit a gadget when an HTML/code sink exists
/// and CSP would not block it. Read-only against the parser; no payload built.
fn csp_bypass_gadget(flows: &[TaintFlow], csp: Option<&str>) -> Option<Gadget> {
    let header = csp?;
    let parsed = Csp::parse(header);
    let permissive = parsed.allows_unsafe_inline_scripts()
        || parsed.allows_unsafe_eval()
        || parsed.has_broad_script_src();
    if !permissive {
        return None;
    }

    // Anchor on a real sink so this is a correlation, not a bare CSP critique.
    let sink_flow = flows
        .iter()
        .find(|f| matches!(flow_sink(&f.sink), Some(FlowSink::HtmlOrCode)))?;

    Some(Gadget {
        category: "csp-bypass".to_owned(),
        description: format!(
            "CSP permits script execution that the sink `{}` needs",
            sink_flow.sink
        ),
        script_url: sink_flow.script_url.clone(),
        exploitability_hint: "sink exists and CSP would likely not block exploitation".to_owned(),
        confidence: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(sink: &str) -> TaintFlow {
        TaintFlow {
            source: "location.hash".to_owned(),
            sink: sink.to_owned(),
            path: vec![],
            script_url: "https://example.com/app.js".to_owned(),
            location: "https://example.com/app.js:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        }
    }

    fn categories(gadgets: &[Gadget]) -> Vec<&str> {
        gadgets.iter().map(|g| g.category.as_str()).collect()
    }

    #[test]
    fn dom_xss_from_html_sink_flow() {
        let src = r#"
            const r = location.hash;
            document.getElementById("o").innerHTML = r;
        "#;
        let g = inventory(&[(src, "https://example.com/app.js")], None);
        assert!(categories(&g).contains(&"dom-xss"), "{g:?}");
    }

    #[test]
    fn open_redirect_from_navigation_sink_flow() {
        let src = r"
            const next = location.hash;
            location.href = next;
        ";
        let g = inventory(&[(src, "https://example.com/app.js")], None);
        assert!(categories(&g).contains(&"open-redirect"), "{g:?}");
    }

    #[test]
    fn prototype_pollution_gadget_from_proto_finding() {
        let src = r"
            const k = location.hash;
            const obj = {};
            obj.__proto__ = k;
        ";
        let g = inventory(&[(src, "https://example.com/app.js")], None);
        assert!(categories(&g).contains(&"prototype-pollution"), "{g:?}");
    }

    #[test]
    fn postmessage_trust_gadget_from_weak_handler_reaching_sink() {
        let src = r#"
            window.addEventListener("message", function (e) {
                if (e.origin.indexOf("trusted") !== -1) {
                    document.body.innerHTML = e.data;
                }
            });
        "#;
        let g = inventory(&[(src, "https://example.com/app.js")], None);
        assert!(categories(&g).contains(&"postmessage-trust"), "{g:?}");
    }

    #[test]
    fn strict_origin_handler_is_not_a_postmessage_gadget() {
        let h = PostMessageHandler {
            script_url: "u".to_owned(),
            location: "u:1:1".to_owned(),
            origin_check: "strict".to_owned(),
            reaches_sink: true,
            confidence: None,
        };
        assert!(gadget_from_handler(&h).is_none());
    }

    #[test]
    fn handler_reaching_no_sink_is_not_a_postmessage_gadget() {
        let h = PostMessageHandler {
            script_url: "u".to_owned(),
            location: "u:1:1".to_owned(),
            origin_check: "none".to_owned(),
            reaches_sink: false,
            confidence: None,
        };
        assert!(gadget_from_handler(&h).is_none());
    }

    #[test]
    fn jsonp_gadget_from_script_src_flow() {
        // A URL source steering a script element's src is the JSONP shape.
        let f = flow("script.src");
        let g = gadget_from_flow(&f).expect("gadget");
        assert_eq!(g.category, "jsonp");
    }

    #[test]
    fn unsafe_template_gadget_from_framework_hatch_flow() {
        let f = flow("dangerouslySetInnerHTML");
        let g = gadget_from_flow(&f).expect("gadget");
        assert_eq!(g.category, "unsafe-template");
    }

    #[test]
    fn csp_bypass_positive_when_sink_exists_and_csp_is_permissive() {
        let flows = vec![flow("innerHTML")];
        let g = csp_bypass_gadget(&flows, Some("script-src 'self' 'unsafe-inline'"))
            .expect("csp-bypass gadget");
        assert_eq!(g.category, "csp-bypass");
        assert_eq!(
            g.exploitability_hint,
            "sink exists and CSP would likely not block exploitation"
        );
    }

    #[test]
    fn csp_bypass_negative_when_csp_is_strict() {
        // A nonce-protected, host-allowlisted policy blocks inline/eval/broad.
        let flows = vec![flow("innerHTML")];
        assert!(csp_bypass_gadget(
            &flows,
            Some("script-src 'self' 'nonce-abc' https://cdn.example.com")
        )
        .is_none());
    }

    #[test]
    fn csp_bypass_negative_when_no_sink_present() {
        // Permissive CSP but no HTML/code sink in the corpus — nothing to bypass.
        let flows: Vec<TaintFlow> = vec![];
        assert!(csp_bypass_gadget(&flows, Some("script-src 'unsafe-inline'")).is_none());
    }

    #[test]
    fn csp_bypass_negative_when_no_csp_header() {
        let flows = vec![flow("innerHTML")];
        assert!(csp_bypass_gadget(&flows, None).is_none());
    }

    #[test]
    fn unrecognized_sink_label_yields_no_flow_gadget() {
        assert!(gadget_from_flow(&flow("totally-unknown-sink")).is_none());
    }
}
