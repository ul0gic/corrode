use swc_common::{Span, Spanned};
use swc_ecma_ast::{
    ArrowExpr, AssignExpr, AssignTarget, BinExpr, BinaryOp, CallExpr, Callee, Expr, FnExpr, Lit,
    MemberProp, Pat, SimpleAssignTarget,
};
use swc_ecma_visit::{Visit, VisitWith};

use super::parse::{self, ParsedModule};
use super::sinks;
use crate::types::PostMessageHandler;

/// Bound the emitted handlers per corpus so a generated bundle that registers
/// listeners in a loop cannot explode the report.
const MAX_HANDLERS: usize = 200;

/// Map the `postMessage` receive/send surface; `scripts` is `(source_text, source_url)`.
/// Unparseable scripts are skipped silently (no panic on hostile input).
pub fn detect(scripts: &[(&str, &str)]) -> Vec<PostMessageHandler> {
    let mut out = Vec::new();
    for (text, url) in scripts {
        let Some(parsed) = parse::parse_script(text, url) else {
            continue;
        };
        let mut visitor = HandlerVisitor::new(&parsed, url);
        parsed.module.visit_with(&mut visitor);
        out.extend(visitor.handlers);
    }
    out
}

/// Origin-validation posture of a handler body, in increasing safety.
// Variant order encodes safety (None < Weak < Strict); `strongest` is `Ord::max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OriginCheck {
    None,
    Weak,
    Strict,
}

impl OriginCheck {
    fn as_str(self) -> &'static str {
        match self {
            OriginCheck::None => "none",
            OriginCheck::Weak => "weak",
            OriginCheck::Strict => "strict",
        }
    }

    /// Keep the strongest posture seen — a body may both `===` the origin and
    /// `.includes` it; the exact match is what actually gates the handler.
    fn strongest(self, other: OriginCheck) -> OriginCheck {
        self.max(other)
    }
}

struct HandlerVisitor<'a> {
    parsed: &'a ParsedModule,
    source_name: String,
    handlers: Vec<PostMessageHandler>,
}

impl<'a> HandlerVisitor<'a> {
    fn new(parsed: &'a ParsedModule, source_name: &str) -> Self {
        Self {
            parsed,
            source_name: source_name.to_owned(),
            handlers: Vec::new(),
        }
    }

    fn loc(&self, span: Span) -> String {
        self.parsed.location(&self.source_name, span)
    }

    /// Analyze a registered `message` handler and record its surface entry.
    fn record_handler(&mut self, handler: &Expr, span: Span) {
        if self.handlers.len() >= MAX_HANDLERS {
            return;
        }
        let param = handler_param(handler);
        let mut body = BodyScan::new(param);
        handler.visit_with(&mut body);
        self.handlers.push(PostMessageHandler {
            script_url: self.source_name.clone(),
            location: self.loc(span),
            origin_check: body.origin.as_str().to_owned(),
            reaches_sink: body.reaches_sink,
            confidence: None,
        });
    }

    /// A wildcard `postMessage(payload, "*")` send is its own finding: delivered to
    /// any origin. Recorded as `origin_check = "none"` — a send-side leak, not a sink.
    fn record_wildcard_send(&mut self, span: Span) {
        if self.handlers.len() >= MAX_HANDLERS {
            return;
        }
        self.handlers.push(PostMessageHandler {
            script_url: self.source_name.clone(),
            location: self.loc(span),
            origin_check: "none".to_owned(),
            reaches_sink: false,
            confidence: None,
        });
    }
}

impl Visit for HandlerVisitor<'_> {
    fn visit_call_expr(&mut self, n: &CallExpr) {
        if let Some(handler) = message_listener_handler(n) {
            self.record_handler(handler, n.span());
        } else if is_wildcard_post_message(n) {
            self.record_wildcard_send(n.span());
        }
        n.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        // `window.onmessage = fn` / `onmessage = fn` registers a handler too.
        if assign_target_is_onmessage(&n.left) {
            self.record_handler(&n.right, n.span);
        }
        n.visit_children_with(self);
    }
}

/// Scan a handler body for its strongest origin check and whether it reaches a sink.
struct BodyScan {
    param: HandlerParam,
    origin: OriginCheck,
    reaches_sink: bool,
}

impl BodyScan {
    fn new(param: HandlerParam) -> Self {
        Self {
            param,
            origin: OriginCheck::None,
            reaches_sink: false,
        }
    }

    /// Whether `expr` reads the handler's message origin (`<param>.origin`, or bare
    /// `origin` when destructured). Scoped to those shapes to keep false positives down.
    fn is_origin_read(&self, expr: &Expr) -> bool {
        match unwrap_paren(expr) {
            Expr::Member(member) => {
                if member_prop_name(&member.prop) != Some("origin") {
                    return false;
                }
                match &self.param {
                    HandlerParam::Named(name) => root_ident(&member.obj).as_deref() == Some(name),
                    // No identifiable param: accept any `.origin` read rather
                    // than misreport real validation as `none`.
                    HandlerParam::DestructuredOrigin | HandlerParam::None => true,
                }
            }
            Expr::Ident(ident) => {
                matches!(self.param, HandlerParam::DestructuredOrigin)
                    && ident.sym.as_ref() == "origin"
            }
            _ => false,
        }
    }
}

/// The handler's first parameter, as far as origin validation cares.
enum HandlerParam {
    /// A plain identifier, e.g. `e` — origin is read as `e.origin`.
    Named(String),
    /// An object pattern binding `origin`, e.g. `({data, origin})` — origin is
    /// read as a bare `origin` ident.
    DestructuredOrigin,
    /// Anything else (no param, or a pattern without `origin`).
    None,
}

impl Visit for BodyScan {
    fn visit_bin_expr(&mut self, n: &BinExpr) {
        if matches!(n.op, BinaryOp::EqEqEq | BinaryOp::NotEqEq)
            && (self.is_origin_read(&n.left) || self.is_origin_read(&n.right))
        {
            self.origin = self.origin.strongest(OriginCheck::Strict);
        }
        n.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        // Weak validation: substring/prefix/unanchored-regex origin checks
        // (`includes`, `startsWith`, `test`, …) that exact-match comparison avoids.
        if let Callee::Expr(callee) = &n.callee {
            if let Expr::Member(member) = &**callee {
                if let Some(method) = member_prop_name(&member.prop) {
                    let weak_method = matches!(
                        method,
                        "includes" | "startsWith" | "endsWith" | "indexOf" | "search" | "match"
                    );
                    if weak_method && self.is_origin_read(&member.obj) {
                        self.origin = self.origin.strongest(OriginCheck::Weak);
                    }
                    // `pattern.test(e.origin)` — origin as the tested argument.
                    if method == "test" && n.args.iter().any(|a| self.is_origin_read(&a.expr)) {
                        self.origin = self.origin.strongest(OriginCheck::Weak);
                    }
                }
            }
        }

        if sinks::classify_call(n).is_some() {
            self.reaches_sink = true;
        }
        n.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, n: &swc_ecma_ast::NewExpr) {
        if sinks::classify_new(&n.callee).is_some() {
            self.reaches_sink = true;
        }
        n.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        match &n.left {
            AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                if sinks::classify_assign_target(member).is_some() {
                    self.reaches_sink = true;
                }
            }
            AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) => {
                if sinks::classify_assign_ident(ident.sym.as_ref()).is_some() {
                    self.reaches_sink = true;
                }
            }
            _ => {}
        }
        n.visit_children_with(self);
    }

    fn visit_jsx_attr(&mut self, n: &swc_ecma_ast::JSXAttr) {
        // `dangerouslySetInnerHTML` / `v-html` as a JSX attribute key.
        if let swc_ecma_ast::JSXAttrName::Ident(ident) = &n.name {
            if sinks::classify_framework_hatch(ident.sym.as_ref()).is_some() {
                self.reaches_sink = true;
            }
        }
        n.visit_children_with(self);
    }
}

/// If `call` is `addEventListener("message", handler)`, return the handler.
/// The receiver is unconstrained — `window`/`self`/`top`/worker port all qualify.
fn message_listener_handler(call: &CallExpr) -> Option<&Expr> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    // `obj.addEventListener(...)` or bare global `addEventListener(...)`.
    let is_add_listener = match &**callee {
        Expr::Member(member) => member_prop_name(&member.prop) == Some("addEventListener"),
        Expr::Ident(ident) => ident.sym.as_ref() == "addEventListener",
        _ => false,
    };
    if !is_add_listener {
        return None;
    }
    match call.args.first().map(|a| &*a.expr) {
        Some(Expr::Lit(Lit::Str(s))) if s.value.to_string_lossy() == "message" => {}
        _ => return None,
    }
    call.args.get(1).map(|a| &*a.expr)
}

/// Whether an assignment target is an `onmessage` handler property: bare
/// `onmessage = …` or `obj.onmessage = …`.
fn assign_target_is_onmessage(target: &AssignTarget) -> bool {
    match target {
        AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
            member_prop_name(&member.prop) == Some("onmessage")
        }
        AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) => ident.sym.as_ref() == "onmessage",
        _ => false,
    }
}

/// Whether `call` is a `postMessage(payload, "*")` send with a wildcard
/// `targetOrigin`. The target origin is the second positional argument.
fn is_wildcard_post_message(call: &CallExpr) -> bool {
    let Callee::Expr(callee) = &call.callee else {
        return false;
    };
    let Expr::Member(member) = &**callee else {
        return false;
    };
    if member_prop_name(&member.prop) != Some("postMessage") {
        return false;
    }
    matches!(
        call.args.get(1).map(|a| &*a.expr),
        Some(Expr::Lit(Lit::Str(s))) if s.value.to_string_lossy() == "*"
    )
}

/// Classify a function/arrow handler's first parameter for origin tracking.
fn handler_param(expr: &Expr) -> HandlerParam {
    let pat = match unwrap_paren(expr) {
        Expr::Arrow(ArrowExpr { params, .. }) => params.first(),
        Expr::Fn(FnExpr { function, .. }) => function.params.first().map(|p| &p.pat),
        _ => None,
    };
    match pat {
        Some(Pat::Ident(id)) => HandlerParam::Named(id.id.sym.to_string()),
        Some(Pat::Object(obj)) if object_pat_binds_origin(obj) => HandlerParam::DestructuredOrigin,
        _ => HandlerParam::None,
    }
}

/// Whether an object-destructuring pattern binds a property named `origin`,
/// e.g. `{ data, origin }` or `{ origin: o }`.
fn object_pat_binds_origin(obj: &swc_ecma_ast::ObjectPat) -> bool {
    use swc_ecma_ast::{ObjectPatProp, PropName};
    obj.props.iter().any(|prop| match prop {
        ObjectPatProp::Assign(a) => a.key.sym.as_ref() == "origin",
        ObjectPatProp::KeyValue(kv) => {
            matches!(&kv.key, PropName::Ident(i) if i.sym.as_ref() == "origin")
        }
        ObjectPatProp::Rest(_) => false,
    })
}

/// The leftmost identifier of a member chain: `e.origin` → `e`, `a.b.c` → `a`.
fn root_ident(expr: &Expr) -> Option<String> {
    match unwrap_paren(expr) {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => root_ident(&member.obj),
        _ => None,
    }
}

fn unwrap_paren(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(p) => unwrap_paren(&p.expr),
        other => other,
    }
}

fn member_prop_name(prop: &MemberProp) -> Option<&str> {
    match prop {
        MemberProp::Ident(ident) => Some(ident.sym.as_ref()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_one(src: &str) -> Vec<PostMessageHandler> {
        detect(&[(src, "https://example.com/app.js")])
    }

    #[test]
    fn weak_origin_handler_reaching_inner_html() {
        let src = r#"
            window.addEventListener("message", function (e) {
                if (e.origin.indexOf("trusted.com") !== -1) {
                    document.getElementById("out").innerHTML = e.data;
                }
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "weak");
        assert!(h[0].reaches_sink);
        assert!(h[0].confidence.is_none());
    }

    #[test]
    fn strict_origin_handler_is_classified_strict() {
        let src = r#"
            window.addEventListener("message", (e) => {
                if (e.origin === "https://trusted.com") {
                    document.body.innerHTML = e.data;
                }
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "strict");
        assert!(h[0].reaches_sink);
    }

    #[test]
    fn strict_check_without_sink_reaches_nothing() {
        let src = r#"
            window.addEventListener("message", (e) => {
                if (e.origin === "https://trusted.com") {
                    console.log(e.data);
                }
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "strict");
        assert!(!h[0].reaches_sink, "console.log is not a sink");
    }

    #[test]
    fn no_origin_check_handler_is_none() {
        let src = r#"
            window.addEventListener("message", function (msg) {
                eval(msg.data);
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "none");
        assert!(h[0].reaches_sink, "eval is a sink");
    }

    #[test]
    fn startswith_and_includes_are_weak() {
        let prefix = r#"
            addEventListener("message", (e) => {
                if (e.origin.startsWith("https://trusted")) { location.href = e.data; }
            });
        "#;
        assert_eq!(detect_one(prefix)[0].origin_check, "weak");

        let includes = r#"
            addEventListener("message", (e) => {
                if (e.origin.includes("trusted.com")) {}
            });
        "#;
        assert_eq!(detect_one(includes)[0].origin_check, "weak");
    }

    #[test]
    fn unanchored_regex_test_against_origin_is_weak() {
        let src = r#"
            addEventListener("message", (e) => {
                if (/trusted\.com/.test(e.origin)) { document.write(e.data); }
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h[0].origin_check, "weak");
        assert!(h[0].reaches_sink);
    }

    #[test]
    fn onmessage_assignment_is_a_handler() {
        let src = r"
            window.onmessage = function (e) {
                document.body.innerHTML = e.data;
            };
        ";
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "none");
        assert!(h[0].reaches_sink);
    }

    #[test]
    fn wildcard_target_origin_send_is_flagged() {
        let src = r#"frame.contentWindow.postMessage(payload, "*");"#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "none");
        assert!(!h[0].reaches_sink);
    }

    #[test]
    fn targeted_post_message_send_is_not_flagged() {
        // A send with an explicit origin is the secure form — no finding.
        let src = r#"win.postMessage(payload, "https://trusted.com");"#;
        assert!(detect_one(src).is_empty());
    }

    #[test]
    fn non_message_event_listener_is_ignored() {
        // Only "message" handlers are postMessage surface.
        let src = r#"
            window.addEventListener("click", (e) => {
                document.body.innerHTML = e.target.value;
            });
        "#;
        assert!(detect_one(src).is_empty());
    }

    #[test]
    fn destructured_origin_param_is_recognized() {
        let src = r#"
            addEventListener("message", ({ data, origin }) => {
                if (origin === "https://trusted.com") {
                    document.body.innerHTML = data;
                }
            });
        "#;
        let h = detect_one(src);
        assert_eq!(h.len(), 1, "{h:?}");
        assert_eq!(h[0].origin_check, "strict");
    }

    #[test]
    fn unparseable_script_degrades_gracefully() {
        assert!(detect(&[("function (((", "https://example.com/x.js")]).is_empty());
    }

    #[test]
    fn strongest_check_wins_when_both_present() {
        // A handler that does both a weak and a strict check is strict-gated.
        let src = r#"
            addEventListener("message", (e) => {
                if (e.origin.includes("trusted") && e.origin === "https://trusted.com") {
                    document.body.innerHTML = e.data;
                }
            });
        "#;
        assert_eq!(detect_one(src)[0].origin_check, "strict");
    }
}
