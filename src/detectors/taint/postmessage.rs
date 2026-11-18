// Does:  Finds message handlers and wildcard message sends.
// Holds: Each parsed script has an independent handler limit.

use swc_common::{Span, Spanned};
use swc_ecma_ast::{
    ArrowExpr, AssignExpr, AssignTarget, BinExpr, BinaryOp, CallExpr, Callee, Expr, FnExpr, Lit,
    MemberProp, Pat, SimpleAssignTarget,
};
use swc_ecma_visit::{Visit, VisitWith};

use super::parse::{self, ParsedModule};
use super::sinks;
use crate::types::PostMessageHandler;

const MAX_HANDLERS: usize = 200;

/// Finds message handlers and wildcard sends in scripts.
/// Unparseable or oversized scripts are skipped.
///
/// ```
/// # use corrode_scanner::detectors::taint::postmessage::detect;
/// let handlers = detect(&[("window.postMessage('hello', '*')", "inline")]);
/// ```
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

// Why: Derived ordering lets the scan retain the strongest observed origin comparison.
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
        if assign_target_is_onmessage(&n.left) {
            self.record_handler(&n.right, n.span);
        }
        n.visit_children_with(self);
    }
}

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

    fn is_origin_read(&self, expr: &Expr) -> bool {
        match unwrap_paren(expr) {
            Expr::Member(member) => {
                if member_prop_name(&member.prop) != Some("origin") {
                    return false;
                }
                match &self.param {
                    HandlerParam::Named(name) => root_ident(&member.obj).as_deref() == Some(name),

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

enum HandlerParam {
    Named(String),

    DestructuredOrigin,

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
            AssignTarget::Simple(SimpleAssignTarget::Member(member))
                if sinks::classify_assign_target(member).is_some() =>
            {
                self.reaches_sink = true;
            }
            AssignTarget::Simple(SimpleAssignTarget::Ident(ident))
                if sinks::classify_assign_ident(ident.sym.as_ref()).is_some() =>
            {
                self.reaches_sink = true;
            }
            _ => {}
        }
        n.visit_children_with(self);
    }

    fn visit_jsx_attr(&mut self, n: &swc_ecma_ast::JSXAttr) {
        if let swc_ecma_ast::JSXAttrName::Ident(ident) = &n.name {
            if sinks::classify_framework_hatch(ident.sym.as_ref()).is_some() {
                self.reaches_sink = true;
            }
        }
        n.visit_children_with(self);
    }
}

fn message_listener_handler(call: &CallExpr) -> Option<&Expr> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };

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

fn assign_target_is_onmessage(target: &AssignTarget) -> bool {
    match target {
        AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
            member_prop_name(&member.prop) == Some("onmessage")
        }
        AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) => ident.sym.as_ref() == "onmessage",
        _ => false,
    }
}

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
        let src = r#"win.postMessage(payload, "https://trusted.com");"#;
        assert!(detect_one(src).is_empty());
    }

    #[test]
    fn non_message_event_listener_is_ignored() {
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
