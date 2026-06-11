use std::collections::HashMap;

use swc_common::{Span, Spanned};
use swc_ecma_ast::{
    ArrowExpr, AssignExpr, AssignTarget, CallExpr, Callee, Expr, FnDecl, FnExpr, Lit, MemberProp,
    Pat, SimpleAssignTarget, Stmt, VarDeclarator,
};
use swc_ecma_visit::{Visit, VisitWith};

use super::parse::{self, ParsedModule};
use super::sources::{self, SourceMatch};

/// A prototype-pollution surface: a tainted source reaching a pollution-shaped
/// sink. `path` is the variable/transform hops between them. Reported as a lead.
#[derive(Debug, Clone)]
pub(crate) struct ProtoFinding {
    source: String,
    sink: String,
    location: String,
}

impl ProtoFinding {
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn sink(&self) -> &str {
        &self.sink
    }

    pub(crate) fn location(&self) -> &str {
        &self.location
    }
}

/// Bound on findings per corpus — keeps a pathological bundle from exploding.
const MAX_FINDINGS: usize = 200;

/// Property names whose write mutates the prototype chain when the base object
/// is attacker-influenced. A write *to* one of these keys is the canonical
/// pollution sink.
const POLLUTION_KEYS: &[&str] = &["__proto__", "prototype", "constructor"];

/// Helper names that recursively copy attacker data into a target object and so
/// can set `__proto__` when fed a tainted, path-shaped payload. Matched on the
/// method/function name regardless of receiver (lodash `_`, `$`, bare imports).
const MERGE_HELPERS: &[&str] = &[
    "merge",
    "mergeWith",
    "deepmerge",
    "deepMerge",
    "extend",
    "defaultsDeep",
    "set",
    "setWith",
    "assignInWith",
    "mergeDeep",
    "deepExtend",
    "deepAssign",
];

/// Scan a corpus of `(source_text, source_url)` scripts for prototype-pollution
/// surfaces. Unparseable/oversized scripts are skipped silently (no panic).
pub(crate) fn detect(scripts: &[(&str, &str)]) -> Vec<ProtoFinding> {
    let mut findings = Vec::new();
    for (text, url) in scripts {
        let Some(parsed) = parse::parse_script(text, url) else {
            continue;
        };
        let mut visitor = ProtoVisitor::new(&parsed, url);
        parsed.module.visit_with(&mut visitor);
        findings.append(&mut visitor.findings);
    }
    dedupe(findings)
}

/// How a variable became tainted: its origin source and the hops it flowed
/// through, for human-readable path rendering.
#[derive(Debug, Clone)]
struct TaintMark {
    source: SourceMatch,
    path: Vec<String>,
}

impl TaintMark {
    fn bump(mut self, hop: &str) -> Self {
        if self.path.last().map(String::as_str) != Some(hop) {
            self.path.push(hop.to_owned());
        }
        self
    }
}

struct ProtoVisitor<'a> {
    parsed: &'a ParsedModule,
    source_name: String,
    /// Variables tainted in the *current* function scope, reset at every
    /// function boundary so taint never crosses functions.
    env: HashMap<String, TaintMark>,
    findings: Vec<ProtoFinding>,
}

impl<'a> ProtoVisitor<'a> {
    fn new(parsed: &'a ParsedModule, source_name: &str) -> Self {
        Self {
            parsed,
            source_name: source_name.to_owned(),
            env: HashMap::new(),
            findings: Vec::new(),
        }
    }

    fn loc(&self, span: Span) -> String {
        self.parsed.location(&self.source_name, span)
    }

    fn in_scope<F: FnOnce(&mut Self)>(&mut self, body: F) {
        let saved = std::mem::take(&mut self.env);
        body(self);
        self.env = saved;
    }

    /// Resolve the taint of an expression: a direct source, a tracked tainted
    /// variable, or a transform/read over one. Returns the origin mark with the
    /// hop appended, or `None` if untainted. Mirrors the engine visitor's shape.
    fn taint_of(&self, expr: &Expr) -> Option<TaintMark> {
        if let Some(source) =
            sources::classify_expr(expr).or_else(|| sources::classify_bare_ident(expr))
        {
            return Some(TaintMark {
                source,
                path: Vec::new(),
            });
        }
        match expr {
            Expr::Ident(ident) => self.env.get(ident.sym.as_ref()).cloned(),
            Expr::Member(member) => self
                .taint_of(&member.obj)
                .map(|m| m.bump("property access")),
            Expr::Paren(p) => self.taint_of(&p.expr),
            Expr::Tpl(tpl) => tpl
                .exprs
                .iter()
                .find_map(|e| self.taint_of(e))
                .map(|m| m.bump("template literal")),
            Expr::Bin(bin) => self
                .taint_of(&bin.left)
                .or_else(|| self.taint_of(&bin.right))
                .map(|m| m.bump("concatenation")),
            Expr::Call(call) => self.taint_of_call(call),
            _ => None,
        }
    }

    /// `JSON.parse(tainted)`, `qs.parse(tainted)`, `decodeURIComponent(tainted)`
    /// and `tainted.split(...)` all keep taint — these are the object-path
    /// parsing steps that turn a string source into a mergeable shape.
    fn taint_of_call(&self, call: &CallExpr) -> Option<TaintMark> {
        if let Some(arg) = call.args.first() {
            if let Some(mark) = self.taint_of(&arg.expr) {
                return Some(mark.bump("parse/transform"));
            }
        }
        if let Callee::Expr(callee) = &call.callee {
            if let Expr::Member(member) = &**callee {
                return self.taint_of(&member.obj).map(|m| m.bump("method call"));
            }
        }
        None
    }

    fn record(&mut self, mark: &TaintMark, sink: String, span: Span) {
        if self.findings.len() >= MAX_FINDINGS {
            return;
        }
        self.findings.push(ProtoFinding {
            source: mark.source.label.clone(),
            sink,
            location: self.loc(span),
        });
    }

    /// An assignment is a pollution sink when either the property written is a
    /// pollution key (`x.__proto__ = …`, `x["constructor"] = …`) or the key is
    /// itself a tainted computed expression (`obj[userKey] = …` — a
    /// configurable-key write). A constant non-pollution key is not a sink.
    fn check_sink_assign(&mut self, assign: &AssignExpr) {
        let AssignTarget::Simple(SimpleAssignTarget::Member(member)) = &assign.left else {
            return;
        };

        // A pollution-key write: the RHS taint is what makes it a live surface.
        if let Some(key) = static_prop(&member.prop) {
            if POLLUTION_KEYS.contains(&key.as_str()) {
                if let Some(mark) = self.taint_of(&assign.right) {
                    self.record(&mark, format!("proto-key write `{key}`"), assign.span());
                }
                return;
            }
        }

        // A configurable-key write: `obj[k] = v` where the *key* is tainted lets
        // an attacker pick `__proto__`. Flag on the tainted key regardless of RHS.
        if let MemberProp::Computed(comp) = &member.prop {
            if let Some(mark) = self.taint_of(&comp.expr) {
                self.record(&mark, "configurable-key write".to_owned(), assign.span());
            }
        }
    }

    /// A call is a pollution sink when it is a deep-merge/extend/deep-set helper
    /// and at least one argument carries taint. A merge of only constant/static
    /// arguments is deliberately not a finding (the plan's low-FP stance).
    fn check_sink_call(&mut self, call: &CallExpr) {
        let Some(name) = callee_name(call) else {
            return;
        };
        if !MERGE_HELPERS.contains(&name.as_str()) {
            return;
        }
        // FP suppression: lodash `set`/`setWith(obj, path, value)` take 3 args;
        // a 2-arg `set` is almost always `Map.set(key, value)`, not path-shaped
        // pollution. Require the 3-arg form for these two to skip Map/Set noise.
        if matches!(name.as_str(), "set" | "setWith") && call.args.len() < 3 {
            return;
        }
        for arg in &call.args {
            if let Some(mark) = self.taint_of(&arg.expr) {
                self.record(&mark, format!("{name}(...) deep-merge"), call.span());
                return;
            }
        }
    }

    /// Propagate taint through `let/const/var x = …` so a parsed payload carries
    /// its origin into a later merge sink in the same scope.
    fn propagate_var(&mut self, decl: &VarDeclarator) {
        let Some(init) = &decl.init else { return };
        let Pat::Ident(binding) = &decl.name else {
            return;
        };
        let name = binding.id.sym.to_string();
        if let Some(mark) = self.taint_of(init) {
            self.env.insert(name.clone(), mark.bump(&name));
        } else {
            self.env.remove(&name);
        }
    }

    fn propagate_assign(&mut self, assign: &AssignExpr) {
        let AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) = &assign.left else {
            return;
        };
        let name = ident.sym.to_string();
        if let Some(mark) = self.taint_of(&assign.right) {
            self.env.insert(name.clone(), mark.bump(&name));
        } else {
            self.env.remove(&name);
        }
    }
}

/// A member property as a static key string, whether dotted (`x.__proto__`) or
/// a string-literal subscript (`x["__proto__"]`). A computed *expression* key is
/// not static and is handled separately as a configurable-key write.
fn static_prop(prop: &MemberProp) -> Option<String> {
    match prop {
        MemberProp::Ident(ident) => Some(ident.sym.to_string()),
        MemberProp::Computed(comp) => match &*comp.expr {
            Expr::Lit(Lit::Str(s)) => Some(s.value.to_string_lossy().to_string()),
            _ => None,
        },
        MemberProp::PrivateName(_) => None,
    }
}

/// The called function's bare name: `merge(...)`, `_.merge(...)`,
/// `lodash.mergeWith(...)`, `$.extend(...)` all resolve to the method/ident.
fn callee_name(call: &CallExpr) -> Option<String> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    match &**callee {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => match &member.prop {
            MemberProp::Ident(ident) => Some(ident.sym.to_string()),
            _ => None,
        },
        _ => None,
    }
}

fn dedupe(mut findings: Vec<ProtoFinding>) -> Vec<ProtoFinding> {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.source.clone(), f.sink.clone(), f.location.clone())));
    findings
}

impl Visit for ProtoVisitor<'_> {
    fn visit_stmt(&mut self, n: &Stmt) {
        if let Stmt::Decl(swc_ecma_ast::Decl::Var(var)) = n {
            for decl in &var.decls {
                self.propagate_var(decl);
            }
        }
        n.visit_children_with(self);
    }

    fn visit_assign_expr(&mut self, n: &AssignExpr) {
        self.check_sink_assign(n);
        self.propagate_assign(n);
        n.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, n: &CallExpr) {
        self.check_sink_call(n);
        n.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        self.in_scope(|this| n.function.visit_children_with(this));
    }

    fn visit_fn_expr(&mut self, n: &FnExpr) {
        self.in_scope(|this| n.function.visit_children_with(this));
    }

    fn visit_arrow_expr(&mut self, n: &ArrowExpr) {
        self.in_scope(|this| n.visit_children_with(this));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_one(src: &str) -> Vec<ProtoFinding> {
        detect(&[(src, "https://example.com/app.js")])
    }

    #[test]
    fn proto_key_write_from_url_source_is_surface() {
        let src = r"
            const key = location.hash;
            const obj = {};
            obj.__proto__ = key;
        ";
        let findings = detect_one(src);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].sink.contains("__proto__"));
        assert!(
            findings[0].source.contains("location") || findings[0].source.contains("hash"),
            "source: {}",
            findings[0].source
        );
    }

    #[test]
    fn deep_merge_of_tainted_payload_is_surface() {
        let src = r"
            const raw = location.search;
            const payload = JSON.parse(raw);
            merge(config, payload);
        ";
        let findings = detect_one(src);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].sink.contains("deep-merge"));
    }

    #[test]
    fn configurable_key_write_with_tainted_key_is_surface() {
        let src = r"
            const k = location.hash;
            target[k] = userValue;
        ";
        let findings = detect_one(src);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].sink.contains("configurable-key"));
    }

    #[test]
    fn merge_with_constant_keys_is_not_a_finding() {
        // A deep-merge of static, untainted data is the dominant false positive
        // and must be suppressed.
        let src = r#"
            const defaults = { theme: "dark", size: 10 };
            merge(config, defaults);
        "#;
        assert!(detect_one(src).is_empty(), "constant merge must not flag");
    }

    #[test]
    fn proto_key_write_with_constant_rhs_is_not_a_finding() {
        let src = r"obj.__proto__ = { polluted: false };";
        assert!(
            detect_one(src).is_empty(),
            "a proto write of constant data is not a tainted surface"
        );
    }

    #[test]
    fn map_set_two_args_is_not_a_merge_finding() {
        // `cache.set(key, tainted)` is a Map write, not lodash path-set pollution.
        let src = r#"
            const v = location.hash;
            cache.set("k", v);
        "#;
        assert!(
            detect_one(src).is_empty(),
            "2-arg set must be treated as Map.set, not pollution"
        );
    }

    #[test]
    fn lodash_set_three_args_with_tainted_path_is_surface() {
        let src = r#"
            const path = location.hash;
            _.set(config, path, "v");
        "#;
        let findings = detect_one(src);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].sink.contains("deep-merge"));
    }

    #[test]
    fn cross_function_taint_does_not_connect() {
        let src = r"
            function a() { const v = location.search; return v; }
            function b(payload) { merge(config, payload); }
        ";
        assert!(
            detect_one(src).is_empty(),
            "intra-function scoping must not link these"
        );
    }

    #[test]
    fn unparseable_script_degrades_gracefully() {
        let findings = detect(&[("function (((", "https://example.com/broken.js")]);
        assert!(findings.is_empty());
    }
}
