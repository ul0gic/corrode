use std::collections::HashSet;

use regex::Regex;
use swc_common::{BytePos, FileName, SourceMap, Span, Spanned, DUMMY_SP};
use swc_ecma_ast::EsVersion;
use swc_ecma_ast::{
    CallExpr, Callee, Expr, KeyValueProp, Lit, MemberProp, Module, ObjectLit, Pat, Prop, PropName,
    PropOrSpread, Tpl, VarDeclarator,
};
use swc_ecma_parser::{
    lexer::Lexer,
    Parser, StringInput,
    Syntax::{Es, Typescript},
};
use swc_ecma_parser::{EsSyntax, TsSyntax};
use swc_ecma_visit::{Visit, VisitWith};

use crate::types::AstFinding;

const MAX_SCRIPT_BYTES: usize = 500_000;

pub fn analyze_script(source: &str, origin: &str) -> Vec<AstFinding> {
    if source.trim().is_empty() || source.len() > MAX_SCRIPT_BYTES {
        return Vec::new();
    }

    let Some((module, cm)) = parse_module(source, origin) else {
        return Vec::new();
    };

    let mut analyzer = AstAnalyzer::new(origin, cm);
    module.visit_with(&mut analyzer);
    analyzer.findings
}

fn parse_module(source: &str, origin: &str) -> Option<(Module, std::sync::Arc<SourceMap>)> {
    let cm: std::sync::Arc<SourceMap> = Default::default();
    let fm = cm.new_source_file(
        FileName::Custom(origin.to_string()).into(),
        source.to_string(),
    );

    let syntaxes = vec![
        Es(EsSyntax {
            jsx: true,
            export_default_from: true,
            fn_bind: false,
            decorators: true,
            decorators_before_export: true,
            import_attributes: true,
            allow_super_outside_method: true,
            allow_return_outside_function: true,
            auto_accessors: true,
            explicit_resource_management: true,
        }),
        Typescript(TsSyntax {
            tsx: true,
            decorators: true,
            dts: false,
            no_early_errors: false,
            disallow_ambiguous_jsx_like: false,
        }),
    ];

    for syntax in syntaxes {
        let lexer = Lexer::new(syntax, EsVersion::Es2022, StringInput::from(&*fm), None);
        let mut parser = Parser::new_from(lexer);
        if let Ok(module) = parser.parse_module() {
            return Some((module, cm.clone()));
        }
    }

    None
}

struct AstAnalyzer {
    source_name: String,
    findings: Vec<AstFinding>,
    seen: HashSet<String>,
    cm: std::sync::Arc<SourceMap>,
    url_regex: Regex,
    credential_hint_regex: Regex,
    jwt_regex: Regex,
}

impl AstAnalyzer {
    fn new(source_name: &str, cm: std::sync::Arc<SourceMap>) -> Self {
        Self {
            source_name: source_name.to_string(),
            findings: Vec::new(),
            seen: HashSet::new(),
            cm,
            url_regex: Regex::new(r#"https?://[^\s"']{6,}"#).unwrap(),
            credential_hint_regex: Regex::new(
                r"(?i)(api[_-]?key|token|secret|bearer|client[_-]?secret|auth)",
            )
            .unwrap(),
            jwt_regex: Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
        }
    }

    fn record(&mut self, kind: &str, value: String, span: Span, context: String) {
        let loc = self.cm.lookup_char_pos(match span {
            Span { lo, .. } if lo != BytePos(0) => lo,
            _ => DUMMY_SP.lo(),
        });
        let location = format!("{}:{}:{}", self.source_name, loc.line, loc.col_display + 1);
        let signature = format!("{}|{}|{}", kind, value, location);
        if self.seen.insert(signature) {
            self.findings.push(AstFinding {
                kind: kind.to_string(),
                value: truncate(&value),
                location,
                context,
            });
        }
    }

    fn visit_object_for_url(&mut self, obj: &ObjectLit, span: Span, context: &str) {
        for prop in &obj.props {
            if let PropOrSpread::Prop(boxed_prop) = prop {
                if let Prop::KeyValue(kv) = &**boxed_prop {
                    if let Some(key) = prop_name(&kv.key) {
                        if key == "url" || key.contains("endpoint") {
                            if let Some(url) = string_from_expr(&kv.value) {
                                if self.url_regex.is_match(&url) {
                                    self.record("endpoint", url, span, context.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn handle_http_call(&mut self, call: &CallExpr) {
        let (kind, maybe_target, context_hint) = match &call.callee {
            Callee::Expr(expr) => match &**expr {
                Expr::Ident(ident) if ident.sym.as_ref() == "fetch" => (
                    "endpoint",
                    call.args.first().map(|a| a.expr.as_ref()),
                    "fetch() call".to_string(),
                ),
                Expr::Member(member) => {
                    let method = member_prop_name(&member.prop);
                    let object = member_object_name(&member.obj);
                    match (object.as_deref(), method.as_deref()) {
                        (Some("axios"), Some(method)) => (
                            "endpoint",
                            call.args.first().map(|a| a.expr.as_ref()),
                            format!("axios.{}()", method),
                        ),
                        (Some("$"), Some("ajax")) | (Some("jQuery"), Some("ajax")) => (
                            "endpoint",
                            call.args.first().map(|a| a.expr.as_ref()),
                            "ajax() call".to_string(),
                        ),
                        _ => ("", None, String::new()),
                    }
                }
                _ => ("", None, String::new()),
            },
            _ => ("", None, String::new()),
        };

        if kind.is_empty() {
            return;
        }

        if let Some(target_expr) = maybe_target {
            if let Some(url) = string_from_expr(target_expr) {
                if self.url_regex.is_match(&url) {
                    self.record(kind, url, call.span, context_hint);
                    return;
                }
            }

            if let Expr::Object(obj) = target_expr {
                self.visit_object_for_url(obj, call.span, &context_hint);
            }
        }
    }

    fn handle_suspicious_literal(&mut self, kv: &KeyValueProp) {
        let Some(key) = prop_name(&kv.key) else {
            return;
        };
        if let Some(value) = string_from_expr(&kv.value) {
            if !self.is_sensitive_literal(&key, &value) {
                return;
            }

            let context = if self.url_regex.is_match(&value) {
                "object url literal"
            } else {
                "credential-like literal"
            };
            let kind = if self.jwt_regex.is_match(&value) {
                "jwt_literal"
            } else if self.url_regex.is_match(&value) {
                "endpoint_literal"
            } else {
                "literal"
            };

            self.record(
                kind,
                format!("{} = {}", key, value),
                kv.value.span(),
                context.to_string(),
            );
        }
    }

    fn is_sensitive_literal(&self, key: &str, value: &str) -> bool {
        let key_l = key.to_lowercase();
        let val_l = value.to_lowercase();
        if val_l.contains("pixel code is not installed correctly") {
            return false;
        }
        let key_hint = self.credential_hint_regex.is_match(key)
            || key_l.contains("supabase")
            || key_l.contains("stripe")
            || key_l.contains("openai")
            || key_l.contains("netlify")
            || key_l.contains("cloudflare")
            || key_l.contains("service_role")
            || key_l.contains("service-role");
        let looks_jwt = self.jwt_regex.is_match(value);
        let looks_url = self.url_regex.is_match(value);
        let looks_keyish =
            value.starts_with("pk_") || value.starts_with("sk_") || value.starts_with("nfp_");
        let long_secret = value.len() > 80;

        key_hint || looks_jwt || looks_url || looks_keyish || long_secret
    }
}

impl Visit for AstAnalyzer {
    fn visit_call_expr(&mut self, n: &CallExpr) {
        self.handle_http_call(n);
        n.visit_children_with(self);
    }

    fn visit_key_value_prop(&mut self, n: &KeyValueProp) {
        self.handle_suspicious_literal(n);
        n.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, n: &VarDeclarator) {
        self.handle_var_declarator(n);
        n.visit_children_with(self);
    }
}

fn string_from_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Lit(Lit::Str(s)) => Some(s.value.to_string_lossy().to_string()),
        Expr::Lit(Lit::Regex(re)) => Some(re.exp.to_string()),
        Expr::Tpl(tpl) => tpl_to_string(tpl),
        _ => None,
    }
}

fn tpl_to_string(tpl: &Tpl) -> Option<String> {
    if tpl.exprs.is_empty() {
        let mut combined = String::new();
        for elem in &tpl.quasis {
            combined.push_str(elem.raw.as_ref());
        }
        return Some(combined);
    }

    None
}

fn prop_name(name: &PropName) -> Option<String> {
    match name {
        PropName::Ident(ident) => Some(ident.sym.to_string()),
        PropName::Str(s) => Some(s.value.to_string_lossy().to_string()),
        _ => None,
    }
}

fn member_prop_name(prop: &MemberProp) -> Option<String> {
    match prop {
        MemberProp::Ident(ident) => Some(ident.sym.to_string()),
        MemberProp::PrivateName(name) => Some(name.name.to_string()),
        MemberProp::Computed(comp) => string_from_expr(&comp.expr).map(|s| s.to_string()),
    }
}

fn member_object_name(obj: &Expr) -> Option<String> {
    match obj {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => member_object_name(&member.obj),
        _ => None,
    }
}

impl AstAnalyzer {
    fn handle_var_declarator(&mut self, decl: &VarDeclarator) {
        let Some(init) = &decl.init else { return };
        let Some(name) = pat_name(&decl.name) else {
            return;
        };
        if let Some(value) = string_from_expr(init) {
            if !self.is_sensitive_literal(&name, &value) {
                return;
            }
            let kind = if self.jwt_regex.is_match(&value) {
                "jwt_literal"
            } else if self.url_regex.is_match(&value) {
                "endpoint_literal"
            } else {
                "literal"
            };
            self.record(
                kind,
                format!("{} = {}", name, value),
                init.span(),
                "var literal".into(),
            );
        }
    }
}

fn pat_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(id) => Some(id.id.sym.to_string()),
        _ => None,
    }
}

fn truncate(value: &str) -> String {
    const MAX_LEN: usize = 180;
    if value.len() > MAX_LEN {
        format!("{}...", &value[..MAX_LEN])
    } else {
        value.to_string()
    }
}
