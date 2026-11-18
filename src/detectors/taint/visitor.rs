// Does:  Tracks taint through script expressions and records sink flows.
// Holds: Each function starts with a fresh taint environment.

use std::collections::HashMap;

use swc_common::{Span, Spanned};
use swc_ecma_ast::{
    ArrowExpr, AssignExpr, AssignTarget, CallExpr, Expr, FnDecl, FnExpr, Lit, MemberExpr,
    SimpleAssignTarget, Stmt, VarDeclarator,
};
use swc_ecma_visit::{Visit, VisitWith};

use super::parse::ParsedModule;
use super::sinks::{self, SinkKind};
use super::sources::{self, SourceMatch};

#[derive(Debug, Clone)]
pub(crate) struct RawFlow {
    pub source_label: String,
    pub sink_label: String,

    pub path: Vec<String>,
    pub location: String,
}

const MAX_FLOWS: usize = 200;

pub(crate) fn run(parsed: &ParsedModule, source_name: &str) -> Vec<RawFlow> {
    let mut visitor = TaintVisitor::new(parsed, source_name);
    parsed.module.visit_with(&mut visitor);
    visitor.flows
}

#[derive(Debug, Clone)]
struct TaintMark {
    source: SourceMatch,
    path: Vec<String>,
}

struct TaintVisitor<'a> {
    parsed: &'a ParsedModule,
    source_name: String,

    env: HashMap<String, TaintMark>,

    message_param: Option<String>,
    flows: Vec<RawFlow>,
}

impl<'a> TaintVisitor<'a> {
    fn new(parsed: &'a ParsedModule, source_name: &str) -> Self {
        Self {
            parsed,
            source_name: source_name.to_owned(),
            env: HashMap::new(),
            message_param: None,
            flows: Vec::new(),
        }
    }

    fn loc(&self, span: Span) -> String {
        self.parsed.location(&self.source_name, span)
    }

    fn in_scope<F: FnOnce(&mut Self)>(&mut self, message_param: Option<String>, body: F) {
        // Why: A fresh environment prevents taint from crossing function boundaries.
        let saved_env = std::mem::take(&mut self.env);
        let saved_msg = self.message_param.take();
        self.message_param = message_param.or(saved_msg.clone());
        body(self);
        self.env = saved_env;
        self.message_param = saved_msg;
    }

    fn taint_of(&self, expr: &Expr) -> Option<TaintMark> {
        // Why: Tracked receiver origins take precedence over reclassifying the call as a new source.
        if let Some(mark) = self.taint_through_tracked_var(expr) {
            return Some(mark);
        }

        if let Some(source) = sources::classify_expr(expr) {
            return Some(TaintMark {
                source,
                path: Vec::new(),
            });
        }
        match expr {
            Expr::Ident(ident) => self.env.get(ident.sym.as_ref()).cloned(),

            Expr::Member(member) => self.taint_of_member(member),
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

    fn taint_through_tracked_var(&self, expr: &Expr) -> Option<TaintMark> {
        use swc_ecma_ast::Callee;
        let receiver = match expr {
            Expr::Call(call) => match &call.callee {
                Callee::Expr(callee) => match &**callee {
                    Expr::Member(member) => &member.obj,
                    _ => return None,
                },
                _ => return None,
            },
            _ => return None,
        };

        match &**receiver {
            Expr::Ident(ident) if self.env.contains_key(ident.sym.as_ref()) => self
                .env
                .get(ident.sym.as_ref())
                .cloned()
                .map(|m| m.bump("method call")),
            _ => None,
        }
    }

    fn taint_of_member(&self, member: &MemberExpr) -> Option<TaintMark> {
        if let Some(param) = &self.message_param {
            if let Some(source) = sources::classify_message_data(member, param) {
                return Some(TaintMark {
                    source,
                    path: Vec::new(),
                });
            }
        }

        self.taint_of(&member.obj)
            .map(|m| m.bump("property access"))
    }

    fn taint_of_call(&self, call: &CallExpr) -> Option<TaintMark> {
        use swc_ecma_ast::Callee;

        if let Some(arg) = call.args.first() {
            if let Some(mark) = self.taint_of(&arg.expr) {
                return Some(mark.bump("function call"));
            }
        }

        if let Callee::Expr(callee) = &call.callee {
            if let Expr::Member(member) = &**callee {
                return self.taint_of(&member.obj).map(|m| m.bump("method call"));
            }
        }
        None
    }

    fn record(&mut self, mark: &TaintMark, sink: &sinks::SinkMatch, span: Span) {
        if self.flows.len() >= MAX_FLOWS {
            return;
        }
        self.flows.push(RawFlow {
            source_label: mark.source.label.clone(),
            sink_label: sink.label.clone(),
            path: mark.path.clone(),
            location: self.loc(span),
        });
    }

    fn check_sink_call(&mut self, call: &CallExpr) {
        let Some(sink) = sinks::classify_call(call) else {
            return;
        };

        if matches!(sink.kind, SinkKind::CodeExecution)
            && sink.label.contains("(string)")
            && !arg_is_stringish(call)
        {
            return;
        }
        for arg in &call.args {
            if let Some(mark) = self.taint_of(&arg.expr) {
                self.record(&mark, &sink, call.span());
                return;
            }
        }
    }

    fn check_sink_assign(&mut self, assign: &AssignExpr) {
        let sink = match &assign.left {
            AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                sinks::classify_assign_target(member)
            }
            AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) => {
                sinks::classify_assign_ident(ident.sym.as_ref())
            }
            _ => None,
        };
        let Some(sink) = sink else { return };
        if let Some(mark) = self.taint_of(&assign.right) {
            self.record(&mark, &sink, assign.span);
        }
    }

    fn propagate_var(&mut self, decl: &VarDeclarator) {
        let Some(init) = &decl.init else { return };
        let swc_ecma_ast::Pat::Ident(binding) = &decl.name else {
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

impl TaintMark {
    fn bump(mut self, hop: &str) -> Self {
        if self.path.last().map(String::as_str) != Some(hop) {
            self.path.push(hop.to_owned());
        }
        self
    }
}

fn arg_is_stringish(call: &CallExpr) -> bool {
    matches!(
        call.args.first().map(|a| &*a.expr),
        Some(Expr::Lit(Lit::Str(_)) | Expr::Tpl(_) | Expr::Ident(_) | Expr::Bin(_))
    )
}

fn message_handler_param(call: &CallExpr) -> Option<String> {
    use swc_ecma_ast::Callee;
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    let Expr::Member(member) = &**callee else {
        return None;
    };
    let swc_ecma_ast::MemberProp::Ident(method) = &member.prop else {
        return None;
    };
    if method.sym.as_ref() != "addEventListener" {
        return None;
    }

    match call.args.first().map(|a| &*a.expr) {
        Some(Expr::Lit(Lit::Str(s))) if s.value.to_string_lossy() == "message" => {}
        _ => return None,
    }
    let handler = call.args.get(1)?;
    first_param_name(&handler.expr)
}

fn first_param_name(expr: &Expr) -> Option<String> {
    let pat = match expr {
        Expr::Arrow(ArrowExpr { params, .. }) => params.first()?,
        Expr::Fn(FnExpr { function, .. }) => return fn_first_param(&function.params),
        _ => return None,
    };
    pat_ident_name(pat)
}

fn fn_first_param(params: &[swc_ecma_ast::Param]) -> Option<String> {
    let pat = &params.first()?.pat;
    match pat {
        swc_ecma_ast::Pat::Ident(id) => Some(id.id.sym.to_string()),
        _ => None,
    }
}

fn pat_ident_name(pat: &swc_ecma_ast::Pat) -> Option<String> {
    match pat {
        swc_ecma_ast::Pat::Ident(id) => Some(id.id.sym.to_string()),
        _ => None,
    }
}

impl Visit for TaintVisitor<'_> {
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
        if let Some(param) = message_handler_param(n) {
            self.in_scope(Some(param), |this| {
                for arg in &n.args {
                    arg.visit_with(this);
                }
            });
            return;
        }
        self.check_sink_call(n);
        n.visit_children_with(self);
    }

    fn visit_fn_decl(&mut self, n: &FnDecl) {
        self.in_scope(None, |this| n.function.visit_children_with(this));
    }

    fn visit_fn_expr(&mut self, n: &FnExpr) {
        self.in_scope(None, |this| n.function.visit_children_with(this));
    }

    fn visit_arrow_expr(&mut self, n: &ArrowExpr) {
        self.in_scope(None, |this| n.visit_children_with(this));
    }
}
