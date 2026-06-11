use std::sync::Arc;

use swc_common::{BytePos, FileName, SourceMap, Span, DUMMY_SP};
use swc_ecma_ast::{EsVersion, Module};
use swc_ecma_parser::{
    lexer::Lexer,
    Parser, StringInput,
    Syntax::{Es, Typescript},
};
use swc_ecma_parser::{EsSyntax, TsSyntax};

/// Scripts larger than this are skipped — see `MAX_SCRIPT_BYTES` in
/// `collectors/ast.rs`. Bundle traversal is bounded, not unbounded.
pub(crate) const MAX_SCRIPT_BYTES: usize = 500_000;

/// A parsed module paired with its source map, for line/col resolution.
pub(crate) struct ParsedModule {
    pub module: Module,
    pub source_map: Arc<SourceMap>,
}

impl ParsedModule {
    /// Resolve a span to a `file:line:col` string. A zero span (synthesized
    /// node) collapses to the file head rather than panicking.
    pub(crate) fn location(&self, source_name: &str, span: Span) -> String {
        let pos = match span {
            Span { lo, .. } if lo != BytePos(0) => lo,
            _ => DUMMY_SP.lo(),
        };
        let loc = self.source_map.lookup_char_pos(pos);
        format!("{source_name}:{}:{}", loc.line, loc.col_display + 1)
    }
}

/// Tries ES syntax first, then TypeScript. Returns `None` on empty/oversized/
/// unparseable input so callers degrade gracefully (no panic on hostile input).
pub(crate) fn parse_script(source: &str, source_name: &str) -> Option<ParsedModule> {
    if source.trim().is_empty() || source.len() > MAX_SCRIPT_BYTES {
        return None;
    }

    let source_map: Arc<SourceMap> = Arc::default();
    let fm = source_map.new_source_file(
        FileName::Custom(source_name.to_owned()).into(),
        source.to_owned(),
    );

    let syntaxes = [
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
            return Some(ParsedModule {
                module,
                source_map: Arc::clone(&source_map),
            });
        }
    }

    None
}

#[cfg(test)]
mod test_helpers {
    use super::parse_script;
    use swc_ecma_ast::{
        AssignTarget, CallExpr, Expr, ExprStmt, MemberExpr, ModuleItem, SimpleAssignTarget, Stmt,
    };

    fn first_expr_stmt(src: &str) -> Option<Box<Expr>> {
        let parsed = parse_script(src, "test.js")?;
        parsed.module.body.into_iter().find_map(|item| match item {
            ModuleItem::Stmt(Stmt::Expr(ExprStmt { expr, .. })) => Some(expr),
            _ => None,
        })
    }

    /// First top-level expression of a snippet — for source-classifier tests.
    pub(crate) fn parse_first_expr(src: &str) -> Option<Expr> {
        first_expr_stmt(src).map(|boxed| *boxed)
    }

    /// First top-level call expression — for sink-classifier tests.
    pub(crate) fn parse_first_call(src: &str) -> Option<CallExpr> {
        match *first_expr_stmt(src)? {
            Expr::Call(call) => Some(call),
            _ => None,
        }
    }

    /// First top-level assignment, returned as `(member_target, rhs)` — for
    /// sink-assignment tests. Only member-target assignments are returned.
    pub(crate) fn parse_first_assign(src: &str) -> Option<(MemberExpr, Box<Expr>)> {
        match *first_expr_stmt(src)? {
            Expr::Assign(assign) => match assign.left {
                AssignTarget::Simple(SimpleAssignTarget::Member(member)) => {
                    Some((member, assign.right))
                }
                _ => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) use test_helpers::{parse_first_assign, parse_first_call, parse_first_expr};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typescript_fallback() {
        let parsed = parse_script("const x: number = 1;", "t.ts");
        assert!(parsed.is_some());
    }

    #[test]
    fn rejects_empty_and_oversized() {
        assert!(parse_script("   ", "t.js").is_none());
        let big = "x".repeat(MAX_SCRIPT_BYTES + 1);
        assert!(parse_script(&big, "t.js").is_none());
    }

    #[test]
    fn unparseable_returns_none_not_panic() {
        assert!(parse_script("function (((", "t.js").is_none());
    }
}
