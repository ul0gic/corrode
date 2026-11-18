// Does:  Classifies expressions that can introduce tainted values.
// Holds: Unrecognized sources do not produce a match.

use swc_ecma_ast::{Callee, Expr, MemberExpr, MemberProp};

#[derive(Debug, Clone)]
pub(crate) struct SourceMatch {
    pub label: String,
}

pub(crate) fn classify_expr(expr: &Expr) -> Option<SourceMatch> {
    match expr {
        Expr::Member(member) => classify_member(member),
        Expr::Call(call) => classify_call(call),
        Expr::New(new) => classify_new(&new.callee),
        Expr::Paren(p) => classify_expr(&p.expr),
        _ => None,
    }
}

fn classify_new(callee: &Expr) -> Option<SourceMatch> {
    let name = ident_name(callee)?;
    match name {
        "URLSearchParams" | "URL" => Some(SourceMatch {
            label: format!("new {name}(...)"),
        }),
        _ => None,
    }
}

fn classify_call(call: &swc_ecma_ast::CallExpr) -> Option<SourceMatch> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    let Expr::Member(member) = &**callee else {
        return None;
    };
    let method = member_prop(&member.prop)?;
    let object = root_object_name(&member.obj);

    match (object.as_deref(), method) {
        (Some("localStorage" | "sessionStorage"), "getItem") => Some(SourceMatch {
            label: format!("{}.getItem(...)", object?),
        }),

        // Why: The receiver hint avoids classifying generic map and cache lookups as URL sources.
        (Some(obj), "get") if is_search_params_name(obj) => Some(SourceMatch {
            label: format!("{obj}.get(...)"),
        }),
        _ => None,
    }
}

fn classify_member(member: &MemberExpr) -> Option<SourceMatch> {
    let prop = member_prop(&member.prop)?;
    let object = root_object_name(&member.obj);

    match (object.as_deref(), prop) {
        (Some("location"), "href" | "search" | "hash" | "pathname") => Some(SourceMatch {
            label: format!("location.{prop}"),
        }),
        (Some("document"), "URL" | "documentURI") => Some(SourceMatch {
            label: format!("document.{prop}"),
        }),
        (Some("document"), "referrer") => Some(SourceMatch {
            label: "document.referrer".to_owned(),
        }),
        (Some("document"), "cookie") => Some(SourceMatch {
            label: "document.cookie".to_owned(),
        }),
        (Some("window" | "self" | "top"), "name") => Some(SourceMatch {
            label: "window.name".to_owned(),
        }),

        (_, "searchParams") => Some(SourceMatch {
            label: "location.searchParams".to_owned(),
        }),
        _ => None,
    }
}

pub(crate) fn classify_bare_ident(expr: &Expr) -> Option<SourceMatch> {
    match ident_name(expr)? {
        "location" => Some(SourceMatch {
            label: "location".to_owned(),
        }),
        _ => None,
    }
}

pub(crate) fn classify_message_data(member: &MemberExpr, event_param: &str) -> Option<SourceMatch> {
    let prop = member_prop(&member.prop)?;
    let object = root_object_name(&member.obj);
    if prop == "data" && object.as_deref() == Some(event_param) {
        return Some(SourceMatch {
            label: format!("{event_param}.data"),
        });
    }
    None
}

fn is_search_params_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("param") || lower.contains("query") || lower == "search"
}

fn root_object_name(obj: &Expr) -> Option<String> {
    match obj {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => root_object_name(&member.obj),
        Expr::Paren(p) => root_object_name(&p.expr),
        Expr::This(_) => Some("this".to_owned()),
        _ => None,
    }
}

fn ident_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Ident(ident) => Some(ident.sym.as_ref()),
        _ => None,
    }
}

fn member_prop(prop: &MemberProp) -> Option<&str> {
    match prop {
        MemberProp::Ident(ident) => Some(ident.sym.as_ref()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::taint::parse::parse_first_expr;

    fn classify(src: &str) -> Option<SourceMatch> {
        let expr = parse_first_expr(src)?;
        classify_expr(&expr).or_else(|| classify_bare_ident(&expr))
    }

    #[test]
    fn recognizes_location_search() {
        let m = classify("location.search").expect("source");
        assert_eq!(m.label, "location.search");
    }

    #[test]
    fn recognizes_storage_get_item() {
        let m = classify("localStorage.getItem('k')").expect("source");
        assert_eq!(m.label, "localStorage.getItem(...)");
    }

    #[test]
    fn recognizes_url_search_params_ctor() {
        let m = classify("new URLSearchParams(location.search)").expect("source");
        assert_eq!(m.label, "new URLSearchParams(...)");
    }

    #[test]
    fn search_params_get_recognized_by_receiver_name() {
        assert!(classify("params.get('x')").is_some());
        assert!(classify("queryString.get('x')").is_some());
    }

    #[test]
    fn plain_map_get_is_not_a_source() {
        assert!(classify("cache.get('x')").is_none());
        assert!(classify("userMap.get(id)").is_none());
    }

    #[test]
    fn referrer_and_cookie_classified() {
        assert_eq!(
            classify("document.referrer").map(|m| m.label),
            Some("document.referrer".to_owned())
        );
        assert_eq!(
            classify("document.cookie").map(|m| m.label),
            Some("document.cookie".to_owned())
        );
    }

    #[test]
    fn non_source_returns_none() {
        assert!(classify("Math.random()").is_none());
        assert!(classify("foo.bar").is_none());
    }
}
