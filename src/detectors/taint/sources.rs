//! Taint sources: attacker-influenceable values reachable from a page's own
//! JavaScript. Each entry recognizes a member-chain or call shape and yields a
//! stable human-readable label. Catalog is `pub(crate)` so the Phase-2 fan-out
//! detectors (proto/postmessage/csp) reuse one source vocabulary.

use swc_ecma_ast::{Callee, Expr, MemberExpr, MemberProp};

/// Coarse classification used by downstream gadget/postMessage detectors to
/// reason about a flow without re-parsing its label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceKind {
    /// `location.*`, `document.URL`, hash/fragment, `URLSearchParams`.
    Url,
    /// `document.referrer`.
    Referrer,
    /// `window.name`.
    WindowName,
    /// `localStorage` / `sessionStorage` reads.
    Storage,
    /// `document.cookie`.
    Cookie,
    /// A `message` event's `.data` (postMessage).
    PostMessage,
}

/// A recognized taint source with its stable label and kind.
#[derive(Debug, Clone)]
pub(crate) struct SourceMatch {
    pub label: String,
    pub kind: SourceKind,
}

/// Classify an expression as a taint source, if it is one. Recognizes member
/// chains (`location.search`, `localStorage.getItem(...)`, `event.data`) and
/// `new URLSearchParams(...)`. Returns `None` for everything else — the
/// conservative default keeps false positives down.
pub(crate) fn classify_expr(expr: &Expr) -> Option<SourceMatch> {
    match expr {
        Expr::Member(member) => classify_member(member),
        Expr::Call(call) => classify_call(call),
        Expr::New(new) => classify_new(&new.callee),
        Expr::Paren(p) => classify_expr(&p.expr),
        _ => None,
    }
}

/// Recognize `new URLSearchParams(...)` and `new URL(...)` constructors as
/// URL-derived sources.
fn classify_new(callee: &Expr) -> Option<SourceMatch> {
    let name = ident_name(callee)?;
    match name {
        "URLSearchParams" | "URL" => Some(SourceMatch {
            label: format!("new {name}(...)"),
            kind: SourceKind::Url,
        }),
        _ => None,
    }
}

/// Recognize call-shaped sources: `localStorage.getItem(...)`,
/// `searchParams.get(...)`, `new URL(...).searchParams.get(...)`.
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
            kind: SourceKind::Storage,
        }),
        // `.get(...)` on a URLSearchParams-ish receiver. We only accept it when
        // the receiver name hints at search params, to avoid map/cache `.get`.
        (Some(obj), "get") if is_search_params_name(obj) => Some(SourceMatch {
            label: format!("{obj}.get(...)"),
            kind: SourceKind::Url,
        }),
        _ => None,
    }
}

/// Recognize member-chain sources: `location.href/search/hash`,
/// `document.URL/documentURI/cookie/referrer`, `window.name`,
/// `event.data`, `.searchParams`.
fn classify_member(member: &MemberExpr) -> Option<SourceMatch> {
    let prop = member_prop(&member.prop)?;
    let object = root_object_name(&member.obj);

    match (object.as_deref(), prop) {
        (Some("location"), "href" | "search" | "hash" | "pathname") => Some(SourceMatch {
            label: format!("location.{prop}"),
            kind: SourceKind::Url,
        }),
        (Some("document"), "URL" | "documentURI") => Some(SourceMatch {
            label: format!("document.{prop}"),
            kind: SourceKind::Url,
        }),
        (Some("document"), "referrer") => Some(SourceMatch {
            label: "document.referrer".to_owned(),
            kind: SourceKind::Referrer,
        }),
        (Some("document"), "cookie") => Some(SourceMatch {
            label: "document.cookie".to_owned(),
            kind: SourceKind::Cookie,
        }),
        (Some("window" | "self" | "top"), "name") => Some(SourceMatch {
            label: "window.name".to_owned(),
            kind: SourceKind::WindowName,
        }),
        // `event.data` / `e.data` / `msg.data`: only treated as a source when
        // the visitor is inside a `message`-event handler (see visitor.rs).
        (_, "searchParams") => Some(SourceMatch {
            label: "location.searchParams".to_owned(),
            kind: SourceKind::Url,
        }),
        _ => None,
    }
}

/// Recognize a bare `location` / `document.location` reference used directly
/// (e.g. assigned into a variable). Bare `location` is URL-tainted.
pub(crate) fn classify_bare_ident(expr: &Expr) -> Option<SourceMatch> {
    match ident_name(expr)? {
        "location" => Some(SourceMatch {
            label: "location".to_owned(),
            kind: SourceKind::Url,
        }),
        _ => None,
    }
}

/// `event.data` within a known message handler. The visitor calls this only
/// when it has established the enclosing function is a message listener, so the
/// receiver-name heuristic here can stay broad without inviting false positives.
pub(crate) fn classify_message_data(member: &MemberExpr, event_param: &str) -> Option<SourceMatch> {
    let prop = member_prop(&member.prop)?;
    let object = root_object_name(&member.obj);
    if prop == "data" && object.as_deref() == Some(event_param) {
        return Some(SourceMatch {
            label: format!("{event_param}.data"),
            kind: SourceKind::PostMessage,
        });
    }
    None
}

fn is_search_params_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("param") || lower.contains("query") || lower == "search"
}

/// The leftmost identifier of a (possibly nested) member chain.
/// `a.b.c` -> `a`. Used to anchor a source on its root object.
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
        assert_eq!(m.kind, SourceKind::Url);
        assert_eq!(m.label, "location.search");
    }

    #[test]
    fn recognizes_storage_get_item() {
        let m = classify("localStorage.getItem('k')").expect("source");
        assert_eq!(m.kind, SourceKind::Storage);
    }

    #[test]
    fn recognizes_url_search_params_ctor() {
        let m = classify("new URLSearchParams(location.search)").expect("source");
        assert_eq!(m.kind, SourceKind::Url);
    }

    #[test]
    fn search_params_get_recognized_by_receiver_name() {
        assert!(classify("params.get('x')").is_some());
        assert!(classify("queryString.get('x')").is_some());
    }

    #[test]
    fn plain_map_get_is_not_a_source() {
        // A generic `.get` on a non-param receiver must not taint — low FP.
        assert!(classify("cache.get('x')").is_none());
        assert!(classify("userMap.get(id)").is_none());
    }

    #[test]
    fn referrer_and_cookie_classified() {
        assert_eq!(
            classify("document.referrer").map(|m| m.kind),
            Some(SourceKind::Referrer)
        );
        assert_eq!(
            classify("document.cookie").map(|m| m.kind),
            Some(SourceKind::Cookie)
        );
    }

    #[test]
    fn non_source_returns_none() {
        assert!(classify("Math.random()").is_none());
        assert!(classify("foo.bar").is_none());
    }
}
