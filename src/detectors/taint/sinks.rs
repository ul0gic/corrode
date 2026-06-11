use swc_ecma_ast::{Callee, Expr, MemberExpr, MemberProp};

/// What an attacker gains by reaching this sink. Drives the gadget classifier
/// and the CSP-bypass correlation in the fan-out detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SinkKind {
    /// HTML parsed into the DOM: `innerHTML`, `document.write`, `insertAdjacentHTML`.
    HtmlInjection,
    /// String compiled and executed: `eval`, `Function`, string `setTimeout`.
    CodeExecution,
    /// Script element whose `src`/`text` becomes live code.
    ScriptLoad,
    /// Navigation / redirect: `location = …`, `location.assign`, `form.action`.
    Navigation,
    /// `iframe.src` / `iframe.srcdoc`.
    FrameContent,
    /// Framework escape hatch: `dangerouslySetInnerHTML`, `bypassSecurityTrust*`, `v-html`.
    FrameworkEscapeHatch,
}

/// A recognized sink with its stable label and kind.
#[derive(Debug, Clone)]
pub(crate) struct SinkMatch {
    pub label: String,
    pub kind: SinkKind,
}

/// HTML-injection / navigation sinks reached via property *assignment*:
/// `el.innerHTML = …`, `iframe.src = …`, `location.href = …`, `form.action = …`.
/// Returns `None` when the assigned property is on the safe allowlist.
pub(crate) fn classify_assign_target(member: &MemberExpr) -> Option<SinkMatch> {
    let prop = member_prop(&member.prop)?;
    if is_safe_property(prop) {
        return None;
    }

    let obj_hint = leaf_object_name(&member.obj);
    match prop {
        "innerHTML" | "outerHTML" => Some(SinkMatch {
            label: prop.to_owned(),
            kind: SinkKind::HtmlInjection,
        }),
        "srcdoc" => Some(SinkMatch {
            label: "iframe.srcdoc".to_owned(),
            kind: SinkKind::FrameContent,
        }),
        // `.src` is a sink only on a script/iframe-ish receiver; on an <img> it
        // is benign. We accept it broadly but classify by receiver hint.
        "src" => {
            let kind = match obj_hint.as_deref() {
                Some(o) if o.contains("iframe") || o.contains("frame") => SinkKind::FrameContent,
                Some(o) if o.contains("script") => SinkKind::ScriptLoad,
                _ => SinkKind::ScriptLoad,
            };
            Some(SinkMatch {
                label: format!("{}.src", obj_hint.as_deref().unwrap_or("element")),
                kind,
            })
        }
        "text" if obj_hint.as_deref().is_some_and(|o| o.contains("script")) => Some(SinkMatch {
            label: "script.text".to_owned(),
            kind: SinkKind::ScriptLoad,
        }),
        "action" if obj_hint.as_deref().is_some_and(|o| o.contains("form")) => Some(SinkMatch {
            label: "form.action".to_owned(),
            kind: SinkKind::Navigation,
        }),
        "href" if obj_hint.as_deref() == Some("location") => Some(SinkMatch {
            label: "location.href".to_owned(),
            kind: SinkKind::Navigation,
        }),
        _ => None,
    }
}

/// `location = …` where the whole `location` identifier is the assignment
/// target (no property). Navigation sink.
pub(crate) fn classify_assign_ident(name: &str) -> Option<SinkMatch> {
    (name == "location").then(|| SinkMatch {
        label: "location".to_owned(),
        kind: SinkKind::Navigation,
    })
}

/// Call-shaped sinks: `eval(…)`, `new Function(…)`, `setTimeout("…")`,
/// `el.insertAdjacentHTML(…)`, `document.write(…)`, `location.assign/replace(…)`.
pub(crate) fn classify_call(call: &swc_ecma_ast::CallExpr) -> Option<SinkMatch> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    match &**callee {
        Expr::Ident(ident) => classify_global_call(ident.sym.as_ref()),
        Expr::Member(member) => {
            if member_prop(&member.prop) == Some("setAttribute") {
                classify_set_attribute(call)
            } else {
                classify_method_call(member)
            }
        }
        _ => None,
    }
}

/// `new Function(…)` — code execution.
pub(crate) fn classify_new(callee: &Expr) -> Option<SinkMatch> {
    match callee {
        Expr::Ident(ident) if ident.sym.as_ref() == "Function" => Some(SinkMatch {
            label: "new Function(...)".to_owned(),
            kind: SinkKind::CodeExecution,
        }),
        _ => None,
    }
}

fn classify_global_call(name: &str) -> Option<SinkMatch> {
    match name {
        "eval" => Some(SinkMatch {
            label: "eval(...)".to_owned(),
            kind: SinkKind::CodeExecution,
        }),
        "Function" => Some(SinkMatch {
            label: "Function(...)".to_owned(),
            kind: SinkKind::CodeExecution,
        }),
        // `setTimeout`/`setInterval` are sinks only with a string first arg;
        // the visitor checks the argument shape before recording.
        "setTimeout" | "setInterval" => Some(SinkMatch {
            label: format!("{name}(string)"),
            kind: SinkKind::CodeExecution,
        }),
        _ => None,
    }
}

fn classify_method_call(member: &MemberExpr) -> Option<SinkMatch> {
    let method = member_prop(&member.prop)?;
    let obj = leaf_object_name(&member.obj);
    match method {
        "insertAdjacentHTML" => Some(SinkMatch {
            label: "insertAdjacentHTML(...)".to_owned(),
            kind: SinkKind::HtmlInjection,
        }),
        "write" | "writeln" if obj.as_deref() == Some("document") => Some(SinkMatch {
            label: format!("document.{method}(...)"),
            kind: SinkKind::HtmlInjection,
        }),
        "assign" | "replace" if obj.as_deref() == Some("location") => Some(SinkMatch {
            label: format!("location.{method}(...)"),
            kind: SinkKind::Navigation,
        }),
        _ => None,
    }
}

/// `el.setAttribute(name, value)` is a sink only when the attribute name is a
/// constant string that `is_safe_attribute` rejects — an `on*` handler or a
/// known script-bearing attribute. A constant safe name, or a non-constant
/// (computed) name we cannot inspect, is not recorded (the low-FP stance).
/// Kind is chosen by attribute: navigation vectors (`href`/`src`/`action`/
/// `formaction`/`xlink:href`) → `Navigation`; `srcdoc` → `FrameContent`; `on*`
/// handlers → `CodeExecution`; everything else dangerous (`style`) →
/// `HtmlInjection`.
fn classify_set_attribute(call: &swc_ecma_ast::CallExpr) -> Option<SinkMatch> {
    let name = string_literal_arg(call, 0)?;
    let lower = name.to_ascii_lowercase();
    if is_safe_attribute(&lower) {
        return None;
    }
    let kind = if lower.starts_with("on") {
        SinkKind::CodeExecution
    } else {
        match lower.as_str() {
            "href" | "src" | "action" | "formaction" | "xlink:href" => SinkKind::Navigation,
            "srcdoc" => SinkKind::FrameContent,
            _ => SinkKind::HtmlInjection,
        }
    };
    Some(SinkMatch {
        label: format!("setAttribute(\"{lower}\", ...)"),
        kind,
    })
}

/// The string-literal value of the call argument at `index`, or `None` when the
/// argument is absent or not a plain string literal (computed names cannot be
/// classified, so they are conservatively not sinks).
fn string_literal_arg(call: &swc_ecma_ast::CallExpr, index: usize) -> Option<String> {
    match call.args.get(index).map(|a| &*a.expr) {
        Some(Expr::Lit(swc_ecma_ast::Lit::Str(s))) => Some(s.value.to_string_lossy().to_string()),
        _ => None,
    }
}

/// React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `bypassSecurityTrust*`.
/// Recognized from a JSX/property key or method name.
pub(crate) fn classify_framework_hatch(name: &str) -> Option<SinkMatch> {
    if name == "dangerouslySetInnerHTML" {
        return Some(SinkMatch {
            label: "dangerouslySetInnerHTML".to_owned(),
            kind: SinkKind::FrameworkEscapeHatch,
        });
    }
    if name == "v-html" {
        return Some(SinkMatch {
            label: "v-html".to_owned(),
            kind: SinkKind::FrameworkEscapeHatch,
        });
    }
    if name.starts_with("bypassSecurityTrust") {
        return Some(SinkMatch {
            label: name.to_owned(),
            kind: SinkKind::FrameworkEscapeHatch,
        });
    }
    None
}

const SAFE_PROPERTIES: &[&str] = &["textContent", "innerText", "value", "className", "id"];

/// Properties that never parse HTML or execute code. Assigning tainted data
/// here is the dominant false-positive class, so they are hard-suppressed.
pub(crate) fn is_safe_property(name: &str) -> bool {
    SAFE_PROPERTIES.contains(&name)
}

const DANGEROUS_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "srcdoc",
    "action",
    "formaction",
    "style",
    "xlink:href",
];

/// `setAttribute(name, value)` is safe unless the attribute can carry script:
/// any `on*` handler or one of the known script-bearing attributes. Unknown
/// attributes default to *safe* — the conservative, low-FP stance: an
/// unrecognized attribute is far more likely benign than a script vector.
pub(crate) fn is_safe_attribute(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("on") {
        return false;
    }
    !DANGEROUS_ATTRIBUTES.contains(&lower.as_str())
}

/// The leaf (closest-to-property) object name of a member chain: for
/// `document.body.innerHTML` this is `body`; for `el.src` it is `el`. Used as a
/// receiver hint to disambiguate `.src` / `.action` / `.text`.
fn leaf_object_name(obj: &Expr) -> Option<String> {
    match obj {
        Expr::Ident(ident) => Some(ident.sym.to_string()),
        Expr::Member(member) => match &member.prop {
            MemberProp::Ident(ident) => Some(ident.sym.to_string()),
            _ => leaf_object_name(&member.obj),
        },
        Expr::Paren(p) => leaf_object_name(&p.expr),
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
    use crate::detectors::taint::parse::{parse_first_assign, parse_first_call};

    #[test]
    fn inner_html_assignment_is_sink() {
        let (target, _) = parse_first_assign("el.innerHTML = x").expect("assign");
        let m = classify_assign_target(&target).expect("sink");
        assert_eq!(m.kind, SinkKind::HtmlInjection);
    }

    #[test]
    fn text_content_is_safe_sink() {
        let (target, _) = parse_first_assign("el.textContent = x").expect("assign");
        assert!(classify_assign_target(&target).is_none());
    }

    #[test]
    fn eval_call_is_code_execution() {
        let call = parse_first_call("eval(payload)").expect("call");
        assert_eq!(
            classify_call(&call).map(|m| m.kind),
            Some(SinkKind::CodeExecution)
        );
    }

    #[test]
    fn document_write_is_html_injection() {
        let call = parse_first_call("document.write(x)").expect("call");
        assert_eq!(
            classify_call(&call).map(|m| m.kind),
            Some(SinkKind::HtmlInjection)
        );
    }

    #[test]
    fn location_assign_is_navigation() {
        let call = parse_first_call("location.assign(url)").expect("call");
        assert_eq!(
            classify_call(&call).map(|m| m.kind),
            Some(SinkKind::Navigation)
        );
    }

    #[test]
    fn framework_hatch_recognized() {
        assert!(classify_framework_hatch("dangerouslySetInnerHTML").is_some());
        assert!(classify_framework_hatch("bypassSecurityTrustHtml").is_some());
        assert!(classify_framework_hatch("v-html").is_some());
        assert!(classify_framework_hatch("onClick").is_none());
    }

    #[test]
    fn set_attribute_href_is_navigation_sink() {
        let call = parse_first_call(r#"el.setAttribute("href", tainted)"#).expect("call");
        assert_eq!(
            classify_call(&call).map(|m| m.kind),
            Some(SinkKind::Navigation)
        );
    }

    #[test]
    fn set_attribute_onclick_is_code_execution_sink() {
        let call = parse_first_call(r#"el.setAttribute("onclick", tainted)"#).expect("call");
        assert_eq!(
            classify_call(&call).map(|m| m.kind),
            Some(SinkKind::CodeExecution)
        );
    }

    #[test]
    fn set_attribute_safe_name_is_not_a_sink() {
        let call = parse_first_call(r#"el.setAttribute("class", tainted)"#).expect("call");
        assert!(classify_call(&call).is_none());
    }

    #[test]
    fn set_attribute_computed_name_is_not_a_sink() {
        // A non-literal attribute name cannot be classified — conservatively skip.
        let call = parse_first_call("el.setAttribute(name, tainted)").expect("call");
        assert!(classify_call(&call).is_none());
    }

    #[test]
    fn dangerous_attributes_not_safe() {
        assert!(!is_safe_attribute("href"));
        assert!(!is_safe_attribute("onclick"));
        assert!(!is_safe_attribute("srcdoc"));
        assert!(is_safe_attribute("class"));
        assert!(is_safe_attribute("aria-label"));
    }
}
