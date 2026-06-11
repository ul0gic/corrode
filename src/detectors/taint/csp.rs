//! Content-Security-Policy directive parser (task 2.7a). Pure string parsing —
//! no AST, no network. Turns a `Content-Security-Policy` header value into the
//! effective `script-src` and answers the bypass questions the sink↔CSP
//! correlation step (2.7b) asks. Reports surface only; constructs no payload.
//!
//! A single header value may carry multiple policies separated by commas, and a
//! response may send the header more than once. Browsers enforce the
//! intersection of all delivered policies, so the query methods answer
//! conservatively: a relaxation is reported only when *every* applicable policy
//! permits it. Pass several headers as one newline- or comma-joined string.

/// One parsed CSP, holding the effective `script-src` token list (after the
/// `default-src` fallback) for each delivered policy. Empty `policies` means no
/// CSP constrained scripts at all.
#[derive(Debug, Clone, Default)]
pub(crate) struct Csp {
    policies: Vec<ScriptPolicy>,
}

/// The `script-src` sources a single policy permits, plus whether the policy
/// even constrained script execution. `present` is false when neither
/// `script-src` nor `default-src` appeared — such a policy places no limit on
/// scripts and so cannot bypass anything by itself.
#[derive(Debug, Clone)]
struct ScriptPolicy {
    present: bool,
    sources: Vec<String>,
}

impl Csp {
    /// Parse a header value (one or more policies) into its effective
    /// `script-src` per policy. Tolerates empty input, duplicate directives
    /// (first wins, matching browser behavior), and malformed tokens (ignored).
    pub(crate) fn parse(header: &str) -> Csp {
        let policies = split_policies(header)
            .map(parse_policy)
            .filter(|p| !p.sources.is_empty() || p.present)
            .collect::<Vec<_>>();
        Csp { policies }
    }

    /// True when an inline `<script>` / inline event handler could execute under
    /// *every* applicable policy: `'unsafe-inline'` present and not neutralized
    /// by a nonce, hash, or `'strict-dynamic'` (any of which makes browsers
    /// ignore `'unsafe-inline'`).
    pub(crate) fn allows_unsafe_inline_scripts(&self) -> bool {
        self.all_constraining_policies(policy_allows_unsafe_inline)
    }

    /// True when `eval`/`Function`-style string execution is permitted under
    /// every applicable policy (`'unsafe-eval'` present in the effective
    /// `script-src`).
    pub(crate) fn allows_unsafe_eval(&self) -> bool {
        self.all_constraining_policies(|p| has_keyword(&p.sources, "unsafe-eval"))
    }

    /// True when script sources are effectively unrestricted: a wildcard or a
    /// bare scheme (`*`, `https:`, `http:`, `data:`) is allowed under every
    /// applicable policy, or no policy constrains scripts at all.
    pub(crate) fn has_broad_script_src(&self) -> bool {
        if self.policies.iter().all(|p| !p.present) {
            return true;
        }
        self.all_constraining_policies(|p| sources_are_broad(&p.sources))
    }

    /// The effective `script-src` token list. With multiple policies this is the
    /// strictest (fewest tokens) constraining one — the policy that bounds what a
    /// script load must satisfy. `None` when no policy constrains scripts.
    pub(crate) fn effective_script_src(&self) -> Option<&[String]> {
        self.policies
            .iter()
            .filter(|p| p.present)
            .min_by_key(|p| p.sources.len())
            .map(|p| p.sources.as_slice())
    }

    /// Run `pred` against every policy that actually constrains scripts. A
    /// relaxation holds only if all such policies agree; a policy that does not
    /// constrain scripts cannot tighten the others, so it is skipped.
    fn all_constraining_policies(&self, pred: impl Fn(&ScriptPolicy) -> bool) -> bool {
        let mut constraining = self.policies.iter().filter(|p| p.present).peekable();
        if constraining.peek().is_none() {
            return false;
        }
        constraining.all(pred)
    }
}

/// True if `'unsafe-inline'` is present and not overridden. A nonce, a hash, or
/// `'strict-dynamic'` causes browsers to ignore `'unsafe-inline'`, so its
/// presence makes the policy effectively safe against inline scripts.
fn policy_allows_unsafe_inline(p: &ScriptPolicy) -> bool {
    if !has_keyword(&p.sources, "unsafe-inline") {
        return false;
    }
    let neutralized = p.sources.iter().any(|s| {
        let lower = s.to_ascii_lowercase();
        lower.starts_with("'nonce-")
            || lower.starts_with("'sha256-")
            || lower.starts_with("'sha384-")
            || lower.starts_with("'sha512-")
            || lower == "'strict-dynamic'"
    });
    !neutralized
}

/// True for `*` or a bare scheme that lets scripts load from anywhere.
fn sources_are_broad(sources: &[String]) -> bool {
    sources.iter().any(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "*" | "https:" | "http:" | "data:"
        )
    })
}

/// Case-insensitive match for a CSP keyword token, with or without the quotes
/// browsers require (`'unsafe-inline'`). We accept the unquoted form too since
/// real-world headers are sloppy and we would rather over-report a relaxation.
fn has_keyword(sources: &[String], keyword: &str) -> bool {
    let quoted = format!("'{keyword}'");
    sources
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&quoted) || s.eq_ignore_ascii_case(keyword))
}

/// Split a header value into individual policies on commas. A comma separates
/// whole policies in a combined header; multiple delivered headers can be joined
/// with newlines, which we also split on.
fn split_policies(header: &str) -> impl Iterator<Item = &str> {
    header
        .split(['\n', ','])
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

/// Resolve one policy's effective `script-src`, applying the `default-src`
/// fallback. Directive names are case-insensitive; the first occurrence of a
/// directive wins (browsers ignore duplicates).
fn parse_policy(policy: &str) -> ScriptPolicy {
    let mut script_src: Option<Vec<String>> = None;
    let mut default_src: Option<Vec<String>> = None;

    for directive in policy.split(';').map(str::trim).filter(|d| !d.is_empty()) {
        let mut tokens = directive.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let values = || tokens.clone().map(str::to_owned).collect::<Vec<_>>();
        match name.to_ascii_lowercase().as_str() {
            "script-src" if script_src.is_none() => script_src = Some(values()),
            "default-src" if default_src.is_none() => default_src = Some(values()),
            _ => {}
        }
    }

    match script_src.or(default_src) {
        Some(sources) => ScriptPolicy {
            present: true,
            sources,
        },
        None => ScriptPolicy {
            present: false,
            sources: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_inline_is_flagged() {
        let csp = Csp::parse("script-src 'self' 'unsafe-inline'");
        assert!(csp.allows_unsafe_inline_scripts());
        assert!(!csp.has_broad_script_src());
    }

    #[test]
    fn nonce_neutralizes_unsafe_inline() {
        let csp = Csp::parse("script-src 'self' 'unsafe-inline' 'nonce-abc123'");
        assert!(
            !csp.allows_unsafe_inline_scripts(),
            "a nonce makes browsers ignore 'unsafe-inline'"
        );
    }

    #[test]
    fn strict_dynamic_neutralizes_unsafe_inline() {
        let csp = Csp::parse("script-src 'unsafe-inline' 'strict-dynamic' 'nonce-x'");
        assert!(!csp.allows_unsafe_inline_scripts());
    }

    #[test]
    fn hash_neutralizes_unsafe_inline() {
        let csp = Csp::parse("script-src 'unsafe-inline' 'sha256-abc='");
        assert!(!csp.allows_unsafe_inline_scripts());
    }

    #[test]
    fn unsafe_eval_is_flagged() {
        let csp = Csp::parse("script-src 'self' 'unsafe-eval'");
        assert!(csp.allows_unsafe_eval());
        assert!(!csp.allows_unsafe_inline_scripts());
    }

    #[test]
    fn missing_script_src_falls_back_to_default_src() {
        let csp = Csp::parse("default-src 'self' 'unsafe-inline'");
        assert!(csp.allows_unsafe_inline_scripts());
        assert_eq!(
            csp.effective_script_src(),
            Some(["'self'".to_owned(), "'unsafe-inline'".to_owned()].as_slice())
        );
    }

    #[test]
    fn no_script_or_default_src_means_broad() {
        let csp = Csp::parse("img-src 'self'; style-src 'self'");
        assert!(csp.has_broad_script_src());
        assert!(!csp.allows_unsafe_inline_scripts());
        assert!(csp.effective_script_src().is_none());
    }

    #[test]
    fn wildcard_and_schemes_are_broad() {
        assert!(Csp::parse("script-src *").has_broad_script_src());
        assert!(Csp::parse("script-src https:").has_broad_script_src());
        assert!(Csp::parse("script-src http: data:").has_broad_script_src());
    }

    #[test]
    fn host_allowlist_is_not_broad() {
        let csp = Csp::parse("script-src 'self' https://cdn.example.com");
        assert!(!csp.has_broad_script_src());
    }

    #[test]
    fn empty_and_whitespace_input_is_graceful() {
        assert!(!Csp::parse("").allows_unsafe_inline_scripts());
        assert!(Csp::parse("").has_broad_script_src());
        assert!(!Csp::parse("   \n  ").allows_unsafe_inline_scripts());
        assert!(Csp::parse("   ").effective_script_src().is_none());
    }

    #[test]
    fn malformed_input_does_not_panic() {
        for junk in [
            ";;;",
            "script-src",
            "   ;  ; script-src ;;",
            "=====",
            "script-src;;;;",
        ] {
            let csp = Csp::parse(junk);
            let _ = csp.allows_unsafe_inline_scripts();
            let _ = csp.allows_unsafe_eval();
            let _ = csp.has_broad_script_src();
            let _ = csp.effective_script_src();
        }
    }

    #[test]
    fn duplicate_directive_first_wins() {
        let csp = Csp::parse("script-src 'self'; script-src 'unsafe-inline'");
        assert!(
            !csp.allows_unsafe_inline_scripts(),
            "first script-src wins, matching browsers"
        );
    }

    #[test]
    fn directive_names_are_case_insensitive() {
        let csp = Csp::parse("Script-Src 'SELF' 'Unsafe-Inline'");
        assert!(csp.allows_unsafe_inline_scripts());
    }

    #[test]
    fn multiple_policies_intersect_conservatively() {
        // Comma joins two policies: one permits unsafe-inline, the other does
        // not. Browsers enforce both, so inline must NOT be reported as allowed.
        let csp = Csp::parse("script-src 'unsafe-inline', script-src 'self'");
        assert!(!csp.allows_unsafe_inline_scripts());

        // Both permit it → reported.
        let both = Csp::parse("script-src 'unsafe-inline', default-src 'unsafe-inline'");
        assert!(both.allows_unsafe_inline_scripts());
    }

    #[test]
    fn non_constraining_policy_does_not_mask_a_broad_one() {
        // One policy is broad (*), the sibling only sets img-src (no script
        // constraint). The broad one is the only constraint on scripts.
        let csp = Csp::parse("script-src *, img-src 'self'");
        assert!(csp.has_broad_script_src());
    }

    #[test]
    fn effective_script_src_picks_strictest_policy() {
        let csp = Csp::parse("script-src 'self' https://a https://b, script-src 'self'");
        assert_eq!(
            csp.effective_script_src(),
            Some(["'self'".to_owned()].as_slice())
        );
    }
}
