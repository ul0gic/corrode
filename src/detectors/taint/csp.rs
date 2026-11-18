// Does:  Classifies script relaxations across delivered CSP policies.
// Holds: A relaxation must be allowed by every policy that constrains scripts.

#[derive(Debug, Clone, Default)]
pub(crate) struct Csp {
    policies: Vec<ScriptPolicy>,
}

#[derive(Debug, Clone)]
struct ScriptPolicy {
    present: bool,
    sources: Vec<String>,
}

impl Csp {
    pub(crate) fn parse(header: &str) -> Csp {
        let policies = split_policies(header)
            .map(parse_policy)
            .filter(|p| !p.sources.is_empty() || p.present)
            .collect::<Vec<_>>();
        Csp { policies }
    }

    pub(crate) fn allows_unsafe_inline_scripts(&self) -> bool {
        self.all_constraining_policies(policy_allows_unsafe_inline)
    }

    pub(crate) fn allows_unsafe_eval(&self) -> bool {
        self.all_constraining_policies(|p| has_keyword(&p.sources, "unsafe-eval"))
    }

    pub(crate) fn has_broad_script_src(&self) -> bool {
        if self.policies.iter().all(|p| !p.present) {
            return true;
        }
        self.all_constraining_policies(|p| sources_are_broad(&p.sources))
    }

    fn all_constraining_policies(&self, pred: impl Fn(&ScriptPolicy) -> bool) -> bool {
        // Why: Policies without a script directive or fallback do not constrain script sources.
        let mut constraining = self.policies.iter().filter(|p| p.present).peekable();
        if constraining.peek().is_none() {
            return false;
        }
        constraining.all(pred)
    }
}

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

fn sources_are_broad(sources: &[String]) -> bool {
    sources.iter().any(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "*" | "https:" | "http:" | "data:"
        )
    })
}

fn has_keyword(sources: &[String], keyword: &str) -> bool {
    let quoted = format!("'{keyword}'");
    sources
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&quoted) || s.eq_ignore_ascii_case(keyword))
}

fn split_policies(header: &str) -> impl Iterator<Item = &str> {
    header
        .split(['\n', ','])
        .map(str::trim)
        .filter(|p| !p.is_empty())
}

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
    }

    #[test]
    fn no_script_or_default_src_means_broad() {
        let csp = Csp::parse("img-src 'self'; style-src 'self'");
        assert!(csp.has_broad_script_src());
        assert!(!csp.allows_unsafe_inline_scripts());
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
        let csp = Csp::parse("script-src 'unsafe-inline', script-src 'self'");
        assert!(!csp.allows_unsafe_inline_scripts());

        let both = Csp::parse("script-src 'unsafe-inline', default-src 'unsafe-inline'");
        assert!(both.allows_unsafe_inline_scripts());
    }

    #[test]
    fn non_constraining_policy_does_not_mask_a_broad_one() {
        let csp = Csp::parse("script-src *, img-src 'self'");
        assert!(csp.has_broad_script_src());
    }
}
