// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Version control system patterns: GitHub, GitLab tokens.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "github",
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        ),
        (
            "github_fine",
            Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap(),
        ),
        ("gitlab", Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap()),
    ]
}
