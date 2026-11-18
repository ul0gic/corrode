// Does:  Defines detection patterns for version control credentials.
// Holds: GitHub and GitLab tokens require their respective fixed prefixes.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

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
