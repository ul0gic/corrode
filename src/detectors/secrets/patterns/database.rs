// Does:  Defines detection patterns for database credentials.
// Holds: Connection string patterns require credential-bearing authority components.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "postgres_url",
            Regex::new(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+").unwrap(),
        ),
        (
            "mongodb_url",
            Regex::new(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+").unwrap(),
        ),
        (
            "mysql_url",
            Regex::new(r"mysql://[^:]+:[^@]+@[^/]+/\w+").unwrap(),
        ),
        (
            "redis_url",
            Regex::new(r"redis://(?:[^:]*:)?[^@]+@[^/]+").unwrap(),
        ),
    ]
}
