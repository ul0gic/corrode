// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Database connection string patterns: `PostgreSQL`, `MongoDB`, `MySQL`, Redis.
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
