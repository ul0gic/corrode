// Does:  Defines detection patterns for Anthropic credentials.
// Holds: The Anthropic key pattern requires the fixed API-key prefix and suffix.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![(
        "anthropic_api_key",
        Regex::new(r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b").unwrap(),
    )]
}
