// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// AI platform patterns: Anthropic API keys.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![(
        "anthropic_api_key",
        Regex::new(r"\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)\b").unwrap(),
    )]
}
