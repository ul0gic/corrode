// Does:  Defines detection patterns for collaboration service credentials.
// Holds: The Algolia key pattern requires nearby Algolia-specific context.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "linear_api_key",
            Regex::new(r"\b(lin_[A-Za-z0-9]{40})\b").unwrap(),
        ),
        (
            "notion_token",
            Regex::new(r"\b(ntn_[A-Za-z0-9]{40,})\b").unwrap(),
        ),
        (
            "algolia_api_key",
            Regex::new(r#"(?i)(?:algolia|x-algolia-api-key|ALGOLIA_API_KEY|algoliaApiKey)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
    ]
}
