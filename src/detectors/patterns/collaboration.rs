// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Collaboration and productivity patterns: Linear, Notion, Algolia.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // Linear API Key
        (
            "linear_api_key",
            Regex::new(r"\b(lin_[A-Za-z0-9]{40})\b").unwrap(),
        ),
        // Notion Integration Token (new format, Sept 2024+)
        (
            "notion_token",
            Regex::new(r"\b(ntn_[A-Za-z0-9]{40,})\b").unwrap(),
        ),
        // Algolia API Key (32 hex + context required)
        (
            "algolia_api_key",
            Regex::new(r#"(?i)(?:algolia|x-algolia-api-key|ALGOLIA_API_KEY|algoliaApiKey)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
    ]
}
