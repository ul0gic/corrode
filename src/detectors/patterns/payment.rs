// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Payment processing patterns: Stripe keys, Plaid credentials.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "stripe_publishable_key",
            Regex::new(r"pk_(?:live|test)_[A-Za-z0-9]{20,}").unwrap(),
        ),
        (
            "stripe_secret_key",
            Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
        ),
        (
            "stripe_restricted",
            Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap(),
        ),
        // Plaid Client ID (24 hex + context)
        (
            "plaid_client_id",
            Regex::new(r#"(?i)(?:plaid|PLAID_CLIENT_ID)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{24})\b"#).unwrap(),
        ),
        // Plaid Secret (30 hex + context)
        (
            "plaid_secret",
            Regex::new(r#"(?i)(?:plaid|PLAID_SECRET)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{30})\b"#).unwrap(),
        ),
    ]
}
