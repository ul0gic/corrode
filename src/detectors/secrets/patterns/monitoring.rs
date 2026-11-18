// Does:  Defines detection patterns for monitoring service credentials.
// Holds: Datadog key patterns require a nearby service-specific label.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "sentry_dsn",
            Regex::new(r"https?://[a-f0-9]{32}@(?:o\d+\.)?(?:ingest\.)?sentry\.io/\d+").unwrap(),
        ),
        (
            "sentry_auth_token",
            Regex::new(r"\b(sntrys_[A-Za-z0-9+/=_\-]{40,})\b").unwrap(),
        ),
        (
            "sentry_user_token",
            Regex::new(r"\b(sntryu_[a-f0-9]{64,})\b").unwrap(),
        ),
        (
            "datadog_api_key",
            Regex::new(r#"(?i)(?:datadog|dd_api|DD_API_KEY)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
        (
            "datadog_app_key",
            Regex::new(r#"(?i)(?:datadog|dd_app|DD_APP_KEY)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{40})\b"#).unwrap(),
        ),
        (
            "pagerduty_api_key",
            Regex::new(r#"(?i)(?:pagerduty|pd_api|PD_TOKEN)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([A-Za-z0-9_+]{20})\b"#).unwrap(),
        ),
        (
            "pagerduty_routing_key",
            Regex::new(r#"(?i)(?:pagerduty|pd_integration|pd_routing|routing_key)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
    ]
}
