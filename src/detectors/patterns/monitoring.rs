// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Monitoring and observability patterns: Sentry, Datadog, `PagerDuty`.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // Sentry DSN URL (Low severity — enables quota abuse, not data access)
        (
            "sentry_dsn",
            Regex::new(r"https?://[a-f0-9]{32}@(?:o\d+\.)?(?:ingest\.)?sentry\.io/\d+").unwrap(),
        ),
        // Sentry Auth Token (High — full API access)
        (
            "sentry_auth_token",
            Regex::new(r"\b(sntrys_[A-Za-z0-9+/=_\-]{40,})\b").unwrap(),
        ),
        // Sentry User Token
        (
            "sentry_user_token",
            Regex::new(r"\b(sntryu_[a-f0-9]{64,})\b").unwrap(),
        ),
        // Datadog API Key (32 hex + context required)
        (
            "datadog_api_key",
            Regex::new(r#"(?i)(?:datadog|dd_api|DD_API_KEY)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
        // Datadog Application Key (40 hex + context required)
        (
            "datadog_app_key",
            Regex::new(r#"(?i)(?:datadog|dd_app|DD_APP_KEY)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{40})\b"#).unwrap(),
        ),
        // PagerDuty REST API Key (20 chars + context)
        (
            "pagerduty_api_key",
            Regex::new(r#"(?i)(?:pagerduty|pd_api|PD_TOKEN)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([A-Za-z0-9_+]{20})\b"#).unwrap(),
        ),
        // PagerDuty Events/Routing Key (32 hex + context)
        (
            "pagerduty_routing_key",
            Regex::new(r#"(?i)(?:pagerduty|pd_integration|pd_routing|routing_key)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{32})\b"#).unwrap(),
        ),
    ]
}
