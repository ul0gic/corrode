// Does:  Defines detection patterns for communication service credentials.
// Holds: Webhook patterns identify service URLs as well as token-shaped values.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "slack",
            Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap(),
        ),
        (
            "slack_webhook",
            Regex::new(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")
                .unwrap(),
        ),
        (
            "discord",
            Regex::new(r"discord(?:app)?\.com/api/webhooks/[\d]+/[\w-]+").unwrap(),
        ),
        (
            "discord_token",
            Regex::new(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}").unwrap(),
        ),
        (
            "sendgrid",
            Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
        ),
        ("twilio", Regex::new(r"SK[0-9a-fA-F]{32}").unwrap()),
        ("twilio_account", Regex::new(r"AC[0-9a-fA-F]{32}").unwrap()),
        ("mailgun", Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap()),
        (
            "mailchimp",
            Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
        ),
        (
            "postmark_server_token",
            Regex::new(r#"(?i)(?:postmark|X-Postmark-Server-Token|POSTMARK_SERVER_TOKEN)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b"#).unwrap(),
        ),
    ]
}
