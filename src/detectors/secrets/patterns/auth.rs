// Does:  Defines detection patterns for authentication credentials.
// Holds: JWT patterns require three dot-separated token segments.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "jwt",
            Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
        ),
        (
            "jwt_in_url",
            Regex::new(r"[?&](?:token|jwt|access_token|id_token)=eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
        ),
        (
            "bearer_token",
            Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*").unwrap(),
        ),
        (
            "basic_auth",
            Regex::new(r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}").unwrap(),
        ),
        (
            "private_key",
            Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
        ),
        (
            "google_oauth",
            Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap(),
        ),
        (
            "openai_api_key",
            Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        ),
    ]
}
