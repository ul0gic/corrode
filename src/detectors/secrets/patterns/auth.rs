// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Authentication and authorization patterns: JWT, Bearer, Basic Auth, keys.
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
        // OpenAI API keys: sk- followed by alphanumeric only (no hyphens/underscores).
        // This naturally excludes Anthropic keys (sk-ant-api03-...) which contain hyphens.
        (
            "openai_api_key",
            Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        ),
    ]
}
