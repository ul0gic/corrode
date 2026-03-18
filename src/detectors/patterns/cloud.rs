// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Cloud provider patterns: Supabase, Firebase, AWS, Netlify, Heroku.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "supabase_url",
            Regex::new(r"https://[a-z0-9]+\.supabase\.co").unwrap(),
        ),
        (
            "supabase_publishable",
            Regex::new(r"sb_publishable_[A-Za-z0-9_-]{20,}").unwrap(),
        ),
        (
            "supabase_secret",
            Regex::new(r"sb_secret_[A-Za-z0-9_-]{20,}").unwrap(),
        ),
        (
            "firebase",
            Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(),
        ),
        (
            "aws_key",
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        ),
        (
            "aws_secret",
            Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap(),
        ),
        (
            "aws_arn",
            Regex::new(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+").unwrap(),
        ),
        (
            "netlify_access_token",
            Regex::new(r"nfp_[A-Za-z0-9]{20,}").unwrap(),
        ),
        (
            "heroku",
            Regex::new(r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
        ),
    ]
}
