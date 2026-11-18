// Does:  Defines detection patterns for cloud service credentials.
// Holds: The AWS secret pattern requires an assignment to its named variable.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

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
            Regex::new(r"(?i)heroku.{0,40}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
        ),
        (
            "digitalocean_token",
            Regex::new(r"\b(do[opr]_v1_[a-f0-9]{64})\b").unwrap(),
        ),
        (
            "vercel_token",
            Regex::new(r"\b(vc[pkiar]_[A-Za-z0-9_\-]{20,})\b").unwrap(),
        ),
        (
            "azure_storage_connection",
            Regex::new(r"DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{86,88}").unwrap(),
        ),
        (
            "azure_ad_client_secret",
            Regex::new(r"\b[A-Za-z0-9_~.]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}\b").unwrap(),
        ),
        (
            "azure_sas_token",
            Regex::new(r"(?:sv=\d{4}-\d{2}-\d{2}&|&sv=\d{4}-\d{2}-\d{2}).*sig=[A-Za-z0-9%+/=]{40,}").unwrap(),
        ),
        (
            "gcp_service_account",
            Regex::new(r"[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com").unwrap(),
        ),
        (
            "cloudflare_origin_ca",
            Regex::new(r"\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b").unwrap(),
        ),
        (
            "cloudflare_api_token",
            Regex::new(r#"(?i)(?:cloudflare|cf_api|CF_TOKEN)[\w.\-]{0,20}[\s'"]{0,3}(?:=|:|=>)[\s'"]{0,5}([a-zA-Z0-9_\-]{40})\b"#).unwrap(),
        ),
        (
            "mapbox_token",
            Regex::new(r"\b([pst]k\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b").unwrap(),
        ),
    ]
}
