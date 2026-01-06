use base64::{engine::general_purpose, Engine as _};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::types::{Comment, SecretFinding};

lazy_static! {
    pub static ref SECRET_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        m.insert(
            "supabase_url",
            Regex::new(r"https://[a-z0-9]+\.supabase\.co").unwrap(),
        );
        // New Supabase key formats (2024+)
        // Note: Legacy anon/service_role JWTs are detected via the jwt pattern + role parsing
        m.insert(
            "supabase_publishable",
            Regex::new(r"sb_publishable_[A-Za-z0-9_-]{20,}").unwrap(),
        );
        m.insert(
            "supabase_secret",
            Regex::new(r"sb_secret_[A-Za-z0-9_-]{20,}").unwrap(),
        );
        m.insert(
            "jwt",
            Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
        );
        m.insert(
            "stripe_publishable_key",
            Regex::new(r"pk_(?:live|test)_[A-Za-z0-9]{20,}").unwrap(),
        );
        m.insert(
            "openai_api_key",
            Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
        );
        m.insert(
            "netlify_access_token",
            Regex::new(r"nfp_[A-Za-z0-9]{20,}").unwrap(),
        );
        m.insert("firebase", Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap());
        m.insert("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
        m.insert(
            "aws_secret",
            Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap(),
        );
        m.insert(
            "stripe_secret_key",
            Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
        );
        m.insert(
            "stripe_restricted",
            Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap(),
        );
        m.insert(
            "slack",
            Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap(),
        );
        m.insert(
            "slack_webhook",
            Regex::new(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+")
                .unwrap(),
        );
        m.insert(
            "github",
            Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap(),
        );
        m.insert(
            "github_fine",
            Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap(),
        );
        m.insert("gitlab", Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap());
        m.insert(
            "discord",
            Regex::new(r"discord(?:app)?\.com/api/webhooks/[\d]+/[\w-]+").unwrap(),
        );
        m.insert(
            "discord_token",
            Regex::new(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}").unwrap(),
        );
        m.insert(
            "heroku",
            Regex::new(r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
        );
        m.insert("mailgun", Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap());
        m.insert(
            "mailchimp",
            Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
        );
        m.insert(
            "sendgrid",
            Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
        );
        m.insert("twilio", Regex::new(r"SK[0-9a-fA-F]{32}").unwrap());
        m.insert("twilio_account", Regex::new(r"AC[0-9a-fA-F]{32}").unwrap());
        m.insert(
            "private_key",
            Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
        );
        m.insert(
            "google_oauth",
            Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap(),
        );
        m.insert(
            "postgres_url",
            Regex::new(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+").unwrap(),
        );
        m.insert(
            "mongodb_url",
            Regex::new(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+").unwrap(),
        );
        m.insert(
            "mysql_url",
            Regex::new(r"mysql://[^:]+:[^@]+@[^/]+/\w+").unwrap(),
        );
        m.insert(
            "redis_url",
            Regex::new(r"redis://(?:[^:]*:)?[^@]+@[^/]+").unwrap(),
        );
        m.insert(
            "bearer_token",
            Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*").unwrap(),
        );
        m.insert(
            "basic_auth",
            Regex::new(r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}").unwrap(),
        );
        m.insert(
            "aws_arn",
            Regex::new(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+").unwrap(),
        );
        m.insert(
            "jwt_in_url",
            Regex::new(r"[?&](?:token|jwt|access_token|id_token)=eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap(),
        );
        // Only match private/internal IP ranges (security concern = exposing internal infra)
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        m.insert(
            "internal_ip",
            Regex::new(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b").unwrap(),
        );
        m
    };
    static ref COMMENT_SINGLE: Regex = Regex::new(r"//(.+)").unwrap();
    static ref COMMENT_MULTI: Regex = Regex::new(r"/\*([\s\S]*?)\*/").unwrap();
}

fn jwt_has_role(jwt: &str, role: &str) -> bool {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        if let Ok(payload) = String::from_utf8(decoded) {
            let role_marker = format!(r#""role":"{}""#, role);
            return payload.contains(role_marker.as_str());
        }
    }
    false
}

fn is_service_role_jwt(jwt: &str) -> bool {
    jwt_has_role(jwt, "service_role")
}

fn is_anon_jwt(jwt: &str) -> bool {
    jwt_has_role(jwt, "anon")
}

#[derive(Default)]
pub struct SecretScanner {
    findings: Arc<Mutex<HashMap<String, Vec<SecretFinding>>>>,
    comments: Arc<Mutex<Vec<Comment>>>,
}

impl SecretScanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn scan_text(&self, text: &str, source: &str) {
        if text.is_empty() {
            return;
        }

        let mut findings = self.findings.lock().await;

        for (pattern_name, regex) in SECRET_PATTERNS.iter() {
            let matches: HashSet<String> = regex
                .find_iter(text)
                .map(|m| m.as_str().to_string())
                .collect();

            if !matches.is_empty() {
                let matches_vec: Vec<String> = matches.into_iter().take(10).collect();

                if *pattern_name == "jwt" {
                    let service_role_jwts: Vec<String> = matches_vec
                        .iter()
                        .filter(|jwt| is_service_role_jwt(jwt))
                        .cloned()
                        .collect();
                    let anon_jwts: Vec<String> = matches_vec
                        .iter()
                        .filter(|jwt| is_anon_jwt(jwt))
                        .cloned()
                        .collect();
                    // JWTs not categorized as Supabase anon/service_role
                    let other_jwts: Vec<String> = matches_vec
                        .iter()
                        .filter(|jwt| !is_service_role_jwt(jwt) && !is_anon_jwt(jwt))
                        .cloned()
                        .collect();

                    if !service_role_jwts.is_empty() {
                        findings
                            .entry("supabase_service_role".to_string())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_string(),
                                matches: service_role_jwts,
                            });
                    }

                    if !anon_jwts.is_empty() {
                        findings
                            .entry("supabase_anon_jwt".to_string())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_string(),
                                matches: anon_jwts,
                            });
                    }

                    // Only add uncategorized JWTs to generic "jwt" bucket
                    if !other_jwts.is_empty() {
                        findings
                            .entry("jwt".to_string())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_string(),
                                matches: other_jwts,
                            });
                    }
                    continue;
                }

                findings
                    .entry((*pattern_name).to_string())
                    .or_insert_with(Vec::new)
                    .push(SecretFinding {
                        source: source.to_string(),
                        matches: matches_vec,
                    });
            }
        }
    }

    pub async fn extract_comments(&self, code: &str, source: &str) {
        if code.is_empty() || code.len() < 10 {
            return;
        }

        let mut comments = self.comments.lock().await;

        for cap in COMMENT_SINGLE.captures_iter(code) {
            if let Some(comment) = cap.get(1) {
                let content = comment.as_str().trim();
                if content.len() > 5 {
                    comments.push(Comment {
                        source: source.to_string(),
                        comment_type: "single".to_string(),
                        content: content.chars().take(200).collect(),
                    });
                }
            }
        }

        for cap in COMMENT_MULTI.captures_iter(code) {
            if let Some(comment) = cap.get(1) {
                let content = comment.as_str().trim();
                if content.len() > 5 {
                    comments.push(Comment {
                        source: source.to_string(),
                        comment_type: "multi".to_string(),
                        content: content.chars().take(500).collect(),
                    });
                }
            }
        }
    }

    pub async fn get_findings(&self) -> HashMap<String, Vec<SecretFinding>> {
        self.findings.lock().await.clone()
    }

    pub async fn get_comments(&self) -> Vec<Comment> {
        self.comments.lock().await.clone()
    }
}
