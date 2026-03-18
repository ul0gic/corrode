// Regex::new() calls in lazy_static! use validated literal patterns that cannot fail at runtime.
// non_std_lazy_statics: lazy_static used consistently; migration to LazyLock deferred to restructuring.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::detectors::jwt::{is_anon_jwt, is_service_role_jwt};
use crate::types::{Comment, SecretFinding};

lazy_static! {
    pub static ref SECRET_PATTERNS: HashMap<&'static str, Regex> = super::patterns::all_patterns();
    static ref COMMENT_SINGLE: Regex = Regex::new(r"//(.+)").unwrap();
    static ref COMMENT_MULTI: Regex = Regex::new(r"/\*([\s\S]*?)\*/").unwrap();
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
                .map(|m| m.as_str().to_owned())
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
                            .entry("supabase_service_role".to_owned())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_owned(),
                                matches: service_role_jwts,
                            });
                    }

                    if !anon_jwts.is_empty() {
                        findings
                            .entry("supabase_anon_jwt".to_owned())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_owned(),
                                matches: anon_jwts,
                            });
                    }

                    // Only add uncategorized JWTs to generic "jwt" bucket
                    if !other_jwts.is_empty() {
                        findings
                            .entry("jwt".to_owned())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_owned(),
                                matches: other_jwts,
                            });
                    }
                    continue;
                }

                findings
                    .entry((*pattern_name).to_owned())
                    .or_insert_with(Vec::new)
                    .push(SecretFinding {
                        source: source.to_owned(),
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
                        source: source.to_owned(),
                        comment_type: "single".to_owned(),
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
                        source: source.to_owned(),
                        comment_type: "multi".to_owned(),
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
