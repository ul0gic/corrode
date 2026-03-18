// Regex::new() calls in lazy_static! use validated literal patterns that cannot fail at runtime.
// non_std_lazy_statics: lazy_static used consistently; migration to LazyLock deferred to restructuring.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::config::CustomPattern;
use crate::detectors::jwt::{is_anon_jwt, is_service_role_jwt};
use crate::types::{Comment, SecretFinding};

lazy_static! {
    pub static ref SECRET_PATTERNS: HashMap<&'static str, Regex> = super::patterns::all_patterns();
    static ref COMMENT_SINGLE: Regex = Regex::new(r"//(.+)").unwrap();
    static ref COMMENT_MULTI: Regex = Regex::new(r"/\*([\s\S]*?)\*/").unwrap();
}

pub struct SecretScanner {
    findings: Arc<Mutex<HashMap<String, Vec<SecretFinding>>>>,
    comments: Arc<Mutex<Vec<Comment>>>,
    /// Compiled custom patterns from config file, keyed by name.
    custom_patterns: Vec<(String, Regex)>,
    /// Built-in pattern names to suppress.
    ignore_patterns: HashSet<String>,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self {
            findings: Arc::new(Mutex::new(HashMap::new())),
            comments: Arc::new(Mutex::new(Vec::new())),
            custom_patterns: Vec::new(),
            ignore_patterns: HashSet::new(),
        }
    }
}

impl SecretScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a scanner with custom patterns and an ignore list.
    /// Custom patterns are compiled from user-supplied regex strings.
    /// Invalid regexes are logged and skipped (not fatal).
    pub fn with_custom_config(custom: &[CustomPattern], ignore: &[String]) -> Self {
        let mut compiled = Vec::new();
        for cp in custom {
            // SEC-003: Limit custom pattern size to prevent memory exhaustion
            if cp.pattern.len() > 500 {
                eprintln!(
                    "[!] Skipping custom pattern '{}': pattern exceeds 500 char limit",
                    cp.name
                );
                continue;
            }
            match regex::RegexBuilder::new(&cp.pattern)
                .size_limit(1_000_000)
                .build()
            {
                Ok(regex) => {
                    compiled.push((cp.name.clone(), regex));
                }
                Err(e) => {
                    eprintln!("[!] Skipping invalid custom pattern '{}': {e}", cp.name);
                }
            }
        }

        Self {
            findings: Arc::new(Mutex::new(HashMap::new())),
            comments: Arc::new(Mutex::new(Vec::new())),
            custom_patterns: compiled,
            ignore_patterns: ignore.iter().cloned().collect(),
        }
    }

    pub async fn scan_text(&self, text: &str, source: &str) {
        if text.is_empty() {
            return;
        }

        let mut findings = self.findings.lock().await;

        // Scan built-in patterns (respecting ignore list)
        for (pattern_name, regex) in SECRET_PATTERNS.iter() {
            if self.ignore_patterns.contains(*pattern_name) {
                continue;
            }

            let matches: HashSet<String> = regex
                .find_iter(text)
                .map(|m| m.as_str().to_owned())
                .collect();

            if !matches.is_empty() {
                let matches_vec: Vec<String> = matches.into_iter().take(10).collect();

                if *pattern_name == "jwt" {
                    Self::categorize_jwts(&mut findings, &matches_vec, source);
                    continue;
                }

                findings
                    .entry((*pattern_name).to_owned())
                    .or_default()
                    .push(SecretFinding {
                        source: source.to_owned(),
                        matches: matches_vec,
                    });
            }
        }

        // Scan custom patterns
        for (name, regex) in &self.custom_patterns {
            let matches: HashSet<String> = regex
                .find_iter(text)
                .map(|m| m.as_str().to_owned())
                .collect();

            if !matches.is_empty() {
                let matches_vec: Vec<String> = matches.into_iter().take(10).collect();
                findings
                    .entry(name.clone())
                    .or_default()
                    .push(SecretFinding {
                        source: source.to_owned(),
                        matches: matches_vec,
                    });
            }
        }
    }

    /// Categorize JWT matches into service-role, anon, or generic JWT buckets.
    fn categorize_jwts(
        findings: &mut HashMap<String, Vec<SecretFinding>>,
        matches: &[String],
        source: &str,
    ) {
        let service_role_jwts: Vec<String> = matches
            .iter()
            .filter(|jwt| is_service_role_jwt(jwt))
            .cloned()
            .collect();
        let anon_jwts: Vec<String> = matches
            .iter()
            .filter(|jwt| is_anon_jwt(jwt))
            .cloned()
            .collect();
        let other_jwts: Vec<String> = matches
            .iter()
            .filter(|jwt| !is_service_role_jwt(jwt) && !is_anon_jwt(jwt))
            .cloned()
            .collect();

        if !service_role_jwts.is_empty() {
            findings
                .entry("supabase_service_role".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: service_role_jwts,
                });
        }

        if !anon_jwts.is_empty() {
            findings
                .entry("supabase_anon_jwt".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: anon_jwts,
                });
        }

        if !other_jwts.is_empty() {
            findings
                .entry("jwt".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: other_jwts,
                });
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
