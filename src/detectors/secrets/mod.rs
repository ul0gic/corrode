// Does:  Scans text for configured secret patterns and comments.
// Holds: A pattern and value pair is recorded at most once per scanner.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: The existing pattern registry uses lazy_static.
#![allow(clippy::non_std_lazy_statics)]

mod jwt;
/// Built-in secret detection patterns.
pub mod patterns;

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;

use self::jwt::{is_anon_jwt, is_service_role_jwt};
use crate::config::CustomPattern;
use crate::types::{Comment, SecretFinding};

lazy_static! {
    /// Built-in detection patterns keyed by name.
    pub static ref SECRET_PATTERNS: HashMap<&'static str, Regex> = self::patterns::all_patterns();
    static ref COMMENT_SINGLE: Regex = Regex::new(r"//(.+)").unwrap();
    static ref COMMENT_MULTI: Regex = Regex::new(r"/\*([\s\S]*?)\*/").unwrap();
}

/// Scanner state and deduplicated findings.
pub struct SecretScanner {
    findings: Arc<Mutex<HashMap<String, Vec<SecretFinding>>>>,
    comments: Arc<Mutex<Vec<Comment>>>,
    seen_values: Arc<Mutex<HashSet<(String, String)>>>,
    custom_patterns: Vec<(String, Regex)>,
    ignore_patterns: HashSet<String>,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self {
            findings: Arc::new(Mutex::new(HashMap::new())),
            comments: Arc::new(Mutex::new(Vec::new())),
            seen_values: Arc::new(Mutex::new(HashSet::new())),
            custom_patterns: Vec::new(),
            ignore_patterns: HashSet::new(),
        }
    }
}

impl SecretScanner {
    /// Creates an empty scanner.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// let scanner = SecretScanner::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a scanner, skipping invalid or oversized custom patterns.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// let scanner = SecretScanner::with_custom_config(&[], &[]);
    /// ```
    pub fn with_custom_config(custom: &[CustomPattern], ignore: &[String]) -> Self {
        let mut compiled = Vec::new();
        for cp in custom {
            // Why: A size limit bounds resource use when compiling user-supplied patterns.
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
            seen_values: Arc::new(Mutex::new(HashSet::new())),
            custom_patterns: compiled,
            ignore_patterns: ignore.iter().cloned().collect(),
        }
    }

    /// Scans text and records previously unseen pattern and value pairs.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// # let scanner = SecretScanner::new();
    /// futures::executor::block_on(scanner.scan_text("", ""));
    /// ```
    pub async fn scan_text(&self, text: &str, source: &str) {
        if text.is_empty() {
            return;
        }

        let mut findings = self.findings.lock().await;
        let mut seen = self.seen_values.lock().await;

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
                    Self::categorize_jwts(&mut findings, &mut seen, &matches_vec, source);
                    continue;
                }

                let deduped = Self::dedupe_new(&mut seen, pattern_name, matches_vec);
                if !deduped.is_empty() {
                    findings
                        .entry((*pattern_name).to_owned())
                        .or_default()
                        .push(SecretFinding {
                            source: source.to_owned(),
                            matches: deduped,
                            confidence: None,
                        });
                }
            }
        }

        for (name, regex) in &self.custom_patterns {
            let matches: HashSet<String> = regex
                .find_iter(text)
                .map(|m| m.as_str().to_owned())
                .collect();

            if !matches.is_empty() {
                let matches_vec: Vec<String> = matches.into_iter().take(10).collect();
                let deduped = Self::dedupe_new(&mut seen, name, matches_vec);
                if !deduped.is_empty() {
                    findings
                        .entry(name.clone())
                        .or_default()
                        .push(SecretFinding {
                            source: source.to_owned(),
                            matches: deduped,
                            confidence: None,
                        });
                }
            }
        }
    }

    fn dedupe_new(
        seen: &mut HashSet<(String, String)>,
        pattern_name: &str,
        matches: Vec<String>,
    ) -> Vec<String> {
        matches
            .into_iter()
            .filter(|value| seen.insert((pattern_name.to_owned(), value.clone())))
            .collect()
    }

    fn categorize_jwts(
        findings: &mut HashMap<String, Vec<SecretFinding>>,
        seen: &mut HashSet<(String, String)>,
        matches: &[String],
        source: &str,
    ) {
        let service_role_jwts = Self::dedupe_new(
            seen,
            "supabase_service_role",
            matches
                .iter()
                .filter(|jwt| is_service_role_jwt(jwt))
                .cloned()
                .collect(),
        );
        let anon_jwts = Self::dedupe_new(
            seen,
            "supabase_anon_jwt",
            matches
                .iter()
                .filter(|jwt| is_anon_jwt(jwt))
                .cloned()
                .collect(),
        );
        let other_jwts = Self::dedupe_new(
            seen,
            "jwt",
            matches
                .iter()
                .filter(|jwt| !is_service_role_jwt(jwt) && !is_anon_jwt(jwt))
                .cloned()
                .collect(),
        );

        if !service_role_jwts.is_empty() {
            findings
                .entry("supabase_service_role".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: service_role_jwts,
                    confidence: None,
                });
        }

        if !anon_jwts.is_empty() {
            findings
                .entry("supabase_anon_jwt".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: anon_jwts,
                    confidence: None,
                });
        }

        if !other_jwts.is_empty() {
            findings
                .entry("jwt".to_owned())
                .or_default()
                .push(SecretFinding {
                    source: source.to_owned(),
                    matches: other_jwts,
                    confidence: None,
                });
        }
    }

    /// Extracts comments from source text.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// # let scanner = SecretScanner::new();
    /// futures::executor::block_on(scanner.extract_comments("", ""));
    /// ```
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

    /// Copies the recorded findings.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// # let scanner = SecretScanner::new();
    /// assert!(futures::executor::block_on(scanner.get_findings()).is_empty());
    /// ```
    pub async fn get_findings(&self) -> HashMap<String, Vec<SecretFinding>> {
        self.findings.lock().await.clone()
    }

    /// Copies the recorded comments.
    ///
    /// ```
    /// # use corrode_scanner::detectors::secrets::SecretScanner;
    /// # let scanner = SecretScanner::new();
    /// assert!(futures::executor::block_on(scanner.get_comments()).is_empty());
    /// ```
    pub async fn get_comments(&self) -> Vec<Comment> {
        self.comments.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    fn total_matches(findings: &HashMap<String, Vec<SecretFinding>>) -> usize {
        findings
            .values()
            .flat_map(|v| v.iter())
            .map(|f| f.matches.len())
            .sum()
    }

    #[tokio::test]
    async fn same_value_across_sources_counted_once() {
        let scanner = SecretScanner::new();
        scanner
            .scan_text(&format!("const k = '{AWS_KEY}';"), "Script: bundle.js")
            .await;
        scanner
            .scan_text(
                &format!("const k = '{AWS_KEY}';"),
                "Source Map: src/config.js",
            )
            .await;

        let findings = scanner.get_findings().await;
        assert_eq!(
            total_matches(&findings),
            1,
            "identical secret value must not be double-counted across sources"
        );
    }

    #[tokio::test]
    async fn distinct_values_both_recorded() {
        let scanner = SecretScanner::new();
        scanner
            .scan_text("const k = 'AKIAIOSFODNN7EXAMPLE';", "Script: bundle.js")
            .await;
        scanner
            .scan_text(
                "const k = 'AKIAI44QH8DHBEXAMPLE';",
                "Source Map: src/other.js",
            )
            .await;

        let findings = scanner.get_findings().await;
        assert_eq!(
            total_matches(&findings),
            2,
            "two distinct secret values must both be recorded"
        );
    }

    #[tokio::test]
    async fn dedupe_is_per_pattern() {
        let mut seen = HashSet::new();
        let first = SecretScanner::dedupe_new(&mut seen, "aws_access_key", vec!["X".to_owned()]);
        let second = SecretScanner::dedupe_new(&mut seen, "generic_secret", vec!["X".to_owned()]);
        assert_eq!(first, vec!["X".to_owned()]);
        assert_eq!(second, vec!["X".to_owned()]);
        let repeat = SecretScanner::dedupe_new(&mut seen, "aws_access_key", vec!["X".to_owned()]);
        assert_eq!(repeat, Vec::<String>::new());
    }
}
