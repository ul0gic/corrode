//! Source-map v3 parsing (task 1.3).
//!
//! We parse only the fields needed to reconstruct attack surface — `sources`,
//! `sourcesContent`, `names`, `sourceRoot`, `x_google_ignoreList`. The VLQ
//! `mappings` field is deliberately ignored: Corrode recovers *what* source
//! existed and its text, not line-accurate position mapping, so decoding VLQ
//! would be cost with no payoff (per the Phase 0 dependency decision — no new
//! crate, hand-rolled over `serde_json`).

use serde::Deserialize;

/// Raw source-map JSON, limited to the fields we consume.
#[derive(Debug, Deserialize)]
struct RawSourceMap {
    #[serde(default)]
    sources: Vec<Option<String>>,
    #[serde(default, rename = "sourcesContent")]
    sources_content: Vec<Option<String>>,
    #[serde(default, rename = "sourceRoot")]
    source_root: Option<String>,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default, rename = "x_google_ignoreList")]
    ignore_list: Vec<usize>,
}

/// One recovered original source file from a map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    /// Source path with `sourceRoot` applied. May be a virtual path
    /// (e.g. `webpack://app/src/auth.ts`).
    pub path: String,
    /// Original source text, if `sourcesContent` carried it for this entry.
    pub content: Option<String>,
    /// True when the tooling marked this source as third-party/ignored
    /// (`x_google_ignoreList`) — e.g. vendored `node_modules` code.
    pub ignored: bool,
}

/// A parsed source map reduced to the entries we care about.
#[derive(Debug, Clone)]
pub struct ParsedSourceMap {
    pub sources: Vec<RecoveredSource>,
    pub names: Vec<String>,
}

impl ParsedSourceMap {
    /// True when at least one source carried embedded `sourcesContent`.
    pub fn has_sources_content(&self) -> bool {
        self.sources.iter().any(|s| s.content.is_some())
    }

    /// Recovered source paths in declaration order.
    pub fn source_paths(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.path.clone()).collect()
    }

    /// Sources that carry text and are not on the ignore list — the
    /// first-party code worth scanning for secrets and routes.
    pub fn first_party_with_content(&self) -> impl Iterator<Item = &RecoveredSource> {
        self.sources
            .iter()
            .filter(|s| !s.ignored && s.content.is_some())
    }
}

/// Parse a source-map JSON document.
///
/// Tolerant by design: a map with no `sourcesContent` parses fine
/// (filenames-only mode), and an out-of-range ignore-list index is skipped
/// rather than rejected. Returns an error only when the JSON itself is
/// malformed or is not an object.
pub fn parse(json: &str) -> Result<ParsedSourceMap, serde_json::Error> {
    // Require a JSON object: serde will otherwise happily build an all-default
    // struct from a sequence (`[]`) or other non-object via struct-from-seq.
    let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_str(json)?;
    let raw: RawSourceMap = serde_json::from_value(serde_json::Value::Object(obj))?;

    let root = raw.source_root.unwrap_or_default();
    let ignored: std::collections::HashSet<usize> = raw.ignore_list.into_iter().collect();

    let sources = raw
        .sources
        .into_iter()
        .enumerate()
        .filter_map(|(idx, src)| {
            let path = src?;
            let path = apply_source_root(&root, &path);
            let content = raw
                .sources_content
                .get(idx)
                .cloned()
                .flatten()
                .filter(|c| !c.is_empty());
            Some(RecoveredSource {
                path,
                content,
                ignored: ignored.contains(&idx),
            })
        })
        .collect();

    Ok(ParsedSourceMap {
        sources,
        names: raw.names,
    })
}

/// Join `sourceRoot` to a source path the way the spec describes — simple
/// prefix concatenation, with a single separator. Absolute or scheme-prefixed
/// source paths (`webpack://`, `/abs`) are left untouched.
fn apply_source_root(root: &str, path: &str) -> String {
    if root.is_empty() || path.contains("://") || path.starts_with('/') {
        return path.to_owned();
    }
    if root.ends_with('/') {
        format!("{root}{path}")
    } else {
        format!("{root}/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_map_with_sources_and_content() {
        let json = r#"{
            "version": 3,
            "sources": ["src/auth.ts", "src/api.ts"],
            "sourcesContent": ["const KEY = 'sk_live_x';", "export const base = '/api';"],
            "names": ["KEY", "base"]
        }"#;
        let map = parse(json).expect("valid map");
        assert_eq!(map.sources.len(), 2);
        assert!(map.has_sources_content());
        assert_eq!(map.source_paths(), vec!["src/auth.ts", "src/api.ts"]);
        assert_eq!(
            map.sources[0].content.as_deref(),
            Some("const KEY = 'sk_live_x';")
        );
    }

    #[test]
    fn handles_missing_sources_content_as_filenames_only() {
        let json = r#"{"version":3,"sources":["src/a.js","src/b.js"]}"#;
        let map = parse(json).expect("valid map");
        assert_eq!(map.sources.len(), 2);
        assert!(!map.has_sources_content());
        assert!(map.sources.iter().all(|s| s.content.is_none()));
    }

    #[test]
    fn applies_source_root_to_relative_paths_only() {
        let json = r#"{
            "version": 3,
            "sourceRoot": "webpack://app",
            "sources": ["./src/x.ts", "/abs/y.ts", "webpack://other/z.ts"]
        }"#;
        let map = parse(json).expect("valid map");
        let paths = map.source_paths();
        assert_eq!(paths[0], "webpack://app/./src/x.ts");
        assert_eq!(paths[1], "/abs/y.ts");
        assert_eq!(paths[2], "webpack://other/z.ts");
    }

    #[test]
    fn marks_ignore_list_entries() {
        let json = r#"{
            "version": 3,
            "sources": ["src/app.ts", "node_modules/lib/index.js"],
            "sourcesContent": ["app code", "vendor code"],
            "x_google_ignoreList": [1]
        }"#;
        let map = parse(json).expect("valid map");
        assert!(!map.sources[0].ignored);
        assert!(map.sources[1].ignored);
        let first_party: Vec<_> = map.first_party_with_content().collect();
        assert_eq!(first_party.len(), 1);
        assert_eq!(first_party[0].path, "src/app.ts");
    }

    #[test]
    fn empty_sources_content_string_is_treated_as_absent() {
        let json = r#"{"version":3,"sources":["a.js"],"sourcesContent":[""]}"#;
        let map = parse(json).expect("valid map");
        assert!(map.sources[0].content.is_none());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse("{ not json").is_err());
        assert!(parse("[]").is_err());
        assert!(parse("\"a string\"").is_err());
    }

    #[test]
    fn tolerates_out_of_range_ignore_index() {
        let json = r#"{"version":3,"sources":["a.js"],"x_google_ignoreList":[5]}"#;
        let map = parse(json).expect("valid map");
        assert!(!map.sources[0].ignored);
    }
}
