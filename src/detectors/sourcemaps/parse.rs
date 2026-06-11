//! Source-map v3 parsing. The VLQ `mappings` field is ignored on purpose — we
//! recover source paths and text, not line-accurate positions.

use serde::Deserialize;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    pub path: String,
    pub content: Option<String>,
    /// Marked third-party by `x_google_ignoreList` (e.g. vendored deps).
    pub ignored: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedSourceMap {
    pub sources: Vec<RecoveredSource>,
    // Parsed for v3-format completeness; no intel path reads the symbol-name
    // table yet (it feeds a future symbol-recovery pass, not secrets/routes).
    #[allow(dead_code)]
    pub names: Vec<String>,
}

impl ParsedSourceMap {
    pub fn has_sources_content(&self) -> bool {
        self.sources.iter().any(|s| s.content.is_some())
    }

    pub fn source_paths(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.path.clone()).collect()
    }

    pub fn first_party_with_content(&self) -> impl Iterator<Item = &RecoveredSource> {
        self.sources
            .iter()
            .filter(|s| !s.ignored && s.content.is_some())
    }
}

/// Errors only on malformed or non-object JSON; missing `sourcesContent` and
/// out-of-range ignore indices are tolerated.
pub fn parse(json: &str) -> Result<ParsedSourceMap, serde_json::Error> {
    // Reject non-objects: serde would otherwise build an all-default struct
    // from a sequence via struct-from-seq.
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

    // --- Fixture-backed coverage (task 1.12) ---

    const FIXTURE_WITH_CONTENT: &str = r#"{
  "version": 3,
  "file": "main.js",
  "sourceRoot": "",
  "sources": [
    "webpack://_N_E/./src/app/page.tsx",
    "webpack://_N_E/./src/app/admin/[id]/route.ts",
    "webpack://_N_E/./src/utils/api.ts",
    "webpack://_N_E/./node_modules/.pnpm/next@14.1.0/dist/client.js"
  ],
  "sourcesContent": [
    "export default function Page() { return null; }",
    "export async function GET(req) { /* TODO: add authz check */ return Response.json({}); }",
    "export const API_BASE = '/api/internal';",
    "module.exports = {};"
  ],
  "names": ["Page", "GET", "API_BASE"],
  "x_google_ignoreList": [3]
}
"#;
    const FIXTURE_FILENAMES_ONLY: &str = r#"{
  "version": 3,
  "file": "vendor.js",
  "sources": [
    "webpack://app/./src/routes/login.ts",
    "webpack://app/./src/routes/dashboard/index.ts"
  ],
  "names": []
}
"#;
    const FIXTURE_TRUNCATED: &str = r#"{
  "version": 3,
  "file": "broken.js",
  "sources": ["webpack://app/./src/app/page.tsx"],
  "sourcesContent": ["export default function Page() { ret
"#;

    #[test]
    fn fixture_with_content_recovers_source_text_and_skips_vendor() {
        let map = parse(FIXTURE_WITH_CONTENT).expect("valid fixture map");
        assert!(map.has_sources_content());
        // The pnpm vendor entry is flagged via x_google_ignoreList.
        let first_party: Vec<_> = map.first_party_with_content().collect();
        assert_eq!(first_party.len(), 3);
        assert!(first_party
            .iter()
            .all(|s| !s.path.contains(".pnpm") && !s.path.contains("node_modules")));
        assert!(first_party
            .iter()
            .any(|s| s.content.as_deref().is_some_and(|c| c.contains("TODO"))));
    }

    #[test]
    fn fixture_filenames_only_has_no_source_text() {
        let map = parse(FIXTURE_FILENAMES_ONLY).expect("valid fixture map");
        assert!(!map.has_sources_content());
        assert_eq!(map.source_paths().len(), 2);
        assert!(map.sources.iter().all(|s| s.content.is_none()));
    }

    #[test]
    fn fixture_truncated_map_fails_gracefully() {
        // A cut-off map must surface as a parse error, never a panic, so the
        // caller can log-and-skip it.
        assert!(parse(FIXTURE_TRUNCATED).is_err());
    }
}
