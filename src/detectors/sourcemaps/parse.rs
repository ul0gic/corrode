// Does:  Recovers paths and source text from a source map.
// Holds: Ignore-list indices refer to the positions in the original sources array.

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

/// A source entry paired with its optional embedded text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    /// Source path after applying the optional map root.
    pub path: String,
    /// Embedded source text, absent for missing or empty entries.
    pub content: Option<String>,
    /// Marked third-party by `x_google_ignoreList` (e.g. vendored deps).
    pub ignored: bool,
}

/// Decoded source entries and the optional symbol-name table.
#[derive(Debug, Clone)]
pub struct ParsedSourceMap {
    /// Entries in map order, omitting null source paths.
    pub sources: Vec<RecoveredSource>,
    /// Symbol names in the order supplied by the map.
    // Why: Map consumers can inspect symbol names even though the scanner only reads source paths.
    #[allow(dead_code)]
    pub names: Vec<String>,
}

impl ParsedSourceMap {
    /// Checks whether any entry includes nonempty source text.
    /// ```
    /// # use corrode_scanner::detectors::sourcemaps::parse::parse;
    /// # let map = parse(r#"{"sources":["app.ts"],"sourcesContent":["export {}"]}"#).unwrap();
    /// assert!(map.has_sources_content());
    /// ```
    pub fn has_sources_content(&self) -> bool {
        self.sources.iter().any(|s| s.content.is_some())
    }

    /// Returns the retained source paths in map order.
    /// ```
    /// # use corrode_scanner::detectors::sourcemaps::parse::parse;
    /// # let map = parse(r#"{"sourceRoot":"src","sources":[null,"app.ts"]}"#).unwrap();
    /// assert_eq!(map.source_paths(), ["src/app.ts"]);
    /// ```
    pub fn source_paths(&self) -> Vec<String> {
        self.sources.iter().map(|s| s.path.clone()).collect()
    }

    /// Yields entries with embedded text whose indices are absent from the map's ignore list.
    /// ```
    /// # use corrode_scanner::detectors::sourcemaps::parse::parse;
    /// # let json = r#"{"sources":["dep.js","app.js"],"sourcesContent":["a","b"],"x_google_ignoreList":[0]}"#;
    /// # let map = parse(json).unwrap();
    /// assert_eq!(map.first_party_with_content().next().unwrap().path, "app.js");
    /// ```
    pub fn first_party_with_content(&self) -> impl Iterator<Item = &RecoveredSource> {
        self.sources
            .iter()
            .filter(|s| !s.ignored && s.content.is_some())
    }
}

/// Parses source paths, optional source text, and ignore-list entries.
/// ```
/// # use corrode_scanner::detectors::sourcemaps::parse::parse;
/// let map = parse(r#"{"sources":["app.ts"]}"#).unwrap();
/// ```
pub fn parse(json: &str) -> Result<ParsedSourceMap, serde_json::Error> {
    // Why: Serde can deserialize a JSON sequence into an all-default struct.
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
}
