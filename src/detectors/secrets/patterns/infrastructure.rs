// Does:  Defines detection patterns for infrastructure and development indicators.
// Holds: Internal IP matching is limited to the three private IPv4 ranges.

// Why: The unwrapped regular expressions are fixed literals.
#![allow(clippy::unwrap_used)]
// Why: Only the shared registry currently needs the lazy-static allowance.
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        (
            "internal_ip",
            Regex::new(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b").unwrap(),
        ),
        (
            "env_var_react",
            Regex::new(r"process\.env\.(REACT_APP_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        (
            "env_var_vite",
            Regex::new(r"import\.meta\.env\.(VITE_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        (
            "env_var_next",
            Regex::new(r"process\.env\.(NEXT_PUBLIC_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        (
            "source_map_url",
            Regex::new(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*(\S+\.map)\b").unwrap(),
        ),
        (
            "webpack_hmr",
            Regex::new(r"__webpack_hmr|webpackHotUpdate").unwrap(),
        ),
        (
            "vite_dev_client",
            Regex::new(r"/@vite/client|/@hmr|__vite_ping").unwrap(),
        ),
        (
            "react_dev_build",
            Regex::new(r"react(?:-dom)?\.development(?:\.min)?\.js").unwrap(),
        ),
        (
            "vue_dev_build",
            Regex::new(r"vue\.(?:global|runtime\.global|esm-browser|esm-bundler)\.js\b").unwrap(),
        ),
    ]
}
