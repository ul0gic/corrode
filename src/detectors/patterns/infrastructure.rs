// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Infrastructure patterns: internal/private IP address ranges, environment variable references.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // Only match private/internal IP ranges (security concern = exposing internal infra)
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        (
            "internal_ip",
            Regex::new(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b").unwrap(),
        ),
        // CRA environment variable references in JS bundles
        (
            "env_var_react",
            Regex::new(r"process\.env\.(REACT_APP_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        // Vite environment variable references in JS bundles
        (
            "env_var_vite",
            Regex::new(r"import\.meta\.env\.(VITE_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        // Next.js public environment variable references in JS bundles
        (
            "env_var_next",
            Regex::new(r"process\.env\.(NEXT_PUBLIC_[A-Z_][A-Z0-9_]*)").unwrap(),
        ),
        // Source map URL references in JavaScript (indicates exposed source maps)
        (
            "source_map_url",
            Regex::new(r"(?://[#@]|/\*[#@])\s*sourceMappingURL\s*=\s*(\S+\.map)\b").unwrap(),
        ),
        // Webpack HMR / dev server indicators
        (
            "webpack_hmr",
            Regex::new(r"__webpack_hmr|webpackHotUpdate").unwrap(),
        ),
        // Vite dev server indicators
        (
            "vite_dev_client",
            Regex::new(r"/@vite/client|/@hmr|__vite_ping").unwrap(),
        ),
        // React development build filename (non-production bundle loaded)
        (
            "react_dev_build",
            Regex::new(r"react(?:-dom)?\.development(?:\.min)?\.js").unwrap(),
        ),
        // Vue.js non-production build filename (vue.global.js, vue.esm-browser.js without .prod)
        (
            "vue_dev_build",
            Regex::new(r"vue\.(?:global|runtime\.global|esm-browser|esm-bundler)\.js\b").unwrap(),
        ),
    ]
}
