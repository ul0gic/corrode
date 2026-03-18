// Regex::new() calls use validated literal patterns that cannot fail at runtime.
#![allow(clippy::unwrap_used)]
#![allow(clippy::non_std_lazy_statics)]

use regex::Regex;

/// Infrastructure patterns: internal/private IP address ranges.
pub fn patterns() -> Vec<(&'static str, Regex)> {
    vec![
        // Only match private/internal IP ranges (security concern = exposing internal infra)
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        (
            "internal_ip",
            Regex::new(r"\b(?:10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|172\.(?:1[6-9]|2\d|3[0-1])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d))\b").unwrap(),
        ),
    ]
}
