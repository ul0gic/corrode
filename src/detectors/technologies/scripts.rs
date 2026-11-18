// Does:  Detects technology signatures in script and network URLs.
// Holds: Detection uses already captured script and network data.

use serde_json::Value;

use crate::types::ApiCall;

/// Detects technology signatures in captured script and network URLs.
///
///     assert!(corrode_scanner::detectors::technologies::scripts::detect(&[], &[]).is_empty());
pub fn detect(scripts: &[Value], calls: &[ApiCall]) -> Vec<String> {
    let mut detected = Vec::new();

    for script in scripts {
        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            detect_from_url(src, &mut detected);
        }
    }

    for call in calls {
        detect_from_url(&call.url, &mut detected);
    }

    detected
}

fn detect_from_url(src: &str, detected: &mut Vec<String>) {
    let lower = src.to_lowercase();

    let url_signatures: &[(&str, &str)] = &[
        ("/_next/static/", "Next.js"),
        ("/_nuxt/", "Nuxt.js"),
        ("/page-data/", "Gatsby"),
        ("/__remix/", "Remix"),
        ("clerk.com/npm/@clerk/", "Clerk"),
        ("clerk.accounts.dev", "Clerk"),
        ("googletagmanager.com", "GTM"),
        ("google-analytics.com", "Google Analytics"),
        ("segment.com/analytics.js", "Segment"),
        ("cdn.amplitude.com", "Amplitude"),
        ("cdn.heapanalytics.com", "Heap"),
        ("static.hotjar.com", "Hotjar"),
        ("cdn.mxpnl.com", "Mixpanel"),
        ("widget.intercom.io", "Intercom"),
        ("js.stripe.com", "Stripe"),
        ("js.sentry-cdn.com", "Sentry"),
        ("cloudflareinsights.com", "Cloudflare"),
        ("static.cloudflareinsights.com", "Cloudflare"),
        ("/_vercel/", "Vercel"),
        ("swagger-ui", "Swagger UI"),
        ("redoc.standalone", "ReDoc"),
        ("rapidoc-min", "RapiDoc"),
        ("accounts.google.com/gsi/", "Google Sign-In"),
        ("appleid.cdn-apple.com", "Apple Sign-In"),
        ("connect.facebook.net", "Facebook Login"),
        ("accounts.google.com/o/oauth2", "Google OAuth"),
        ("unpkg.com/htmx", "HTMX"),
        ("unpkg.com/alpinejs", "Alpine.js"),
        ("cdn.jsdelivr.net/npm/alpinejs", "Alpine.js"),
    ];

    for (pattern, name) in url_signatures {
        if lower.contains(pattern) && !detected.contains(&(*name).to_owned()) {
            detected.push((*name).to_owned());
        }
    }

    if lower.contains("/assets/") && has_vite_hash_pattern(src) {
        add_unique(detected, "Vite");
    }

    if lower.contains("?_rsc=") || lower.contains("&_rsc=") {
        add_unique(detected, "Next.js (App Router)");
    }

    if lower.contains("?dpl=dpl_") || lower.contains("&dpl=dpl_") {
        add_unique(detected, "Vercel");
    }
}

fn has_vite_hash_pattern(url: &str) -> bool {
    let path = url.rsplit('/').next().unwrap_or("");
    if let Some(stem) = path
        .strip_suffix(".js")
        .or_else(|| path.strip_suffix(".css"))
    {
        if let Some(hash_start) = stem.rfind('-') {
            let hash = &stem[hash_start + 1..];
            let len = hash.len();
            return (6..=10).contains(&len) && hash.chars().all(|c| c.is_ascii_alphanumeric());
        }
    }
    false
}

fn add_unique(detected: &mut Vec<String>, name: &str) {
    if !detected.contains(&name.to_owned()) {
        detected.push(name.to_owned());
    }
}
