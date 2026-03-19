use serde_json::Value;

use crate::types::ApiCall;

/// Detect technologies from script URLs, network request URLs, and bundle naming patterns.
pub fn detect(scripts: &[Value], calls: &[ApiCall]) -> Vec<String> {
    let mut detected = Vec::new();

    // Check DOM script src attributes
    for script in scripts {
        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            detect_from_url(src, &mut detected);
        }
    }

    // Check network request URLs (catches resources not in document.scripts)
    for call in calls {
        detect_from_url(&call.url, &mut detected);
    }

    detected
}

fn detect_from_url(src: &str, detected: &mut Vec<String>) {
    let lower = src.to_lowercase();

    // Bundler/build tool detection from URL patterns
    let url_signatures: &[(&str, &str)] = &[
        // Next.js
        ("/_next/static/", "Next.js"),
        // Nuxt.js
        ("/_nuxt/", "Nuxt.js"),
        // Gatsby
        ("/page-data/", "Gatsby"),
        // Remix
        ("/__remix/", "Remix"),
        // Clerk
        ("clerk.com/npm/@clerk/", "Clerk"),
        ("clerk.accounts.dev", "Clerk"),
        // Analytics/tracking
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
        // Cloud/platform
        ("cloudflareinsights.com", "Cloudflare"),
        ("static.cloudflareinsights.com", "Cloudflare"),
        ("/_vercel/", "Vercel"),
        // API documentation
        ("swagger-ui", "Swagger UI"),
        ("redoc.standalone", "ReDoc"),
        ("rapidoc-min", "RapiDoc"),
        // Additional frameworks
        ("unpkg.com/htmx", "HTMX"),
        ("unpkg.com/alpinejs", "Alpine.js"),
        ("cdn.jsdelivr.net/npm/alpinejs", "Alpine.js"),
    ];

    for (pattern, name) in url_signatures {
        if lower.contains(pattern) && !detected.contains(&(*name).to_owned()) {
            detected.push((*name).to_owned());
        }
    }

    // Vite detection: asset URLs like /assets/index-B0psoMpO.js (8-char hash)
    if lower.contains("/assets/") && has_vite_hash_pattern(src) {
        add_unique(detected, "Vite");
    }

    // Next.js App Router: RSC payload requests use ?_rsc= query parameter
    if lower.contains("?_rsc=") || lower.contains("&_rsc=") {
        add_unique(detected, "Next.js (App Router)");
    }

    // Vercel deployment ID: ?dpl=dpl_ query parameter
    if lower.contains("?dpl=dpl_") || lower.contains("&dpl=dpl_") {
        add_unique(detected, "Vercel");
    }
}

/// Vite produces filenames like `index-B0psoMpO.js` with an 8-char base62 hash.
fn has_vite_hash_pattern(url: &str) -> bool {
    // Match pattern: word-HASH.js where HASH is 6-10 alphanumeric chars
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
