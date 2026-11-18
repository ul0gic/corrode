// Does:  Identifies browser-visible React Server Component signals.
// Holds: A bare router query alone does not establish an RSC surface.

use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::LazyLock;

use regex::Regex;

// Why: The unwrapped regular expressions are fixed literals.
#[allow(clippy::unwrap_used)]
static FLIGHT_PUSH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:self\.)?__next_f\s*(?:\.push|\[)").unwrap());

// Why: The unwrapped regular expressions are fixed literals.
#[allow(clippy::unwrap_used)]
static SERVER_DOM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"react-server-dom-(?:webpack|parcel|turbopack)").unwrap());

// Why: The unwrapped regular expressions are fixed literals.
#[allow(clippy::unwrap_used)]
static SERVER_ACTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"createServerReference|callServerReference|\bcallServer\b|react\.server\.reference")
        .unwrap()
});

// Why: Independent surface signals can occur in any combination.
#[allow(clippy::struct_excessive_bools)]
/// Independent React server component surface signals.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RscSurface {
    /// Flight stream markers were observed.
    pub flight_markers: bool,
    /// React server DOM bridge was observed.
    pub server_dom: bool,
    /// Server action markers were observed.
    pub server_actions: bool,
    /// App Router markers were observed.
    pub app_router: bool,
    /// Pages Router markers were observed.
    pub pages_router: bool,
}

impl RscSurface {
    pub(crate) fn is_present(&self) -> bool {
        self.flight_markers || self.server_dom || self.server_actions
    }
}

/// Identifies React server component surface signals from captured material.
///
/// ```
/// # use corrode_scanner::detectors::technologies::rsc::fingerprint;
/// # use std::collections::HashMap;
/// assert_eq!(fingerprint(&[], &HashMap::<String, String>::new()), Default::default());
/// ```
pub fn fingerprint<S: BuildHasher>(
    scripts: &[(&str, &str)],
    window_objects: &HashMap<String, String, S>,
) -> RscSurface {
    let mut surface = RscSurface::default();

    if window_objects.keys().any(|k| k == "__next_f") {
        surface.flight_markers = true;
        surface.app_router = true;
    }
    if window_objects.keys().any(|k| k == "__NEXT_DATA__") {
        surface.pages_router = true;
    }

    for (text, _) in scripts {
        if FLIGHT_PUSH_RE.is_match(text) {
            surface.flight_markers = true;
            surface.app_router = true;
        }
        if SERVER_DOM_RE.is_match(text) {
            surface.server_dom = true;
        }
        if SERVER_ACTION_RE.is_match(text) {
            surface.server_actions = true;
        }
    }

    surface
}
