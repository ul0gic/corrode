//! Shared route-template helpers: dedupe and dynamic-segment detection across
//! the per-framework parsers. Templates are reported verbatim, never instantiated.

use std::collections::HashSet;

use crate::types::RouteSurface;

/// A path is dynamic when it carries any framework's parameter marker:
/// Next/SvelteKit `[seg]`, Remix `:param`, or a splat/catch-all `*`.
pub fn is_dynamic(path: &str) -> bool {
    path.contains('[') || path.contains(':') || path.contains('*')
}

/// Next.js/SvelteKit framework internals that are not user-reachable routes.
pub fn is_framework_internal(path: &str) -> bool {
    const INTERNAL: &[&str] = &[
        "/_app",
        "/_error",
        "/_document",
        "/_next",
        "/__layout",
        "/__error",
    ];
    INTERNAL.contains(&path)
}

/// Accumulates `RouteSurface`s deduped by `(path, kind)`, keeping the first
/// (highest-trust) source seen for a given pair.
#[derive(Default)]
pub struct RouteSet {
    seen: HashSet<(String, String)>,
    routes: Vec<RouteSurface>,
}

impl RouteSet {
    // Test-only constructor; production callers use `RouteSet::default()`.
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, path: &str, kind: &str, source: &str) {
        if path.is_empty() {
            return;
        }
        let dynamic = is_dynamic(path);
        if self.seen.insert((path.to_owned(), kind.to_owned())) {
            self.routes.push(RouteSurface {
                path: path.to_owned(),
                kind: kind.to_owned(),
                source: source.to_owned(),
                dynamic,
                confidence: None,
            });
        }
    }

    pub fn into_vec(self) -> Vec<RouteSurface> {
        self.routes
    }

    /// Snapshot of accumulated paths — used to populate a manifest's flat
    /// `routes` list without consuming the set.
    pub fn clone_paths(&self) -> Vec<String> {
        self.routes.iter().map(|r| r.path.clone()).collect()
    }

    // Test-only: production code consumes the set via `into_vec`/`clone_paths`.
    #[cfg(test)]
    pub fn clone_routes(&self) -> Vec<RouteSurface> {
        self.routes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_dynamic_segments_across_frameworks() {
        assert!(is_dynamic("/users/[id]"));
        assert!(is_dynamic("/blog/[...slug]"));
        assert!(is_dynamic("/users/:id"));
        assert!(is_dynamic("/files/*"));
        assert!(!is_dynamic("/about"));
        assert!(!is_dynamic("/"));
    }

    #[test]
    fn recognizes_framework_internals() {
        assert!(is_framework_internal("/_app"));
        assert!(is_framework_internal("/_error"));
        assert!(!is_framework_internal("/about"));
    }

    #[test]
    fn dedupes_by_path_and_kind_keeping_first_source() {
        let mut set = RouteSet::new();
        set.push("/users/[id]", "route", "first");
        set.push("/users/[id]", "route", "second");
        set.push("/users/[id]", "api", "third");
        let routes = set.into_vec();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].source, "first");
        assert!(routes[0].dynamic);
        assert_eq!(routes[1].kind, "api");
    }

    #[test]
    fn skips_empty_paths() {
        let mut set = RouteSet::new();
        set.push("", "route", "s");
        assert!(set.into_vec().is_empty());
    }
}
