//! Pillar 1 — Framework manifest intelligence.
//!
//! Parses framework build/route manifests (Next.js `__BUILD_MANIFEST` /
//! `__SSG_MANIFEST` / route manifests, Remix route modules, Nuxt payload/state,
//! Astro islands, `SvelteKit` manifest, Vite/webpack chunk graphs) into discovered
//! routes, dynamic patterns, and build fingerprints. Gated by the existing
//! tech-fingerprint result so only present frameworks are parsed. Passive.
//!
//! Phase 1 fills this module in. Planned entry point:
//!
//! ```ignore
//! pub fn analyze(
//!     technologies: &[TechnologyVersion],
//!     window_objects: &HashMap<String, String>,
//! ) -> (Vec<FrameworkManifest>, Vec<RouteSurface>);
//! ```
//!
//! Declared here in Phase 0 so the parallel Phase 1/2 work never races on
//! `detectors/mod.rs`. See `.project/enhance-plan.md` Phase 1.
