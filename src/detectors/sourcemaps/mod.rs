//! Pillar 1 — Source-map intelligence.
//!
//! Recovers attack-surface intelligence from exposed `JavaScript` source maps:
//! original filenames, embedded source text, secrets-from-source, internal
//! routes, and package versions. Strictly passive — GET-only fetches of `.map`
//! assets already referenced by the page, scoped to the target origin.
//!
//! Phase 1 fills this module in. Planned entry point:
//!
//! ```ignore
//! pub async fn analyze(
//!     ctx: &ScanContext,
//!     scripts: &[ScriptRef],
//! ) -> (Vec<SourceMapIntel>, Vec<RouteSurface>);
//! ```
//!
//! Declared here in Phase 0 so the parallel Phase 1/2 work never races on
//! `detectors/mod.rs`. See `.project/enhance-plan.md` Phase 1.
