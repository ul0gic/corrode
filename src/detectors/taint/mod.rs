//! Pillar 2 — Client-side taint & gadget mapping.
//!
//! Static source→sink correlation over the SWC AST (`collectors/ast.rs`) plus
//! runtime-observed values: DOM-XSS flows, prototype-pollution surface,
//! postMessage handlers, gadget inventory, and CSP-bypass correlation. Reports
//! that a flow *exists* — never constructs or fires a payload. Strictly passive.
//!
//! Phase 2 fills this module in. Planned entry point:
//!
//! ```ignore
//! pub fn analyze(
//!     scripts: &[ScriptSource],
//!     csp: Option<&str>,
//! ) -> TaintReport; // { flows, gadgets, post_message_handlers }
//! ```
//!
//! Declared here in Phase 0 so the parallel Phase 1/2 work never races on
//! `detectors/mod.rs`. See `.project/enhance-plan.md` Phase 2.
