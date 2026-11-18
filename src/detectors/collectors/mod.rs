// Does:  Groups collectors for scripts and page artifacts.
// Holds: Static script analysis accepts captured text independently of the browser-backed collectors.

/// Static script analysis.
pub mod ast;
/// DOM and storage artifact collection.
pub mod dom;
/// Script and framework artifact collection.
pub mod javascript;
