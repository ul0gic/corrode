// Does:  Combines the built-in secret detection patterns.
// Holds: Patterns are keyed by name in the resulting map.

mod ai;
mod auth;
mod cloud;
mod collaboration;
mod communication;
mod database;
mod infrastructure;
mod monitoring;
mod payment;
mod vcs;

use regex::Regex;
use std::collections::HashMap;

/// Collects built-in patterns keyed by name.
///
///     assert!(!corrode_scanner::detectors::secrets::patterns::all_patterns().is_empty());
pub fn all_patterns() -> HashMap<&'static str, Regex> {
    let mut m = HashMap::new();
    for (name, regex) in cloud::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in auth::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in payment::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in communication::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in vcs::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in database::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in infrastructure::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in ai::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in monitoring::patterns() {
        m.insert(name, regex);
    }
    for (name, regex) in collaboration::patterns() {
        m.insert(name, regex);
    }
    m
}
