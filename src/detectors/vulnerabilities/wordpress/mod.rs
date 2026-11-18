// Does:  Groups WordPress core advisory checks.
// Holds: Asset-version hints remain outside the critical chain assessment.

mod cve_2026_63030;
pub(crate) use cve_2026_63030::assess;
pub use cve_2026_63030::check_cves;
