// Does:  Shares the upstream NGINX release boundaries for the November HTTP/2 advisories.
// Holds: Each check supplies the release that introduced its own affected code.

pub(super) mod cve_2026_123007;
pub(super) mod cve_2026_123633;

use super::deployment::{Nginx, Version};

impl Nginx {
    fn affected_since(&self, introduced: Version) -> bool {
        let version = self.unmodified_upstream_version;
        (introduced..Version(1, 30, 7)).contains(&version)
            || matches!(version, Version(1, 31, 0..=8))
    }
}
