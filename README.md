# Corrode

Passive web reconnaissance for exposed credentials, client-side attack surface,
and evidence-backed security findings.

[![CI](https://github.com/ul0gic/corrode/actions/workflows/ci.yml/badge.svg)](https://github.com/ul0gic/corrode/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/corrode-scanner.svg)](https://crates.io/crates/corrode-scanner)
[![Downloads](https://img.shields.io/crates/d/corrode-scanner.svg)](https://crates.io/crates/corrode-scanner)
[![Rust](https://img.shields.io/badge/rust-1.100.0-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license-and-contributing)

Corrode loads a target in headless Chrome and analyzes what the browser can see:
HTML, JavaScript, DOM state, storage, cookies, network activity, source maps, and
framework metadata. It turns those observations into a concise operator report
while preserving complete evidence for deeper review.

## Why Corrode

- Detects 45+ credential and secret formats across cloud, authentication,
  payments, monitoring, collaboration, and database services.
- Maps API endpoints, routes, framework manifests, source maps, client-side
  taint flows, gadgets, prototype-pollution surfaces, and `postMessage` handlers.
- Classifies browser-visible access tokens, refresh tokens, sessions, and JWT
  claims without validating or replaying credentials.
- Checks high-impact advisories against WordPress generator evidence or an
  owner-supplied record of the running deployment.
- Separates actionable findings, manual-validation leads, and neutral inventory.
- Scores confidence independently from severity and records evidence provenance.
- Supports single targets, sequential batch scans, custom patterns, and
  machine-readable JSON.

## Passive by Design

Corrode analyzes the requested page, its naturally observed browser activity,
and already-referenced first-party artifacts. It does not:

- execute exploits or replay credentials;
- fuzz parameters or inject payloads;
- probe guessed or unreferenced paths;
- create accounts, upload files, or establish persistence; or
- claim a vulnerability without direct supporting evidence.

Static inferences and context-dependent observations are reported as
manual-validation leads, not confirmed vulnerabilities.

## Installation

Install from crates.io:

```bash
cargo install corrode-scanner --locked
```

Or build from source:

```bash
git clone https://github.com/ul0gic/corrode.git
cd corrode
cargo build --release
```

Prebuilt Linux and macOS binaries are available on the
[GitHub Releases](https://github.com/ul0gic/corrode/releases) page.

### Requirements

| Requirement | Notes |
|-------------|-------|
| Chrome or Chromium | Required at runtime; auto-detected from `PATH` and common install locations |
| Rust 1.97.1 or newer | Minimum for Cargo installs and source builds. The repository and CI use Rust 1.100.0. |
| CMake | Build-time dependency for the Rust TLS backend; unnecessary for prebuilt binaries |
| Operating system | Linux or macOS |

Override browser detection with `--chrome-bin <path>` or the `CHROME_BIN`
environment variable.

## Quick Start

Scan one authorized target:

```bash
corrode-scanner --url https://example.com
```

Write Markdown and JSON:

```bash
corrode-scanner --url https://example.com --format both
```

Scan a list of targets:

```bash
corrode-scanner --file targets.txt --output assessment
```

`targets.txt` accepts one HTTP(S) URL per line. Blank lines and lines beginning
with `#` are ignored.

## Output

Each target receives its own directory:

```text
corrode-output/
└── example-com/
    ├── REPORT.md
    ├── EVIDENCE.md
    └── scan_result.json
```

- `REPORT.md` prioritizes actionable findings, leads, remediation, and useful
  attack-surface inventory.
- `EVIDENCE.md` contains exhaustive passive observations, including network,
  DOM, AST, source-map, route, and static-analysis details.
- `scan_result.json` is emitted with `--format json` or `--format both` and uses
  schema version `0.6`.
- `SUMMARY.md` is added at the output root for multi-target scans.

Markdown redacts credential values. JSON retains complete evidence and should be
handled as sensitive assessment data.

## Detection Coverage

| Surface | Examples |
|---------|----------|
| Secrets and credentials | AWS, Azure, GCP, Supabase, Firebase, GitHub, GitLab, Stripe, Slack, OpenAI, Anthropic, database URLs, private keys, JWTs |
| Sessions and storage | Access and refresh tokens, privileged JWT roles/scopes, expiry, tenant/account claims, persisted sessions, public client configuration |
| Client-side attack surface | API endpoints, routes, manifests, source maps, DOM taint flows, gadgets, prototype-pollution heuristics, `postMessage` origin checks |
| Security posture | Cookie flags, CORS, CSP and other security headers, mixed content, debug builds, exposed source maps |
| Technology inventory | Frontend frameworks, servers, authentication, payments, analytics, CMS, API documentation, state management, cloud, and monitoring services |
| Advisory correlation | WordPress core RCE chain from a site generator version; React2Shell, PHP2Shell, upstream NGINX HTTP/2 and Vite development-server advisories from owner-supplied deployment evidence |

### Checking deployed software

The same URL scan works against localhost and a remote site. Product names,
client bundles and HTTP banners contribute to inventory. For server-side
advisories, supply the **actual running upstream release and configuration**
from the deployment you own. Use an exact page URL in the configuration file:

```toml
[deployments."https://app.example.org/".react]
package = "react-server-dom-webpack"
unmodified_upstream_version = "19.1.1"
serves_server_components = true
```

Run `corrode-scanner --url https://app.example.org/ --config deployment.toml`. For a
local service, use its localhost URL (including the port) in both places.
Records are matched to the requested and final document URLs, including paths
and query strings. A redirect to another URL skips the supplied record.
Each product table is optional. Omit any component whose build provenance is
unknown. For distributions, patched forks, NGINX Plus, or vendor backports,
consult the supplier's package advisory.

Each supported advisory has a row in the report and an entry in JSON
`advisory_checks`. A `matched` result means the owner record or site generator
metadata met the published criteria. Confirm the running package, patch history,
and relevant settings on the deployment. Corrode does not test host exploitability.
A `no_match` applies only to that rule and the evidence compared.
A `not_assessed` result explains which evidence was missing or unsuitable.
Reports from before schema 0.6 have no recorded per-rule coverage.

| Deployment table | Evidence in addition to `unmodified_upstream_version` | Advisory |
|---|---|---|
| `react` | Installed RSC server `package` and `serves_server_components` | [React2Shell](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) |
| `php` | `serves_web_requests` for the installed PHP 8.2–8.5 runtime | [PHP October security releases](https://www.php.net/archive/2026.php) |
| `nginx_open_source` | `serves_http2` on this service. The second check also requires `proxies_to_backend` and `low_worker_connections_observed` | [HTTP/2 flow control](https://my.f5.com/manage/s/article/K000163926), [HTTP/2 proxy worker](https://my.f5.com/manage/s/article/K000163928) |
| `vite` | `dev_server_exposed_to_network` for an explicitly exposed Vite development server | [Vite virtual-module advisory](https://github.com/vitejs/vite/security/advisories/GHSA-p4f5-76q4-ffq7) |

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url <URL>` | Scan one HTTP(S) target | No default |
| `--file <PATH>` | Scan URLs from a file | No default |
| `-o, --output <DIR>` | Output directory | `corrode-output` |
| `--format <FORMAT>` | `md`, `json`, or `both` | `md` |
| `-t, --timeout <SECS>` | Page-load timeout | `30` |
| `--chrome-bin <PATH>` | Chrome/Chromium override | auto-detected |
| `-v, --verbose` | Detailed progress output | off |
| `--config <PATH>` | Explicit TOML configuration | auto-discovered |
| `--no-config` | Ignore configuration files | off |

Exactly one of `--url` or `--file` is required. Run
`corrode-scanner --help` for the canonical CLI reference.

## Configuration

Configuration is loaded in this order:

1. `--config <PATH>`
2. `./corrode.toml`
3. `~/.config/corrode/config.toml`

CLI values take precedence. A minimal configuration:

```toml
[scan]
timeout = 60
format = "both"
output_dir = "assessment"

[patterns]
ignore_patterns = ["internal_ip"]

[[patterns.custom_patterns]]
name = "Internal API Token"
pattern = 'int_[A-Za-z0-9]{32,48}'
severity = "critical"
```

See [`examples/corrode.toml`](examples/corrode.toml) for the full configuration
reference.

## Interpreting Results

Severity describes potential impact. Confidence describes how strongly the
captured evidence supports the assessment. A high-severity, low-confidence lead
should be validated before escalation; an actionable finding has direct evidence
and contributes to the highest finding severity. Advisory matches are reported separately.

Corrode is reconnaissance, not proof of exploitability. Browser state varies
with authentication, user interaction, feature flags, geography, and timing, so
a scan can miss code paths or behavior that the loaded page did not expose.

## Authorized Use

Use Corrode only on systems you own or have explicit permission to assess. You
are responsible for scope, legal authorization, handling captured data, and
responsible disclosure. The software is provided without warranty and may
produce false positives or miss vulnerabilities.

## License and Contributing

Corrode is available under the [MIT License](LICENSE). Commercial, private, and
open-source use are permitted under its terms. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

For questions, bug reports, or security concerns, open a
[GitHub issue](https://github.com/ul0gic/corrode/issues).
