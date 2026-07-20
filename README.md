# Corrode

Passive web reconnaissance for exposed credentials, client-side attack surface,
and evidence-backed security findings.

[![CI](https://github.com/ul0gic/corrode/actions/workflows/ci.yml/badge.svg)](https://github.com/ul0gic/corrode/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/corrode-scanner.svg)](https://crates.io/crates/corrode-scanner)
[![Downloads](https://img.shields.io/crates/d/corrode-scanner.svg)](https://crates.io/crates/corrode-scanner)
[![Rust](https://img.shields.io/badge/rust-1.97.1-orange.svg)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

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
- Correlates directly observed React, Next.js, and WordPress versions with
  supported security advisories.
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
| Rust 1.97.1 | Required when installing with Cargo or building from source |
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
  schema version `0.5`.
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
| Advisory correlation | React Server Components, Next.js, and WordPress advisories when sufficient passive version evidence is available |

Advisory matching includes the supported React RSC CVE cluster, Next.js
middleware/SSRF/cache/auth/DoS advisories, and the July 2026 WordPress SQLi and
RCE-chain ranges. Unknown or weakly inferred versions remain validation leads or
inventory and do not raise headline risk.

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
and contributes to the headline risk rating.

Corrode is reconnaissance, not proof of exploitability. Browser state varies
with authentication, user interaction, feature flags, geography, and timing, so
a scan can miss code paths or behavior that the loaded page did not expose.

## Authorized Use

Use Corrode only on systems you own or have explicit permission to assess. You
are responsible for scope, legal authorization, handling captured data, and
responsible disclosure. The software is provided without warranty and may
produce false positives or miss vulnerabilities.

## License and Contributing

Corrode is licensed under
[AGPL-3.0-only](https://www.gnu.org/licenses/agpl-3.0.html). See [LICENSE](LICENSE)
for the complete terms and [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request.

For questions, bug reports, or security concerns, open a
[GitHub issue](https://github.com/ul0gic/corrode/issues).
