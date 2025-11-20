# Corrode Release TODO

## Vision
- Ship Corrode as an ergonomic single-target security scanner installable via `cargo install corrode`
- Provide polished documentation, helpful CLI UX (`corrode --url https://example.com`), and production-ready reporting
- Keep the codebase modular: each capability (secret detection, DOM analysis, network capture, reporting) belongs in its own module for easy growth

## Licensing
- ✅ Adopt AGPL-3.0-only with ul0gic attribution; `Cargo.toml`, README, LICENSE, and CONTRIBUTING all aligned.
- Document contribution guidelines to ensure inbound code stays compatible (done in CONTRIBUTING).

## Crate Publishing Readiness
- Keep `Cargo.toml` metadata (repository, homepage, documentation, readme, keywords, categories) accurate and in sync with README.
- Resolve Git dependency on `chromiumoxide_stealth`; upstream release or vendor a crate.
- Replace hard-coded Chrome path with CLI flag/env detection so binaries installed via cargo work cross-platform.
- Run `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo package --allow-dirty --dry-run` before publishing.
- Create crates.io account + API token; configure `.cargo/credentials` locally for publish flow.

## CLI UX Changes
- ✅ Replace positional `TARGET` file arg with explicit `--url <https://site>` flag (required) so the workflow is always single-target.
- Drop the unused `--concurrency` flag (currently no effect) until multi-target scanning returns.
- Optional secondary inputs:
  - `--input-file <path>` for bulk testing (low priority)
  - `--stdin` flag to read URLs from STDIN if we need later
- Keep additional knobs minimal: `--timeout`, `--chrome-bin`, `--output-dir`, `--json-only`, `--markdown-only`, `--no-browser-cache`.
- Update Clap definitions so `corrode --help` mirrors the new interface with practical examples.
- Remove references to `targets.txt` from README/install instructions once CLI changes land.

## Installation Strategy
- Deprecate `install.sh` and redundant `make install` instructions once crate publish works; keep docs focused on `cargo install corrode` and local `cargo run --release`.
- Provide guidance for Chromium dependency detection and installation.

## Documentation
- Restore sanitized `targets.txt.example` or rewrite docs to focus on `--url` workflow.
- Tighten README sections: quick start, prerequisites, Chrome path configuration, CLI flags, sample report, troubleshooting.
- Add mention of network capture limitations/status.
- Write a clear disclaimer stating Corrode is for authorized testing only and the author (ul0gic) is not responsible for misuse.

## Code Organization & Refactors
- ✅ Broke `src/main.rs` apart: CLI/config/detector modules plus `scanner::workflow` now own the scanning pipeline, and reporting lives in `reporting::json`/`reporting::markdown`.
- ✅ Extracted DOM + JavaScript detectors into `detectors::dom` and `detectors::javascript` with `scanner::page_utils` helpers so `workflow` simply orchestrates stages.
- Break remaining logic into finer helpers as needed:

```
src/
├── main.rs                 # entry point: parse CLI, call scanner::run
├── cli.rs                  # Clap definitions + config builder
├── config.rs               # normalized runtime configuration
├── scanner/
│   ├── mod.rs              # exposes run(config)
│   ├── browser.rs          # chromiumoxide setup + page helpers
│   └── workflow.rs         # orchestrates a single scan (current scan_url)
├── detectors/
│   ├── mod.rs
│   ├── secrets.rs          # SECRET_PATTERNS + SecretScanner
│   ├── dom.rs              # DOM/forms/iframes/data-attrs extraction
│   ├── javascript.rs       # script fetching, window objects
│   └── technologies.rs     # tech fingerprinting logic
├── network/
│   ├── mod.rs
│   └── monitor.rs          # existing NetworkMonitor
├── api/
│   ├── discovery.rs        # existing api_discovery.rs
│   └── testing.rs          # existing api_testing.rs
├── reporting/
│   ├── mod.rs
│   ├── json.rs             # ScanResult → JSON
│   └── markdown.rs         # ScanResult → REPORT.md
├── types.rs                # shared structs for everything (now canonical)
└── vulnerability.rs        # optional home for vuln definitions
```

- ✅ CLI parsing lives in `cli.rs`, config in `config.rs`, detectors/reporting/scanner modules are active.
- Next: continue refining modules (e.g., split `scanner::workflow` into smaller files/functions, add `detectors::dom`, etc.).
- Remove unused `src/vulnerability.rs` or repurpose it for vulnerability definitions/reporting.
- Ensure every module consumes the shared structs from `types.rs` (no duplication).

## Detection Enhancements
- Add AST-based JavaScript analysis (via swc or similar) to find deeply embedded secrets/endpoints beyond regex patterns.
  - Parse inline/external scripts and walk the AST for fetch/axios/xhr URLs, literal URLs, and credential-like identifiers.
  - Tag findings with origin + line/col for triage and surface them alongside regex-based secret detection.
  - Keep parsing resilient (skip oversized/invalid scripts) so scans remain fast even on noisy bundles.
- Beef up detection logic: expand secret patterns, storage/DOM heuristics, and wire in remaining API tests (`test_auth_differences`, `test_mass_assignment`).
- Fix network header capture in `network::monitor` so reports include request/response metadata.

## Reporting Makeover
- Redesign `reporting/markdown.rs` to produce a professional ASCII layout with distinct sections, summaries, and callouts.
- Ensure JSON mirrors all new fields (headers, AST findings) and document the schema.
- Add a `--format`/`--json-only` knob so users can tailor output.

## CLI & UX
- After detectors/reporting feel solid, switch to the planned `corrode --url https://target` interface and remove the implicit `targets.txt` workflow.
- Document the new CLI in README, drop `install.sh` instructions, and focus installation guidance on `cargo install`.

## Tooling & QA
- ✅ `cargo clippy -- -D warnings` now passes clean; keep it in CI to catch regressions.
- Add unit/integration tests for detectors and API testers; wire into CI before crates.io publish.

## Reporting Improvements
- Output JSON and Markdown reports into the current working directory unless `--output-dir` overrides it.
- JSON should include structured sections: secrets, network (full request/response metadata), API tests, DOM findings, recommendations.
- Markdown companion (REPORT.md) with ASCII boxes / sections highlighting secrets, API endpoints, RLS/storage findings, network captures, remediation checklist.
- Consider `--format json|md|both` for future flexibility.

## Network Monitoring Improvements
- Finish header capture in `network_monitor.rs`; ensure request/response headers populate properly and API calls are persisted to the JSON/Markdown reports.
- Detect and label API endpoints (method, status, auth hints) from captured traffic; surface key ones in the Markdown report.
- Consider storing HAR-like output for deeper debugging.
- Verify async tasks don't leak; add graceful shutdown.

## Testing & QA
- Add integration smoke test hitting a mock server to validate scanning pipeline without Chrome (feature flag?).
- Add unit tests for `api_discovery`, `api_testing` helpers.

## Account / Release Logistics
- Create crates.io org/user, link GitHub, configure access.
- Tag releases (`v0.1.0` etc.), publish GitHub Releases with changelog.
