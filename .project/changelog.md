# Corrode — Changelog

> All notable changes to this project will be documented in this file.
> Format based on [Keep a Changelog](https://keepachangelog.com/).
> Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [0.3.0] — 2026-03-19

### Added

**Modular Detector Architecture**
- `detectors/technologies/` — technology fingerprinting split into 4 signal source modules: `runtime.rs` (window objects), `headers.rs` (HTTP headers), `meta.rs` (meta tags), `scripts.rs` (script URLs + network requests)
- `detectors/vulnerabilities/` — per-framework CVE detection: `nextjs.rs` (5 CVEs), `react.rs` (4 CVEs)
- `detectors/collectors/` — page data extraction: `dom.rs`, `javascript.rs`, `ast.rs`
- `detectors/secrets/` — credential engine with `jwt.rs` and `patterns/` as submodules

**Technology Detection Expansion**
- Runtime: React Query, TanStack Router, Zustand, HTMX, Alpine.js, Livewire
- Headers: Axum, Actix, Warp, Hyper, Werkzeug, Tornado, Puma, Phoenix, Gin, Fiber, Echo, NestJS, AdonisJS, Sails.js + 9 more server signatures
- Scripts: Swagger UI, ReDoc, RapiDoc (exposed API docs), Google Sign-In, Apple Sign-In, Facebook Login, Google OAuth, Vercel (`/_vercel/` paths, `?dpl=` deployment IDs)
- Meta: Remix, TYPO3, Craft CMS, Strapi generators
- Next.js App Router detection via `?_rsc=` RSC payload requests
- Network request URL scanning (not just DOM script sources)

### Changed

- **Dependencies upgraded**: clap 4.5→4.6, colored 2→3, swc_common 17→19, swc_ecma_ast 18→21, swc_ecma_parser 27→35, swc_ecma_visit 18→21
- **Report version**: now uses compile-time `env!("CARGO_PKG_VERSION")` instead of hardcoded string
- **Recommendations**: contextual based on actual findings, shows "No actionable findings" when scan is clean
- **README**: removed redundant mermaid diagrams, fixed binary name, added CI/crates.io/downloads badges, updated Chrome install instructions

### Fixed

- **CORS false positives**: wildcard ACAO on static assets (JS, CSS, images, video, audio), framework internals (`/_next/`, `/_vercel/`, `/cdn-cgi/`, `?_rsc=`), third-party CDNs, and non-first-party domains are no longer flagged
- **Duplicate missing headers**: security header check now runs once on the first HTML document response, not on every RSC/prefetch response
- **Technology detection gaps**: Vercel and Next.js App Router now detected via network request URLs, not just DOM script sources

### Security

- CI/CD workflow action SHAs pinned and updated to latest versions

---

## [0.2.0] — 2026-03-18

### Added

**Detection Patterns (Phase 2)**
- 15 new secret/credential patterns, expanding coverage from 30+ to 45+ pattern types
- Anthropic API key detection (`sk-ant-api03-` prefix) in new `detectors/patterns/ai.rs` module
- DigitalOcean token detection (`doo/dop/dor_v1_` prefixes)
- Vercel token detection (`vc[pkiar]_` prefixes)
- Azure Storage connection string detection
- Azure AD Client Secret detection (`Q~`-prefixed secrets)
- Azure SAS Token detection
- GCP Service Account email detection
- Cloudflare Origin CA key detection (`v1.0-` prefix)
- Mapbox token detection — public (`pk.`) and secret (`sk.`) JWT-encoded tokens
- Sentry DSN and Sentry Auth Token (`sntrys_`) detection in new `detectors/patterns/monitoring.rs`
- Datadog API key and App key detection (context-anchored)
- PagerDuty REST API key detection (context-anchored)
- Linear API key detection (`lin_` prefix) in new `detectors/patterns/collaboration.rs`
- Notion API key detection (`ntn_` prefix)
- Algolia API key detection (context-anchored)
- Plaid client secret detection (context-anchored) in `detectors/patterns/payment.rs`
- Postmark server/account token detection (context-anchored) in `detectors/patterns/communication.rs`

**CVE Detection (Phase 2)**
- React Server Components RCE detection: CVE-2025-55182 (Critical, react-server-dom-webpack < 19.1.0)
- React Server Components Source Code Exposure: CVE-2025-55183 (Medium, 19.0.0 – 19.2.2)
- React Server Components DoS: CVE-2025-55184 / CVE-2025-67779 (High, 19.0.0 – 19.2.2)
- React Server Components DoS: CVE-2026-23864 (High, 19.0.0 – 19.2.3)
- Next.js Middleware Auth Bypass: CVE-2025-29927 (Critical, < 15.2.3)
- Next.js SSRF: CVE-2024-34351 (High, < 14.1.1)
- Next.js Cache Poisoning: CVE-2024-46982 (High, < 14.2.10)
- Next.js Auth Bypass: CVE-2024-51479 (High, 14.2.0 – 14.2.15)
- Next.js DoS: CVE-2024-56332 (Medium, < 15.1.7)
- Informational advisory emitted when Next.js is detected but version cannot be confirmed

**Technology Version Extraction (Phase 2)**
- React version extraction via `__REACT_DEVTOOLS_GLOBAL_HOOK__`, `window.React.version`, CDN URL patterns, and license comments
- Next.js router type detection (Pages Router vs App Router) via `__NEXT_DATA__` presence and chunk path patterns
- Next.js `buildId` and `runtimeConfig` extraction from `__NEXT_DATA__`
- `TechnologyVersion` struct added to `ScanResult` for structured version reporting

**Runtime Detection Enhancements (Phase 2)**
- Window object deep scanning: values from all extracted globals now pass through `SecretScanner` (critical gap fix)
- Expanded window object extraction to 17 globals: `__APOLLO_STATE__`, `__APOLLO_CLIENT__`, `APOLLO_STATE`, `__remixContext`, `__NUXT_DATA__`, `__pinia`, `__INITIAL_STATE__`, `__sveltekit_data`, `_$HY`, `__RELAY_STORE__`, `__REACT_QUERY_STATE__`, `__REDWOOD__API_PROXY_PATH`, `__PAYLOAD_CONFIG__`, and existing Next.js/Nuxt globals
- Environment variable detection: `process.env.REACT_APP_*`, `import.meta.env.VITE_*`, `process.env.NEXT_PUBLIC_*` references in JS source, with elevated severity for names containing SECRET/PASSWORD/PRIVATE/KEY
- Expanded debug mode detection: React development builds (`renderers.bundleType === 1`), `react-error-overlay`, Vue devtools (`Vue.config.devtools`), Angular debug (`window.ng.probe`), HMR signals (`__webpack_hmr`, `webpackHotUpdate`, `/@vite/client`)
- Enhanced source map detection: `sourceMappingURL` comment scanning in fetched scripts, `SourceMap`/`X-SourceMap` response header detection, CSS source map detection

**Batch Scanning (Phase 3)**
- `--file <PATH>` CLI flag for multi-URL batch scanning
- URL file format: one URL per line, blank lines and `#`-prefixed comment lines skipped
- Each URL validated to start with `http://` or `https://` before scanning begins
- Per-URL progress indicator (`[N/total] Scanning URL...`) during batch runs
- Scan continues past individual URL failures with error logged; exit code 1 if any target failed
- `SUMMARY.md` written to output root for batch runs: per-target secrets found, vulns found, and status

**Config File Support (Phase 3)**
- `.corrode.toml` config file support with auto-discovery (current directory, then `~/.config/corrode/config.toml`)
- `--config <PATH>` flag for explicit config file path
- `--no-config` flag to ignore all config files
- `[scan]` section: timeout, verbose, format, output_dir
- `[chrome]` section: binary path, extra Chrome arguments
- `[patterns]` section: custom_patterns (user-defined regexes with name and severity), ignore_patterns (suppress built-in patterns by name)
- `[report]` section: redact_secrets (mask values in Markdown output), include_network_log
- Priority: CLI flags > config file > built-in defaults
- `examples/corrode.toml` added — fully documented reference configuration

**Test Suite (Phase 4)**
- `fixtures/test-credentials.html` — fixture page with planted secrets for all 15+ new patterns
- `fixtures/test-cves.html` — fixture page with React version hooks and Next.js `__NEXT_DATA__` for CVE detection testing
- `fixtures/test-runtime.html` — fixture page with window objects, exposed env vars, debug indicators, and `sourceMappingURL` comments
- `tests/patterns.rs` — unit tests for all new credential patterns with true positive and true negative cases, including OpenAI/Anthropic collision regression test
- `tests/cve_detection.rs` — unit tests for each CVE detector, including boundary versions (last vulnerable, first patched)
- `tests/config.rs` — unit tests for TOML config parsing, merge priority, `--no-config` behavior, and invalid regex handling
- `tests/batch.rs` — unit tests for URL file parsing: valid URLs, blank lines, comments, invalid URLs, empty file

### Changed

**Codebase Restructuring (Phase 1)**
- `src/detectors/secrets.rs` split into `src/detectors/patterns/` directory module (10 sub-modules: cloud, auth, payment, communication, vcs, database, infrastructure, ai, monitoring, collaboration)
- JWT decoding logic extracted to `src/detectors/jwt.rs`
- Security analysis (cookie/header/CORS checks) extracted from `scanner/workflow.rs` to `src/detectors/security.rs`
- Chrome binary resolution extracted from `scanner/workflow.rs` to `src/scanner/chrome.rs`
- `src/reporting/markdown.rs` converted to section-based directory module (`src/reporting/markdown/`): summary, findings, network, technologies, appendix sections

**Default Output Format (Phase 3)**
- Default `--format` changed from `both` to `md`. JSON output requires `--format json` or `--format both`.

**Markdown Report Redesign (Phase 3)**
- Summary section redesigned: target URL, scan timestamp, per-severity finding counts, technologies detected, executive summary paragraph
- Findings section reorganized by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO with clear visual separation; each finding shows type, source, value, context, and location
- Security posture section added: header analysis table, per-cookie audit, CORS status, mixed content findings
- Technology section groups technologies by category (Frameworks, Auth, Payment, Analytics, CMS, Libraries, State)
- Network section adds first-party vs third-party breakdown and external domain contact table

### Fixed

- **OpenAI/Anthropic pattern collision** — OpenAI pattern `sk-[A-Za-z0-9]{32,}` now naturally excludes Anthropic keys (`sk-ant-api03-...`) because the character class `[A-Za-z0-9]` does not include hyphens; the match stops at 3 characters, failing the `{32,}` minimum. No regex change required — collision is structurally impossible. (SEC-001)
- **RSC RCE regex false positive** — RSC CVE regex separator widened from `{0,6}` to `{0,15}` for minified bundle compatibility; version overlap between CVE-2025-55183 and CVE-2025-55184 resolved so the same version no longer triggers duplicate reports. (SEC-007)
- **`file://` local file read** — External script fetching in `javascript.rs` now rejects `src` attributes with `file://` scheme before passing to `reqwest`, preventing local file system reads. (SEC-005)
- **`bytes` crate advisory (RUSTSEC-2026-0007)** — Integer overflow in `BytesMut::reserve` addressed; dependency updated or advisory confirmed mitigated. (SEC-004)
- **Heroku pattern over-matching** — Heroku UUID pattern rewritten to avoid catastrophic backtracking from alternation character classes. (SEC-009)
- **Custom pattern ReDoS risk** — User-supplied custom patterns in `.corrode.toml` are now compiled with a size limit and timeout guard to prevent ReDoS from malicious or poorly crafted patterns. (SEC-003)

### Security

**Fixed (5 issues resolved)**
- SEC-003 (HIGH): Custom pattern ReDoS risk — size limit and timeout guard added
- SEC-004 (MEDIUM): `bytes` crate RUSTSEC-2026-0007 — integer overflow mitigated
- SEC-005 (HIGH): `file://` scheme local file read — scheme check added before fetch
- SEC-007 (LOW): RSC CVE regex version overlap — duplicate reports eliminated
- SEC-009 (LOW): Heroku pattern catastrophic backtracking — regex rewritten

**Open / Deferred (6 issues)**
- SEC-001 (MEDIUM): OpenAI/Anthropic pattern — confirmed not a bug; character class naturally excludes Anthropic keys
- SEC-002 (MEDIUM): PagerDuty pattern false positives — pattern tightening deferred
- SEC-006 (LOW): Batch URL file error messages leak filesystem paths — deferred
- SEC-008 (LOW): Config file `output_dir` path traversal — deferred
- SEC-010 (MEDIUM): Azure AD Client Secret weak pattern — pattern hardening deferred
- SEC-011 (MEDIUM): External script fetching lacks SSRF IP validation — deferred

---

## Version Guidelines

### Version Format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes or significant milestones (1.0 = first public release)
- **MINOR**: New features, completed phases
- **PATCH**: Bug fixes, small improvements

### Change Types

| Type | Description |
|------|-------------|
| **Added** | New features or capabilities |
| **Changed** | Changes to existing functionality |
| **Deprecated** | Features marked for removal |
| **Removed** | Features that were removed |
| **Fixed** | Bug fixes |
| **Security** | Security-related changes |

---

## Milestones

| Version | Milestone | Date |
|---------|-----------|------|
| 0.1.0   | Foundation: headless scanning, 30+ patterns, JSON+MD output | – |
| 0.2.0   | Detection Expansion: 45+ patterns, 9 CVEs, runtime detection | 2026-03-18 |
| 0.3.0   | Modular Architecture: detector restructuring, expanded tech fingerprinting, false positive fixes | 2026-03-19 |
| 1.0.0   | Public Release | TBD |

---

*Last updated: 2026-03-19*
