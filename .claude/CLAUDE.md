# Corrode

> Passive web reconnaissance tool for extracting secrets, credentials, and security data from web applications — built in Rust with headless Chrome.

## Project Documentation

Read these before making changes:

- @.project/prd.md — Product requirements, features, acceptance criteria
- @.project/tech-stack.md — Technology choices, architecture, dependencies
- @.project/build-plan.md — Current task progress and phase tracking
- @.project/changelog.md — Version history and recent changes
- @.project/issues/ISSUE_TEMPLATE.md — Issue template for bug/debt/security findings

## Commands

### Build & Test

```bash
# Build (debug)
cargo build --workspace

# Build (release)
cargo build --release

# Test
cargo test --workspace

# Lint
cargo clippy -- -D warnings

# Format check
cargo fmt -- --check

# Run (single URL)
./target/release/corrode --url https://example.com

# Run with options
./target/release/corrode --url https://example.com -o recon-output -t 60 -v --format both

# Batch scan from file
./target/release/corrode --file targets.txt -o recon-output -v

# With custom config
./target/release/corrode --url https://example.com --config my-config.toml

# Skip config file
./target/release/corrode --url https://example.com --no-config
```

### Security Auditing

```bash
# Dependency vulnerability scan
cargo audit

# SAST scanning
semgrep scan --config "p/rust" --config "p/owasp-top-ten" --config "p/secrets" src/
```

### Publishing

```bash
# Dry-run publish check
cargo publish --dry-run

# List files that would be published
cargo package --list
```

## Project Structure

```
src/
├── main.rs              # Entry point, tokio runtime bootstrap
├── cli.rs               # Clap derive definitions (--url, --output, --timeout, --verbose, --format, --chrome-bin)
├── config.rs            # Runtime config, .corrode.toml loading, URL file parsing
├── types.rs             # Shared data structures (ScanResult, SecretFinding, TechnologyVersion, etc.)
├── scanner/
│   ├── workflow.rs      # Top-level scan orchestration — browser launch, page load, collector dispatch
│   ├── chrome.rs        # Chrome/Chromium binary resolution and detection
│   └── page_utils.rs    # DOM interaction helpers — JS evaluation, element queries, content extraction
├── detectors/
│   ├── collectors/      # Page-level data extraction from headless Chrome
│   │   ├── ast.rs       # SWC-based JavaScript AST analysis
│   │   ├── dom.rs       # DOM analysis — forms, hidden inputs, cookies, localStorage, sessionStorage
│   │   └── javascript.rs # Script extraction, window objects, debug flags, source maps
│   ├── secrets/         # Credential and secret detection engine
│   │   ├── mod.rs       # SecretScanner — pattern matching, custom patterns, ignore lists
│   │   ├── jwt.rs       # JWT role decoding — service_role, anon detection
│   │   └── patterns/    # Categorized regex patterns (45+)
│   │       ├── ai.rs, auth.rs, cloud.rs, payment.rs, communication.rs
│   │       ├── collaboration.rs, monitoring.rs, vcs.rs, database.rs
│   │       └── infrastructure.rs
│   ├── security/        # Security posture analysis
│   │   └── mod.rs       # Cookie, header, CORS, mixed content checks
│   ├── technologies/    # Technology fingerprinting from 4 signal sources
│   │   ├── runtime.rs   # Window object checks + version extraction
│   │   ├── headers.rs   # HTTP Server/X-Powered-By detection
│   │   ├── meta.rs      # <meta generator="..."> detection
│   │   └── scripts.rs   # Script URL patterns + Vite hash detection
│   └── vulnerabilities/ # Known CVE detection per framework
│       ├── nextjs.rs    # Next.js CVE advisories (5 CVEs)
│       └── react.rs     # React RSC CVE detection (4 CVEs)
├── api/
│   └── discovery.rs     # Passive API endpoint extraction from JavaScript source
├── network/
│   └── monitor.rs       # Chrome DevTools Protocol network event capture
└── reporting/
    ├── json.rs          # JSON output writer
    └── markdown/        # Markdown report generator (section-based)
        ├── mod.rs       # Report orchestrator — calls section renderers, writes file
        ├── summary.rs   # Executive summary, risk level, key summary box
        ├── findings.rs  # Secrets and vulnerabilities organized by severity
        ├── security.rs  # Security posture — headers, cookies, CORS, mixed content
        ├── network.rs   # Network activity — first/third-party breakdown, external domains
        ├── technologies.rs  # Technology stack and DOM insights
        └── appendix.rs  # AST findings, network insights, source maps, recommendations
fixtures/                # Static fixture pages for local testing
corrode-output/          # Default output directory (per scan)
```

## Architecture

- **Language:** Rust 1.70+ (2021 edition)
- **Async runtime:** Tokio (full features)
- **Browser automation:** chromiumoxide 0.6.0 via Chrome DevTools Protocol
- **JS parsing:** SWC (swc_ecma_parser + swc_ecma_visit) for AST-based analysis
- **CLI:** clap 4.5 with derive macros and env var support
- **Error handling:** anyhow for contextual error propagation
- **Pattern matching:** regex with lazy_static for compile-once patterns
- **Serialization:** serde + serde_json for scan results
- **HTTP:** reqwest for fetching external scripts
- **Output:** colored terminal output + JSON + Markdown reports
- **Runtime dependency:** Chrome/Chromium (auto-detected or via `--chrome-bin` / `CHROME_BIN`)
- **Published as:** `corrode-scanner` on crates.io
- **License:** AGPL-3.0-only

## Coding Standards

Standards are auto-loaded from `.claude/rules/`. Universal rules always apply. Path-scoped rules activate only when touching matching files.

**Universal (always active):**

- `context-management.md` — Planning, context window discipline, verification loops
- `build-discipline.md` — Zero tolerance for warnings/errors, commit discipline
- `code-quality.md` — DRY, clear over clever, error handling, file organization
- `testing.md` — Test behavior not implementation, error paths, edge cases
- `security.md` — No hardcoded secrets, input validation, HTTPS only
- `self-improvement.md` — Keep CLAUDE.md current, recognize skill/rule opportunities
- `orchestration.md` — Agent teams, file ownership, gate protocol, collision prevention

**Path-scoped (activate on matching files):**

- `rust.md` — No `.unwrap()` in production, Clippy zero warnings, error handling, unsafe audit

## Available Agents

Use these by switching to the appropriate agent when the task matches.

| Agent | Use When |
|-------|----------|
| `cli-engineer` | Rust implementation — detection engines, scanner workflow, CLI interface, new features |
| `detection-researcher` | Research credential formats, CVE patterns, and technology fingerprints — produces research briefs, never writes code |
| `build-plan-architect` | Create orchestration-aware build plans from PRD + tech-stack |
| `code-review-engineer` | Full codebase or PR review |
| `security-engineer` | Security audits, dependency review, detection pattern validation |
| `qa-engineer` | Testing strategy, cargo test, fixtures, coverage, integration tests |
| `refactor-engineer` | Restructuring, module boundary enforcement, dead code removal |
| `lint-engineer` | Clippy remediation, code style enforcement |
| `devops-engineer` | GitHub Actions CI/CD, crates.io publishing, cross-compilation, releases |
| `documentation-engineer` | API docs, architecture docs, READMEs, changelogs |

## Available Skills

| Skill | What It Does |
|-------|-------------|
| `/review` | Run structured code review with severity ratings |
| `/security-check` | Security audit against OWASP/CWE standards |
| `/refactor` | Analyze codebase and produce phased refactor plan |
| `/lint-fix [file]` | Fix all lint errors in a specific file |
| `/plan-project` | Generate orchestration-aware build plan with parallelization, gates, agent assignments |

## Issue Management

When you discover bugs, security issues, performance problems, or technical debt during any work:
1. Create an issue file in `.project/issues/open/` using the `ISSUE_TEMPLATE.md` format
2. Use the appropriate prefix based on source:
   - `ISSUE-XXX-short-description.md` — General bugs, tech debt, enhancements
   - `SEC-XXX-short-description.md` — Security audit findings (from `/security-check` or security-engineer)
   - `QA-XXX-short-description.md` — QA audit findings (from qa-engineer)
3. Increment from the highest existing number within each prefix
4. Fill in severity, type, affected files, and suggested fix
5. Continue your current work — issues are tracked, not blockers unless CRITICAL
6. Move resolved issues to `.project/issues/closed/`

## Critical Rules

- Always read relevant project docs before making changes
- Run build/test commands after every task — zero warnings, zero errors (`cargo clippy -- -D warnings`)
- Never commit secrets, .env files, or credentials
- Update `.project/build-plan.md` after completing tasks
- Update `.project/changelog.md` at milestones
- File issues for bugs/debt discovered during work — don't silently ignore problems
- Respect file ownership boundaries during parallel phases
- This is a **passive-only** tool — never add active exploitation, fuzzing, or injection features
