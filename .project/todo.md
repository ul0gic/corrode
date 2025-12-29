# Corrode Release TODO

## Vision
Corrode is a **passive reconnaissance tool** for web security assessments. It extracts secrets, credentials, API endpoints, and security-relevant data from web applications without making active exploitation requests. Output is designed to inform manual penetration testing.

## Scope (Passive Only)
- ✅ Load target URL in headless Chrome
- ✅ Extract secrets from HTML, JS, DOM, cookies, localStorage
- ✅ Capture network traffic (requests made by the page)
- ✅ Discover API endpoints from JavaScript (for manual testing)
- ✅ Fingerprint technologies
- ✅ Report findings in JSON + Markdown
- ❌ NO active API testing (auth bypass, IDOR, fuzzing)
- ❌ NO active exploitation or injection testing

## Crate Publishing Checklist
- ✅ `Cargo.toml` metadata complete (repository, homepage, keywords, categories)
- ✅ AGPL-3.0-only license with ul0gic attribution
- ✅ Chrome binary auto-detection + `--chrome-bin` override
- ✅ `cargo clippy -- -D warnings` passes clean
- ✅ Removed active API testing module
- [ ] Create crates.io account + API token
- [ ] Run `cargo publish --dry-run` final validation
- [ ] Tag v0.1.0 release

## Current Structure
```
src/
├── main.rs              # entry point
├── cli.rs               # Clap definitions
├── config.rs            # runtime configuration
├── types.rs             # shared data structures
├── scanner/
│   ├── workflow.rs      # orchestrates scan
│   └── page_utils.rs    # DOM interaction helpers
├── detectors/
│   ├── secrets.rs       # regex-based secret patterns
│   ├── ast.rs           # swc-based JS analysis
│   ├── dom.rs           # forms, cookies, storage
│   └── javascript.rs    # script extraction, window objects
├── api/
│   └── discovery.rs     # passive endpoint extraction from JS
├── network/
│   └── monitor.rs       # Chrome DevTools network capture
└── reporting/
    ├── json.rs          # JSON output
    └── markdown.rs      # Markdown report
```

## Roadmap (Passive Features)
- [ ] GraphQL endpoint and schema extraction
- [ ] WebSocket URL discovery
- [ ] Enhanced header security analysis
- [ ] Custom secret pattern definitions via config file
- [ ] HTML report generation
