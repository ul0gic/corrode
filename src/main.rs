mod types;
mod api_discovery;
mod api_testing;
mod network_monitor;

use anyhow::{Result, Context};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::Page;
use clap::Parser;
use colored::Colorize;
use futures::StreamExt;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use api_discovery::extract_api_endpoints;
use base64::{Engine as _, engine::general_purpose};

#[derive(Parser, Debug)]
#[command(name = "corrode")]
#[command(about = "High-performance security scanner for exposed credentials and vulnerabilities", long_about = None)]
#[command(version, long_about = r#"
Corrode - Web Application Security Scanner

A blazing-fast Rust-based security scanner that discovers exposed credentials,
API vulnerabilities, and security misconfigurations in web applications.

Features:
  • 30+ secret pattern detection (AWS, Firebase, Supabase, JWTs, etc.)
  • API endpoint discovery and vulnerability testing
  • Network traffic monitoring and analysis
  • Technology stack fingerprinting (40+ frameworks/services)
  • Comprehensive JSON and Markdown reporting
  • Cookie security analysis
  • JavaScript comment extraction
  • Source map detection

For more information: https://github.com/ul0gic/corrode
"#)]
struct Args {
    /// Target URL or file path
    ///
    /// Can be:
    ///   - Single URL: https://example.com
    ///   - File with URLs: targets.txt (one URL per line, # for comments)
    ///   - Any .txt file or path that exists will be treated as a URL list
    #[arg(value_name = "TARGET", default_value = "targets.txt")]
    target: String,

    /// Number of concurrent browser instances
    ///
    /// Higher values = faster scans but more resource usage.
    /// Recommended: 10-20 for most systems, 50+ for powerful machines.
    #[arg(short, long, default_value = "10", value_name = "NUM")]
    concurrency: usize,

    /// Output directory for scan results
    ///
    /// Results saved as: <OUTPUT>/<domain>/scan_result.json and REPORT.md
    #[arg(short, long, default_value = "corrode-output", value_name = "DIR")]
    output: PathBuf,

    /// Timeout for page load in seconds
    ///
    /// Maximum time to wait for a page to load before moving on.
    #[arg(short, long, default_value = "30", value_name = "SECS")]
    timeout: u64,

    /// Enable verbose output
    ///
    /// Shows detailed progress, found secrets, and API test results in real-time.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanResult {
    url: String,
    timestamp: String,
    secrets: HashMap<String, Vec<SecretFinding>>,
    network: NetworkAnalysis,
    dom: DOMAnalysis,
    javascript: JavaScriptAnalysis,
    security: SecurityAnalysis,
    technologies: Vec<String>,
    vulnerabilities: Vec<Vulnerability>,
    comments: Vec<Comment>,
    api_tests: Vec<types::ApiTestResult>,
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecretFinding {
    source: String,
    matches: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetworkAnalysis {
    total_requests: usize,
    api_calls: Vec<String>,
    third_party: Vec<String>,
    websockets: Vec<String>,
    redirects: Vec<Redirect>,
    auth_schemes: Vec<AuthScheme>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Redirect {
    from: String,
    to: String,
    status: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuthScheme {
    auth_type: String,
    url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DOMAnalysis {
    scripts: usize,
    forms: Vec<FormInfo>,
    hidden_inputs: Vec<HiddenInput>,
    iframes: Vec<String>,
    meta_tags: Vec<MetaTag>,
    data_attributes: Vec<DataAttribute>,
    local_storage: HashMap<String, String>,
    session_storage: HashMap<String, String>,
    cookies: Vec<CookieInfo>,
    all_links: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FormInfo {
    action: String,
    method: String,
    input_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HiddenInput {
    name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MetaTag {
    name: String,
    content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DataAttribute {
    tag: String,
    attributes: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CookieInfo {
    name: String,
    domain: String,
    secure: bool,
    http_only: bool,
    same_site: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct JavaScriptAnalysis {
    window_objects: HashMap<String, String>,
    source_maps: Vec<String>,
    debug_mode: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SecurityAnalysis {
    missing_headers: Vec<String>,
    cors_issues: Vec<CORSIssue>,
    insecure_cookies: Vec<String>,
    mixed_content: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CORSIssue {
    url: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Vulnerability {
    vuln_type: String,
    severity: String,
    description: String,
    remediation: String,
    url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Comment {
    source: String,
    comment_type: String,
    content: String,
}

lazy_static! {
    static ref SECRET_PATTERNS: HashMap<&'static str, Regex> = {
        let mut m = HashMap::new();
        m.insert("supabase_url", Regex::new(r"https://[a-z0-9]+\.supabase\.co").unwrap());
        m.insert("supabase_anon_key", Regex::new(r"sb[a-z]{38}").unwrap());
        m.insert("jwt", Regex::new(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap());
        m.insert("firebase", Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap());
        m.insert("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap());
        m.insert("aws_secret", Regex::new(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}").unwrap());
        m.insert("stripe", Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap());
        m.insert("stripe_restricted", Regex::new(r"rk_live_[0-9a-zA-Z]{24,}").unwrap());
        m.insert("slack", Regex::new(r"xox[baprs]-[0-9a-zA-Z]{10,48}").unwrap());
        m.insert("slack_webhook", Regex::new(r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+").unwrap());
        m.insert("github", Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap());
        m.insert("github_fine", Regex::new(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}").unwrap());
        m.insert("gitlab", Regex::new(r"glpat-[0-9a-zA-Z\-_]{20}").unwrap());
        m.insert("discord", Regex::new(r"discord(?:app)?\.com/api/webhooks/[\d]+/[\w-]+").unwrap());
        m.insert("discord_token", Regex::new(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}").unwrap());
        m.insert("heroku", Regex::new(r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap());
        m.insert("mailgun", Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap());
        m.insert("mailchimp", Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap());
        m.insert("sendgrid", Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap());
        m.insert("twilio", Regex::new(r"SK[0-9a-fA-F]{32}").unwrap());
        m.insert("twilio_account", Regex::new(r"AC[a-zA-Z0-9_\-]{32}").unwrap());
        m.insert("private_key", Regex::new(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap());
        m.insert("google_oauth", Regex::new(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com").unwrap());
        m.insert("postgres_url", Regex::new(r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+").unwrap());
        m.insert("mongodb_url", Regex::new(r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+").unwrap());
        m.insert("mysql_url", Regex::new(r"mysql://[^:]+:[^@]+@[^/]+/\w+").unwrap());
        m.insert("redis_url", Regex::new(r"redis://(?:[^:]*:)?[^@]+@[^/]+").unwrap());
        m.insert("bearer_token", Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*").unwrap());
        m.insert("basic_auth", Regex::new(r"(?i)basic\s+[a-zA-Z0-9+/]+=*").unwrap());
        m.insert("aws_arn", Regex::new(r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/]+").unwrap());
        m.insert("jwt_in_url", Regex::new(r"[?&](?:token|jwt|access_token|id_token)=eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap());
        m.insert("ip_address", Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap());
        m
    };

    static ref COMMENT_SINGLE: Regex = Regex::new(r"//(.+)").unwrap();
    static ref COMMENT_MULTI: Regex = Regex::new(r"/\*([\s\S]*?)\*/").unwrap();
}

fn is_service_role_jwt(jwt: &str) -> bool {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Decode payload (second part)
    if let Ok(decoded) = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
        if let Ok(payload) = String::from_utf8(decoded) {
            return payload.contains(r#""role":"service_role""#) ||
                   payload.contains(r#""role": "service_role""#);
        }
    }
    false
}

struct SecretScanner {
    findings: Arc<Mutex<HashMap<String, Vec<SecretFinding>>>>,
    comments: Arc<Mutex<Vec<Comment>>>,
}

impl SecretScanner {
    fn new() -> Self {
        Self {
            findings: Arc::new(Mutex::new(HashMap::new())),
            comments: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn scan_text(&self, text: &str, source: &str) {
        if text.is_empty() {
            return;
        }

        let mut findings = self.findings.lock().await;

        for (pattern_name, regex) in SECRET_PATTERNS.iter() {
            let matches: HashSet<String> = regex
                .find_iter(text)
                .map(|m| m.as_str().to_string())
                .collect();

            if !matches.is_empty() {
                let mut matches_vec: Vec<String> = matches.into_iter().take(10).collect();

                // Special handling for JWTs - check if they're service_role keys
                if *pattern_name == "jwt" {
                    let service_role_jwts: Vec<String> = matches_vec
                        .iter()
                        .filter(|jwt| is_service_role_jwt(jwt))
                        .cloned()
                        .collect();

                    if !service_role_jwts.is_empty() {
                        findings
                            .entry("supabase_service_role".to_string())
                            .or_insert_with(Vec::new)
                            .push(SecretFinding {
                                source: source.to_string(),
                                matches: service_role_jwts,
                            });
                    }
                }

                findings
                    .entry(pattern_name.to_string())
                    .or_insert_with(Vec::new)
                    .push(SecretFinding {
                        source: source.to_string(),
                        matches: matches_vec,
                    });
            }
        }
    }

    async fn extract_comments(&self, code: &str, source: &str) {
        if code.is_empty() || code.len() < 10 {
            return;
        }

        let mut comments = self.comments.lock().await;

        for cap in COMMENT_SINGLE.captures_iter(code) {
            if let Some(comment) = cap.get(1) {
                let content = comment.as_str().trim();
                if content.len() > 5 {
                    comments.push(Comment {
                        source: source.to_string(),
                        comment_type: "single".to_string(),
                        content: content.chars().take(200).collect(),
                    });
                }
            }
        }

        for cap in COMMENT_MULTI.captures_iter(code) {
            if let Some(comment) = cap.get(1) {
                let content = comment.as_str().trim();
                if content.len() > 5 {
                    comments.push(Comment {
                        source: source.to_string(),
                        comment_type: "multi".to_string(),
                        content: content.chars().take(500).collect(),
                    });
                }
            }
        }
    }

    async fn get_findings(&self) -> HashMap<String, Vec<SecretFinding>> {
        self.findings.lock().await.clone()
    }

    async fn get_comments(&self) -> Vec<Comment> {
        self.comments.lock().await.clone()
    }
}

async fn scan_url(url: String, browser: Arc<Browser>, verbose: bool, output_dir: &PathBuf) -> Result<ScanResult> {
    let start = Instant::now();

    if verbose {
        println!("{} {}", "[*]".cyan(), format!("Scanning {}", url).dimmed());
    }

    let scanner = SecretScanner::new();
    let network_monitor = network_monitor::NetworkMonitor::new();

    // Create page and navigate with timeout
    let page_result = tokio::time::timeout(
        Duration::from_secs(60),
        browser.new_page(&url)
    ).await;

    let page = match page_result {
        Err(_) => return Err(anyhow::anyhow!("Page creation/navigation timeout after 60s")),
        Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to create page: {}", e)),
        Ok(Ok(p)) => p,
    };

    // Enable network monitoring
    if let Err(e) = network_monitor.enable(&page).await {
        if verbose {
            println!("{} Failed to enable network monitoring: {}", "[!]".yellow(), e);
        }
    } else {
        network_monitor.start_monitoring(&page).await;
    }

    // Inject stealth mode to avoid bot detection (disabled due to library issues)
    // if let Err(e) = chromiumoxide_stealth::inject(&page).await {
    //     if verbose {
    //         println!("{} Failed to inject stealth mode: {}", "[!]".yellow(), e);
    //     }
    // }

    // Wait for page to stabilize
    tokio::time::sleep(Duration::from_secs(3)).await;

    let html = page.content().await.context("Failed to get page content")?;
    scanner.scan_text(&html, "HTML").await;

    trigger_dynamic_content(&page).await;

    let scripts = match page
        .evaluate("Array.from(document.scripts).map(s => ({ src: s.src, inline: !s.src, content: s.src ? null : s.textContent.substring(0, 5000) }))")
        .await {
            Ok(result) => result.into_value().unwrap_or_else(|_| serde_json::json!([])),
            Err(_) => serde_json::json!([]),
        };

    let scripts_array: Vec<serde_json::Value> = serde_json::from_value(scripts).unwrap_or_default();
    let mut source_maps = Vec::new();

    for script in &scripts_array {
        if let Some(content) = script.get("content").and_then(|v| v.as_str()) {
            scanner.scan_text(content, "Inline Script").await;
            scanner.extract_comments(content, "Inline Script").await;
        }

        if let Some(src) = script.get("src").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                if src.ends_with(".map") || src.contains(".js.map") {
                    source_maps.push(src.to_string());
                }

                if let Ok(resp) = tokio::time::timeout(Duration::from_secs(10), reqwest::get(src)).await {
                    if let Ok(resp) = resp {
                        if let Ok(text) = resp.text().await {
                            scanner.scan_text(&text, &format!("Script: {}", src)).await;
                            scanner.extract_comments(&text, &format!("Script: {}", src)).await;
                        }
                    }
                }
            }
        }
    }

    let forms = extract_safe::<Vec<FormInfo>>(&page, 
        "Array.from(document.forms).map(f => ({ action: f.action, method: f.method, input_count: f.elements.length }))"
    ).await;

    let hidden_inputs = extract_safe::<Vec<HiddenInput>>(&page,
        "Array.from(document.querySelectorAll('input[type=\"hidden\"]')).map(i => ({ name: i.name, value: i.value }))"
    ).await;

    for input in &hidden_inputs {
        scanner.scan_text(&input.value, &format!("Hidden Input: {}", input.name)).await;
    }

    let meta_tags = extract_safe::<Vec<MetaTag>>(&page,
        "Array.from(document.querySelectorAll('meta')).map(m => ({ name: m.name || m.getAttribute('property') || '', content: m.content }))"
    ).await;

    let data_attributes = extract_safe::<Vec<DataAttribute>>(&page, r#"
        Array.from(document.querySelectorAll('[data-api], [data-url], [data-endpoint], [data-key], [data-token], [data-config]')).map(el => {
            const attrs = {};
            for (const attr of el.attributes) {
                if (attr.name.startsWith('data-')) {
                    attrs[attr.name] = attr.value;
                }
            }
            return { tag: el.tagName.toLowerCase(), attributes: attrs };
        })
    "#).await;

    for attr in &data_attributes {
        let attr_json = serde_json::to_string(&attr.attributes).unwrap_or_default();
        scanner.scan_text(&attr_json, &format!("Data Attributes: {}", attr.tag)).await;
    }

    let iframes = extract_safe::<Vec<String>>(&page,
        "Array.from(document.querySelectorAll('iframe')).map(i => i.src)"
    ).await;

    let all_links = extract_safe::<usize>(&page,
        "new Set([...Array.from(document.querySelectorAll('[href]')).map(e => e.getAttribute('href')), ...Array.from(document.querySelectorAll('[src]')).map(e => e.getAttribute('src'))]).size"
    ).await;

    let local_storage = extract_safe::<HashMap<String, String>>(&page, "JSON.stringify({...localStorage})").await;
    scanner.scan_text(&serde_json::to_string(&local_storage)?, "localStorage").await;

    let session_storage = extract_safe::<HashMap<String, String>>(&page, "JSON.stringify({...sessionStorage})").await;
    scanner.scan_text(&serde_json::to_string(&session_storage)?, "sessionStorage").await;

    let cookies = page.get_cookies().await.unwrap_or_default();
    let cookie_info: Vec<CookieInfo> = cookies
        .iter()
        .map(|c| CookieInfo {
            name: c.name.clone(),
            domain: c.domain.clone(),
            secure: c.secure,
            http_only: c.http_only,
            same_site: format!("{:?}", c.same_site),
        })
        .collect();

    let technologies = detect_technologies(&page).await;

    let window_objects = extract_safe::<HashMap<String, String>>(&page, r#"
        (() => {
            const windowProps = {};
            const sensitiveKeys = ['__NEXT_DATA__', '__NUXT__', '__INITIAL_STATE__', '__APOLLO_STATE__', '__CONFIG__', '__ENV__', 'ENV', 'config', 'CONFIG'];
            for (const key of Object.keys(window)) {
                if (sensitiveKeys.some(k => key.toUpperCase().includes(k.toUpperCase()))) {
                    try {
                        windowProps[key] = JSON.stringify(window[key]).substring(0, 500);
                    } catch (e) {
                        windowProps[key] = '[Unable to serialize]';
                    }
                }
            }
            return windowProps;
        })()
    "#).await;
    scanner.scan_text(&serde_json::to_string(&window_objects)?, "Window Object").await;

    let debug_mode = extract_safe::<Vec<String>>(&page, r#"
        (() => {
            const modes = [];
            if (window.DEBUG) modes.push('window.DEBUG = true');
            if (window.__DEV__) modes.push('window.__DEV__ = true');
            if (window.development) modes.push('window.development = true');
            if (localStorage.getItem('debug')) modes.push('localStorage.debug set');
            return modes;
        })()
    "#).await;

    let (vulnerabilities, security) = analyze_security(&url, &cookie_info, &debug_mode);

    // Extract API endpoints from JavaScript
    let mut discovered_endpoints = Vec::new();
    for script in &scripts_array {
        if let Some(content) = script.get("content").and_then(|v| v.as_str()) {
            let endpoints = extract_api_endpoints(content, "Inline Script");
            discovered_endpoints.extend(endpoints);
        }
    }

    // Also check the HTML for API endpoints
    let html_endpoints = extract_api_endpoints(&html, "HTML");
    discovered_endpoints.extend(html_endpoints);

    // Test discovered API endpoints for vulnerabilities
    let mut api_tests = Vec::new();
    if verbose && !discovered_endpoints.is_empty() {
        println!("{} Found {} API endpoints, testing...", "[*]".cyan(), discovered_endpoints.len());
    }

    let tester = api_testing::ApiTester::new();
    for endpoint in &discovered_endpoints {
        // Test for auth bypass
        if let Some(result) = tester.test_auth_bypass(endpoint, &url).await {
            if verbose {
                println!("{} {} - {}", "[!]".red().bold(), result.test_type, result.endpoint);
            }
            api_tests.push(result);
        }

        // Test for IDOR
        let idor_results = tester.test_idor(endpoint, &url).await;
        for result in idor_results {
            if verbose {
                println!("{} {} - {}", "[!]".red().bold(), result.test_type, result.endpoint);
            }
            api_tests.push(result);
        }
    }

    let elapsed = start.elapsed();
    let secrets = scanner.get_findings().await;
    let comments = scanner.get_comments().await;
    let secret_count: usize = secrets.values().map(|v| v.len()).sum();

    // Collect network data
    let all_calls = network_monitor.get_all_calls().await;
    let api_calls_list = network_monitor.get_api_calls().await;

    let api_call_urls: Vec<String> = api_calls_list.iter().map(|c| c.url.clone()).collect();
    let third_party: Vec<String> = all_calls.iter()
        .filter(|c| !c.url.contains(&url))
        .map(|c| c.url.clone())
        .collect();

    if verbose {
        println!(
            "{} {} ({} secrets, {} comments, {} network requests in {:.2}s)",
            "[✓]".green(),
            url,
            secret_count,
            comments.len(),
            all_calls.len(),
            elapsed.as_secs_f64()
        );
    }

    let result = ScanResult {
        url: url.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        secrets,
        network: NetworkAnalysis {
            total_requests: all_calls.len(),
            api_calls: api_call_urls,
            third_party,
            websockets: vec![],
            redirects: vec![],
            auth_schemes: vec![],
        },
        dom: DOMAnalysis {
            scripts: scripts_array.len(),
            forms,
            hidden_inputs,
            iframes,
            meta_tags,
            data_attributes,
            local_storage,
            session_storage,
            cookies: cookie_info,
            all_links,
        },
        javascript: JavaScriptAnalysis {
            window_objects,
            source_maps,
            debug_mode,
        },
        security,
        technologies,
        vulnerabilities,
        comments,
        api_tests,
        success: true,
        error: None,
    };

    generate_markdown_report(&result, output_dir)?;

    Ok(result)
}

async fn extract_safe<T: for<'de> Deserialize<'de> + Default>(page: &Page, script: &str) -> T {
    page.evaluate(script)
        .await
        .ok()
        .and_then(|v| v.into_value().ok())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

async fn trigger_dynamic_content(page: &Page) {
    let _ = page
        .evaluate(r#"
            (async () => {
                const scrollStep = 500;
                const scrollDelay = 300;
                for (let i = 0; i < 5; i++) {
                    window.scrollBy(0, scrollStep);
                    await new Promise(resolve => setTimeout(resolve, scrollDelay));
                }
                window.scrollTo(0, 0);
                await new Promise(resolve => setTimeout(resolve, 300));
            })()
        "#)
        .await;

    tokio::time::sleep(Duration::from_secs(2)).await;
}

async fn detect_technologies(page: &Page) -> Vec<String> {
    extract_safe::<Vec<String>>(page, r#"
        (() => {
            const detected = [];
            if (window.React || document.querySelector('[data-reactroot]')) detected.push('React');
            if (window.Vue || document.querySelector('[data-v-]')) detected.push('Vue.js');
            if (window.angular || document.querySelector('[ng-app]')) detected.push('Angular');
            if (window.Svelte) detected.push('Svelte');
            if (window.Solid) detected.push('Solid.js');
            if (window.__NEXT_DATA__) detected.push('Next.js');
            if (window.__NUXT__) detected.push('Nuxt.js');
            if (window.__remixContext) detected.push('Remix');
            if (window.Gatsby) detected.push('Gatsby');
            if (window.supabase || document.documentElement.innerHTML.includes('supabase')) detected.push('Supabase');
            if (window.firebase) detected.push('Firebase');
            if (window.Appwrite) detected.push('Appwrite');
            if (window.Auth0Lock || document.documentElement.innerHTML.includes('auth0')) detected.push('Auth0');
            if (window.Clerk) detected.push('Clerk');
            if (window.Okta) detected.push('Okta');
            if (document.documentElement.innerHTML.includes('cognito')) detected.push('AWS Cognito');
            if (window.Stripe) detected.push('Stripe');
            if (window.paypal) detected.push('PayPal');
            if (window.Square) detected.push('Square');
            if (window.braintree) detected.push('Braintree');
            if (window.gtag || window.ga) detected.push('Google Analytics');
            if (window.mixpanel) detected.push('Mixpanel');
            if (window.analytics && window.analytics.page) detected.push('Segment');
            if (window.Intercom) detected.push('Intercom');
            if (window.amplitude) detected.push('Amplitude');
            if (window._hsq) detected.push('HubSpot');
            if (document.querySelector('meta[name="generator"][content*="WordPress"]')) detected.push('WordPress');
            if (window.Drupal) detected.push('Drupal');
            if (window.Webflow) detected.push('Webflow');
            if (document.documentElement.innerHTML.includes('contentful')) detected.push('Contentful');
            if (document.documentElement.innerHTML.includes('sanity')) detected.push('Sanity');
            if (window.jQuery || window.$) detected.push('jQuery');
            if (document.querySelector('[class*="bootstrap"]')) detected.push('Bootstrap');
            if (document.querySelector('[class*="tailwind"]')) detected.push('Tailwind CSS');
            if (window.MaterialUI) detected.push('Material-UI');
            if (window.__REDUX_DEVTOOLS_EXTENSION__) detected.push('Redux');
            if (window.MobX) detected.push('MobX');
            if (window.Zustand) detected.push('Zustand');
            if (window.__APOLLO_CLIENT__) detected.push('Apollo Client');
            if (window.relay) detected.push('Relay');
            return detected;
        })()
    "#).await
}

fn analyze_security(
    url: &str,
    cookies: &[CookieInfo],
    debug_mode: &[String],
) -> (Vec<Vulnerability>, SecurityAnalysis) {
    let mut vulnerabilities = Vec::new();
    let mut insecure_cookies = Vec::new();

    for cookie in cookies {
        let mut issues = Vec::new();

        if !cookie.secure && url.starts_with("https") {
            issues.push("Missing Secure flag");
        }
        if !cookie.http_only {
            issues.push("Missing HttpOnly flag");
        }
        if cookie.same_site.contains("None") || cookie.same_site == "None" {
            issues.push("Weak SameSite policy");
        }

        if !issues.is_empty() {
            insecure_cookies.push(cookie.name.clone());
            vulnerabilities.push(Vulnerability {
                vuln_type: "Insecure Cookie".to_string(),
                severity: "medium".to_string(),
                description: format!("Cookie '{}' has security issues: {}", cookie.name, issues.join(", ")),
                remediation: "Set Secure, HttpOnly, and SameSite=Strict flags".to_string(),
                url: None,
            });
        }
    }

    if !debug_mode.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "Debug Mode Enabled".to_string(),
            severity: "medium".to_string(),
            description: format!("Debug mode detected: {}", debug_mode.join(", ")),
            remediation: "Disable debug mode in production".to_string(),
            url: None,
        });
    }

    let security = SecurityAnalysis {
        missing_headers: vec![],
        cors_issues: vec![],
        insecure_cookies,
        mixed_content: vec![],
    };

    (vulnerabilities, security)
}

fn generate_markdown_report(result: &ScanResult, base_output_dir: &PathBuf) -> Result<()> {
    let mut report = Vec::new();

    report.push(format!("# 🦀 Corrode Security Scan Report\n"));
    report.push(format!("**Target**: {}", result.url));
    report.push(format!("**Scan Date**: {}", result.timestamp));
    report.push(format!("**Scanner**: Corrode v0.1.0\n"));

    report.push(format!("---\n## Executive Summary\n"));

    let critical_vulns = result.vulnerabilities.iter().filter(|v| v.severity == "critical").count();
    let high_vulns = result.vulnerabilities.iter().filter(|v| v.severity == "high").count();
    let medium_vulns = result.vulnerabilities.iter().filter(|v| v.severity == "medium").count();
    let low_vulns = result.vulnerabilities.iter().filter(|v| v.severity == "low").count();
    let secret_count = result.secrets.len();

    let risk_level = if critical_vulns > 0 {
        "🔴 CRITICAL"
    } else if high_vulns > 0 {
        "🟠 HIGH"
    } else if medium_vulns > 0 {
        "🟡 MEDIUM"
    } else {
        "🟢 LOW"
    };

    report.push(format!("**Risk Level**: {}\n", risk_level));
    report.push(format!("- Critical Vulnerabilities: {}", critical_vulns));
    report.push(format!("- High Vulnerabilities: {}", high_vulns));
    report.push(format!("- Medium Vulnerabilities: {}", medium_vulns));
    report.push(format!("- Low Vulnerabilities: {}", low_vulns));
    report.push(format!("- Secret Types Found: {}", secret_count));
    report.push(format!("- Technologies Detected: {}\n", result.technologies.len()));

    if !result.secrets.is_empty() {
        report.push(format!("---\n## 🔑 Secrets & Credentials Found\n"));
        report.push(format!("⚠️ **CRITICAL**: The following secrets were exposed in the application:\n"));

        for (secret_type, findings) in &result.secrets {
            let total_matches: usize = findings.iter().map(|f| f.matches.len()).sum();
            report.push(format!("### {} ({} matches)", secret_type, total_matches));

            for finding in findings {
                report.push(format!("**Source**: {}", finding.source));
                report.push(format!("**Matches**: {}", finding.matches.len()));
                for m in finding.matches.iter().take(3) {
                    let display = if m.len() > 60 {
                        format!("{}...", &m[..60])
                    } else {
                        m.clone()
                    };
                    report.push(format!("- `{}`", display));
                }
                report.push("".to_string());
            }
        }
    }

    if !result.vulnerabilities.is_empty() {
        report.push(format!("---\n## 🚨 Vulnerabilities\n"));

        for severity in &["critical", "high", "medium", "low"] {
            let vulns: Vec<&Vulnerability> = result.vulnerabilities.iter()
                .filter(|v| v.severity == *severity)
                .collect();

            if !vulns.is_empty() {
                let icon = match *severity {
                    "critical" => "🔴",
                    "high" => "🟠",
                    "medium" => "🟡",
                    _ => "🟢",
                };
                report.push(format!("### {} {} ({})\n", icon, severity.to_uppercase(), vulns.len()));

                for (i, vuln) in vulns.iter().enumerate() {
                    report.push(format!("#### {}. {}", i + 1, vuln.vuln_type));
                    report.push(format!("**Description**: {}", vuln.description));
                    if let Some(url) = &vuln.url {
                        report.push(format!("**URL**: `{}`", url));
                    }
                    report.push(format!("**Remediation**: {}\n", vuln.remediation));
                }
            }
        }
    }

    if !result.api_tests.is_empty() {
        report.push(format!("---\n## 🎯 API Security Tests\n"));

        let critical_api = result.api_tests.iter().filter(|t| t.severity == "CRITICAL" && t.vulnerable).count();
        let high_api = result.api_tests.iter().filter(|t| t.severity == "HIGH" && t.vulnerable).count();
        let medium_api = result.api_tests.iter().filter(|t| t.severity == "MEDIUM" && t.vulnerable).count();

        report.push(format!("**Found {} vulnerable API endpoints**\n", result.api_tests.len()));

        if critical_api > 0 {
            report.push(format!("### 🔴 CRITICAL Issues ({})\n", critical_api));
            for test in result.api_tests.iter().filter(|t| t.severity == "CRITICAL" && t.vulnerable) {
                report.push(format!("#### {}", test.test_type));
                report.push(format!("**Endpoint**: `{}`", test.endpoint));
                report.push(format!("**Evidence**: {}", test.evidence));
                report.push(format!("**Details**: {}\n", test.details));
            }
        }

        if high_api > 0 {
            report.push(format!("### 🟠 HIGH Issues ({})\n", high_api));
            for test in result.api_tests.iter().filter(|t| t.severity == "HIGH" && t.vulnerable) {
                report.push(format!("#### {}", test.test_type));
                report.push(format!("**Endpoint**: `{}`", test.endpoint));
                report.push(format!("**Evidence**: {}", test.evidence));
                report.push(format!("**Details**: {}\n", test.details));
            }
        }

        if medium_api > 0 {
            report.push(format!("### 🟡 MEDIUM Issues ({})\n", medium_api));
            for test in result.api_tests.iter().filter(|t| t.severity == "MEDIUM" && t.vulnerable) {
                report.push(format!("#### {}", test.test_type));
                report.push(format!("**Endpoint**: `{}`", test.endpoint));
                report.push(format!("**Evidence**: {}", test.evidence));
                report.push(format!("**Details**: {}\n", test.details));
            }
        }
    }

    if !result.comments.is_empty() {
        report.push(format!("---\n## 💬 JavaScript Comments Found\n"));
        report.push(format!("Found {} comments that may contain sensitive information:\n", result.comments.len()));

        for comment in result.comments.iter().take(20) {
            report.push(format!("**Source**: {} ({})", comment.source, comment.comment_type));
            report.push(format!("```\n{}\n```\n", comment.content));
        }

        if result.comments.len() > 20 {
            report.push(format!("... and {} more comments\n", result.comments.len() - 20));
        }
    }

    if !result.javascript.source_maps.is_empty() || !result.javascript.window_objects.is_empty() {
        report.push(format!("---\n## 🔍 JavaScript Analysis\n"));

        if !result.javascript.source_maps.is_empty() {
            report.push(format!("### Source Maps ({})", result.javascript.source_maps.len()));
            report.push(format!("⚠️ Source maps exposed - attackers can reverse engineer minified code\n"));
            for url in result.javascript.source_maps.iter().take(10) {
                report.push(format!("- `{}`", url));
            }
            report.push("".to_string());
        }

        if !result.javascript.window_objects.is_empty() {
            report.push(format!("### Exposed Window Objects ({})", result.javascript.window_objects.len()));
            for (key, value) in &result.javascript.window_objects {
                let display = if value.len() > 100 {
                    format!("{}...", &value[..100])
                } else {
                    value.clone()
                };
                report.push(format!("- **{}**: `{}`", key, display));
            }
            report.push("".to_string());
        }
    }

    report.push(format!("---\n## 🌐 DOM Analysis\n"));
    report.push(format!("- Scripts: {}", result.dom.scripts));
    report.push(format!("- Forms: {}", result.dom.forms.len()));
    report.push(format!("- Hidden Inputs: {}", result.dom.hidden_inputs.len()));
    report.push(format!("- iFrames: {}", result.dom.iframes.len()));
    report.push(format!("- Unique Links: {}", result.dom.all_links));
    report.push(format!("- localStorage Items: {}", result.dom.local_storage.len()));
    report.push(format!("- sessionStorage Items: {}", result.dom.session_storage.len()));
    report.push(format!("- Cookies: {}\n", result.dom.cookies.len()));

    if !result.technologies.is_empty() {
        report.push(format!("---\n## 🛠️ Technology Stack\n"));
        for tech in &result.technologies {
            report.push(format!("- {}", tech));
        }
        report.push("".to_string());
    }

    report.push(format!("---\n## 💡 Recommendations\n"));
    report.push(format!("1. **Immediately rotate** any exposed secrets and credentials"));
    report.push(format!("2. Remove or restrict access to source maps in production"));
    report.push(format!("3. Implement proper security headers (CSP, HSTS, etc.)"));
    report.push(format!("4. Review and fix all HIGH and CRITICAL vulnerabilities"));
    report.push(format!("5. Disable debug mode in production"));
    report.push(format!("6. Use HttpOnly, Secure, and SameSite flags on cookies\n"));

    let domain = url::Url::parse(&result.url)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
        .replace('.', "-");

    // Create site-specific folder
    let site_dir = base_output_dir.join(&domain);
    fs::create_dir_all(&site_dir)?;

    let report_path = site_dir.join("REPORT.md");
    fs::write(report_path, report.join("\n"))?;

    Ok(())
}

async fn scan_urls(urls: Vec<String>, args: Args) -> Result<()> {
    println!(
        "{} Corroding through {} targets...\n",
        "[*]".cyan().bold(),
        urls.len()
    );

    let (browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .disable_cache()
            .chrome_executable("/usr/bin/google-chrome")
            .args(vec![
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--headless",
                "--disable-software-rasterizer",
                "--disable-extensions",
                "--disable-background-networking",
                "--no-first-run",
                "--disable-sync"
            ])
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build browser config: {}", e))?,
    )
    .await?;

    let browser = Arc::new(browser);

    // Spawn handler task - keep it running
    tokio::spawn(async move {
        loop {
            match handler.next().await {
                Some(Ok(_)) => continue,
                Some(Err(_)) => continue,  // Don't break on errors
                None => break,
            }
        }
    });

    // Give browser time to initialize
    tokio::time::sleep(Duration::from_millis(500)).await;

    fs::create_dir_all(&args.output)?;

    let output_dir = args.output.clone();
    let mut results = Vec::new();
    let mut total_secrets = 0;
    let mut total_vulns = 0;
    let mut total_comments = 0;

    // Scan URLs sequentially with single browser
    for url in urls {
        match scan_url(url, browser.clone(), args.verbose, &output_dir).await {
            Ok(result) => {
                let secrets_count: usize = result.secrets.values().map(|v| v.len()).sum();
                let vulns_count = result.vulnerabilities.len();
                let comments_count = result.comments.len();
                total_secrets += secrets_count;
                total_vulns += vulns_count;
                total_comments += comments_count;

                let domain = url::Url::parse(&result.url)
                    .ok()
                    .and_then(|u| u.host_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown".to_string())
                    .replace('.', "-");

                // Create a folder for each site
                let site_dir = args.output.join(&domain);
                fs::create_dir_all(&site_dir)?;

                let output_file = site_dir.join("scan_result.json");
                fs::write(&output_file, serde_json::to_string_pretty(&result)?)?;

                if secrets_count > 0 || vulns_count > 0 {
                    println!(
                        "{} {} - {} secrets, {} vulns, {} comments",
                        "[!]".red().bold(),
                        result.url.yellow(),
                        secrets_count.to_string().red().bold(),
                        vulns_count.to_string().yellow().bold(),
                        comments_count
                    );

                    for (pattern_type, findings) in &result.secrets {
                        let total_matches: usize = findings.iter().map(|f| f.matches.len()).sum();
                        println!("    {} {}: {} matches",
                            "→".dimmed(),
                            pattern_type.cyan(),
                            total_matches
                        );
                    }

                    if !result.technologies.is_empty() {
                        println!("    {} Technologies: {}",
                            "🛠".dimmed(),
                            result.technologies.join(", ").dimmed()
                        );
                    }
                }

                results.push(result);
            },
            Err(e) => {
                eprintln!("{} Scan failed: {}", "[!]".red(), e);
            }
        }
    }

    println!("\n{}", "=".repeat(60).dimmed());
    println!(
        "{} Scan complete: {}/{} targets successful",
        "[✓]".green().bold(),
        results.iter().filter(|r| r.success).count(),
        results.len()
    );
    println!(
        "{} Total secrets found: {}",
        "[!]".red().bold(),
        total_secrets.to_string().red().bold()
    );
    println!(
        "{} Total vulnerabilities: {}",
        "[!]".yellow().bold(),
        total_vulns.to_string().yellow().bold()
    );
    println!(
        "{} Total comments extracted: {}",
        "[*]".cyan(),
        total_comments
    );
    println!("{} Results saved to: {}", "[*]".cyan(), args.output.display());
    println!("{}", "=".repeat(60).dimmed());

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let urls = if args.target.ends_with(".txt") || std::path::Path::new(&args.target).exists() {
        let content = fs::read_to_string(&args.target)?;
        content
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_string())
            .collect()
    } else {
        vec![args.target.clone()]
    };

    scan_urls(urls, args).await
}
