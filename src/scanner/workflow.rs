use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use futures::StreamExt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;

use crate::config::{Config, OutputFormat};
use crate::detectors::vulnerabilities::rsc;
use crate::detectors::{
    collectors::{
        dom::{self, DomArtifacts},
        javascript::{self, ScriptArtifacts},
    },
    manifests, scoring,
    secrets::SecretScanner,
    security::analyze_security,
    sourcemaps, taint, technologies, vulnerabilities,
};
use crate::network::monitor::NetworkMonitor;
use crate::reporting::{json as json_report, markdown};
use crate::scanner::chrome::resolve_chrome_binary;
use crate::scanner::page_utils;
use crate::types::{DomAnalysis, JavaScriptAnalysis, NetworkAnalysis, ScanResult};
use chromiumoxide::browser::{Browser, BrowserConfig};

/// Tracks per-URL scan outcomes for the batch summary.
struct ScanOutcome {
    url: String,
    secrets: usize,
    vulns: usize,
    status: ScanStatus,
}

enum ScanStatus {
    Success,
    Failed(String),
}

#[allow(clippy::too_many_lines)]
pub async fn run(config: Config) -> Result<()> {
    // Build the list of URLs to scan
    let urls = resolve_urls(&config)?;
    let total = urls.len();
    let is_batch = total > 1;

    let chrome_binary = resolve_chrome_binary(config.chrome_bin.clone())?;

    println!(
        "{} Using Chrome binary: {}",
        "[*]".cyan(),
        chrome_binary.display()
    );

    if is_batch {
        println!(
            "{} Batch scan: {} targets loaded\n",
            "[*]".cyan().bold(),
            total
        );
    }

    // Build Chrome args: built-in defaults + config file args
    let mut chrome_args: Vec<&str> = vec![
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--headless",
        "--disable-software-rasterizer",
        "--disable-extensions",
        "--disable-background-networking",
        "--no-first-run",
        "--disable-sync",
    ];

    // Collect owned strings from config to extend lifetime
    let extra_args = config.chrome_args.clone();
    for arg in &extra_args {
        chrome_args.push(arg.as_str());
    }

    let (browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .disable_cache()
            .chrome_executable(chrome_binary)
            .args(chrome_args)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build browser config: {e}"))?,
    )
    .await?;

    let browser = Arc::new(browser);

    tokio::spawn(async move { while let Some(_event) = handler.next().await {} });

    time::sleep(Duration::from_millis(500)).await;

    let timeout = config.timeout.max(1);
    let output_format = config.format;
    let verbose = config.verbose;

    let output_root = Arc::new(config.output.clone());
    fs::create_dir_all(output_root.as_ref())?;

    let mut results = Vec::new();
    let mut outcomes: Vec<ScanOutcome> = Vec::new();
    let mut total_secrets: usize = 0;
    let mut total_vulns: usize = 0;
    let mut total_comments: usize = 0;
    let mut any_failed = false;

    for (idx, url) in urls.iter().enumerate() {
        if is_batch {
            println!(
                "{} [{}/{}] Scanning {}...",
                "[*]".cyan().bold(),
                idx + 1,
                total,
                url
            );
        } else {
            println!("{} Corroding target {}...\n", "[*]".cyan().bold(), url);
        }

        match scan_url(
            url.clone(),
            Arc::clone(&browser),
            verbose,
            output_root.as_ref().as_path(),
            timeout,
            output_format,
            &config,
        )
        .await
        {
            Ok(result) => {
                let secrets_count: usize = result.secrets.values().map(std::vec::Vec::len).sum();
                let vulns_count = result.vulnerabilities.len();
                let comments_count = result.comments.len();
                total_secrets += secrets_count;
                total_vulns += vulns_count;
                total_comments += comments_count;

                let domain = url::Url::parse(&result.url)
                    .ok()
                    .and_then(|u| u.host_str().map(std::borrow::ToOwned::to_owned))
                    .unwrap_or_else(|| "unknown".to_owned())
                    .replace('.', "-");

                let site_dir = output_root.as_ref().join(&domain);
                fs::create_dir_all(&site_dir)?;

                if matches!(output_format, OutputFormat::Json | OutputFormat::Both) {
                    let output_file = site_dir.join("scan_result.json");
                    json_report::write(&output_file, &result)?;
                }

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
                        println!(
                            "    {} {}: {} matches",
                            "->".dimmed(),
                            pattern_type.cyan(),
                            total_matches
                        );
                    }

                    if !result.technologies.is_empty() {
                        println!(
                            "    {} Technologies: {}",
                            "**".dimmed(),
                            result.technologies.join(", ").dimmed()
                        );
                    }
                }

                outcomes.push(ScanOutcome {
                    url: url.clone(),
                    secrets: secrets_count,
                    vulns: vulns_count,
                    status: ScanStatus::Success,
                });

                results.push(result);
            }
            Err(e) => {
                eprintln!("{} Scan failed ({}): {}", "[!]".red(), url, e);
                any_failed = true;
                outcomes.push(ScanOutcome {
                    url: url.clone(),
                    secrets: 0,
                    vulns: 0,
                    status: ScanStatus::Failed(format!("{e}")),
                });
            }
        }
    }

    // Print summary
    println!("\n{}", "=".repeat(60).dimmed());

    if is_batch {
        println!(
            "{} Batch scan complete: {}/{} targets succeeded",
            "[*]".green().bold(),
            results.len(),
            total
        );
        println!();

        // Per-target summary table
        let header_status = "Status";
        println!(
            "  {:<50} {:<10} {:<10} {}",
            "URL", "Secrets", "Vulns", header_status
        );
        println!("  {}", "-".repeat(80));
        for outcome in &outcomes {
            let status_str = match &outcome.status {
                ScanStatus::Success => "OK".green().to_string(),
                ScanStatus::Failed(msg) => {
                    let truncated: String = msg.chars().take(30).collect();
                    format!("FAIL: {truncated}").red().to_string()
                }
            };
            let url_display: String = outcome.url.chars().take(48).collect();
            println!(
                "  {:<50} {:<10} {:<10} {}",
                url_display, outcome.secrets, outcome.vulns, status_str
            );
        }
        println!();
    } else {
        let first_url = urls.first().map_or("unknown", String::as_str);
        let success = results.iter().any(|r| r.success);
        println!(
            "{} Scan complete for {} ({})",
            "[*]".green().bold(),
            first_url,
            if success { "success" } else { "failed" }
        );
    }

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
    println!(
        "{} Results saved to: {}",
        "[*]".cyan(),
        output_root.as_ref().display()
    );
    println!("{}", "=".repeat(60).dimmed());

    // Write batch summary if multi-URL
    if is_batch && matches!(output_format, OutputFormat::Md | OutputFormat::Both) {
        write_batch_summary(output_root.as_ref(), &outcomes, total_secrets, total_vulns)?;
    }

    if any_failed {
        // Exit code 1 if any scan failed
        std::process::exit(1);
    }

    Ok(())
}

/// Resolve the list of URLs from either `--url` or `--file`.
fn resolve_urls(config: &Config) -> Result<Vec<String>> {
    if !config.urls.is_empty() {
        return Ok(config.urls.clone());
    }
    if let Some(url) = &config.url {
        return Ok(vec![url.clone()]);
    }
    anyhow::bail!("No URLs to scan. Provide --url or --file.");
}

/// Write a `SUMMARY.md` batch summary to the output root.
fn write_batch_summary(
    output_dir: &Path,
    outcomes: &[ScanOutcome],
    total_secrets: usize,
    total_vulns: usize,
) -> Result<()> {
    let mut lines = Vec::new();
    lines.push("# Corrode Batch Scan Summary\n".to_owned());
    lines.push(format!("**Scan Date**: {}", Utc::now().to_rfc3339()));
    lines.push(format!("**Targets Scanned**: {}", outcomes.len()));

    let succeeded = outcomes
        .iter()
        .filter(|o| matches!(o.status, ScanStatus::Success))
        .count();
    let failed = outcomes.len() - succeeded;

    lines.push(format!("**Succeeded**: {succeeded}"));
    lines.push(format!("**Failed**: {failed}"));
    lines.push(format!("**Total Secrets**: {total_secrets}"));
    lines.push(format!("**Total Vulnerabilities**: {total_vulns}\n"));

    lines.push("---\n".to_owned());
    lines.push("## Per-Target Results\n".to_owned());
    lines.push("| URL | Secrets | Vulns | Status |".to_owned());
    lines.push("|-----|---------|-------|--------|".to_owned());

    for outcome in outcomes {
        let status = match &outcome.status {
            ScanStatus::Success => "OK".to_owned(),
            ScanStatus::Failed(msg) => {
                let truncated: String = msg.chars().take(60).collect();
                format!("FAIL: {truncated}")
            }
        };
        lines.push(format!(
            "| {} | {} | {} | {} |",
            outcome.url, outcome.secrets, outcome.vulns, status
        ));
    }

    lines.push(String::new());

    let summary_path = output_dir.join("SUMMARY.md");
    fs::write(summary_path, lines.join("\n"))?;

    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn scan_url(
    url: String,
    browser: Arc<Browser>,
    verbose: bool,
    output_dir: &Path,
    timeout_secs: u64,
    output_format: OutputFormat,
    config: &Config,
) -> Result<ScanResult> {
    let start = Instant::now();

    if verbose {
        println!("{} {}", "[*]".cyan(), format!("Scanning {url}").dimmed());
    }

    // Build scanner: use custom patterns + ignore list from config
    let scanner = if config.custom_patterns.is_empty() && config.ignore_patterns.is_empty() {
        SecretScanner::new()
    } else {
        SecretScanner::with_custom_config(&config.custom_patterns, &config.ignore_patterns)
    };

    let network_monitor = NetworkMonitor::new();

    let page_result =
        time::timeout(Duration::from_secs(timeout_secs), browser.new_page(&url)).await;

    let page = match page_result {
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Page creation/navigation timeout after 60s"
            ))
        }
        Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to create page: {e}")),
        Ok(Ok(p)) => p,
    };

    if let Err(e) = network_monitor.enable(&page).await {
        if verbose {
            println!(
                "{} Failed to enable network monitoring: {}",
                "[!]".yellow(),
                e
            );
        }
    } else {
        network_monitor.start_monitoring(&page).await;
    }

    time::sleep(Duration::from_secs(6)).await;

    let html = page.content().await.context("Failed to get page content")?;
    scanner.scan_text(&html, "HTML").await;

    page_utils::trigger_dynamic_content(&page).await;

    let dom_data = dom::collect(&page, &scanner).await?;
    let target_host = url::Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(std::borrow::ToOwned::to_owned));
    let script_data = javascript::collect(&page, &scanner, target_host.as_deref(), &url).await?;

    let DomArtifacts {
        forms,
        hidden_inputs,
        meta_tags,
        data_attributes,
        iframes,
        all_links,
        local_storage,
        session_storage,
        cookies: cookie_info,
        raw_cookies,
    } = dom_data;

    let ScriptArtifacts {
        script_count,
        scripts_array,
        mut source_maps,
        source_map_candidates,
        script_bodies,
        chunk_names,
        astro_islands,
        window_objects,
        debug_flags,
        api_endpoints,
        ast_findings,
    } = script_data;

    // Recover referenced source maps, then scan recovered first-party source;
    // best-effort: `analyze` logs and skips any bad/off-origin/oversized map.
    let source_map_report =
        sourcemaps::analyze(&source_map_candidates, target_host.as_deref()).await;
    for (path, content) in &source_map_report.recovered_sources {
        let label = format!("Source Map: {path}");
        scanner.scan_text(content, &label).await;
        scanner.extract_comments(content, &label).await;
    }
    if verbose {
        for entry in &source_map_report.fetch_log {
            println!("{} source-map {}", "[*]".cyan(), entry.dimmed());
        }
    }

    let elapsed = start.elapsed();
    let secrets = scanner.get_findings().await;
    let comments = scanner.get_comments().await;
    let secret_count: usize = secrets.values().map(std::vec::Vec::len).sum();

    let all_calls = network_monitor.get_all_calls().await;
    let header_source_maps = network_monitor.get_source_map_headers().await;
    source_maps.extend(header_source_maps);
    let api_calls_list = network_monitor.get_api_calls().await;

    // Technology detection — all sources, one module
    let tech = technologies::detect_all(&page, &all_calls, &meta_tags, &scripts_array).await;

    let api_call_urls: Vec<String> = api_calls_list.iter().map(|c| c.url.clone()).collect();
    let third_party: Vec<String> = all_calls
        .iter()
        .filter(|c| !c.url.contains(&url))
        .map(|c| c.url.clone())
        .collect();

    if verbose {
        println!(
            "{} {} ({} secrets, {} comments, {} network requests in {:.2}s)",
            "[*]".green(),
            url,
            secret_count,
            comments.len(),
            all_calls.len(),
            elapsed.as_secs_f64()
        );
    }

    let (mut all_vulns, security) = analyze_security(&raw_cookies, &all_calls, &url);

    // `rsc::detect` is the sole owner of RSC vuln emission; we still de-dupe on
    // (`vuln_type`, url) to guard against a CVE arriving via another path.
    let script_refs: Vec<(&str, &str)> = script_bodies
        .iter()
        .map(|(text, src)| (text.as_str(), src.as_str()))
        .collect();
    let rsc_vulns = rsc::detect(&script_refs, &window_objects);
    let mut seen_vulns: std::collections::HashSet<(String, Option<String>)> = all_vulns
        .iter()
        .map(|v| (v.vuln_type.clone(), v.url.clone()))
        .collect();
    for vuln in rsc_vulns {
        if seen_vulns.insert((vuln.vuln_type.clone(), vuln.url.clone())) {
            all_vulns.push(vuln);
        }
    }
    all_vulns.extend(vulnerabilities::check_all(&tech.versions));

    // Extract framework manifests from in-page state (best-effort per parser);
    // routes are appended to the source-map route surface, then deduped by (path, kind).
    let manifest_report = manifests::analyze(
        &window_objects,
        &tech.technologies,
        &chunk_names,
        &astro_islands,
    );
    let framework_manifests = manifest_report.manifests;

    let mut route_surface = source_map_report.routes;
    route_surface.extend(manifest_report.routes);
    let mut seen_routes: std::collections::HashSet<(String, String)> =
        std::collections::HashSet::new();
    route_surface.retain(|r| seen_routes.insert((r.path.clone(), r.kind.clone())));

    // Merge source-map-recovered versions into the technology surface, deduped
    // by (name, version) so a version already detected at runtime isn't doubled.
    let mut technology_versions = tech.versions;
    let mut seen_versions: std::collections::HashSet<(String, Option<String>)> =
        technology_versions
            .iter()
            .map(|v| (v.name.clone(), v.version.clone()))
            .collect();
    for version in source_map_report.versions {
        if seen_versions.insert((version.name.clone(), version.version.clone())) {
            technology_versions.push(version);
        }
    }

    // Static, passive taint/gadget mapping (flows reported, never fired);
    // CSP for bypass correlation comes from the document response, if present.
    let csp_header = all_calls
        .iter()
        .find(|c| c.url == url || c.url.starts_with(&url))
        .and_then(|c| {
            c.response_headers
                .get("content-security-policy")
                .or_else(|| c.response_headers.get("Content-Security-Policy"))
        })
        .map(String::as_str);
    let taint_flows = taint::analyze(&script_refs);
    let post_message_handlers = taint::postmessage::detect(&script_refs);
    let gadgets = taint::gadgets::inventory(&script_refs, csp_header);

    let mut result = ScanResult {
        url: url.clone(),
        timestamp: Utc::now().to_rfc3339(),
        secrets,
        network: NetworkAnalysis {
            total_requests: all_calls.len(),
            api_calls: api_call_urls,
            third_party,
            websockets: vec![],
            redirects: vec![],
            auth_schemes: vec![],
            calls: all_calls,
        },
        dom: DomAnalysis {
            scripts: script_count,
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
            debug_mode: debug_flags,
            api_endpoints: api_endpoints.clone(),
            ast_findings,
        },
        security,
        technologies: tech.technologies,
        technology_versions,
        vulnerabilities: all_vulns,
        comments,
        api_tests: vec![],
        source_maps_intel: source_map_report.intel,
        framework_manifests,
        route_surface,
        taint_flows,
        gadgets,
        post_message_handlers,
        success: true,
        error: None,
    };

    // Phase 3 — score every finding's confidence (orthogonal to severity) now that
    // the full result is assembled. Origin is judged against the scan target host.
    scoring::score_all(&mut result, target_host.as_deref());

    if matches!(output_format, OutputFormat::Md | OutputFormat::Both) {
        markdown::write(&result, output_dir)?;
    }

    Ok(result)
}
