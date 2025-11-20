use anyhow::{Context, Result};
use chrono::Utc;
use colored::Colorize;
use futures::StreamExt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time;

use crate::api::testing::ApiTester;
use crate::config::Config;
use crate::detectors::{
    dom::{self, DomArtifacts},
    javascript::{self, ScriptArtifacts},
    secrets::SecretScanner,
};
use crate::network::monitor::NetworkMonitor;
use crate::reporting::{json as json_report, markdown};
use crate::scanner::page_utils;
use crate::types::{
    DomAnalysis, JavaScriptAnalysis, NetworkAnalysis, ScanResult, SecurityAnalysis, Vulnerability,
};
use chromiumoxide::browser::{Browser, BrowserConfig};

pub async fn run(config: Config) -> Result<()> {
    println!(
        "{} Corroding through {} targets...\n",
        "[*]".cyan().bold(),
        1
    );

    let Config {
        url,
        output,
        timeout,
        verbose,
    } = config;

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
                "--disable-sync",
            ])
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build browser config: {}", e))?,
    )
    .await?;

    let browser = Arc::new(browser);

    tokio::spawn(async move {
        loop {
            match handler.next().await {
                Some(Ok(_)) => continue,
                Some(Err(_)) => continue,
                None => break,
            }
        }
    });

    time::sleep(Duration::from_millis(500)).await;

    let timeout = timeout.max(1);

    let output_root = Arc::new(output);
    fs::create_dir_all(output_root.as_ref())?;

    let mut results = Vec::new();
    let mut total_secrets = 0;
    let mut total_vulns = 0;
    let mut total_comments = 0;

    match scan_url(
        url.clone(),
        browser,
        verbose,
        output_root.as_ref().as_path(),
        timeout,
    )
    .await
    {
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

            let site_dir = output_root.as_ref().join(&domain);
            fs::create_dir_all(&site_dir)?;

            let output_file = site_dir.join("scan_result.json");
            json_report::write(&output_file, &result)?;

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
                        "→".dimmed(),
                        pattern_type.cyan(),
                        total_matches
                    );
                }

                if !result.technologies.is_empty() {
                    println!(
                        "    {} Technologies: {}",
                        "🛠".dimmed(),
                        result.technologies.join(", ").dimmed()
                    );
                }
            }

            results.push(result);
        }
        Err(e) => {
            eprintln!("{} Scan failed ({}): {}", "[!]".red(), url, e);
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
    println!(
        "{} Results saved to: {}",
        "[*]".cyan(),
        output_root.as_ref().display()
    );
    println!("{}", "=".repeat(60).dimmed());

    Ok(())
}

async fn scan_url(
    url: String,
    browser: Arc<Browser>,
    verbose: bool,
    output_dir: &Path,
    timeout_secs: u64,
) -> Result<ScanResult> {
    let start = Instant::now();

    if verbose {
        println!("{} {}", "[*]".cyan(), format!("Scanning {}", url).dimmed());
    }

    let scanner = SecretScanner::new();
    let network_monitor = NetworkMonitor::new();

    let page_result =
        time::timeout(Duration::from_secs(timeout_secs), browser.new_page(&url)).await;

    let page = match page_result {
        Err(_) => {
            return Err(anyhow::anyhow!(
                "Page creation/navigation timeout after 60s"
            ))
        }
        Ok(Err(e)) => return Err(anyhow::anyhow!("Failed to create page: {}", e)),
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

    time::sleep(Duration::from_secs(3)).await;

    let html = page.content().await.context("Failed to get page content")?;
    scanner.scan_text(&html, "HTML").await;

    page_utils::trigger_dynamic_content(&page).await;

    let dom_data = dom::collect(&page, &scanner).await?;
    let script_data = javascript::collect(&page, &scanner).await?;

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
        source_maps,
        window_objects,
        debug_flags,
        api_endpoints,
        technologies,
        ast_findings,
    } = script_data;

    let tester = ApiTester::new();
    let mut api_tests = Vec::new();

    for endpoint in &api_endpoints {
        if let Some(result) = tester.test_auth_bypass(endpoint, &url).await {
            if verbose {
                println!(
                    "{} {} - {}",
                    "[!]".red().bold(),
                    result.test_type,
                    result.endpoint
                );
            }
            api_tests.push(result);
        }

        let idor_results = tester.test_idor(endpoint, &url).await;
        for result in idor_results {
            if verbose {
                println!(
                    "{} {} - {}",
                    "[!]".red().bold(),
                    result.test_type,
                    result.endpoint
                );
            }
            api_tests.push(result);
        }

        if let Some(result) = tester.test_auth_differences(endpoint, &url).await {
            if verbose {
                println!(
                    "{} {} - {}",
                    "[!]".red().bold(),
                    result.test_type,
                    result.endpoint
                );
            }
            api_tests.push(result);
        }

        if let Some(result) = tester.test_mass_assignment(endpoint, &url).await {
            if verbose {
                println!(
                    "{} {} - {}",
                    "[!]".red().bold(),
                    result.test_type,
                    result.endpoint
                );
            }
            api_tests.push(result);
        }
    }

    let elapsed = start.elapsed();
    let secrets = scanner.get_findings().await;
    let comments = scanner.get_comments().await;
    let secret_count: usize = secrets.values().map(|v| v.len()).sum();

    let all_calls = network_monitor.get_all_calls().await;
    let api_calls_list = network_monitor.get_api_calls().await;

    let api_call_urls: Vec<String> = api_calls_list.iter().map(|c| c.url.clone()).collect();
    let third_party: Vec<String> = all_calls
        .iter()
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

    let (vulnerabilities, security) = analyze_security(&raw_cookies);

    let result = ScanResult {
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
        technologies,
        vulnerabilities,
        comments,
        api_tests,
        success: true,
        error: None,
    };

    markdown::write(&result, output_dir)?;

    Ok(result)
}

fn analyze_security(
    cookies: &[chromiumoxide::cdp::browser_protocol::network::Cookie],
) -> (Vec<Vulnerability>, SecurityAnalysis) {
    let mut vulnerabilities = Vec::new();
    let mut insecure_cookies = Vec::new();

    for cookie in cookies {
        if !cookie.secure || !cookie.http_only {
            insecure_cookies.push(cookie.name.clone());
        }
    }

    if !insecure_cookies.is_empty() {
        vulnerabilities.push(Vulnerability {
            vuln_type: "Insecure Cookies".to_string(),
            severity: "medium".to_string(),
            description: "Cookies missing Secure/HttpOnly flags".to_string(),
            remediation: "Set Secure and HttpOnly flags on all session cookies".to_string(),
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
