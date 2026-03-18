use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

use crate::config::{self, Config, OutputFormat};

#[derive(Parser, Debug)]
#[command(name = "corrode")]
#[command(about = "High-performance security scanner for exposed credentials and vulnerabilities", long_about = None)]
#[command(
    version,
    long_about = r#"
Corrode - Web Application Security Scanner

A blazing-fast Rust-based security scanner that discovers exposed credentials,
API vulnerabilities, and security misconfigurations in web applications.

Features:
  * 45+ secret pattern detection (AWS, Firebase, Supabase, JWTs, etc.)
  * API endpoint discovery and vulnerability testing
  * Network traffic monitoring and analysis
  * Technology stack fingerprinting (40+ frameworks/services)
  * Comprehensive JSON and Markdown reporting
  * Cookie security analysis
  * JavaScript comment extraction
  * Source map detection
  * Config file support (.corrode.toml)
  * Multi-URL batch scanning (--file targets.txt)

For more information: https://github.com/ul0gic/corrode
"#
)]
pub struct Args {
    /// Target URL to scan (must include protocol)
    #[arg(
        long = "url",
        value_name = "https://target",
        help = "Target URL to scan"
    )]
    pub url: Option<String>,

    /// File containing URLs to scan (one per line, # comments allowed)
    #[arg(
        long = "file",
        value_name = "PATH",
        conflicts_with = "url",
        help = "File containing URLs to scan (one per line)"
    )]
    pub file: Option<PathBuf>,

    /// Output directory for scan results
    ///
    /// Results saved as: <OUTPUT>/<domain>/`scan_result.json` and REPORT.md
    #[arg(short, long, default_value = "corrode-output", value_name = "DIR")]
    pub output: PathBuf,

    /// Path to Chrome/Chromium binary (overrides auto-detect)
    #[arg(
        long,
        env = "CHROME_BIN",
        value_name = "PATH",
        help = "Path to Chrome/Chromium binary (overrides auto-detect)"
    )]
    pub chrome_bin: Option<PathBuf>,

    /// Timeout for page load in seconds
    ///
    /// Maximum time to wait for a page to load before moving on.
    #[arg(short, long, default_value = "30", value_name = "SECS")]
    pub timeout: u64,

    /// Enable verbose output
    ///
    /// Shows detailed progress, found secrets, and API test results in real-time.
    #[arg(short, long)]
    pub verbose: bool,

    /// Output format: json, md, or both
    #[arg(
        long,
        value_enum,
        default_value = "md",
        value_name = "FORMAT",
        help = "Output format: json, md, or both"
    )]
    pub format: OutputFormat,

    /// Path to a custom config file (overrides auto-discovery)
    #[arg(
        long = "config",
        value_name = "PATH",
        help = "Path to a custom .corrode.toml config file"
    )]
    pub config_path: Option<PathBuf>,

    /// Ignore all config files (use built-in defaults only)
    #[arg(
        long = "no-config",
        help = "Ignore all config files, use defaults only"
    )]
    pub no_config: bool,
}

impl Args {
    pub fn into_config(self) -> Result<Config> {
        // Validate: at least one of --url or --file must be provided
        if self.url.is_none() && self.file.is_none() {
            bail!("Either --url or --file must be provided");
        }

        // Parse URL file if --file was given
        let urls = if let Some(ref file_path) = self.file {
            config::parse_url_file(file_path)?
        } else {
            Vec::new()
        };

        let mut cfg = Config {
            url: self.url,
            urls,
            output: self.output,
            timeout: self.timeout,
            verbose: self.verbose,
            chrome_bin: self.chrome_bin,
            format: self.format,
            chrome_args: Vec::new(),
            custom_patterns: Vec::new(),
            ignore_patterns: Vec::new(),
            redact_secrets: false,
            include_network_log: false,
        };

        // Load and merge config file unless --no-config
        if !self.no_config {
            let config_file = config::load_config_file(self.config_path.as_deref())?;
            if let Some(file_config) = &config_file {
                config::merge_config_file(&mut cfg, file_config);
            }
        }

        Ok(cfg)
    }
}

pub fn parse() -> Result<Config> {
    Args::parse().into_config()
}
