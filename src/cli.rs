// Does:  Resolves command-line arguments into scan settings.
// Holds: Batch input and explicit configuration files are read before browser startup.

use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;

use crate::config::{self, Config, OutputFormat};

/// Command-line options for a single target or a URL file.
#[derive(Parser, Debug)]
#[command(name = "corrode")]
#[command(about = "Passive web scanner for exposed credentials, security observations and advisory matches", long_about = None)]
#[command(
    version,
    long_about = r#"
Corrode - Web Application Security Scanner

Collects browser-visible security evidence and compares deployment records with published advisories.

Features:
  * 45+ secret pattern detection (AWS, Firebase, Supabase, JWTs, etc.)
  * Passive API endpoint discovery and advisory comparisons
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

    /// Output directory for per-domain REPORT.md, EVIDENCE.md, and optional JSON
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

    /// Timeout for page load in seconds (max wait before moving on)
    #[arg(short, long, default_value = "30", value_name = "SECS")]
    pub timeout: u64,

    /// Enable verbose output (real-time progress, secrets, and API results)
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
    /// Resolves batch targets and overlays file settings unless `--no-config` is present.
    /// ```
    /// # use clap::Parser;
    /// # use corrode_scanner::cli::Args;
    /// # let args = Args::parse_from(["corrode", "--no-config", "--url", "https://example.test"]);
    /// assert_eq!(args.into_config().unwrap().url.as_deref(), Some("https://example.test"));
    /// ```
    pub fn into_config(self) -> Result<Config> {
        if self.url.is_none() && self.file.is_none() {
            bail!("Either --url or --file must be provided");
        }

        let urls = if let Some(ref file_path) = self.file {
            config::parse_url_file(file_path)?
        } else {
            Vec::new()
        };

        let mut cfg = Config {
            deployments: crate::detectors::vulnerabilities::Deployments::default(),
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

        if !self.no_config {
            let config_file = config::load_config_file(self.config_path.as_deref())?;
            if let Some(file_config) = &config_file {
                config::merge_config_file(&mut cfg, file_config);
            }
        }

        Ok(cfg)
    }
}

/// Parses the process arguments and resolves the scan settings.
/// ```no_run
/// corrode_scanner::cli::parse()?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn parse() -> Result<Config> {
    Args::parse().into_config()
}
