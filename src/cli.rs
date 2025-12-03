use clap::Parser;
use std::path::PathBuf;

use crate::config::{Config, OutputFormat};

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
  • 30+ secret pattern detection (AWS, Firebase, Supabase, JWTs, etc.)
  • API endpoint discovery and vulnerability testing
  • Network traffic monitoring and analysis
  • Technology stack fingerprinting (40+ frameworks/services)
  • Comprehensive JSON and Markdown reporting
  • Cookie security analysis
  • JavaScript comment extraction
  • Source map detection

For more information: https://github.com/ul0gic/corrode
"#
)]
pub struct Args {
    /// Target URL to scan (must include protocol)
    #[arg(
        long = "url",
        value_name = "https://target",
        help = "Target URL to scan",
        required = true
    )]
    pub url: String,

    /// Output directory for scan results
    ///
    /// Results saved as: <OUTPUT>/<domain>/scan_result.json and REPORT.md
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
        default_value = "both",
        value_name = "FORMAT",
        help = "Output format: json, md, or both"
    )]
    pub format: OutputFormat,
}

impl Args {
    pub fn into_config(self) -> Config {
        Config {
            url: self.url,
            output: self.output,
            timeout: self.timeout,
            verbose: self.verbose,
            chrome_bin: self.chrome_bin,
            format: self.format,
        }
    }
}

pub fn parse() -> Config {
    Args::parse().into_config()
}
