use clap::Parser;
use std::path::PathBuf;

use crate::config::Config;

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
    /// Target URL or file path
    ///
    /// Can be:
    ///   - Single URL: https://example.com
    ///   - File with URLs: targets.txt (one URL per line, # for comments)
    ///   - Any .txt file or path that exists will be treated as a URL list
    #[arg(value_name = "TARGET", default_value = "targets.txt")]
    pub target: String,

    /// Number of concurrent browser instances
    ///
    /// Higher values = faster scans but more resource usage.
    /// Recommended: 10-20 for most systems, 50+ for powerful machines.
    #[arg(short, long, default_value = "10", value_name = "NUM")]
    pub concurrency: usize,

    /// Output directory for scan results
    ///
    /// Results saved as: <OUTPUT>/<domain>/scan_result.json and REPORT.md
    #[arg(short, long, default_value = "corrode-output", value_name = "DIR")]
    pub output: PathBuf,

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
}

impl Args {
    pub fn into_config(self) -> Config {
        Config {
            target: self.target,
            concurrency: self.concurrency,
            output: self.output,
            timeout: self.timeout,
            verbose: self.verbose,
        }
    }
}

pub fn parse() -> Config {
    Args::parse().into_config()
}
