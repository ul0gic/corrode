// Does:  Combines file settings with CLI defaults and reads batch targets.
// Holds: An invalid batch line rejects the entire list before any target is returned.

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Report formats requested for a scan.
#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    /// Machine-readable scan result.
    Json,
    /// Markdown report and evidence files.
    Md,
    /// Both JSON and Markdown artifacts.
    Both,
}

/// Effective browser, target, and reporting settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Optional owner-supplied deployment evidence keyed by exact URL.
    pub deployments: crate::detectors::vulnerabilities::Deployments,
    /// Single target supplied on the command line.
    pub url: Option<String>,
    /// Targets read from the batch file in input order.
    pub urls: Vec<String>,
    /// Base directory for scan artifacts.
    pub output: PathBuf,
    /// Configured page timeout in seconds.
    pub timeout: u64,
    /// Whether to print detailed scan progress.
    pub verbose: bool,
    /// Optional explicit browser executable.
    pub chrome_bin: Option<PathBuf>,
    /// Requested output format.
    pub format: OutputFormat,
    /// Additional browser launch arguments in configuration order.
    pub chrome_args: Vec<String>,
    /// Extra named patterns to compile for this scan.
    pub custom_patterns: Vec<CustomPattern>,
    /// Built-in pattern names excluded from matching.
    pub ignore_patterns: Vec<String>,
    /// Stored redaction preference. The bundled report writers emit captured secret values independently.
    pub redact_secrets: bool,
    /// Stored network-log preference. The bundled report writers choose network output independently.
    pub include_network_log: bool,
}

/// Named regular expression supplied in the configuration file.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CustomPattern {
    /// Identifier under which matches are grouped.
    pub name: String,
    /// Regular expression text compiled when the scanner is configured.
    pub pattern: String,
    /// Severity label supplied by the configuration author.
    pub severity: String,
}

/// Optional TOML sections for scan, browser, pattern, and report settings.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigFile {
    /// Deployed package versions and configuration supplied by the site owner.
    #[serde(default)]
    pub deployments: crate::detectors::vulnerabilities::Deployments,
    /// Scan settings supplied by the file.
    pub scan: Option<ScanSection>,
    /// Browser launch settings supplied by the file.
    pub chrome: Option<ChromeSection>,
    /// Pattern additions or exclusions supplied by the file.
    pub patterns: Option<PatternsSection>,
    /// Report preferences supplied by the file.
    pub report: Option<ReportSection>,
}

/// File overrides for scan timing, console output, and report destinations.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanSection {
    /// Optional page timeout in seconds.
    pub timeout: Option<u64>,
    /// Optional detailed progress setting.
    pub verbose: Option<bool>,
    /// Output format name, accepting JSON, Markdown, or both.
    pub format: Option<String>,
    /// Optional base directory for reports.
    pub output_dir: Option<String>,
}

/// Browser executable and additional launch arguments.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChromeSection {
    /// Path to use when the CLI has no explicit browser executable.
    pub binary: Option<String>,
    /// Arguments appended to the existing browser argument list.
    pub args: Option<Vec<String>>,
}

/// Scanner pattern additions and built-in exclusions.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatternsSection {
    /// Named regular expressions appended to the scan configuration.
    pub custom_patterns: Option<Vec<CustomPattern>>,
    /// Built-in pattern names to suppress.
    pub ignore_patterns: Option<Vec<String>>,
}

/// Report preferences supplied by the configuration file.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ReportSection {
    /// Requested redaction of secret values.
    pub redact_secrets: Option<bool>,
    /// Requested inclusion of network logs.
    pub include_network_log: Option<bool>,
}

/// Reads an explicit TOML file, or searches the current directory before the user config directory.
/// An explicit missing or invalid file is an error.
/// ```
/// # use corrode_scanner::config::load_config_file;
/// # use std::{fs::{self, File}, io::Write};
/// # let path = std::env::temp_dir().join(format!("corrode-settings-{}.toml", std::process::id()));
/// # writeln!(File::create_new(&path).unwrap(), "[scan]\ntimeout = 45").unwrap();
/// let settings = load_config_file(Some(&path)).unwrap().unwrap();
/// # assert_eq!(settings.scan.unwrap().timeout, Some(45));
/// # fs::remove_file(path).unwrap();
/// ```
pub fn load_config_file(explicit_path: Option<&Path>) -> Result<Option<ConfigFile>> {
    if let Some(path) = explicit_path {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: ConfigFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        return Ok(Some(config));
    }

    let local_path = PathBuf::from("corrode.toml");
    if local_path.is_file() {
        let content =
            fs::read_to_string(&local_path).with_context(|| "Failed to read ./corrode.toml")?;
        let config: ConfigFile =
            toml::from_str(&content).with_context(|| "Failed to parse ./corrode.toml")?;
        return Ok(Some(config));
    }

    if let Some(config_dir) = dirs::config_dir() {
        let global_path = config_dir.join("corrode").join("config.toml");
        if global_path.is_file() {
            let content = fs::read_to_string(&global_path)
                .with_context(|| format!("Failed to read {}", global_path.display()))?;
            let config: ConfigFile = toml::from_str(&content)
                .with_context(|| format!("Failed to parse {}", global_path.display()))?;
            return Ok(Some(config));
        }
    }

    Ok(None)
}

fn parse_format(s: &str) -> Option<OutputFormat> {
    match s.to_lowercase().as_str() {
        "json" => Some(OutputFormat::Json),
        "md" | "markdown" => Some(OutputFormat::Md),
        "both" => Some(OutputFormat::Both),
        _ => None,
    }
}

/// Applies file settings to default-valued CLI fields, appends lists, and replaces supplied report flags.
/// ```
/// # use clap::Parser;
/// # use corrode_scanner::{cli::Args, config::{merge_config_file, ConfigFile}};
/// # let args = Args::parse_from(["corrode", "--no-config", "--url", "https://example.test"]);
/// # let mut settings = args.into_config().unwrap();
/// # let overrides: ConfigFile = toml::from_str("[scan]\ntimeout = 45").unwrap();
/// merge_config_file(&mut settings, &overrides);
/// # assert_eq!(settings.timeout, 45);
/// ```
pub fn merge_config_file(config: &mut Config, file: &ConfigFile) {
    config.deployments.clone_from(&file.deployments);
    // Why: The CLI supplies values without tracking whether the caller explicitly chose a default.
    if let Some(scan) = &file.scan {
        if let Some(timeout) = scan.timeout {
            if config.timeout == 30 {
                config.timeout = timeout;
            }
        }
        if let Some(verbose) = scan.verbose {
            if !config.verbose {
                config.verbose = verbose;
            }
        }
        if let Some(format_str) = &scan.format {
            if config.format == OutputFormat::Md {
                if let Some(fmt) = parse_format(format_str) {
                    config.format = fmt;
                }
            }
        }
        if let Some(output_dir) = &scan.output_dir {
            if config.output.as_os_str() == "corrode-output" {
                config.output = PathBuf::from(output_dir);
            }
        }
    }

    if let Some(chrome) = &file.chrome {
        if let Some(binary) = &chrome.binary {
            if config.chrome_bin.is_none() {
                config.chrome_bin = Some(PathBuf::from(binary));
            }
        }
        if let Some(args) = &chrome.args {
            config.chrome_args.extend(args.clone());
        }
    }

    if let Some(patterns) = &file.patterns {
        if let Some(custom) = &patterns.custom_patterns {
            config.custom_patterns.extend(custom.clone());
        }
        if let Some(ignore) = &patterns.ignore_patterns {
            config.ignore_patterns.extend(ignore.clone());
        }
    }

    if let Some(report) = &file.report {
        if let Some(redact) = report.redact_secrets {
            config.redact_secrets = redact;
        }
        if let Some(include) = report.include_network_log {
            config.include_network_log = include;
        }
    }
}

// Holds: The length limit counts Unicode scalar values so truncation leaves a valid string.
fn truncate_display(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_owned();
    }
    let head: String = value.chars().take(max).collect();
    format!("{head}...")
}

/// Reads trimmed HTTP(S)-prefixed lines in order, ignoring blanks and lines beginning with `#`.
/// An empty list or a rejected line fails the batch.
/// ```
/// # use corrode_scanner::config::parse_url_file;
/// # use std::{fs::{self, File}, io::Write};
/// # let path = std::env::temp_dir().join(format!("corrode-targets-{}.txt", std::process::id()));
/// # writeln!(File::create_new(&path).unwrap(), "# Primary site\nhttps://example.test").unwrap();
/// assert_eq!(parse_url_file(&path).unwrap(), ["https://example.test"]);
/// # fs::remove_file(path).unwrap();
/// ```
pub fn parse_url_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read URL file: {}", path.display()))?;

    let mut urls = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
            let shown = truncate_display(trimmed, 80);
            anyhow::bail!(
                "Invalid URL on line {} of {}: '{}' (must start with http:// or https://)",
                line_num + 1,
                path.display(),
                shown
            );
        }
        urls.push(trimmed.to_owned());
    }

    if urls.is_empty() {
        anyhow::bail!("URL file {} contains no valid URLs", path.display());
    }

    Ok(urls)
}
