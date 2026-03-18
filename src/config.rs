use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Md,
    Both,
}

/// Runtime configuration used throughout the scan.
/// Produced by merging CLI flags, config file, and built-in defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub url: Option<String>,
    pub urls: Vec<String>,
    pub output: PathBuf,
    pub timeout: u64,
    pub verbose: bool,
    pub chrome_bin: Option<PathBuf>,
    pub format: OutputFormat,
    pub chrome_args: Vec<String>,
    pub custom_patterns: Vec<CustomPattern>,
    pub ignore_patterns: Vec<String>,
    pub redact_secrets: bool,
    pub include_network_log: bool,
}

/// A user-defined secret detection pattern loaded from `.corrode.toml`.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
    pub severity: String,
}

// --- Config file TOML structures ---

/// Top-level `.corrode.toml` file representation.
/// All fields are `Option<T>` so partial configs are valid.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfigFile {
    pub scan: Option<ScanSection>,
    pub chrome: Option<ChromeSection>,
    pub patterns: Option<PatternsSection>,
    pub report: Option<ReportSection>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScanSection {
    pub timeout: Option<u64>,
    pub verbose: Option<bool>,
    pub format: Option<String>,
    pub output_dir: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ChromeSection {
    pub binary: Option<String>,
    pub args: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PatternsSection {
    pub custom_patterns: Option<Vec<CustomPattern>>,
    pub ignore_patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ReportSection {
    pub redact_secrets: Option<bool>,
    pub include_network_log: Option<bool>,
}

/// Discover and load a `.corrode.toml` config file.
///
/// Discovery order:
/// 1. Explicit path from `--config` flag (error if not found / invalid)
/// 2. `./corrode.toml` in the current working directory
/// 3. `~/.config/corrode/config.toml` (global config via `dirs` crate)
///
/// Returns `Ok(None)` if no config file is found at any location.
pub fn load_config_file(explicit_path: Option<&Path>) -> Result<Option<ConfigFile>> {
    if let Some(path) = explicit_path {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: ConfigFile = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        return Ok(Some(config));
    }

    // Try ./corrode.toml
    let local_path = PathBuf::from("corrode.toml");
    if local_path.is_file() {
        let content =
            fs::read_to_string(&local_path).with_context(|| "Failed to read ./corrode.toml")?;
        let config: ConfigFile =
            toml::from_str(&content).with_context(|| "Failed to parse ./corrode.toml")?;
        return Ok(Some(config));
    }

    // Try ~/.config/corrode/config.toml
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

/// Parse an output format string from a config file into an `OutputFormat`.
fn parse_format(s: &str) -> Option<OutputFormat> {
    match s.to_lowercase().as_str() {
        "json" => Some(OutputFormat::Json),
        "md" | "markdown" => Some(OutputFormat::Md),
        "both" => Some(OutputFormat::Both),
        _ => None,
    }
}

/// Merge a `ConfigFile` into a `Config`, respecting priority:
/// CLI flags (already in `config`) > config file values > built-in defaults.
///
/// Fields in `config` that have non-default values (i.e., were set by CLI)
/// are NOT overwritten by the config file.
pub fn merge_config_file(config: &mut Config, file: &ConfigFile) {
    if let Some(scan) = &file.scan {
        // Only apply config file timeout if CLI used the default (30)
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
            // Only apply if CLI used the default ("md")
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

/// Parse a URL file (one URL per line, skip blanks and `#` comments).
/// Validates each URL starts with `http://` or `https://`.
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
            anyhow::bail!(
                "Invalid URL on line {} of {}: '{}' (must start with http:// or https://)",
                line_num + 1,
                path.display(),
                trimmed
            );
        }
        urls.push(trimmed.to_owned());
    }

    if urls.is_empty() {
        anyhow::bail!("URL file {} contains no valid URLs", path.display());
    }

    Ok(urls)
}
