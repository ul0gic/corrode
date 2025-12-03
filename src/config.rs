use clap::ValueEnum;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Md,
    Both,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub output: PathBuf,
    pub timeout: u64,
    pub verbose: bool,
    pub chrome_bin: Option<PathBuf>,
    pub format: OutputFormat,
}
