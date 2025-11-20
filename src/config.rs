use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub output: PathBuf,
    pub timeout: u64,
    pub verbose: bool,
}
