use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub target: String,
    pub concurrency: usize,
    pub output: PathBuf,
    pub timeout: u64,
    pub verbose: bool,
}
