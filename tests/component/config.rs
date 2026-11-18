// Does:  Exercises batch input, configuration precedence, and CLI failure output.
// Holds: Invalid input stops the batch before scanning and its diagnostic is bounded.

use clap::Parser;
use corrode_scanner::{cli::Args, config::OutputFormat};
use std::path::Path;
use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/config");

#[test]
fn batch_loads_file_settings_and_preserves_explicit_cli_timeout() {
    let args = Args::try_parse_from([
        "corrode-scanner",
        "--file",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/config/urls.txt"
        ),
        "--config",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/config/batch.toml"
        ),
        "--timeout",
        "12",
    ])
    .expect("valid batch arguments");
    let config = args.into_config().expect("load config and URL file");
    assert_eq!(config.timeout, 12);
    assert_eq!(config.format, OutputFormat::Json);
    assert!(config.redact_secrets);
    assert_eq!(
        config.urls,
        [
            "https://example.test/first",
            "http://example.test/second?view=public"
        ]
    );
}

#[test]
fn invalid_batch_exits_with_a_bounded_utf8_error() {
    // Why: Only the process boundary exposes the exit status and the error printed to contributors.
    #[allow(clippy::disallowed_methods)]
    let output = Command::new(env!("CARGO_BIN_EXE_corrode-scanner"))
        .args(["--no-config", "--file"])
        .arg(Path::new(FIXTURES).join("invalid-urls.txt"))
        .output()
        .expect("run scanner CLI");
    assert_eq!(output.status.code(), Some(1));
    let error = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
    assert!(error.contains("Invalid URL on line 2"), "{error}");
    assert!(
        error.contains(&format!("'{}...'", "☃".repeat(80))),
        "{error}"
    );
    assert!(!error.contains(&"☃".repeat(81)));
}
