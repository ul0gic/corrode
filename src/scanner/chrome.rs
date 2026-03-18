use anyhow::{bail, Result};
use std::env;
use std::path::PathBuf;

pub(crate) fn resolve_chrome_binary(override_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "Chrome/Chromium binary not found at provided path: {}",
            path.display()
        );
    }

    for key in ["CHROME_BIN", "CHROMIUM_BIN"] {
        if let Ok(val) = env::var(key) {
            let candidate = PathBuf::from(val);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            candidates.extend(candidate_names().map(|name| dir.join(name)));
            if cfg!(windows) {
                candidates.extend(candidate_names().map(|name| dir.join(format!("{name}.exe"))));
            }
        }
    }

    candidates.extend(known_locations());

    if let Some(found) = candidates.into_iter().find(|p| p.is_file()) {
        return Ok(found);
    }

    bail!(
        "Could not locate Chrome/Chromium. Set --chrome-bin or CHROME_BIN. Checked common names (google-chrome, chromium, chrome) on PATH and standard install locations."
    );
}

fn candidate_names() -> impl Iterator<Item = &'static str> {
    [
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
    ]
    .into_iter()
}

fn known_locations() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();

    if cfg!(target_os = "macos") {
        paths.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into());
        paths.push("/Applications/Chromium.app/Contents/MacOS/Chromium".into());
    }

    if cfg!(target_os = "windows") {
        paths.push(r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe".into());
        paths.push(r"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe".into());
        paths.push(r"C:\\Program Files\\Chromium\\Application\\chrome.exe".into());
    }

    if cfg!(target_os = "linux") {
        paths.extend(
            [
                "/usr/bin/google-chrome",
                "/usr/bin/google-chrome-stable",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
                "/snap/bin/chromium",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }

    paths
}
