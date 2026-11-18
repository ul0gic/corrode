// Does:  Evaluates browser scripts and triggers dynamic page content.
// Holds: Failed JSON extraction returns the requested type’s default.

use chromiumoxide::Page;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tokio::time;

/// Evaluates a script and decodes its value, returning the type default on failure.
///
/// ```no_run
/// # use corrode_scanner::scanner::page_utils::extract_json;
/// # async fn inspect(page: &chromiumoxide::Page) {
/// let title: String = extract_json(page, "document.title").await;
/// # }
/// ```
pub async fn extract_json<T: DeserializeOwned + Default>(page: &Page, script: &str) -> T {
    page.evaluate(script)
        .await
        .ok()
        .and_then(|v| v.into_value().ok())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

/// Scrolls a page to trigger dynamic content and waits after evaluation.
///
/// ```no_run
/// # use corrode_scanner::scanner::page_utils::trigger_dynamic_content;
/// # async fn inspect(page: &chromiumoxide::Page) {
/// trigger_dynamic_content(page).await;
/// # }
/// ```
pub async fn trigger_dynamic_content(page: &Page) {
    let _ = page
        .evaluate(
            r"
            (async () => {
                const scrollStep = 500;
                const scrollDelay = 300;
                for (let i = 0; i < 5; i++) {
                    window.scrollBy(0, scrollStep);
                    await new Promise(resolve => setTimeout(resolve, scrollDelay));
                }
                window.scrollTo(0, 0);
                await new Promise(resolve => setTimeout(resolve, 300));
            })()
        ",
        )
        .await;

    time::sleep(Duration::from_secs(2)).await;
}
