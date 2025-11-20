use chromiumoxide::Page;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tokio::time;

pub async fn extract_json<T: DeserializeOwned + Default>(page: &Page, script: &str) -> T {
    page.evaluate(script)
        .await
        .ok()
        .and_then(|v| v.into_value().ok())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

pub async fn trigger_dynamic_content(page: &Page) {
    let _ = page
        .evaluate(
            r#"
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
        "#,
        )
        .await;

    time::sleep(Duration::from_secs(2)).await;
}
