// Does:  Collects page DOM, storage, and cookie artifacts.
// Holds: Hidden inputs, selected data attributes, and storage values are scanned for secrets.

use anyhow::Result;
use chromiumoxide::Page;
use serde_json;
use std::collections::HashMap;

use crate::detectors::secrets::SecretScanner;
use crate::scanner::page_utils;
use crate::types::{CookieInfo, DataAttribute, FormInfo, HiddenInput, MetaTag};

/// DOM, storage, and cookie observations from a page.
pub struct DomArtifacts {
    /// Observed forms.
    pub forms: Vec<FormInfo>,
    /// Observed hidden inputs.
    pub hidden_inputs: Vec<HiddenInput>,
    /// Observed metadata tags.
    pub meta_tags: Vec<MetaTag>,
    /// Selected elements and their data attributes.
    pub data_attributes: Vec<DataAttribute>,
    /// Resolved iframe URLs.
    pub iframes: Vec<String>,
    /// Count of distinct observed href and src values.
    pub all_links: usize,
    /// Local storage entries.
    pub local_storage: HashMap<String, String>,
    /// Session storage entries.
    pub session_storage: HashMap<String, String>,
    /// Cookie summaries.
    pub cookies: Vec<CookieInfo>,
    /// Browser cookie records.
    pub raw_cookies: Vec<chromiumoxide::cdp::browser_protocol::network::Cookie>,
}

/// Collects DOM, storage, and cookie artifacts from a page.
/// Returns an error if selected values cannot be serialized.
///
/// ```no_run
/// # use corrode_scanner::detectors::collectors::dom::collect;
/// # use corrode_scanner::detectors::secrets::SecretScanner;
/// # async fn example(page: &chromiumoxide::Page, scanner: &SecretScanner) -> anyhow::Result<()> {
/// let artifacts = collect(page, scanner).await?;
/// # Ok(())
/// # }
/// ```
pub async fn collect(page: &Page, scanner: &SecretScanner) -> Result<DomArtifacts> {
    let forms = page_utils::extract_json::<Vec<FormInfo>>(page,
        "Array.from(document.forms).map(f => ({ action: f.action, method: f.method, input_count: f.elements.length }))"
    ).await;

    let hidden_inputs = page_utils::extract_json::<Vec<HiddenInput>>(page,
        "Array.from(document.querySelectorAll('input[type=\"hidden\"]')).map(i => ({ name: i.name, value: i.value }))"
    ).await;

    for input in &hidden_inputs {
        scanner
            .scan_text(&input.value, &format!("Hidden Input: {}", input.name))
            .await;
    }

    let meta_tags = page_utils::extract_json::<Vec<MetaTag>>(page,
        "Array.from(document.querySelectorAll('meta')).map(m => ({ name: m.name || m.getAttribute('property') || '', content: m.content }))"
    ).await;

    let data_attributes = page_utils::extract_json::<Vec<DataAttribute>>(page, r"
        Array.from(document.querySelectorAll('[data-api], [data-url], [data-endpoint], [data-key], [data-token], [data-config]')).map(el => {
            const attrs = {};
            for (const attr of el.attributes) {
                if (attr.name.startsWith('data-')) {
                    attrs[attr.name] = attr.value;
                }
            }
            return { tag: el.tagName.toLowerCase(), attributes: attrs };
        })
    ").await;

    for attr in &data_attributes {
        let attr_json = serde_json::to_string(&attr.attributes)?;
        scanner
            .scan_text(&attr_json, &format!("Data Attributes: {}", attr.tag))
            .await;
    }

    let iframes = page_utils::extract_json::<Vec<String>>(
        page,
        "Array.from(document.querySelectorAll('iframe')).map(i => i.src)",
    )
    .await;

    let all_links = page_utils::extract_json::<usize>(page,
        "new Set([...Array.from(document.querySelectorAll('[href]')).map(e => e.getAttribute('href')), ...Array.from(document.querySelectorAll('[src]')).map(e => e.getAttribute('src'))]).size"
    ).await;

    let local_storage = page_utils::extract_json::<HashMap<String, String>>(
        page,
        r"
        (() => {
            try { return Object.assign({}, window.localStorage); }
            catch (e) { return {}; }
        })()
    ",
    )
    .await;
    let local_storage_json = serde_json::to_string(&local_storage)?;
    scanner.scan_text(&local_storage_json, "localStorage").await;

    let session_storage = page_utils::extract_json::<HashMap<String, String>>(
        page,
        r"
        (() => {
            try { return Object.assign({}, window.sessionStorage); }
            catch (e) { return {}; }
        })()
    ",
    )
    .await;
    let session_storage_json = serde_json::to_string(&session_storage)?;
    scanner
        .scan_text(&session_storage_json, "sessionStorage")
        .await;

    let cookies = page.get_cookies().await.unwrap_or_default();
    let cookie_info: Vec<CookieInfo> = cookies
        .iter()
        .map(|c| CookieInfo {
            name: c.name.clone(),
            domain: c.domain.clone(),
            secure: c.secure,
            http_only: c.http_only,
            same_site: format!("{:?}", c.same_site),
        })
        .collect();

    Ok(DomArtifacts {
        forms,
        hidden_inputs,
        meta_tags,
        data_attributes,
        iframes,
        all_links,
        local_storage,
        session_storage,
        cookies: cookie_info,
        raw_cookies: cookies,
    })
}
