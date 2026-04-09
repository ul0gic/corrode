use crate::types::ApiCall;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventLoadingFinished, EventRequestWillBeSent, EventResponseReceived,
    GetResponseBodyParams, PostDataEntry,
};
use chromiumoxide::Page;
use futures::StreamExt;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct NetworkMonitor {
    api_calls: Arc<Mutex<HashMap<String, ApiCall>>>,
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            api_calls: Arc::default(),
        }
    }

    pub async fn enable(&self, page: &Page) -> Result<(), Box<dyn std::error::Error>> {
        // Enable network tracking
        page.execute(EnableParams::default()).await?;
        Ok(())
    }

    pub async fn start_monitoring(&self, page: &Page) {
        let api_calls = Arc::clone(&self.api_calls);

        // Listen for request events — if event_listener fails, skip this monitor
        let request_listener = page.event_listener::<EventRequestWillBeSent>().await;
        if let Ok(mut request_events) = request_listener {
            let api_calls_req = Arc::clone(&api_calls);

            tokio::spawn(async move {
                while let Some(event) = request_events.next().await {
                    let request = &event.request;
                    let request_id = event.request_id.inner().clone();

                    // Only track HTTP(S) requests
                    if !request.url.starts_with("http") {
                        continue;
                    }

                    let mut calls = api_calls_req.lock().await;
                    let entry = calls.entry(request_id.clone()).or_insert(ApiCall {
                        url: request.url.clone(),
                        method: request.method.clone(),
                        status: 0,
                        request_headers: HashMap::new(),
                        response_headers: HashMap::new(),
                        response_content_type: None,
                        request_body: extract_post_data(request.post_data_entries.as_ref()),
                        response_body: None,
                        response_size: 0,
                    });

                    entry.url.clone_from(&request.url);
                    entry.method.clone_from(&request.method);
                    entry.request_headers = headers_to_map(&request.headers);
                    entry.request_body = extract_post_data(request.post_data_entries.as_ref());
                }
            });
        }

        // Listen for response events
        let response_listener = page.event_listener::<EventResponseReceived>().await;
        if let Ok(mut response_events) = response_listener {
            let api_calls_resp = Arc::clone(&api_calls);

            tokio::spawn(async move {
                while let Some(event) = response_events.next().await {
                    let request_id = event.request_id.inner().clone();
                    let response = &event.response;

                    // Cast i64 status to u16; clamp to 0 on out-of-range (defensive)
                    let status = u16::try_from(response.status).unwrap_or_default();

                    let mut calls = api_calls_resp.lock().await;
                    let entry = calls.entry(request_id).or_insert(ApiCall {
                        url: response.url.clone(),
                        method: String::new(),
                        status,
                        request_headers: HashMap::new(),
                        response_headers: HashMap::new(),
                        response_content_type: None,
                        request_body: None,
                        response_body: None,
                        response_size: 0,
                    });

                    entry.status = status;
                    if entry.url.is_empty() {
                        entry.url.clone_from(&response.url);
                    }
                    entry.response_headers = headers_to_map(&response.headers);
                    entry.response_content_type =
                        header_value(&entry.response_headers, "content-type")
                            .map(std::borrow::ToOwned::to_owned);
                    if entry.request_headers.is_empty() {
                        if let Some(req_headers) = &response.request_headers {
                            entry.request_headers = headers_to_map(req_headers);
                        }
                    }
                }
            });
        }

        // Listen for loading finished to get response body
        let finished_listener = page.event_listener::<EventLoadingFinished>().await;
        if let Ok(mut finished_events) = finished_listener {
            let api_calls_fin = Arc::clone(&api_calls);
            let page_clone = page.clone();

            tokio::spawn(async move {
                while let Some(event) = finished_events.next().await {
                    let request_id_str = event.request_id.inner().clone();

                    // Try to get response body
                    if let Ok(body_result) = page_clone
                        .execute(GetResponseBodyParams {
                            request_id: event.request_id.clone(),
                        })
                        .await
                    {
                        let mut calls = api_calls_fin.lock().await;
                        if let Some(call) = calls.get_mut(&request_id_str) {
                            call.response_size = body_result.body.len();
                            call.response_body = Some(body_result.body.clone());
                        }
                    }
                }
            });
        }
    }

    pub async fn get_api_calls(&self) -> Vec<ApiCall> {
        let calls = self.api_calls.lock().await;
        calls
            .values()
            .filter(|c| {
                // Filter to only API-like calls
                c.url.contains("/api/")
                    || c.url.contains("/graphql")
                    || c.url.contains("/v1/")
                    || c.url.contains("/v2/")
                    || c.url.contains("/v3/")
                    || c.url.contains(".json")
            })
            .cloned()
            .collect()
    }

    pub async fn get_all_calls(&self) -> Vec<ApiCall> {
        let calls = self.api_calls.lock().await;
        calls.values().cloned().collect()
    }

    /// Extract source map URLs from `SourceMap` or `X-SourceMap` response headers.
    pub async fn get_source_map_headers(&self) -> Vec<String> {
        let calls = self.api_calls.lock().await;
        let mut source_maps = Vec::new();
        for call in calls.values() {
            if let Some(sm) = header_value(&call.response_headers, "SourceMap") {
                source_maps.push(sm.to_owned());
            }
            if let Some(sm) = header_value(&call.response_headers, "X-SourceMap") {
                source_maps.push(sm.to_owned());
            }
        }
        source_maps
    }
}

fn headers_to_map<T: serde::Serialize>(headers: &T) -> HashMap<String, String> {
    serde_json::to_value(headers)
        .ok()
        .and_then(|val| match val {
            Value::Object(map) => Some(
                map.into_iter()
                    .map(|(k, v)| (k, value_to_string(v)))
                    .collect::<HashMap<_, _>>(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

fn value_to_string(v: Value) -> String {
    match v {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_owned(),
        Value::Array(arr) => arr
            .into_iter()
            .map(value_to_string)
            .collect::<Vec<_>>()
            .join(", "),
        Value::Object(obj) => serde_json::to_string(&obj).unwrap_or_default(),
    }
}

fn header_value<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

/// Reconstruct the request body from CDP's `postDataEntries` (replaces the
/// removed `postData` field in newer CDP versions).
fn extract_post_data(entries: Option<&Vec<PostDataEntry>>) -> Option<String> {
    let entries = entries?;
    let combined: String = entries
        .iter()
        .filter_map(|e| e.bytes.as_ref().map(AsRef::<str>::as_ref))
        .collect();
    if combined.is_empty() {
        None
    } else {
        Some(combined)
    }
}
