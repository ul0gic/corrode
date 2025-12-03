use crate::types::ApiCall;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventLoadingFinished, EventRequestWillBeSent, EventResponseReceived,
    GetResponseBodyParams,
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

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            api_calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn enable(&self, page: &Page) -> Result<(), Box<dyn std::error::Error>> {
        // Enable network tracking
        page.execute(EnableParams::default()).await?;
        Ok(())
    }

    pub async fn start_monitoring(&self, page: &Page) {
        let api_calls = self.api_calls.clone();

        // Listen for request events
        let mut request_events = page
            .event_listener::<EventRequestWillBeSent>()
            .await
            .unwrap();
        let api_calls_req = api_calls.clone();

        tokio::spawn(async move {
            while let Some(event) = request_events.next().await {
                let request = &event.request;
                let request_id = event.request_id.inner().to_string();

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
                    request_body: request.post_data.clone(),
                    response_body: None,
                    response_size: 0,
                });

                entry.url = request.url.clone();
                entry.method = request.method.clone();
                entry.request_headers = headers_to_map(&request.headers);
                entry.request_body = request.post_data.clone();
            }
        });

        // Listen for response events
        let mut response_events = page
            .event_listener::<EventResponseReceived>()
            .await
            .unwrap();
        let api_calls_resp = api_calls.clone();

        tokio::spawn(async move {
            while let Some(event) = response_events.next().await {
                let request_id = event.request_id.inner().to_string();
                let response = &event.response;

                let mut calls = api_calls_resp.lock().await;
                let entry = calls.entry(request_id).or_insert(ApiCall {
                    url: response.url.clone(),
                    method: String::new(),
                    status: response.status as u16,
                    request_headers: HashMap::new(),
                    response_headers: HashMap::new(),
                    response_content_type: None,
                    request_body: None,
                    response_body: None,
                    response_size: 0,
                });

                entry.status = response.status as u16;
                if entry.url.is_empty() {
                    entry.url = response.url.clone();
                }
                entry.response_headers = headers_to_map(&response.headers);
                entry.response_content_type =
                    header_value(&entry.response_headers, "content-type").map(|s| s.to_string());
                if entry.request_headers.is_empty() {
                    if let Some(req_headers) = &response.request_headers {
                        entry.request_headers = headers_to_map(req_headers);
                    }
                }
            }
        });

        // Listen for loading finished to get response body
        let mut finished_events = page.event_listener::<EventLoadingFinished>().await.unwrap();
        let api_calls_fin = api_calls.clone();
        let page_clone = page.clone();

        tokio::spawn(async move {
            while let Some(event) = finished_events.next().await {
                let request_id_str = event.request_id.inner().to_string();

                // Try to get response body
                if let Ok(body_result) = page_clone
                    .execute(GetResponseBodyParams {
                        request_id: event.request_id.clone(),
                    })
                    .await
                {
                    let mut calls = api_calls_fin.lock().await;
                    if let Some(call) = calls.get_mut(&request_id_str) {
                        call.response_body = Some(body_result.body.clone());
                        call.response_size = body_result.body.len();
                    }
                }
            }
        });
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
        Value::Null => "null".to_string(),
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
