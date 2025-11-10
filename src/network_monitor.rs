use crate::types::ApiCall;
use chromiumoxide::Page;
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventRequestWillBeSent, EventResponseReceived, EventLoadingFinished,
    GetResponseBodyParams,
};
use futures::StreamExt;
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
        let mut request_events = page.event_listener::<EventRequestWillBeSent>().await.unwrap();
        let api_calls_req = api_calls.clone();
        
        tokio::spawn(async move {
            while let Some(event) = request_events.next().await {
                let request = &event.request;
                let request_id = event.request_id.inner().to_string();
                
                // Only track HTTP(S) requests
                if !request.url.starts_with("http") {
                    continue;
                }
                
                // Headers is not Option anymore in newer chromiumoxide
                let headers: HashMap<String, String> = HashMap::new();
                // Note: request.headers doesn't have a public iterator in newer versions
                
                let mut calls = api_calls_req.lock().await;
                calls.insert(request_id.clone(), ApiCall {
                    url: request.url.clone(),
                    method: request.method.clone(),
                    status: 0,  // Will be updated on response
                    request_headers: headers,
                    response_headers: HashMap::new(),
                    request_body: request.post_data.clone(),
                    response_body: None,
                    response_size: 0,
                });
            }
        });
        
        // Listen for response events
        let mut response_events = page.event_listener::<EventResponseReceived>().await.unwrap();
        let api_calls_resp = api_calls.clone();
        
        tokio::spawn(async move {
            while let Some(event) = response_events.next().await {
                let request_id = event.request_id.inner().to_string();
                let response = &event.response;
                
                // Headers is a HashMap-like structure, convert to our format
                let headers: HashMap<String, String> = HashMap::new();
                // Note: response.headers doesn't have a public iterator in newer versions
                
                let mut calls = api_calls_resp.lock().await;
                if let Some(call) = calls.get_mut(&request_id) {
                    call.status = response.status as u16;
                    call.response_headers = headers;
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
                if let Ok(body_result) = page_clone.execute(GetResponseBodyParams {
                    request_id: event.request_id.clone(),
                }).await {
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
        calls.values()
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
