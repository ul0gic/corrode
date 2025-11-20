use crate::types::{ApiTestResult, DiscoveredEndpoint};
use reqwest::{header, Client};
use std::time::Duration;

pub struct ApiTester {
    client: Client,
}

impl ApiTester {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        Self { client }
    }

    /// Test if endpoint is accessible without authentication
    pub async fn test_auth_bypass(
        &self,
        endpoint: &DiscoveredEndpoint,
        base_url: &str,
    ) -> Option<ApiTestResult> {
        let url = normalize_url(&endpoint.url, base_url);

        // Test without any auth headers
        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return None,
        };

        let status = response.status().as_u16();
        let body = response.text().await.ok()?;
        let body_size = body.len();

        // Flag if we get 200 with substantial data
        if status == 200 && body_size > 100 {
            // Check if response contains sensitive data indicators
            let has_sensitive_data = body.contains("email") 
                || body.contains("password")
                || body.contains("token")
                || body.contains("api_key")
                || body.contains("user")
                || body.contains("data")
                || body.contains("[{")  // Array of objects
                || body.contains("\"id\":");

            if has_sensitive_data {
                let preview = if body.len() > 200 {
                    format!("{}...", &body[..200])
                } else {
                    body.clone()
                };

                return Some(ApiTestResult {
                    endpoint: url.clone(),
                    test_type: "Authentication Bypass".to_string(),
                    severity: "CRITICAL".to_string(),
                    vulnerable: true,
                    evidence: format!("HTTP {} - {} bytes - Response preview: {}", status, body_size, preview),
                    details: format!("Endpoint {} returned {} bytes without authentication. This may expose sensitive data.", url, body_size),
                });
            }
        }

        None
    }

    /// Test for IDOR vulnerabilities by trying different IDs
    pub async fn test_idor(
        &self,
        endpoint: &DiscoveredEndpoint,
        base_url: &str,
    ) -> Vec<ApiTestResult> {
        let mut results = Vec::new();

        // Only test endpoints with ID parameters
        if !endpoint.parameters.is_empty() {
            let test_ids = vec!["1", "2", "3", "100", "1000", "me", "admin"];

            for test_id in test_ids {
                let mut test_url = normalize_url(&endpoint.url, base_url);

                // Replace parameter placeholders with test ID
                for param in &endpoint.parameters {
                    test_url = test_url.replace(&format!("{{{}}}", param), test_id);
                    test_url = test_url.replace(&format!("${{{}}}", param), test_id);
                    test_url = test_url.replace(&format!(":{}", param), test_id);
                }

                if let Ok(response) = self.client.get(&test_url).send().await {
                    let status = response.status().as_u16();
                    if let Ok(body) = response.text().await {
                        if status == 200 && body.len() > 50 {
                            results.push(ApiTestResult {
                                endpoint: test_url.clone(),
                                test_type: "IDOR (Insecure Direct Object Reference)".to_string(),
                                severity: "HIGH".to_string(),
                                vulnerable: true,
                                evidence: format!("HTTP {} - Accessible with ID: {}", status, test_id),
                                details: "Endpoint allows access to different object IDs without authorization.".to_string(),
                            });
                            break; // Found one, don't spam
                        }
                    }
                }
            }
        }

        results
    }

    /// Test if endpoint reveals different behavior with/without auth
    pub async fn test_auth_differences(
        &self,
        endpoint: &DiscoveredEndpoint,
        base_url: &str,
    ) -> Option<ApiTestResult> {
        let url = normalize_url(&endpoint.url, base_url);

        // Test without auth
        let response_no_auth = self.client.get(&url).send().await.ok()?;
        let status_no_auth = response_no_auth.status().as_u16();
        let body_no_auth = response_no_auth.text().await.ok()?;

        // Test with invalid token
        let response_invalid = self
            .client
            .get(&url)
            .header(header::AUTHORIZATION, "Bearer invalid_token_12345")
            .send()
            .await
            .ok()?;
        let status_invalid = response_invalid.status().as_u16();

        // If both return 200, that's suspicious
        if status_no_auth == 200 && status_invalid == 200 {
            return Some(ApiTestResult {
                endpoint: url.clone(),
                test_type: "Missing Authentication Check".to_string(),
                severity: "HIGH".to_string(),
                vulnerable: true,
                evidence: "Returns HTTP 200 both with and without auth token".to_string(),
                details: "Endpoint does not properly validate authentication tokens.".to_string(),
            });
        }

        // If no auth returns data but different status codes
        if status_no_auth == 200 && body_no_auth.len() > 100 {
            return Some(ApiTestResult {
                endpoint: url.clone(),
                test_type: "Publicly Accessible API".to_string(),
                severity: "MEDIUM".to_string(),
                vulnerable: true,
                evidence: format!(
                    "HTTP {} - {} bytes returned without authentication",
                    status_no_auth,
                    body_no_auth.len()
                ),
                details: "Endpoint is publicly accessible and returns data.".to_string(),
            });
        }

        None
    }

    /// Test for mass assignment vulnerabilities
    pub async fn test_mass_assignment(
        &self,
        endpoint: &DiscoveredEndpoint,
        base_url: &str,
    ) -> Option<ApiTestResult> {
        if endpoint.method != "POST" && endpoint.method != "PUT" && endpoint.method != "PATCH" {
            return None;
        }

        let url = normalize_url(&endpoint.url, base_url);

        // Try to POST/PUT with admin fields
        let dangerous_fields = serde_json::json!({
            "role": "admin",
            "is_admin": true,
            "admin": true,
            "privileges": ["admin"],
            "is_superuser": true
        });

        let response = self
            .client
            .request(endpoint.method.parse().unwrap(), &url)
            .json(&dangerous_fields)
            .send()
            .await
            .ok()?;

        let status = response.status().as_u16();

        // If it doesn't reject our admin fields, flag it
        if status == 200 || status == 201 {
            return Some(ApiTestResult {
                endpoint: url.clone(),
                test_type: "Potential Mass Assignment".to_string(),
                severity: "MEDIUM".to_string(),
                vulnerable: true,
                evidence: format!("HTTP {} - Server accepted admin-related fields", status),
                details: "Endpoint may be vulnerable to mass assignment attacks.".to_string(),
            });
        }

        None
    }
}

fn normalize_url(endpoint_url: &str, base_url: &str) -> String {
    if endpoint_url.starts_with("http://") || endpoint_url.starts_with("https://") {
        endpoint_url.to_string()
    } else if endpoint_url.starts_with('/') {
        if let Ok(parsed) = reqwest::Url::parse(base_url) {
            format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                endpoint_url
            )
        } else {
            endpoint_url.to_string()
        }
    } else {
        endpoint_url.to_string()
    }
}
