use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub url: String,
    pub timestamp: String,
    pub secrets: HashMap<String, Vec<SecretFinding>>,
    pub network: NetworkAnalysis,
    pub dom: DomAnalysis,
    pub javascript: JavaScriptAnalysis,
    pub security: SecurityAnalysis,
    pub technologies: Vec<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub comments: Vec<Comment>,
    pub api_tests: Vec<ApiTestResult>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretFinding {
    pub source: String,
    pub matches: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Comment {
    pub source: String,
    pub comment_type: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkAnalysis {
    pub total_requests: usize,
    pub api_calls: Vec<String>,
    pub third_party: Vec<String>,
    pub websockets: Vec<String>,
    pub redirects: Vec<String>,
    pub auth_schemes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiCall {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub request_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub response_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomAnalysis {
    pub scripts: usize,
    pub forms: Vec<FormInfo>,
    pub hidden_inputs: Vec<HiddenInput>,
    pub iframes: Vec<String>,
    pub meta_tags: Vec<MetaTag>,
    pub data_attributes: Vec<DataAttribute>,
    pub local_storage: HashMap<String, String>,
    pub session_storage: HashMap<String, String>,
    pub cookies: Vec<CookieInfo>,
    pub all_links: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FormInfo {
    pub action: String,
    pub method: String,
    pub input_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetaTag {
    pub name: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HiddenInput {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataAttribute {
    pub tag: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CookieInfo {
    pub name: String,
    pub domain: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JavaScriptAnalysis {
    pub window_objects: HashMap<String, String>,
    pub source_maps: Vec<String>,
    pub debug_mode: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
    pub auth_required: Option<bool>,
    pub parameters: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityAnalysis {
    pub missing_headers: Vec<String>,
    pub cors_issues: Vec<String>,
    pub insecure_cookies: Vec<String>,
    pub mixed_content: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub vuln_type: String,
    pub severity: String,
    pub description: String,
    pub remediation: String,
    pub url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiTestResult {
    pub endpoint: String,
    pub test_type: String,
    pub severity: String,
    pub vulnerable: bool,
    pub evidence: String,
    pub details: String,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            url: String::new(),
            timestamp: String::new(),
            secrets: HashMap::new(),
            network: NetworkAnalysis::default(),
            dom: DomAnalysis::default(),
            javascript: JavaScriptAnalysis::default(),
            security: SecurityAnalysis::default(),
            technologies: Vec::new(),
            vulnerabilities: Vec::new(),
            comments: Vec::new(),
            api_tests: Vec::new(),
            success: false,
            error: None,
        }
    }
}

impl Default for NetworkAnalysis {
    fn default() -> Self {
        Self {
            total_requests: 0,
            api_calls: Vec::new(),
            third_party: Vec::new(),
            websockets: Vec::new(),
            redirects: Vec::new(),
            auth_schemes: Vec::new(),
        }
    }
}

impl Default for DomAnalysis {
    fn default() -> Self {
        Self {
            scripts: 0,
            forms: Vec::new(),
            hidden_inputs: Vec::new(),
            iframes: Vec::new(),
            meta_tags: Vec::new(),
            data_attributes: Vec::new(),
            local_storage: HashMap::new(),
            session_storage: HashMap::new(),
            cookies: Vec::new(),
            all_links: 0,
        }
    }
}

impl Default for JavaScriptAnalysis {
    fn default() -> Self {
        Self {
            window_objects: HashMap::new(),
            source_maps: Vec::new(),
            debug_mode: Vec::new(),
            api_endpoints: Vec::new(),
        }
    }
}

impl Default for SecurityAnalysis {
    fn default() -> Self {
        Self {
            missing_headers: Vec::new(),
            cors_issues: Vec::new(),
            insecure_cookies: Vec::new(),
            mixed_content: Vec::new(),
        }
    }
}
