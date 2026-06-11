use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScanResult {
    pub url: String,
    pub timestamp: String,
    pub secrets: HashMap<String, Vec<SecretFinding>>,
    pub network: NetworkAnalysis,
    pub dom: DomAnalysis,
    pub javascript: JavaScriptAnalysis,
    pub security: SecurityAnalysis,
    pub technologies: Vec<String>,
    pub technology_versions: Vec<TechnologyVersion>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub comments: Vec<Comment>,
    pub api_tests: Vec<ApiTestResult>,
    // Skipped from JSON when empty so pre-0.4 output is unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_maps_intel: Vec<SourceMapIntel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub framework_manifests: Vec<FrameworkManifest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_surface: Vec<RouteSurface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_flows: Vec<TaintFlow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gadgets: Vec<Gadget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_message_handlers: Vec<PostMessageHandler>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TechnologyVersion {
    pub name: String,
    pub version: Option<String>,
    pub detection_method: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretFinding {
    pub source: String,
    pub matches: Vec<String>,
    // Confidence is orthogonal to severity. None = unscored (Phase 3 fills this in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Comment {
    pub source: String,
    pub comment_type: String,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkAnalysis {
    pub total_requests: usize,
    pub api_calls: Vec<String>,
    pub third_party: Vec<String>,
    pub websockets: Vec<String>,
    pub redirects: Vec<String>,
    pub auth_schemes: Vec<String>,
    pub calls: Vec<ApiCall>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiCall {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub request_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    pub response_content_type: Option<String>,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
    pub response_size: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
pub struct AstFinding {
    pub kind: String,
    pub value: String,
    pub location: String,
    pub context: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JavaScriptAnalysis {
    pub window_objects: HashMap<String, String>,
    pub source_maps: Vec<String>,
    pub debug_mode: Vec<String>,
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    pub ast_findings: Vec<AstFinding>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveredEndpoint {
    pub url: String,
    pub method: String,
    pub source: String,
    pub auth_required: Option<bool>,
    pub parameters: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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
    // Orthogonal to severity; None until scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
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

/// Confidence band, ordered Low < Medium < High so findings sort by it.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

/// Evidence origin, ranked by trustworthiness during scoring.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Runtime,
    Network,
    Ast,
    Dom,
    Header,
    SourceMap,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfidenceFactor {
    pub dimension: String,
    pub delta: i8,
    pub note: String,
}

/// Banded 0–100 score plus the factors that produced it.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Confidence {
    pub level: ConfidenceLevel,
    pub score: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<ConfidenceFactor>,
}

/// Intelligence recovered from an exposed JavaScript source map.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceMapIntel {
    pub map_url: String,
    pub script_url: String,
    pub recovered_sources: Vec<String>,
    pub has_sources_content: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// A parsed framework build/route manifest.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrameworkManifest {
    pub framework: String,
    pub manifest_type: String,
    pub routes: Vec<String>,
    pub build_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// A discovered client-side route, API path, controller, or component.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteSurface {
    pub path: String,
    pub kind: String,
    pub source: String,
    pub dynamic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// A static source→sink taint flow — reported, never fired.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaintFlow {
    pub source: String,
    pub sink: String,
    pub path: Vec<String>,
    pub script_url: String,
    pub location: String,
    pub runtime_observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// A classified client-side gadget candidate with an exploitability hint.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Gadget {
    pub category: String,
    pub description: String,
    pub script_url: String,
    pub exploitability_hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// A `message` event handler and its origin-validation posture.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostMessageHandler {
    pub script_url: String,
    pub location: String,
    pub origin_check: String,
    pub reaches_sink: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}
