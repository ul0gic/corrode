// Does:  Defines the serializable scan result and observation types.
// Holds: Additive optional collections deserialize empty and are omitted when empty.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete scan result and its observations.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ScanResult {
    /// Observed URL.
    pub url: String,
    /// UTC scan timestamp in RFC 3339 format.
    pub timestamp: String,
    /// Secret findings grouped by pattern.
    pub secrets: HashMap<String, Vec<SecretFinding>>,
    /// Network observations.
    pub network: NetworkAnalysis,
    /// Document observations.
    pub dom: DomAnalysis,
    /// JavaScript observations.
    pub javascript: JavaScriptAnalysis,
    /// Security posture observations.
    pub security: SecurityAnalysis,
    /// Detected technology names.
    pub technologies: Vec<String>,
    /// Detected technology versions.
    pub technology_versions: Vec<TechnologyVersion>,
    /// Security assessments.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Per-advisory evidence comparisons for this scan. Older reports lack coverage data.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_checks: Vec<AdvisoryCheck>,
    /// Storage assessments; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage_assessments: Vec<StorageAssessment>,
    /// Extracted comments.
    pub comments: Vec<Comment>,
    /// API test results; the current scan workflow leaves this empty.
    pub api_tests: Vec<ApiTestResult>,
    /// Recovered source-map evidence; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_maps_intel: Vec<SourceMapIntel>,
    /// Framework manifests; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub framework_manifests: Vec<FrameworkManifest>,
    /// Inferred routes; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_surface: Vec<RouteSurface>,
    /// Static taint flows; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taint_flows: Vec<TaintFlow>,
    /// Gadget candidates; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gadgets: Vec<Gadget>,
    /// Message handlers; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_message_handlers: Vec<PostMessageHandler>,
    /// Whether the scan succeeded.
    pub success: bool,
    /// Scan failure message, if present.
    pub error: Option<String>,
}

/// Detected technology and optional version.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TechnologyVersion {
    /// Name.
    pub name: String,
    /// Detected version, if available.
    pub version: Option<String>,
    /// Method used to detect the technology.
    pub detection_method: String,
}

/// Matches for one secret pattern and source.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretFinding {
    /// Source of the observation.
    pub source: String,
    /// Matched values, which may contain secrets.
    pub matches: Vec<String>,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Comment extracted from a source.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Comment {
    /// Source of the observation.
    pub source: String,
    /// Comment classification.
    pub comment_type: String,
    /// Extracted content.
    pub content: String,
}

/// Network observations from a scan.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkAnalysis {
    /// Number of captured requests.
    pub total_requests: usize,
    /// URLs classified as API calls.
    pub api_calls: Vec<String>,
    /// Captured URLs that do not contain the scanned URL as a substring.
    pub third_party: Vec<String>,
    /// WebSocket URLs; the current scan workflow leaves this empty.
    pub websockets: Vec<String>,
    /// Redirect URLs; the current scan workflow leaves this empty.
    pub redirects: Vec<String>,
    /// Authentication schemes; the current scan workflow leaves this empty.
    pub auth_schemes: Vec<String>,
    /// All captured HTTP-like call details, including non-API calls.
    pub calls: Vec<ApiCall>,
}

/// Captured request and response details.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiCall {
    /// Observed URL.
    pub url: String,
    /// HTTP method.
    pub method: String,
    /// Response status, or zero when unavailable.
    pub status: u16,
    /// Captured request headers.
    pub request_headers: HashMap<String, String>,
    /// Captured response headers.
    pub response_headers: HashMap<String, String>,
    /// Response content type, if captured.
    pub response_content_type: Option<String>,
    /// Concatenated CDP post-data entry strings, if available; they may contain secrets.
    pub request_body: Option<String>,
    /// CDP response body string, if captured; it may be encoded and may contain secrets.
    pub response_body: Option<String>,
    /// CDP response body string length in bytes, or zero if unavailable; it is not decoded.
    pub response_size: usize,
}

/// Observed document and browser storage details.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DomAnalysis {
    /// Number of script elements.
    pub scripts: usize,
    /// Observed forms.
    pub forms: Vec<FormInfo>,
    /// Observed hidden inputs.
    pub hidden_inputs: Vec<HiddenInput>,
    /// Observed iframe URLs.
    pub iframes: Vec<String>,
    /// Observed meta tags.
    pub meta_tags: Vec<MetaTag>,
    /// Data attributes of elements selected by API, URL, endpoint, key, token, or config attributes.
    pub data_attributes: Vec<DataAttribute>,
    /// Local storage entries, including their unredacted values.
    pub local_storage: HashMap<String, String>,
    /// Session storage entries, including their unredacted values.
    pub session_storage: HashMap<String, String>,
    /// Observed cookie properties.
    pub cookies: Vec<CookieInfo>,
    /// Number of distinct href and src attribute values.
    pub all_links: usize,
}

/// Observed form details.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FormInfo {
    /// Form action.
    pub action: String,
    /// HTTP method.
    pub method: String,
    /// Number of elements in the form’s `elements` collection.
    pub input_count: usize,
}

/// Observed meta tag.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MetaTag {
    /// Name.
    pub name: String,
    /// Extracted content.
    pub content: String,
}

/// Observed hidden form input.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HiddenInput {
    /// Name.
    pub name: String,
    /// Observed value.
    pub value: String,
}

/// Element and its data attributes.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataAttribute {
    /// Element tag name.
    pub tag: String,
    /// Attribute names and values.
    pub attributes: HashMap<String, String>,
}

/// Observed cookie properties.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CookieInfo {
    /// Name.
    pub name: String,
    /// Cookie domain.
    pub domain: String,
    /// Cookie secure flag.
    pub secure: bool,
    /// Cookie `HttpOnly` flag.
    pub http_only: bool,
    /// Cookie `SameSite` value.
    pub same_site: String,
}

/// Finding extracted from a JavaScript syntax tree.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AstFinding {
    /// Classification.
    pub kind: String,
    /// Observed value.
    pub value: String,
    /// Source location.
    pub location: String,
    /// Surrounding context.
    pub context: String,
}

/// JavaScript observations from a scan.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct JavaScriptAnalysis {
    /// Observed window object values.
    pub window_objects: HashMap<String, String>,
    /// Source-map references.
    pub source_maps: Vec<String>,
    /// Detected debug indicators.
    pub debug_mode: Vec<String>,
    /// Discovered endpoint candidates.
    pub api_endpoints: Vec<DiscoveredEndpoint>,
    /// JavaScript syntax-tree findings.
    pub ast_findings: Vec<AstFinding>,
}

/// Endpoint candidate extracted from JavaScript.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveredEndpoint {
    /// Observed URL.
    pub url: String,
    /// HTTP method.
    pub method: String,
    /// Source of the observation.
    pub source: String,
    /// Authentication requirement, if determined; endpoint extraction leaves this unset.
    pub auth_required: Option<bool>,
    /// Extracted URL parameter names.
    pub parameters: Vec<String>,
}

/// Security posture observations.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecurityAnalysis {
    /// Missing security headers.
    pub missing_headers: Vec<String>,
    /// CORS observations.
    pub cors_issues: Vec<String>,
    /// Insecure cookie observations.
    pub insecure_cookies: Vec<String>,
    /// Mixed-content observations.
    pub mixed_content: Vec<String>,
}

/// Comparison of one published advisory with the available evidence.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdvisoryCheck {
    /// Advisory identifiers covered by this comparison.
    pub advisory: String,
    /// Source of evidence required by the rule.
    pub method: String,
    /// Result of comparing evidence with advisory criteria.
    #[serde(flatten)]
    pub outcome: AdvisoryOutcome,
}

/// Advisory comparison outcomes describe evidence and leave host exploitability unverified.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdvisoryOutcome {
    /// Supplied evidence satisfies the rule.
    Matched { details: Vulnerability },
    /// The available evidence falls outside this rule's criteria.
    NoMatch { reason: String },
    /// Required evidence was missing or unsuitable.
    NotAssessed { reason: String },
}

/// Security assessment and its supporting evidence.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    /// Assessment type.
    pub vuln_type: String,
    /// Severity label.
    pub severity: String,
    /// Assessment description.
    pub description: String,
    /// Suggested remediation.
    pub remediation: String,
    /// Associated URL, if available.
    pub url: Option<String>,
    /// Reporting disposition; defaults to finding.
    #[serde(default)]
    pub disposition: AssessmentDisposition,
    /// Supporting observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Reporting disposition; only findings contribute to headline risk.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentDisposition {
    /// Actionable finding and the default disposition.
    #[default]
    Finding,
    /// Observation requiring manual validation.
    Lead,
    /// Informational inventory.
    Inventory,
}

/// Typed observation supporting an assessment.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct FindingEvidence {
    /// Origin of the observation.
    pub source: EvidenceSource,
    /// Source location, if available.
    pub location: Option<String>,
    /// Observation summary.
    pub summary: String,
}

/// Classification of browser-visible session material.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageAssessment {
    /// Storage risk classification.
    pub classification: StorageRiskClass,
    /// Associated keys or parameter names from the observed sources.
    pub keys: Vec<String>,
    /// Unredacted value used for the assessment.
    pub value: String,
    /// Severity label.
    pub severity: String,
    /// Reporting disposition.
    pub disposition: AssessmentDisposition,
    /// Supporting observations.
    pub evidence: Vec<FindingEvidence>,
    /// Decoded claims, if the value was parsed as a JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_claims: Option<JwtClaims>,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Classification of browser-visible session material.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StorageRiskClass {
    /// JWT with privileged claims.
    PrivilegedJwt,
    /// Access token.
    AccessToken,
    /// Refresh token.
    RefreshToken,
    /// Persisted session material.
    PersistedSession,
    /// Public configuration value.
    PublicConfiguration,
    /// Sensitive-looking name with ambiguous content.
    AmbiguousSensitiveName,
}

/// Locally decoded JWT claims; the token is not validated.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct JwtClaims {
    /// JWT issuer.
    pub issuer: Option<String>,
    /// JWT audiences.
    pub audience: Vec<String>,
    /// Expiration time as Unix seconds, if present.
    pub expires_at: Option<i64>,
    /// Expiration assessment, if determined.
    pub expired: Option<bool>,
    /// Decoded roles.
    pub roles: Vec<String>,
    /// Decoded scopes.
    pub scopes: Vec<String>,
    /// Decoded tenants.
    pub tenants: Vec<String>,
    /// Decoded accounts.
    pub accounts: Vec<String>,
}

/// Result of an API test.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiTestResult {
    /// Tested endpoint.
    pub endpoint: String,
    /// Test classification.
    pub test_type: String,
    /// Severity label.
    pub severity: String,
    /// Whether the test indicated a vulnerability.
    pub vulnerable: bool,
    /// Evidence produced by the test.
    pub evidence: String,
    /// Test details.
    pub details: String,
}

/// Confidence band ordered from low to high.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    /// Low confidence.
    Low,
    /// Medium confidence.
    Medium,
    /// High confidence.
    High,
}

/// Origin of an observation used in confidence scoring.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Installed component and configuration declared by the deployment owner.
    Deployment,
    /// Browser runtime observation.
    Runtime,
    /// Network observation.
    Network,
    /// JavaScript syntax-tree observation.
    Ast,
    /// Document observation.
    Dom,
    /// HTTP header observation.
    Header,
    /// Source-map observation.
    SourceMap,
}

/// Contribution to a confidence score.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfidenceFactor {
    /// Scoring dimension.
    pub dimension: String,
    /// Score adjustment.
    pub delta: i8,
    /// Reason for the adjustment.
    pub note: String,
}

/// Confidence band, score, and scoring factors.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Confidence {
    /// Confidence band.
    pub level: ConfidenceLevel,
    /// Confidence score, clamped to 0–100 by the scorer.
    pub score: u8,
    /// Scoring factors; omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<ConfidenceFactor>,
}

/// Evidence recovered from a source map.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceMapIntel {
    /// Source-map URL.
    pub map_url: String,
    /// Associated script URL.
    pub script_url: String,
    /// Recovered source paths.
    pub recovered_sources: Vec<String>,
    /// Whether a retained source has nonempty embedded content.
    pub has_sources_content: bool,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Parsed framework build or route manifest.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrameworkManifest {
    /// Framework name.
    pub framework: String,
    /// Manifest classification.
    pub manifest_type: String,
    /// Routes extracted from the manifest.
    pub routes: Vec<String>,
    /// Build identifier, if present.
    pub build_id: Option<String>,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Discovered route, API path, controller, or component.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RouteSurface {
    /// Discovered path.
    pub path: String,
    /// Classification.
    pub kind: String,
    /// Source of the observation.
    pub source: String,
    /// Whether the route is dynamic.
    pub dynamic: bool,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Static source-to-sink flow and runtime observation state.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaintFlow {
    /// Taint source.
    pub source: String,
    /// Taint sink.
    pub sink: String,
    /// Intermediate steps between source and sink.
    pub path: Vec<String>,
    /// Associated script URL.
    pub script_url: String,
    /// Source location.
    pub location: String,
    /// Runtime match flag; the scan workflow currently leaves this false.
    pub runtime_observed: bool,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Classified client-side gadget candidate.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Gadget {
    /// Gadget category.
    pub category: String,
    /// Assessment description.
    pub description: String,
    /// Associated script URL.
    pub script_url: String,
    /// Manual assessment hint.
    pub exploitability_hint: String,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

/// Message handler and origin-check assessment.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostMessageHandler {
    /// Associated script URL.
    pub script_url: String,
    /// Source location.
    pub location: String,
    /// Origin-check classification.
    pub origin_check: String,
    /// Whether the handler reaches a sink.
    pub reaches_sink: bool,
    /// Confidence assessment; absent when unscored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}
