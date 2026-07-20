use std::collections::{HashMap, HashSet};

use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;

use crate::types::{
    ApiCall, AssessmentDisposition, EvidenceSource, FindingEvidence, JwtClaims, StorageAssessment,
    StorageRiskClass,
};

const MAX_NESTING_DEPTH: usize = 6;
const MAX_ASSESSMENTS: usize = 128;

struct Candidate {
    key: String,
    value: String,
    source: EvidenceSource,
    location: String,
    container: bool,
}

struct Classification {
    class: StorageRiskClass,
    severity: &'static str,
    disposition: AssessmentDisposition,
    claims: Option<JwtClaims>,
}

/// Analyze browser-visible material without issuing requests or validating credentials.
pub(crate) fn analyze(
    local_storage: &HashMap<String, String>,
    session_storage: &HashMap<String, String>,
    cookies: &[(&str, &str)],
    calls: &[ApiCall],
    runtime_state: &HashMap<String, String>,
) -> Vec<StorageAssessment> {
    analyze_at(
        local_storage,
        session_storage,
        cookies,
        calls,
        runtime_state,
        chrono::Utc::now().timestamp(),
    )
}

fn analyze_at(
    local_storage: &HashMap<String, String>,
    session_storage: &HashMap<String, String>,
    cookies: &[(&str, &str)],
    calls: &[ApiCall],
    runtime_state: &HashMap<String, String>,
    now_epoch: i64,
) -> Vec<StorageAssessment> {
    let mut candidates = Vec::new();
    collect_map(
        local_storage,
        "localStorage",
        EvidenceSource::Runtime,
        &mut candidates,
    );
    collect_map(
        session_storage,
        "sessionStorage",
        EvidenceSource::Runtime,
        &mut candidates,
    );
    collect_map(
        runtime_state,
        "runtime state",
        EvidenceSource::Runtime,
        &mut candidates,
    );

    for (name, value) in cookies {
        if !sensitive_key(name) && !public_key(name) && !jwt_shaped(value) {
            continue;
        }
        candidates.push(Candidate {
            key: (*name).to_owned(),
            value: (*value).to_owned(),
            source: EvidenceSource::Runtime,
            location: format!("Cookie `{name}`"),
            container: false,
        });
    }
    collect_url_parameters(calls, &mut candidates);

    let mut assessments: Vec<StorageAssessment> = Vec::new();
    let mut index: HashMap<(StorageRiskClass, String), usize> = HashMap::new();

    for candidate in candidates {
        if assessments.len() >= MAX_ASSESSMENTS {
            break;
        }
        let Some(classification) = classify(&candidate, now_epoch) else {
            continue;
        };
        let aggregate_key = (classification.class, candidate.value.clone());
        let evidence = FindingEvidence {
            source: candidate.source,
            location: Some(candidate.location),
            summary: evidence_summary(classification.class, &candidate.key),
        };

        if let Some(existing_index) = index.get(&aggregate_key).copied() {
            if let Some(existing) = assessments.get_mut(existing_index) {
                if !existing.keys.contains(&candidate.key) {
                    existing.keys.push(candidate.key);
                }
                if !existing.evidence.iter().any(|item| {
                    item.source == evidence.source && item.location == evidence.location
                }) {
                    existing.evidence.push(evidence);
                }
            }
            continue;
        }

        index.insert(aggregate_key, assessments.len());
        assessments.push(StorageAssessment {
            classification: classification.class,
            keys: vec![candidate.key],
            value: candidate.value,
            severity: classification.severity.to_owned(),
            disposition: classification.disposition,
            evidence: vec![evidence],
            jwt_claims: classification.claims,
            confidence: None,
        });
    }

    assessments
}

fn collect_map(
    values: &HashMap<String, String>,
    source_label: &str,
    source: EvidenceSource,
    candidates: &mut Vec<Candidate>,
) {
    for (key, raw) in values {
        let before = candidates.len();
        match serde_json::from_str::<Value>(raw) {
            Ok(value @ (Value::Object(_) | Value::Array(_))) => {
                collect_json(&value, key, source_label, source, 0, candidates);
                if candidates.len() == before && sensitive_key(key) {
                    candidates.push(Candidate {
                        key: key.clone(),
                        value: raw.clone(),
                        source,
                        location: format!("{source_label} `{key}`"),
                        container: true,
                    });
                }
            }
            Ok(Value::String(value)) => {
                push_scalar(key, &value, source_label, source, false, candidates);
            }
            _ => push_scalar(key, raw, source_label, source, false, candidates),
        }
    }
}

fn collect_json(
    value: &Value,
    path: &str,
    source_label: &str,
    source: EvidenceSource,
    depth: usize,
    candidates: &mut Vec<Candidate>,
) {
    if depth >= MAX_NESTING_DEPTH || candidates.len() >= MAX_ASSESSMENTS {
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                collect_json(
                    nested,
                    &format!("{path}.{key}"),
                    source_label,
                    source,
                    depth + 1,
                    candidates,
                );
            }
        }
        Value::Array(values) => {
            for (position, nested) in values.iter().enumerate() {
                collect_json(
                    nested,
                    &format!("{path}[{position}]"),
                    source_label,
                    source,
                    depth + 1,
                    candidates,
                );
            }
        }
        Value::String(text) => {
            push_scalar(path, text, source_label, source, false, candidates);
        }
        Value::Number(number) => push_scalar(
            path,
            &number.to_string(),
            source_label,
            source,
            false,
            candidates,
        ),
        Value::Bool(boolean) => push_scalar(
            path,
            &boolean.to_string(),
            source_label,
            source,
            false,
            candidates,
        ),
        Value::Null => {}
    }
}

fn push_scalar(
    key: &str,
    value: &str,
    source_label: &str,
    source: EvidenceSource,
    container: bool,
    candidates: &mut Vec<Candidate>,
) {
    let leaf = leaf_key(key);
    if !sensitive_key(leaf) && !public_key(leaf) && !jwt_shaped(value) {
        return;
    }
    if candidates.len() < MAX_ASSESSMENTS {
        candidates.push(Candidate {
            key: key.to_owned(),
            value: value.to_owned(),
            source,
            location: format!("{source_label} `{key}`"),
            container,
        });
    }
}

fn collect_url_parameters(calls: &[ApiCall], candidates: &mut Vec<Candidate>) {
    for call in calls {
        let Ok(mut parsed) = url::Url::parse(&call.url) else {
            continue;
        };
        let parameters: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        parsed.set_query(None);
        parsed.set_fragment(None);
        for (key, value) in parameters {
            if !sensitive_key(&key) && decode_jwt(&value, 0).is_none() {
                continue;
            }
            candidates.push(Candidate {
                key: key.clone(),
                value,
                source: EvidenceSource::Network,
                location: format!("{parsed} query parameter `{key}`"),
                container: false,
            });
        }
    }
}

fn classify(candidate: &Candidate, now_epoch: i64) -> Option<Classification> {
    let leaf = leaf_key(&candidate.key);
    if let Some(mut claims) = decode_jwt(&candidate.value, now_epoch) {
        let expired = claims.expired == Some(true);
        let public = public_key(leaf)
            || claims
                .roles
                .iter()
                .any(|role| matches!(normalized(role).as_str(), "anon" | "anonymous" | "public"));
        let privileged = claims.roles.iter().any(|role| privileged_term(role))
            || claims.scopes.iter().any(|scope| privileged_term(scope));

        let (class, severity, disposition) = if expired || public {
            (
                StorageRiskClass::PublicConfiguration,
                "info",
                AssessmentDisposition::Inventory,
            )
        } else if privileged {
            (
                StorageRiskClass::PrivilegedJwt,
                "high",
                AssessmentDisposition::Finding,
            )
        } else {
            (
                StorageRiskClass::AccessToken,
                "high",
                AssessmentDisposition::Finding,
            )
        };
        claims.roles.sort();
        claims.roles.dedup();
        claims.scopes.sort();
        claims.scopes.dedup();
        return Some(Classification {
            class,
            severity,
            disposition,
            claims: Some(claims),
        });
    }

    if public_key(leaf) && !sensitive_key(leaf) {
        return Some(Classification {
            class: StorageRiskClass::PublicConfiguration,
            severity: "info",
            disposition: AssessmentDisposition::Inventory,
            claims: None,
        });
    }

    if jwt_shaped(&candidate.value) && sensitive_key(leaf) {
        return Some(Classification {
            class: StorageRiskClass::AmbiguousSensitiveName,
            severity: "low",
            disposition: AssessmentDisposition::Lead,
            claims: None,
        });
    }

    let class = if refresh_key(leaf) {
        Some(StorageRiskClass::RefreshToken)
    } else if access_key(leaf) {
        Some(StorageRiskClass::AccessToken)
    } else if session_key(leaf) {
        Some(StorageRiskClass::PersistedSession)
    } else {
        None
    }?;

    if candidate.container || !credential_like(&candidate.value) {
        return Some(Classification {
            class: StorageRiskClass::AmbiguousSensitiveName,
            severity: "low",
            disposition: AssessmentDisposition::Lead,
            claims: None,
        });
    }

    let severity = if class == StorageRiskClass::PersistedSession {
        "medium"
    } else {
        "high"
    };
    Some(Classification {
        class,
        severity,
        disposition: AssessmentDisposition::Finding,
        claims: None,
    })
}

fn jwt_shaped(value: &str) -> bool {
    let mut parts = value.trim().split('.');
    parts.next().is_some_and(|part| !part.is_empty())
        && parts.next().is_some_and(|part| !part.is_empty())
        && parts.next().is_some_and(|part| !part.is_empty())
        && parts.next().is_none()
}

fn decode_jwt(value: &str, now_epoch: i64) -> Option<JwtClaims> {
    let token = value
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| value.trim().strip_prefix("bearer "))
        .unwrap_or(value.trim());
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    let payload: Value = serde_json::from_slice(&decoded).ok()?;
    let object = payload.as_object()?;

    let expires_at = object.get("exp").and_then(Value::as_i64);
    let mut claims = JwtClaims {
        issuer: object.get("iss").and_then(Value::as_str).map(str::to_owned),
        audience: values_for(object.get("aud"), false),
        expires_at,
        expired: expires_at.map(|expiry| expiry <= now_epoch),
        roles: values_for_keys(object, &["role", "roles", "groups"], false),
        scopes: values_for_keys(object, &["scope", "scp", "permissions"], true),
        tenants: values_for_keys(
            object,
            &["tenant", "tenant_id", "tid", "organization_id", "org_id"],
            false,
        ),
        accounts: values_for_keys(object, &["account", "account_id"], false),
    };

    if let Some(realm_roles) = object
        .get("realm_access")
        .and_then(Value::as_object)
        .and_then(|realm| realm.get("roles"))
    {
        claims.roles.extend(values_for(Some(realm_roles), false));
    }
    if let Some(metadata) = object.get("app_metadata").and_then(Value::as_object) {
        claims
            .roles
            .extend(values_for_keys(metadata, &["role", "roles"], false));
    }
    Some(claims)
}

fn values_for_keys(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
    split_words: bool,
) -> Vec<String> {
    keys.iter()
        .flat_map(|key| values_for(object.get(*key), split_words))
        .collect()
}

fn values_for(value: Option<&Value>, split_words: bool) -> Vec<String> {
    match value {
        Some(Value::String(value)) if split_words => {
            value.split_whitespace().map(str::to_owned).collect()
        }
        Some(Value::String(value)) => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn leaf_key(key: &str) -> &str {
    key.rsplit(['.', '['])
        .next()
        .unwrap_or(key)
        .trim_end_matches(']')
}

fn normalized(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn contains_any(key: &str, terms: &[&str]) -> bool {
    let key = normalized(key);
    terms.iter().any(|term| key.contains(term))
}

fn refresh_key(key: &str) -> bool {
    contains_any(key, &["refresh_token", "refreshtoken", "refresh_jwt"])
}

fn access_key(key: &str) -> bool {
    contains_any(
        key,
        &[
            "access_token",
            "accesstoken",
            "auth_token",
            "authtoken",
            "bearer_token",
            "id_token",
            "idtoken",
            "jwt",
        ],
    ) || matches!(
        normalized(key).as_str(),
        "token" | "authorization" | "bearer"
    )
}

fn session_key(key: &str) -> bool {
    let key = normalized(key);
    matches!(
        key.as_str(),
        "session" | "session_id" | "sessionid" | "sid" | "auth" | "authentication"
    ) || key.contains("session")
        || key.contains("sessid")
        || key.contains("session_token")
        || key.contains("sessiontoken")
}

fn sensitive_key(key: &str) -> bool {
    refresh_key(key) || access_key(key) || session_key(key)
}

fn public_key(key: &str) -> bool {
    contains_any(
        key,
        &[
            "public_config",
            "publicconfig",
            "publishable",
            "anon_key",
            "anonkey",
            "client_id",
            "clientid",
            "api_url",
            "apiurl",
            "base_url",
            "baseurl",
            "endpoint",
        ],
    )
}

fn privileged_term(value: &str) -> bool {
    let normalized = normalized(value);
    let terms: HashSet<&str> = normalized
        .split('_')
        .filter(|term| !term.is_empty())
        .collect();
    normalized == "*"
        || terms.iter().any(|term| {
            matches!(
                *term,
                "admin"
                    | "administrator"
                    | "root"
                    | "superuser"
                    | "owner"
                    | "maintainer"
                    | "service"
                    | "write"
            )
        })
        || normalized.contains("service_role")
        || normalized.contains("full_access")
}

fn credential_like(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 16 || value.chars().any(char::is_whitespace) {
        return false;
    }
    let distinct: HashSet<char> = value.chars().collect();
    distinct.len() >= 6 && url::Url::parse(value).is_err()
}

fn evidence_summary(class: StorageRiskClass, key: &str) -> String {
    let observation = match class {
        StorageRiskClass::PrivilegedJwt => "Privileged JWT claims observed",
        StorageRiskClass::AccessToken => "Access-token material observed",
        StorageRiskClass::RefreshToken => "Refresh-token material observed",
        StorageRiskClass::PersistedSession => "Persisted session material observed",
        StorageRiskClass::PublicConfiguration => "Public or non-actionable configuration observed",
        StorageRiskClass::AmbiguousSensitiveName => {
            "Sensitive name observed without credential-shaped material"
        }
    };
    format!("{observation} under `{key}`")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        let header = general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = general_purpose::URL_SAFE_NO_PAD.encode(payload);
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn privileged_jwt_decodes_security_claims() {
        let token = jwt(
            r#"{"iss":"https://issuer.example","aud":["api"],"exp":2000,"role":"admin","scope":"read write","tenant_id":"tenant-1","account_id":"acct-2"}"#,
        );
        let local = HashMap::from([("access_token".to_owned(), token)]);
        let results = analyze_at(&local, &HashMap::new(), &[], &[], &HashMap::new(), 1000);

        assert_eq!(results.len(), 1);
        let result = results.first().expect("assessment");
        assert_eq!(result.classification, StorageRiskClass::PrivilegedJwt);
        assert_eq!(result.disposition, AssessmentDisposition::Finding);
        let claims = result.jwt_claims.as_ref().expect("claims");
        assert_eq!(claims.issuer.as_deref(), Some("https://issuer.example"));
        assert_eq!(claims.audience, vec!["api"]);
        assert_eq!(claims.roles, vec!["admin"]);
        assert_eq!(claims.scopes, vec!["read", "write"]);
        assert_eq!(claims.tenants, vec!["tenant-1"]);
        assert_eq!(claims.accounts, vec!["acct-2"]);
        assert_eq!(claims.expired, Some(false));
    }

    #[test]
    fn expired_and_public_tokens_are_inventory() {
        let expired = jwt(r#"{"exp":999,"role":"authenticated"}"#);
        let public = jwt(r#"{"exp":2000,"role":"anon"}"#);
        let local = HashMap::from([
            ("access_token".to_owned(), expired),
            ("anon_key".to_owned(), public),
        ]);
        let results = analyze_at(&local, &HashMap::new(), &[], &[], &HashMap::new(), 1000);

        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|result| result.disposition == AssessmentDisposition::Inventory));
    }

    #[test]
    fn opaque_tokens_are_findings_but_names_alone_are_leads() {
        let session = HashMap::from([
            (
                "refreshToken".to_owned(),
                "r4nd0m-refresh-token-material-12345".to_owned(),
            ),
            ("session".to_owned(), "enabled".to_owned()),
        ]);
        let results = analyze_at(&HashMap::new(), &session, &[], &[], &HashMap::new(), 1000);

        assert!(results.iter().any(|result| {
            result.classification == StorageRiskClass::RefreshToken
                && result.disposition == AssessmentDisposition::Finding
        }));
        assert!(results.iter().any(|result| {
            result.classification == StorageRiskClass::AmbiguousSensitiveName
                && result.disposition == AssessmentDisposition::Lead
        }));
    }

    #[test]
    fn malformed_jwt_does_not_become_a_token_finding() {
        let local = HashMap::from([(
            "access_token".to_owned(),
            "eyJ.invalid.signature".to_owned(),
        )]);
        let results = analyze_at(&local, &HashMap::new(), &[], &[], &HashMap::new(), 1000);

        assert_eq!(results.len(), 1);
        assert_eq!(
            results.first().map(|result| result.disposition),
            Some(AssessmentDisposition::Lead)
        );
    }

    #[test]
    fn captured_url_provenance_excludes_the_token_value() {
        let call = ApiCall {
            url: "https://example.test/callback?access_token=secret-material-1234567890".to_owned(),
            method: "GET".to_owned(),
            status: 200,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            response_content_type: None,
            request_body: None,
            response_body: None,
            response_size: 0,
        };
        let results = analyze_at(
            &HashMap::new(),
            &HashMap::new(),
            &[],
            &[call],
            &HashMap::new(),
            1000,
        );

        let evidence = results
            .first()
            .and_then(|result| result.evidence.first())
            .and_then(|item| item.location.as_deref())
            .expect("location");
        assert!(evidence.contains("query parameter `access_token`"));
        assert!(!evidence.contains("secret-material"));
        assert_eq!(
            results
                .first()
                .and_then(|result| result.evidence.first())
                .map(|item| item.source),
            Some(EvidenceSource::Network)
        );
    }

    #[test]
    fn nested_runtime_tokens_are_analyzed_without_network_activity() {
        let runtime = HashMap::from([(
            "__INITIAL_STATE__".to_owned(),
            r#"{"auth":{"refresh_token":"refresh-material-abcdefghijklmnopqrstuvwxyz"}}"#
                .to_owned(),
        )]);
        let results = analyze_at(&HashMap::new(), &HashMap::new(), &[], &[], &runtime, 1000);

        assert_eq!(results.len(), 1);
        assert_eq!(
            results.first().map(|result| result.classification),
            Some(StorageRiskClass::RefreshToken)
        );
    }
}
