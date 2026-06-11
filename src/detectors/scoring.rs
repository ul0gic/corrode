use crate::detectors::confidence::{
    self, EntropySignal, Exploitability, FindingCategory, FindingInputs, Origin, Suppressor,
};
use crate::types::{
    Confidence, EvidenceSource, Gadget, PostMessageHandler, RouteSurface, ScanResult,
    SecretFinding, SourceMapIntel, TaintFlow, Vulnerability,
};

/// Three-state, not the `bool` `is_first_party` helpers: those default unknown
/// origins to first-party, erasing the neutral `Unknown` band the scorer needs.
pub fn classify_origin(url: &str, target_host: Option<&str>) -> Origin {
    let Some(target) = target_host else {
        return Origin::Unknown;
    };
    let target = target.to_lowercase();

    match url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned).map(|h| h.to_lowercase()))
    {
        Some(host) => {
            if host == target
                || host.ends_with(&format!(".{target}"))
                || target.ends_with(&format!(".{host}"))
            {
                Origin::FirstParty
            } else {
                Origin::ThirdParty
            }
        }
        // A relative/opaque reference (no parseable host) names an in-page or
        // same-origin artifact far more often than a third-party one.
        None => Origin::FirstParty,
    }
}

/// Whether a URL points at a source-map asset (`.map`), ignoring any query
/// string and case. Used to pick SourceMap-trust over Network/AST.
fn is_map_url(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.to_lowercase().ends_with(".map")
}

/// Score every finding type on the result in place. `None` confidence fields are
/// filled; nothing else is touched (severity is never read or written).
pub fn score_all(result: &mut ScanResult, target_host: Option<&str>) {
    for (pattern_name, findings) in &mut result.secrets {
        for finding in findings.iter_mut() {
            finding.confidence = Some(score_secret(pattern_name, finding, target_host));
        }
    }
    for vuln in &mut result.vulnerabilities {
        vuln.confidence = Some(score_vulnerability(vuln, target_host));
    }
    for intel in &mut result.source_maps_intel {
        intel.confidence = Some(score_source_map(intel, target_host));
    }
    for flow in &mut result.taint_flows {
        flow.confidence = Some(score_taint_flow(flow, target_host));
    }
    for gadget in &mut result.gadgets {
        gadget.confidence = Some(score_gadget(gadget, target_host));
    }
    for handler in &mut result.post_message_handlers {
        handler.confidence = Some(score_post_message(handler, target_host));
    }
    for route in &mut result.route_surface {
        route.confidence = Some(score_route(route, target_host));
    }
}

// --- SecretFinding -------------------------------------------------------

/// Map a collector's `SecretScanner` source label to the `EvidenceSource` it implies.
fn evidence_source_for_label(label: &str) -> EvidenceSource {
    if label.starts_with("Window Object:") {
        EvidenceSource::Runtime
    } else if label.starts_with("Source Map:") {
        EvidenceSource::SourceMap
    } else if label.starts_with("Script:") {
        // An external script URL: observed on the wire, scanned statically. Treat
        // a remote bundle as Network-trust (it was fetched); inline stays AST.
        EvidenceSource::Network
    } else if label == "localStorage"
        || label == "sessionStorage"
        || label.starts_with("Hidden Input:")
        || label.starts_with("Data Attributes:")
        || label.starts_with("Cookie")
    {
        EvidenceSource::Dom
    } else {
        // "Inline Script", "HTML", and any custom label: static page text.
        EvidenceSource::Ast
    }
}

/// Whether a matched secret value looks like a placeholder / test value.
fn looks_like_placeholder(value: &str) -> bool {
    const NEEDLES: [&str; 9] = [
        "example",
        "test",
        "xxxx",
        "your_",
        "your-",
        "changeme",
        "placeholder",
        "dummy",
        "akiaiosfodnn7example",
    ];
    let lower = value.to_lowercase();
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        return true;
    }
    // An all-zero / single-repeated-char run is a stand-in, not a real secret.
    let trimmed = value.trim();
    trimmed.len() >= 8 && trimmed.chars().all(|c| c == '0')
}

/// Shannon entropy (bits/char) over the variable portion: fixed prefixes are
/// stripped first so a long literal prefix can't deflate a real key's entropy.
fn shannon_entropy(value: &str) -> f64 {
    let stripped = strip_known_prefix(value);
    let chars: Vec<char> = stripped.chars().collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0) += 1;
    }
    let len = f64::from(u32::try_from(chars.len()).unwrap_or(u32::MAX));
    counts
        .values()
        .map(|&n| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum()
}

fn strip_known_prefix(value: &str) -> &str {
    const PREFIXES: [&str; 8] = [
        "sk_live_", "pk_live_", "sk_test_", "pk_test_", "ghp_", "AKIA", "xoxb-", "xoxp-",
    ];
    for prefix in PREFIXES {
        if let Some(rest) = value.strip_prefix(prefix) {
            return rest;
        }
    }
    value
}

/// Entropy signal for a secret value, or `NotApplicable` for short tokens where
/// entropy carries no signal (a 6-char value is too short to judge).
fn entropy_signal(value: &str) -> EntropySignal {
    let variable = strip_known_prefix(value);
    if variable.len() < 12 {
        return EntropySignal::NotApplicable;
    }
    let bits = shannon_entropy(value);
    if bits < 3.0 {
        EntropySignal::Low
    } else if bits >= 4.0 {
        EntropySignal::High
    } else {
        EntropySignal::NotApplicable
    }
}

/// Exploitability hint from the pattern name (brief §3.7). JWT role distinctions
/// and key-class (live vs publishable) drive actionability.
fn exploitability_for_pattern(pattern_name: &str) -> Exploitability {
    match pattern_name {
        "supabase_service_role"
        | "supabase_secret"
        | "aws_secret"
        | "private_key"
        | "stripe_secret_key"
        | "postgres_url"
        | "mongodb_url"
        | "mysql_url"
        | "redis_url" => Exploitability::PrivilegedNoPrecondition,
        "supabase_anon_jwt"
        | "supabase_publishable"
        | "stripe_publishable_key"
        | "mapbox_pk"
        | "sentry_dsn" => Exploitability::Benign,
        // Context-keyword-gated but structureless: a 20-char value that can't be told
        // apart from a generic identifier. Downgraded so it can't reach High on its own
        // without corroboration (SEC-002).
        "pagerduty_api_key" => Exploitability::PreconditionUnmet,
        _ => Exploitability::None,
    }
}

pub(crate) fn score_secret(
    pattern_name: &str,
    finding: &SecretFinding,
    target_host: Option<&str>,
) -> Confidence {
    let source = evidence_source_for_label(&finding.source);
    // One `SecretFinding` per source label is one signal; its match list does not
    // multiply that (three regex hits in one bundle are still one corroboration).
    let evidence_count = 1;

    let representative = finding.matches.first().map_or("", String::as_str);
    let suppressor = if looks_like_placeholder(representative) {
        Some(Suppressor::PlaceholderOrTestValue)
    } else {
        None
    };

    // Origin from the script URL embedded in a `Script: <url>` label, else
    // first-party (window/storage/inline/HTML are same-origin artifacts).
    let origin = finding
        .source
        .strip_prefix("Script: ")
        .map_or(Origin::FirstParty, |url| classify_origin(url, target_host));

    let runtime_observed = matches!(source, EvidenceSource::Runtime);

    let inputs = FindingInputs {
        sources: vec![source],
        evidence_count,
        category: FindingCategory::SecretOrVersion,
        origin,
        runtime_observed,
        entropy: entropy_signal(representative),
        constant_assignment: false,
        exploitability: exploitability_for_pattern(pattern_name),
        suppressor,
    };
    confidence::score(&inputs)
}

// --- Vulnerability -------------------------------------------------------

pub(crate) fn score_vulnerability(vuln: &Vulnerability, target_host: Option<&str>) -> Confidence {
    // `inferred:` prefix means the surface is present but no concrete version was
    // observed: the CVE precondition is not met.
    let inferred = vuln.description.to_lowercase().contains("inferred:");

    let source = vuln.url.as_deref().map_or(EvidenceSource::Header, |url| {
        // A version observed in a recovered source map vs on the wire vs a header.
        if is_map_url(url) {
            EvidenceSource::SourceMap
        } else {
            EvidenceSource::Network
        }
    });

    let origin = vuln
        .url
        .as_deref()
        .map_or(Origin::FirstParty, |url| classify_origin(url, target_host));

    let exploitability = if inferred {
        Exploitability::PreconditionUnmet
    } else {
        // A concrete observed version match is a met precondition for the CVE.
        Exploitability::PrivilegedNoPrecondition
    };

    let inputs = FindingInputs {
        sources: vec![source],
        evidence_count: 1,
        category: FindingCategory::SecretOrVersion,
        origin,
        runtime_observed: false,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability,
        suppressor: None,
    };
    confidence::score(&inputs)
}

// --- SourceMapIntel ------------------------------------------------------

pub(crate) fn score_source_map(intel: &SourceMapIntel, target_host: Option<&str>) -> Confidence {
    // Recovered source is concrete; corroboration scales with distinct artifacts.
    let evidence_count = u32::try_from(intel.recovered_sources.len())
        .unwrap_or(u32::MAX)
        .max(1);
    let inputs = FindingInputs {
        sources: vec![EvidenceSource::SourceMap],
        evidence_count,
        category: FindingCategory::SecretOrVersion,
        origin: classify_origin(&intel.script_url, target_host),
        runtime_observed: false,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability: Exploitability::None,
        suppressor: None,
    };
    confidence::score(&inputs)
}

// --- RouteSurface --------------------------------------------------------

pub(crate) fn score_route(route: &RouteSurface, target_host: Option<&str>) -> Confidence {
    // Routes recovered from a `.map` source are SourceMap-trust; those parsed from
    // in-page manifest state are Runtime; everything else is AST (static bundle).
    let source = if is_map_url(&route.source) {
        EvidenceSource::SourceMap
    } else if route.source.starts_with("__") {
        EvidenceSource::Runtime
    } else {
        EvidenceSource::Ast
    };
    let inputs = FindingInputs {
        sources: vec![source],
        evidence_count: 1,
        category: FindingCategory::SecretOrVersion,
        origin: classify_origin(&route.source, target_host),
        runtime_observed: matches!(source, EvidenceSource::Runtime),
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability: Exploitability::None,
        suppressor: None,
    };
    confidence::score(&inputs)
}

// --- TaintFlow -----------------------------------------------------------

/// Exploitability of a taint flow from its sink shape. HTML/code-execution sinks
/// fed by a controllable source are actionable; navigation-only is weaker.
fn taint_exploitability(sink: &str) -> Exploitability {
    let lower = sink.to_lowercase();
    if lower.contains("eval")
        || lower.contains("function")
        || lower.contains("innerhtml")
        || lower.contains("outerhtml")
        || lower.contains("document.write")
        || lower.contains("insertadjacenthtml")
    {
        Exploitability::PrivilegedNoPrecondition
    } else {
        // location/iframe/form navigation: actionable only under conditions.
        Exploitability::PreconditionUnmet
    }
}

/// Scoring-side backstop to the upstream taint allowlist: a text-only sink or a
/// known auto-escaping step in the path forces the flow to Low.
fn taint_suppressor(flow: &TaintFlow) -> Option<Suppressor> {
    let sink = flow.sink.to_lowercase();
    if sink.contains("textcontent") || sink.contains("innertext") {
        return Some(Suppressor::AllowlistedSafeSink);
    }
    let sanitized = flow.path.iter().any(|step| {
        let step = step.to_lowercase();
        step.contains("sanitize")
            || step.contains("dompurify")
            || step.contains("escapehtml")
            || step.contains("encodeuri")
    });
    if sanitized {
        return Some(Suppressor::FrameworkSanitizedPath);
    }
    None
}

pub(crate) fn score_taint_flow(flow: &TaintFlow, target_host: Option<&str>) -> Confidence {
    // A runtime-observed flow corroborates the static one: two independent signals.
    let evidence_count = if flow.runtime_observed { 2 } else { 1 };
    let mut sources = vec![EvidenceSource::Ast];
    if flow.runtime_observed {
        sources.push(EvidenceSource::Runtime);
    }
    let inputs = FindingInputs {
        sources,
        evidence_count,
        category: FindingCategory::Taint,
        origin: classify_origin(&flow.script_url, target_host),
        runtime_observed: flow.runtime_observed,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability: taint_exploitability(&flow.sink),
        suppressor: taint_suppressor(flow),
    };
    confidence::score(&inputs)
}

// --- Gadget --------------------------------------------------------------

pub(crate) fn score_gadget(gadget: &Gadget, target_host: Option<&str>) -> Confidence {
    // The free-text exploitability hint drives actionability; parse its keywords.
    let hint = gadget.exploitability_hint.to_lowercase();
    let exploitability = if hint.contains("requires") || hint.contains("strict") {
        Exploitability::PreconditionUnmet
    } else if hint.contains("unsafe-inline") || hint.contains("unsafe-eval") {
        Exploitability::PrivilegedNoPrecondition
    } else {
        Exploitability::None
    };
    let inputs = FindingInputs {
        sources: vec![EvidenceSource::Ast],
        evidence_count: 1,
        category: FindingCategory::Taint,
        origin: classify_origin(&gadget.script_url, target_host),
        runtime_observed: false,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability,
        suppressor: None,
    };
    confidence::score(&inputs)
}

// --- PostMessageHandler --------------------------------------------------

pub(crate) fn score_post_message(
    handler: &PostMessageHandler,
    target_host: Option<&str>,
) -> Confidence {
    // Origin-check posture drives exploitability; reaching a sink raises it.
    let exploitability = match handler.origin_check.to_lowercase().as_str() {
        "none" => Exploitability::PrivilegedNoPrecondition,
        "weak" => {
            if handler.reaches_sink {
                Exploitability::PrivilegedNoPrecondition
            } else {
                Exploitability::PreconditionUnmet
            }
        }
        "strict" => Exploitability::Benign,
        _ => Exploitability::None,
    };
    let inputs = FindingInputs {
        sources: vec![EvidenceSource::Ast],
        evidence_count: 1,
        category: FindingCategory::Taint,
        origin: classify_origin(&handler.script_url, target_host),
        runtime_observed: false,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability,
        suppressor: None,
    };
    confidence::score(&inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ConfidenceLevel;

    fn secret(source: &str, value: &str) -> SecretFinding {
        SecretFinding {
            source: source.to_owned(),
            matches: vec![value.to_owned()],
            confidence: None,
        }
    }

    #[test]
    fn classify_origin_three_states() {
        assert_eq!(
            classify_origin("https://app.example.com/a.js", Some("example.com")),
            Origin::FirstParty
        );
        assert_eq!(
            classify_origin("https://cdn.thirdparty.io/a.js", Some("example.com")),
            Origin::ThirdParty
        );
        assert_eq!(
            classify_origin("https://app.example.com/a.js", None),
            Origin::Unknown
        );
        // A relative reference with no host resolves to first-party.
        assert_eq!(
            classify_origin("/static/a.js", Some("example.com")),
            Origin::FirstParty
        );
    }

    #[test]
    fn high_confidence_runtime_secret() {
        // service_role in a window object, first-party, high-entropy value.
        let value = "eyJhbGciOiJIUzI1NiJ9.aGVsbG93b3JsZGZvb2JhcnF1eA.sig";
        let f = secret("Window Object: __SUPABASE__", value);
        let c = score_secret("supabase_service_role", &f, Some("example.com"));
        assert_eq!(c.level, ConfidenceLevel::High);
    }

    #[test]
    fn placeholder_secret_is_suppressed() {
        let f = secret("Window Object: cfg", "AKIAIOSFODNN7EXAMPLE");
        let c = score_secret("aws_key", &f, Some("example.com"));
        assert_eq!(c.level, ConfidenceLevel::Low);
        assert!(c.score <= 20);
    }

    #[test]
    fn anon_jwt_scores_lower_than_service_role() {
        let value = "eyJhbGciOiJIUzI1NiJ9.aGVsbG93b3JsZGZvb2JhcnF1eA.sig";
        let f = secret("Window Object: __SUPABASE__", value);
        let service = score_secret("supabase_service_role", &f, Some("example.com"));
        let anon = score_secret("supabase_anon_jwt", &f, Some("example.com"));
        assert!(anon.score < service.score);
    }

    #[test]
    fn pagerduty_api_key_is_downgraded_below_high() {
        // SEC-002: a structureless 20-char value (the common case is a config literal
        // in inline page text) can't be told apart from a generic identifier, so it must
        // not reach High on a static, uncorroborated hit and must score below a
        // structured secret of the same shape and provenance.
        let value = "u+Abc123456789012345";
        let f = secret("Inline Script", value);

        let pagerduty = score_secret("pagerduty_api_key", &f, Some("example.com"));
        assert_ne!(pagerduty.level, ConfidenceLevel::High);

        let structured = score_secret("stripe_secret_key", &f, Some("example.com"));
        assert!(
            pagerduty.score < structured.score,
            "pagerduty ({}) must score below a structured key ({})",
            pagerduty.score,
            structured.score
        );
    }

    #[test]
    fn low_confidence_static_taint() {
        // Static, third-party, navigation-only sink => below the Medium floor.
        let flow = TaintFlow {
            source: "location.search".to_owned(),
            sink: "location.assign(...)".to_owned(),
            path: vec![],
            script_url: "https://cdn.thirdparty.io/x.js".to_owned(),
            location: "x.js:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        };
        let c = score_taint_flow(&flow, Some("example.com"));
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn runtime_observed_taint_scores_high() {
        let flow = TaintFlow {
            source: "location.hash".to_owned(),
            sink: "innerHTML".to_owned(),
            path: vec!["redirect".to_owned()],
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "main.js:10:5".to_owned(),
            runtime_observed: true,
            confidence: None,
        };
        let c = score_taint_flow(&flow, Some("example.com"));
        assert_eq!(c.level, ConfidenceLevel::High);
    }

    #[test]
    fn strict_origin_post_message_is_low() {
        let handler = PostMessageHandler {
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "main.js:3:1".to_owned(),
            origin_check: "strict".to_owned(),
            reaches_sink: false,
            confidence: None,
        };
        let c = score_post_message(&handler, Some("example.com"));
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn none_origin_post_message_reaching_sink_is_actionable() {
        let handler = PostMessageHandler {
            script_url: "https://app.example.com/main.js".to_owned(),
            location: "main.js:3:1".to_owned(),
            origin_check: "none".to_owned(),
            reaches_sink: true,
            confidence: None,
        };
        let c = score_post_message(&handler, Some("example.com"));
        assert!(
            c.score
                > score_post_message(
                    &PostMessageHandler {
                        origin_check: "strict".to_owned(),
                        ..handler.clone()
                    },
                    Some("example.com")
                )
                .score
        );
    }

    #[test]
    fn inferred_vulnerability_scores_lower_than_observed() {
        let observed = Vulnerability {
            vuln_type: "Next.js RCE".to_owned(),
            severity: "critical".to_owned(),
            description: "Observed react-server-dom 18.2.0".to_owned(),
            remediation: "upgrade".to_owned(),
            url: Some("https://app.example.com/main.js".to_owned()),
            confidence: None,
        };
        let inferred = Vulnerability {
            description: "inferred: App Router surface present, no version observed".to_owned(),
            ..observed.clone()
        };
        let obs = score_vulnerability(&observed, Some("example.com"));
        let inf = score_vulnerability(&inferred, Some("example.com"));
        assert!(inf.score < obs.score);
    }

    #[test]
    fn score_all_fills_every_finding_type() {
        let mut result = ScanResult::default();
        result
            .secrets
            .insert("aws_key".to_owned(), vec![secret("HTML", "abc")]);
        result.vulnerabilities.push(Vulnerability {
            vuln_type: "v".to_owned(),
            severity: "high".to_owned(),
            description: "d".to_owned(),
            remediation: "r".to_owned(),
            url: None,
            confidence: None,
        });
        result.source_maps_intel.push(SourceMapIntel {
            map_url: "https://app.example.com/m.js.map".to_owned(),
            script_url: "https://app.example.com/m.js".to_owned(),
            recovered_sources: vec!["a.ts".to_owned()],
            has_sources_content: true,
            confidence: None,
        });
        result.route_surface.push(RouteSurface {
            path: "/admin".to_owned(),
            kind: "route".to_owned(),
            source: "https://app.example.com/m.js.map".to_owned(),
            dynamic: false,
            confidence: None,
        });
        result.taint_flows.push(TaintFlow {
            source: "location.hash".to_owned(),
            sink: "innerHTML".to_owned(),
            path: vec![],
            script_url: "https://app.example.com/m.js".to_owned(),
            location: "m.js:1:1".to_owned(),
            runtime_observed: false,
            confidence: None,
        });
        result.gadgets.push(Gadget {
            category: "dom-xss".to_owned(),
            description: "d".to_owned(),
            script_url: "https://app.example.com/m.js".to_owned(),
            exploitability_hint: "requires controllable hash".to_owned(),
            confidence: None,
        });
        result.post_message_handlers.push(PostMessageHandler {
            script_url: "https://app.example.com/m.js".to_owned(),
            location: "m.js:1:1".to_owned(),
            origin_check: "weak".to_owned(),
            reaches_sink: true,
            confidence: None,
        });

        score_all(&mut result, Some("example.com"));

        assert!(result.secrets["aws_key"][0].confidence.is_some());
        assert!(result.vulnerabilities[0].confidence.is_some());
        assert!(result.source_maps_intel[0].confidence.is_some());
        assert!(result.route_surface[0].confidence.is_some());
        assert!(result.taint_flows[0].confidence.is_some());
        assert!(result.gadgets[0].confidence.is_some());
        assert!(result.post_message_handlers[0].confidence.is_some());
    }
}
