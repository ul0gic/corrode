// Does:  Scores finding confidence from caller-supplied evidence.
// Holds: A hard suppressor forces Low confidence while preserving the factor trail.

use crate::types::{Confidence, ConfidenceFactor, ConfidenceLevel, EvidenceSource};

const BASE: u8 = 40;

const EVIDENCE_2: i8 = 10;
const EVIDENCE_3: i8 = 18;
const EVIDENCE_4_PLUS: i8 = 24;

const TRUST_RUNTIME: i8 = 20;
const TRUST_NETWORK: i8 = 14;
const TRUST_SOURCEMAP: i8 = 12;
const TRUST_HEADER: i8 = 10;
const TRUST_DOM: i8 = 6;
const TRUST_AST: i8 = 0;

const ORIGIN_FIRST_PARTY: i8 = 8;
const ORIGIN_THIRD_PARTY: i8 = -12;
const ORIGIN_UNKNOWN: i8 = 0;

const RUNTIME_OBSERVED: i8 = 22;

const FP_LOW_ENTROPY: i8 = -25;
const FP_HIGH_ENTROPY: i8 = 8;
const FP_CONSTANT_ASSIGNMENT: i8 = -20;

const EXPL_PRIVILEGED: i8 = 10;
const EXPL_PRECONDITION_UNMET: i8 = -8;
const EXPL_BENIGN: i8 = -15;

const SUPPRESSOR_CEILING: u8 = 20;

const BAND_MEDIUM_FLOOR: u8 = 40;
const BAND_HIGH_FLOOR: u8 = 75;

/// Finding category used to select source trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    /// Secret, version, or recovered route evidence.
    SecretOrVersion,
    /// Static source-to-sink evidence.
    Taint,
}

/// Relationship between an artifact and the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Artifact associated with the target.
    FirstParty,
    /// Artifact associated with another host.
    ThirdParty,
    /// Artifact with unknown relationship to the target.
    Unknown,
}

/// Entropy evidence for a secret-bearing value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropySignal {
    /// Low entropy for a claimed secret.
    Low,
    /// High entropy consistent with a structured secret.
    High,
    /// Entropy is not applicable.
    NotApplicable,
}

/// Actionability signal for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exploitability {
    /// Privileged behavior without a precondition.
    PrivilegedNoPrecondition,
    /// Actionability depends on an unmet precondition.
    PreconditionUnmet,
    /// Evidence indicates a benign value or behavior.
    Benign,
    /// No exploitability hint.
    None,
}

/// Condition that forces a finding into the Low band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppressor {
    /// Known placeholder or test value.
    PlaceholderOrTestValue,
    /// Flow through a framework-escaped path.
    FrameworkSanitizedPath,
    /// Flow to an allowlisted sink.
    AllowlistedSafeSink,
}

impl Suppressor {
    fn note(self) -> &'static str {
        match self {
            Suppressor::PlaceholderOrTestValue => "matched known placeholder/test value",
            Suppressor::FrameworkSanitizedPath => "flow passes through framework-sanitized path",
            Suppressor::AllowlistedSafeSink => "flow reaches allowlisted safe sink",
        }
    }
}

/// Evidence and heuristics supplied to the confidence scorer.
#[derive(Debug, Clone)]
pub struct FindingInputs {
    /// Evidence source types.
    pub sources: Vec<EvidenceSource>,
    /// Number of independent corroborating signals, deduplicated by the caller.
    pub evidence_count: u32,
    /// Finding category used for source trust.
    pub category: FindingCategory,
    /// Artifact origin relative to the target.
    pub origin: Origin,
    /// Whether the value or flow was observed at runtime.
    pub runtime_observed: bool,
    /// Entropy signal for a secret-bearing value.
    pub entropy: EntropySignal,
    /// Whether a sink receives a constant rather than a tainted source.
    pub constant_assignment: bool,
    /// Actionability signal.
    pub exploitability: Exploitability,
    /// Optional condition that forces Low confidence.
    pub suppressor: Option<Suppressor>,
}

/// Scores a finding; hard suppressors cap the score at 20.
///
/// ```
/// # use corrode_scanner::detectors::confidence::*;
/// # let inputs = FindingInputs {
/// #     sources: vec![], evidence_count: 1, category: FindingCategory::Taint, origin: Origin::Unknown,
/// #     runtime_observed: false, entropy: EntropySignal::NotApplicable, constant_assignment: false,
/// #     exploitability: Exploitability::None, suppressor: None,
/// # };
/// let confidence = score(&inputs);
/// ```
pub fn score(inputs: &FindingInputs) -> Confidence {
    let mut factors: Vec<ConfidenceFactor> = Vec::new();
    let mut acc: u8 = BASE;

    let mut apply = |dimension: &str, delta: i8, note: &str| {
        if delta != 0 {
            acc = acc.saturating_add_signed(delta);
            factors.push(ConfidenceFactor {
                dimension: dimension.to_owned(),
                delta,
                note: note.to_owned(),
            });
        }
    };

    let evidence_delta = match inputs.evidence_count {
        0 | 1 => 0,
        2 => EVIDENCE_2,
        3 => EVIDENCE_3,
        _ => EVIDENCE_4_PLUS,
    };
    let evidence_note = format!("{} independent signal(s)", inputs.evidence_count);
    apply("evidence_count", evidence_delta, &evidence_note);

    let (trust, trust_note) = highest_trust(&inputs.sources, inputs.category);
    apply("source_type", trust, &trust_note);

    let (origin_delta, origin_note) = match inputs.origin {
        Origin::FirstParty => (ORIGIN_FIRST_PARTY, "first-party artifact"),
        Origin::ThirdParty => (ORIGIN_THIRD_PARTY, "third-party artifact"),
        Origin::Unknown => (ORIGIN_UNKNOWN, "unknown origin"),
    };
    apply("origin", origin_delta, origin_note);

    if inputs.runtime_observed {
        apply(
            "runtime_observed",
            RUNTIME_OBSERVED,
            "value/flow observed at runtime",
        );
    }

    match inputs.entropy {
        EntropySignal::Low => apply(
            "entropy",
            FP_LOW_ENTROPY,
            "low entropy for a claimed secret",
        ),
        EntropySignal::High => apply(
            "entropy",
            FP_HIGH_ENTROPY,
            "high entropy consistent with a structured secret",
        ),
        EntropySignal::NotApplicable => {}
    }
    if inputs.constant_assignment {
        apply(
            "constant_assignment",
            FP_CONSTANT_ASSIGNMENT,
            "sink fed by a constant, not a tainted source",
        );
    }

    let (expl_delta, expl_note) = match inputs.exploitability {
        Exploitability::PrivilegedNoPrecondition => {
            (EXPL_PRIVILEGED, "privileged, no precondition")
        }
        Exploitability::PreconditionUnmet => (EXPL_PRECONDITION_UNMET, "precondition not met"),
        Exploitability::Benign => (EXPL_BENIGN, "benign by construction"),
        Exploitability::None => (0, ""),
    };
    apply("exploitability", expl_delta, expl_note);

    let clamped = acc.clamp(0, 100);

    let (level, final_score) = match inputs.suppressor {
        Some(s) => {
            factors.push(ConfidenceFactor {
                dimension: "suppressor".to_owned(),
                delta: 0,
                note: s.note().to_owned(),
            });
            (ConfidenceLevel::Low, clamped.min(SUPPRESSOR_CEILING))
        }
        None => (band(clamped), clamped),
    };

    Confidence {
        level,
        score: final_score,
        factors,
    }
}

fn highest_trust(sources: &[EvidenceSource], category: FindingCategory) -> (i8, String) {
    let best = sources
        .iter()
        .map(|s| trust_for(*s, category))
        .max_by_key(|(delta, _)| *delta);

    match best {
        Some((delta, label)) => (delta, format!("highest-trust source: {label}")),
        None => (0, "no evidence source".to_owned()),
    }
}

fn trust_for(source: EvidenceSource, category: FindingCategory) -> (i8, &'static str) {
    match source {
        EvidenceSource::Deployment => (0, "owner-supplied deployment record"),
        EvidenceSource::Runtime => (TRUST_RUNTIME, "runtime"),
        EvidenceSource::Network => (TRUST_NETWORK, "network"),
        EvidenceSource::SourceMap => match category {
            FindingCategory::SecretOrVersion => (TRUST_SOURCEMAP, "source map"),
            FindingCategory::Taint => (TRUST_AST, "source map (static, AST-tier)"),
        },
        EvidenceSource::Header => (TRUST_HEADER, "header"),
        EvidenceSource::Dom => (TRUST_DOM, "DOM"),
        EvidenceSource::Ast => (TRUST_AST, "AST"),
    }
}

fn band(score: u8) -> ConfidenceLevel {
    if score >= BAND_HIGH_FLOOR {
        ConfidenceLevel::High
    } else if score >= BAND_MEDIUM_FLOOR {
        ConfidenceLevel::Medium
    } else {
        ConfidenceLevel::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> FindingInputs {
        FindingInputs {
            sources: vec![EvidenceSource::Ast],
            evidence_count: 1,
            category: FindingCategory::Taint,
            origin: Origin::Unknown,
            runtime_observed: false,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::None,
            suppressor: None,
        }
    }

    fn has_dimension(c: &Confidence, dim: &str) -> bool {
        c.factors.iter().any(|f| f.dimension == dim)
    }

    #[test]
    fn lone_ast_signal_lands_at_base() {
        let c = score(&base_inputs());
        assert_eq!(c.score, 40);
        assert_eq!(c.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn strong_evidence_runtime_secret_is_high() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Runtime, EvidenceSource::Network],
            evidence_count: 2,
            category: FindingCategory::SecretOrVersion,
            origin: Origin::FirstParty,
            runtime_observed: true,
            entropy: EntropySignal::High,
            constant_assignment: false,
            exploitability: Exploitability::PrivilegedNoPrecondition,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 100, "should clamp at 100");
        assert_eq!(c.level, ConfidenceLevel::High);
        assert!(has_dimension(&c, "evidence_count"));
        assert!(has_dimension(&c, "source_type"));
        assert!(has_dimension(&c, "runtime_observed"));
        assert!(has_dimension(&c, "exploitability"));
    }

    #[test]
    fn low_confidence_static_taint_guess_is_medium() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Ast],
            evidence_count: 1,
            category: FindingCategory::Taint,
            origin: Origin::FirstParty,
            runtime_observed: false,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::PrivilegedNoPrecondition,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 58);
        assert_eq!(c.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn truly_low_static_only_taint_is_low() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Ast],
            evidence_count: 1,
            category: FindingCategory::Taint,
            origin: Origin::ThirdParty,
            runtime_observed: false,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::PreconditionUnmet,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 20);
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn placeholder_value_is_hard_suppressed_to_low() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Runtime, EvidenceSource::Network],
            evidence_count: 4,
            category: FindingCategory::SecretOrVersion,
            origin: Origin::FirstParty,
            runtime_observed: true,
            entropy: EntropySignal::High,
            constant_assignment: false,
            exploitability: Exploitability::PrivilegedNoPrecondition,
            suppressor: Some(Suppressor::PlaceholderOrTestValue),
        };
        let c = score(&inputs);
        assert_eq!(c.level, ConfidenceLevel::Low);
        assert!(c.score <= SUPPRESSOR_CEILING);
        assert!(has_dimension(&c, "runtime_observed"));
        assert!(has_dimension(&c, "suppressor"));
    }

    #[test]
    fn framework_sanitized_taint_is_hard_suppressed() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Ast, EvidenceSource::Runtime],
            evidence_count: 2,
            category: FindingCategory::Taint,
            origin: Origin::FirstParty,
            runtime_observed: true,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::PrivilegedNoPrecondition,
            suppressor: Some(Suppressor::FrameworkSanitizedPath),
        };
        let c = score(&inputs);
        assert_eq!(c.level, ConfidenceLevel::Low);
        assert!(c.score <= SUPPRESSOR_CEILING);
    }

    #[test]
    fn third_party_benign_key_is_medium() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Network],
            evidence_count: 1,
            category: FindingCategory::SecretOrVersion,
            origin: Origin::ThirdParty,
            runtime_observed: true,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::Benign,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 49);
        assert_eq!(c.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn corroborated_runtime_taint_is_high() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Ast, EvidenceSource::Runtime],
            evidence_count: 2,
            category: FindingCategory::Taint,
            origin: Origin::FirstParty,
            runtime_observed: true,
            entropy: EntropySignal::NotApplicable,
            constant_assignment: false,
            exploitability: Exploitability::PrivilegedNoPrecondition,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 100);
        assert_eq!(c.level, ConfidenceLevel::High);
    }

    #[test]
    fn sourcemap_is_ast_tier_for_taint() {
        let mut inputs = base_inputs();
        inputs.sources = vec![EvidenceSource::SourceMap];
        inputs.category = FindingCategory::Taint;
        let taint = score(&inputs);

        inputs.category = FindingCategory::SecretOrVersion;
        let secret = score(&inputs);

        assert_eq!(taint.score, 40, "SourceMap is AST-tier (+0) for taint");
        assert_eq!(secret.score, 52, "SourceMap is +12 for secrets/versions");
    }

    #[test]
    fn clamps_at_lower_bound() {
        let inputs = FindingInputs {
            sources: vec![EvidenceSource::Ast],
            evidence_count: 1,
            category: FindingCategory::SecretOrVersion,
            origin: Origin::ThirdParty,
            runtime_observed: false,
            entropy: EntropySignal::Low,
            constant_assignment: true,
            exploitability: Exploitability::Benign,
            suppressor: None,
        };
        let c = score(&inputs);
        assert_eq!(c.score, 0);
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn low_evidence_count_adds_nothing() {
        let c = score(&base_inputs());
        assert!(!has_dimension(&c, "evidence_count"));
    }
}
