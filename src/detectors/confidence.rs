//! Confidence scoring engine — the orthogonal-to-severity "how sure are we?" axis.
//!
//! Pure, deterministic, additive-then-clamp scoring over a small [`FindingInputs`]
//! value struct. The scorer never reaches into `ScanResult`; callers build
//! `FindingInputs` from their own domain knowledge and own evidence-count dedup.
//!
//! Model spec: `.project/research/confidence-model-brief.md`. Weights live as named
//! `const`s below so false-positive tuning (task 4.4) is a one-line edit.
//
use crate::types::{Confidence, ConfidenceFactor, ConfidenceLevel, EvidenceSource};

// --- Weights (brief §3). Tuning is a one-line change here. ---

/// Base score: bottom of the Medium band — a lone, plausible signal.
const BASE: u8 = 40;

// Dimension 1 — evidence count (independent corroborating signals, diminishing).
const EVIDENCE_2: i8 = 10;
const EVIDENCE_3: i8 = 18;
const EVIDENCE_4_PLUS: i8 = 24;

// Dimension 2 — source-type trust rank (highest applicable for the category).
const TRUST_RUNTIME: i8 = 20;
const TRUST_NETWORK: i8 = 14;
const TRUST_SOURCEMAP: i8 = 12;
const TRUST_HEADER: i8 = 10;
const TRUST_DOM: i8 = 6;
const TRUST_AST: i8 = 0;

// Dimension 3 — first- vs third-party origin.
const ORIGIN_FIRST_PARTY: i8 = 8;
const ORIGIN_THIRD_PARTY: i8 = -12;
const ORIGIN_UNKNOWN: i8 = 0;

// Dimension 4 — runtime-observed vs static-only.
const RUNTIME_OBSERVED: i8 = 22;

// Dimension 5 — false-positive heuristics (soft; hard suppressors bypass the math).
const FP_LOW_ENTROPY: i8 = -25;
const FP_HIGH_ENTROPY: i8 = 8;
const FP_CONSTANT_ASSIGNMENT: i8 = -20;

// Dimension 6 — exploitability hint.
const EXPL_PRIVILEGED: i8 = 10;
const EXPL_PRECONDITION_UNMET: i8 = -8;
const EXPL_BENIGN: i8 = -15;

/// Hard-suppressor ceiling: a suppressed finding is forced to Low with score ≤ 20.
const SUPPRESSOR_CEILING: u8 = 20;

// Band thresholds (brief §2): 0–39 Low, 40–74 Medium, 75–100 High.
const BAND_MEDIUM_FLOOR: u8 = 40;
const BAND_HIGH_FLOOR: u8 = 75;

/// Finding category, used to make source-type trust context-sensitive (brief §3.5).
///
/// A `SourceMap` signal is high-trust for secrets/versions (recovered real source) but
/// `AST`-equivalent for taint/gadget findings (recovered code is still *static* — it
/// does not prove a flow fires).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    /// Secrets, versions, route/manifest recovery — `SourceMap` is high-trust here.
    SecretOrVersion,
    /// Static source→sink reasoning — `SourceMap` is treated as `AST`-tier.
    Taint,
}

/// Origin classification of the artifact the finding came from (brief dim 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    FirstParty,
    ThirdParty,
    Unknown,
}

/// Entropy assessment of a secret-bearing value (brief dim 5).
///
/// `NotApplicable` for findings that are not secret values (taint flows, versions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropySignal {
    /// Low Shannon entropy over the variable portion (< ~3.0 bits/char).
    Low,
    /// High entropy of expected length for a structured secret (≥ ~4.0).
    High,
    NotApplicable,
}

/// Exploitability hint (brief dim 6) — modulates confidence the finding is *actionable*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exploitability {
    /// Privileged with no precondition (e.g. JWT `service_role`, `sk_live_`, met sink).
    PrivilegedNoPrecondition,
    /// Actionable but gated on a precondition that is not met (unreachable source).
    PreconditionUnmet,
    /// Benign by construction (public/publishable key, `anon` role).
    Benign,
    /// No structured hint available.
    None,
}

/// Hard suppressor (brief §4) — forces the finding to Low regardless of corroboration.
///
/// Modeled as a flag rather than a soft delta so the additive math stays pure and the
/// override is explicit at the combination step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppressor {
    /// Matched a known placeholder / test value (`sk_test_`, `AKIAIOSFODNN7EXAMPLE`, …).
    PlaceholderOrTestValue,
    /// Taint flow passes through a known auto-escaping path (React text child, …).
    FrameworkSanitizedPath,
    /// Flow reaches an allowlisted safe sink (`textContent`, …).
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

/// Pure inputs to [`score`]. Built by the caller from domain knowledge.
///
/// Evidence-count dedup is the **caller's** responsibility: three regex hits in one
/// file are one independent signal, not three. The scorer trusts the integer given.
#[derive(Debug, Clone)]
pub struct FindingInputs {
    /// Distinct evidence sources observed for this finding (drives dim 2 trust rank).
    pub sources: Vec<EvidenceSource>,
    /// Count of *independent* corroborating signals (caller-deduped; dim 1).
    pub evidence_count: u32,
    pub category: FindingCategory,
    pub origin: Origin,
    /// Whether the value/flow was observed at runtime (dim 4) — distinct from a Runtime
    /// *source*: a static flow can still operate over a runtime-sourced artifact.
    pub runtime_observed: bool,
    pub entropy: EntropySignal,
    /// Constant/non-controllable assignment fed by a literal, not a tainted source.
    pub constant_assignment: bool,
    pub exploitability: Exploitability,
    /// Any hard suppressor that fired (caller-detected).
    pub suppressor: Option<Suppressor>,
}

/// Score a finding into a [`Confidence`]. Pure and deterministic — order-independent.
///
/// Algorithm (brief §4): start at [`BASE`] = 40, apply signed per-dimension deltas with
/// saturating arithmetic, clamp to `[0,100]`, then band. A hard suppressor overrides the
/// band to Low and caps the score at [`SUPPRESSOR_CEILING`] — the additive `factors`
/// trail is still recorded so the report can explain what was found.
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

    // Dimension 1 — evidence count (diminishing returns, saturating).
    let evidence_delta = match inputs.evidence_count {
        0 | 1 => 0,
        2 => EVIDENCE_2,
        3 => EVIDENCE_3,
        _ => EVIDENCE_4_PLUS,
    };
    let evidence_note = format!("{} independent signal(s)", inputs.evidence_count);
    apply("evidence_count", evidence_delta, &evidence_note);

    // Dimension 2 — highest applicable source-type trust for this finding category.
    let (trust, trust_note) = highest_trust(&inputs.sources, inputs.category);
    apply("source_type", trust, &trust_note);

    // Dimension 3 — origin.
    let (origin_delta, origin_note) = match inputs.origin {
        Origin::FirstParty => (ORIGIN_FIRST_PARTY, "first-party artifact"),
        Origin::ThirdParty => (ORIGIN_THIRD_PARTY, "third-party artifact"),
        Origin::Unknown => (ORIGIN_UNKNOWN, "unknown origin"),
    };
    apply("origin", origin_delta, origin_note);

    // Dimension 4 — runtime-observed.
    if inputs.runtime_observed {
        apply(
            "runtime_observed",
            RUNTIME_OBSERVED,
            "value/flow observed at runtime",
        );
    }

    // Dimension 5 — false-positive heuristics (soft).
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

    // Dimension 6 — exploitability hint.
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

    // Hard suppressor overrides the band (brief §4) but keeps the factors trail.
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

/// Trust delta for the highest-trust source present, made category-sensitive: `SourceMap`
/// drops to the `AST` tier for taint findings (brief §3.5 implementer note).
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
        EvidenceSource::Runtime => (TRUST_RUNTIME, "runtime"),
        EvidenceSource::Network => (TRUST_NETWORK, "network"),
        EvidenceSource::SourceMap => match category {
            FindingCategory::SecretOrVersion => (TRUST_SOURCEMAP, "source map"),
            // Recovered source is still static for taint reasoning.
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

    /// A non-secret, non-taint baseline so individual dimensions are easy to reason about.
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
        // Only the source_type dim applies and AST is +0, so we stay at the BASE.
        let c = score(&base_inputs());
        assert_eq!(c.score, 40);
        assert_eq!(c.level, ConfidenceLevel::Medium);
    }

    #[test]
    fn strong_evidence_runtime_secret_is_high() {
        // Brief worked example 1: Supabase service_role in first-party window.
        // 40 +10(ct) +20(Runtime) +8(1p) +22(obs) +8(entropy) +10(expl) -> clamp 100.
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
        // The factors trail must explain the score.
        assert!(has_dimension(&c, "evidence_count"));
        assert!(has_dimension(&c, "source_type"));
        assert!(has_dimension(&c, "runtime_observed"));
        assert!(has_dimension(&c, "exploitability"));
    }

    #[test]
    fn low_confidence_static_taint_guess_is_medium() {
        // Brief worked example 3: static DOM-XSS taint, never runtime-seen, first-party.
        // 40 +0(ct) +0(AST) +8(1p) +0(static) +10(expl) = 58 -> Medium.
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
        // Unmet precondition over a third-party AST-only flow drops below the Medium floor.
        // 40 +0(ct) +0(AST) -12(3p) +0(static) -8(expl) = 20 -> Low.
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
        // Brief worked example 2: AKIAIOSFODNN7EXAMPLE in a source map.
        // Even with corroboration, the placeholder suppressor forces Low / <=20.
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
        // Additive trail still explains what was found despite the override.
        assert!(has_dimension(&c, "runtime_observed"));
        assert!(has_dimension(&c, "suppressor"));
    }

    #[test]
    fn framework_sanitized_taint_is_hard_suppressed() {
        // Brief worked example 6: dangerouslySetInnerHTML via React-escaped text child.
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
        // Brief worked example 5: Algolia search-only key in third-party analytics script.
        // 40 +0(ct) +14(Network) -12(3p) +22(obs) -15(benign) = 49 -> Medium.
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
        // Brief worked example 4: the static flow, now observed flowing at runtime.
        // 40 +10(ct) +20(Runtime) +8(1p) +22(obs) +10(expl) -> clamp 100.
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
        // SourceMap must not grant SourceMap-trust to a taint finding (brief §3.5).
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
        // Stack every negative lever; saturating add must floor at 0, never wrap.
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
        // 40 -12 -25 -20 -15 = saturates to 0.
        let c = score(&inputs);
        assert_eq!(c.score, 0);
        assert_eq!(c.level, ConfidenceLevel::Low);
    }

    #[test]
    fn low_evidence_count_adds_nothing() {
        // A single signal must not earn a corroboration bonus.
        let c = score(&base_inputs());
        assert!(!has_dimension(&c, "evidence_count"));
    }
}
