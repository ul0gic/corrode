// Does:  Checks how scored and unscored findings appear in reports.
// Holds: Missing confidence preserves the severity-only label.

use corrode_scanner::detectors::confidence::{
    score, EntropySignal, Exploitability, FindingCategory, FindingInputs, Origin,
};
use corrode_scanner::reporting::markdown::summary::severity_confidence;
use corrode_scanner::types::{Confidence, EvidenceSource};

fn taint_inputs(origin: Origin, expl: Exploitability) -> FindingInputs {
    FindingInputs {
        sources: vec![EvidenceSource::Ast],
        evidence_count: 1,
        category: FindingCategory::Taint,
        origin,
        runtime_observed: false,
        entropy: EntropySignal::NotApplicable,
        constant_assignment: false,
        exploitability: expl,
        suppressor: None,
    }
}

#[test]
fn label_combines_severity_and_scored_confidence() {
    let scored = score(&taint_inputs(
        Origin::FirstParty,
        Exploitability::PrivilegedNoPrecondition,
    ));
    assert_eq!(
        severity_confidence("High", Some(&scored)),
        "High severity / Medium confidence"
    );
}

#[test]
fn unscored_finding_renders_bare_severity_for_back_compat() {
    let none: Option<&Confidence> = None;
    assert_eq!(severity_confidence("Medium", none), "Medium severity");
}
