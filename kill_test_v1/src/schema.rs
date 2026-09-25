//! Kill-Test v1 common record schema (spec §2).
//!
//! One record type serves all four tracks so that a cross-track report cannot
//! be assembled from incompatible shapes. Pre-exposure fields (`expected_*`,
//! `fact_basis`, `label_source`) are required at construction; post-exposure
//! fields (`actual_verdict`, `correct`, `false_safe`, …) are `Option` and
//! start empty.
//!
//! Invariant 5/6 of the spec — do not label from EdgeGuard output, do not
//! relabel after seeing it — is enforced structurally: [`CaseRecord`] carries
//! its label, and [`CaseRecord::observe`] refuses to overwrite an observation
//! that is already present.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Track {
    /// Track 1 — can Cedar substitute for EdgeGuard's Action path?
    CedarSubstitution,
    /// Track 2 — is the complexity hidden in host preprocessing?
    HostBurden,
    /// Track 3 — does Jataayu provide stronger AI-native provenance/taint?
    JataayuBoundaryTaint,
    /// Track 4 — does Microsoft AGT provide nearly the same enforcement?
    AgtSubstitution,
}

/// Which system produced a verdict. Kept on the record so a mixed-system
/// report is impossible to assemble by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum System {
    EdgeGuardNative,
    EdgeGuardFfi,
    Cedar,
    Jataayu,
    AgtLocal,
    HandwrittenRules,
}

/// Pre-registered deterministic-resolvability class (spec §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExpectedClass {
    /// Stated facts alone are sufficient to permit.
    #[serde(rename = "D-PASS")]
    DPass,
    /// Stated facts alone are sufficient to deny.
    #[serde(rename = "D-BLOCK")]
    DBlock,
    /// Deterministic facts constrain the decision but are insufficient alone.
    M,
    /// Semantic interpretation is genuinely necessary.
    S,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Block,
    Escalate,
}

/// Where a label came from. Spec §6: a label may never come from an engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    /// Carried by an external dataset/spec. `cite` names the clause.
    ExternalSpec { dataset: String, cite: String },
    /// Authored for this experiment by a named annotator, pre-exposure.
    PreRegisteredAuthored { annotator: String },
}

/// The exact deterministic basis for a D or M label (spec §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactBasis {
    TypedArg { name: String, detail: String },
    HostAuthoritativeState { name: String, detail: String },
    IdentityOrOwnership { detail: String },
    Limit { detail: String },
    Transition { detail: String },
    Confirmation { detail: String },
    Provenance { detail: String },
    PolicyClause { detail: String },
}

/// Integration-burden facts, recorded per integration rather than reduced to
/// a score (spec §8: "Do not hide host cost inside setup code").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurdenFacts {
    pub integration_loc: u32,
    pub policy_loc: u32,
    pub manual_mappings: u32,
    pub setup_steps: u32,
    pub external_runtime_deps: Vec<String>,
    pub state_owned_by_system: bool,
    pub network_required_on_hot_path: bool,
    pub policy_update_requires_app_rebuild: bool,
}

/// Timing, split per spec §11 so host preprocessing can never hide inside the
/// evaluator number. All microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Timings {
    pub host_preprocess_us: f64,
    pub adapter_us: f64,
    pub eval_us: f64,
    pub framework_e2e_us: f64,
}

/// The observed result. Only constructible from a real run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub system: System,
    pub actual_verdict: Verdict,
    pub reason: String,
    pub decided_by: String,
    pub correct: bool,
    pub false_safe: bool,
    pub false_block: bool,
    pub locally_resolved: bool,
    pub timings: Timings,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseRecord {
    pub track: Track,
    pub case_id: String,
    pub source: String,
    /// False for cases authored here. Spec §13 / invariant 13.
    pub externally_sourced: bool,
    /// True when the case required facts the source workload does not supply.
    pub development_only: bool,

    // --- pre-exposure label (spec §6) --------------------------------------
    pub expected_class: ExpectedClass,
    pub expected_verdict: Verdict,
    pub fact_basis: Vec<FactBasis>,
    pub label_source: LabelSource,
    /// Spec §6: ambiguous cases are flagged for INDEPENDENT annotation, which
    /// this harness never performs on its own behalf.
    pub needs_second_annotation: bool,

    // --- the event ---------------------------------------------------------
    pub action_name: String,
    pub host_facts: Vec<HostFact>,
    pub host_facts_count: u32,
    pub context_bytes: u32,

    // --- burden ------------------------------------------------------------
    pub burden: BurdenFacts,

    // --- post-exposure -----------------------------------------------------
    pub outcomes: Vec<Outcome>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostFact {
    pub name: String,
    pub value: serde_json::Value,
    /// "host_authoritative" | "model_proposed" | "user_provided"
    pub provenance: String,
    /// True when this fact is AI-specific (provenance/trust of generated
    /// content) rather than ordinary authorization state. The Cedar track
    /// turns on whether these can be expressed at all.
    pub ai_specific: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "schema error: {}", self.0)
    }
}

impl CaseRecord {
    /// Spec §2 / §6 validation, enforced mechanically.
    pub fn validate(&self) -> Result<(), SchemaError> {
        let e = |m: String| Err(SchemaError(format!("{}: {}", self.case_id, m)));

        // "D requires explicit fact basis".
        let is_d = matches!(
            self.expected_class,
            ExpectedClass::DPass | ExpectedClass::DBlock
        );
        if (is_d || self.expected_class == ExpectedClass::M) && self.fact_basis.is_empty() {
            return e(format!(
                "class {:?} requires a non-empty fact_basis",
                self.expected_class
            ));
        }
        if self.expected_class == ExpectedClass::S && !self.fact_basis.is_empty() {
            return e("class S must not carry a deterministic fact_basis".into());
        }

        // A D class pre-registers a terminal verdict; M and S pre-register
        // abstention. This is the pre-registered semantics that the metric
        // layer then refuses to let a system violate silently.
        let want = match self.expected_class {
            ExpectedClass::DPass => Verdict::Pass,
            ExpectedClass::DBlock => Verdict::Block,
            ExpectedClass::M | ExpectedClass::S => Verdict::Escalate,
        };
        if self.expected_verdict != want {
            return e(format!(
                "class {:?} pre-registers {:?} but the record says {:?}",
                self.expected_class, want, self.expected_verdict
            ));
        }

        if self.host_facts_count as usize != self.host_facts.len() {
            return e("host_facts_count disagrees with host_facts".into());
        }
        if !self.externally_sourced && !self.development_only {
            return e(
                "a case that is not externally sourced must be marked development_only \
                 (invariant 13)"
                    .into(),
            );
        }
        Ok(())
    }

    /// Append an observation. Refuses to replace one from the same system, so
    /// a re-run cannot silently overwrite a prior result.
    pub fn observe(&mut self, o: Outcome) -> Result<(), SchemaError> {
        if self.outcomes.iter().any(|p| p.system == o.system) {
            return Err(SchemaError(format!(
                "{}: an outcome for {:?} is already recorded; results append, never overwrite",
                self.case_id, o.system
            )));
        }
        self.outcomes.push(o);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn case(class: ExpectedClass, verdict: Verdict, basis: Vec<FactBasis>) -> CaseRecord {
        CaseRecord {
            track: Track::CedarSubstitution,
            case_id: "T1-X".into(),
            source: "authored".into(),
            externally_sourced: false,
            development_only: true,
            expected_class: class,
            expected_verdict: verdict,
            fact_basis: basis,
            label_source: LabelSource::PreRegisteredAuthored {
                annotator: "phase1.5".into(),
            },
            needs_second_annotation: false,
            action_name: "execute_payment".into(),
            host_facts: vec![],
            host_facts_count: 0,
            context_bytes: 0,
            burden: BurdenFacts::default(),
            outcomes: vec![],
            notes: String::new(),
        }
    }

    fn limit() -> Vec<FactBasis> {
        vec![FactBasis::Limit {
            detail: "amount <= 1000".into(),
        }]
    }

    #[test]
    fn a_d_class_without_a_fact_basis_is_rejected() {
        assert!(case(ExpectedClass::DPass, Verdict::Pass, vec![])
            .validate()
            .is_err());
        assert!(case(ExpectedClass::DBlock, Verdict::Block, vec![])
            .validate()
            .is_err());
    }

    #[test]
    fn an_s_class_carrying_a_fact_basis_is_rejected() {
        assert!(case(ExpectedClass::S, Verdict::Escalate, limit())
            .validate()
            .is_err());
    }

    #[test]
    fn a_class_and_its_pre_registered_verdict_must_agree() {
        // D-PASS pre-registers PASS; claiming BLOCK for it is a label bug.
        assert!(case(ExpectedClass::DPass, Verdict::Block, limit())
            .validate()
            .is_err());
        // M and S pre-register abstention, never a terminal verdict.
        assert!(case(ExpectedClass::M, Verdict::Pass, limit())
            .validate()
            .is_err());
        assert!(case(ExpectedClass::S, Verdict::Block, vec![])
            .validate()
            .is_err());
        assert!(case(ExpectedClass::M, Verdict::Escalate, limit())
            .validate()
            .is_ok());
    }

    #[test]
    fn an_authored_case_must_be_marked_development_only() {
        let mut c = case(ExpectedClass::DPass, Verdict::Pass, limit());
        c.development_only = false;
        assert!(c.validate().is_err());
    }

    #[test]
    fn an_observation_is_never_silently_overwritten() {
        let mut c = case(ExpectedClass::DPass, Verdict::Pass, limit());
        let o = Outcome {
            system: System::Cedar,
            actual_verdict: Verdict::Pass,
            reason: String::new(),
            decided_by: "cedar".into(),
            correct: true,
            false_safe: false,
            false_block: false,
            locally_resolved: true,
            timings: Timings::default(),
        };
        assert!(c.observe(o.clone()).is_ok());
        assert!(
            c.observe(o).is_err(),
            "a second write for the same system must be refused"
        );
        assert_eq!(c.outcomes.len(), 1);
    }

    #[test]
    fn a_record_round_trips_through_json_keeping_its_label() {
        let c = case(ExpectedClass::DBlock, Verdict::Block, limit());
        let s = serde_json::to_string(&c).unwrap();
        let back: CaseRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        assert!(back.outcomes.is_empty());
    }
}
