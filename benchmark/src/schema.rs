//! Benchmark case schema.
//!
//! # The separation that matters
//!
//! A corpus case is two disjoint objects: an [`EventSpec`], which is the only
//! thing the engine is ever allowed to see, and a [`GroundTruth`], which the
//! engine must never see. They are separate Rust types, and [`build_event`]
//! accepts only the former - so there is no expression in this crate that can
//! place a label, an expected verdict, a D/S/M class, an attack family, or any
//! other benchmark metadata into a `SecurityEvent`, whether or not anyone
//! remembers the rule. `tests/leakage.rs` additionally checks the built events
//! at runtime, because a caller could still *manually* write a label into a
//! payload string.

use edgeguard::event::{
    ActionRule, AttributedValue, EventKind, Provenance, SecurityEvent, Value,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ---------------------------------------------------------------------------
// Side A: what the engine sees.
// ---------------------------------------------------------------------------

/// Which of the three contract channels this case exercises.
///
/// Serialized separately from the event body so the reporter can partition by
/// channel without inspecting payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Channel {
    Input,
    Output,
    Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceSpec {
    HostAuthoritative,
    ModelProposed,
    UserProvided,
}

impl From<ProvenanceSpec> for Provenance {
    fn from(p: ProvenanceSpec) -> Self {
        match p {
            ProvenanceSpec::HostAuthoritative => Provenance::HostAuthoritative,
            ProvenanceSpec::ModelProposed => Provenance::ModelProposed,
            ProvenanceSpec::UserProvided => Provenance::UserProvided,
        }
    }
}

/// A JSON-shaped mirror of [`Value`].
///
/// `Value` is part of the frozen contract and carries no serde derives; adding
/// them would mean editing the frozen engine. This type exists solely so a
/// corpus can be written as JSON, and converts into `Value` losslessly.
/// `Map` uses a `BTreeMap` so a corpus file round-trips byte-identically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ValueSpec {
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    List(Vec<ValueSpec>),
    Map(BTreeMap<String, ValueSpec>),
}

impl From<&ValueSpec> for Value {
    fn from(v: &ValueSpec) -> Self {
        match v {
            ValueSpec::Null => Value::Null,
            ValueSpec::Bool(b) => Value::Bool(*b),
            ValueSpec::Integer(i) => Value::Integer(*i),
            ValueSpec::Float(f) => Value::Float(*f),
            ValueSpec::String(s) => Value::String(s.clone()),
            ValueSpec::List(items) => Value::List(items.iter().map(Value::from).collect()),
            ValueSpec::Map(entries) => Value::Map(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from(v)))
                    .collect(),
            ),
        }
    }
}

/// One payload field: a key, a value, and the provenance the host asserts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    pub key: String,
    pub provenance: ProvenanceSpec,
    pub value: ValueSpec,
}

/// Everything the engine is permitted to observe about a case.
///
/// This type has no field that could carry a verdict, a class, or a label.
/// That is the point: it is the complete surface [`build_event`] can read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSpec {
    pub channel: Channel,
    /// Required when `channel == Action`, forbidden otherwise; validated by
    /// [`EventSpec::validate`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub fields: Vec<FieldSpec>,
}

impl EventSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.channel, &self.action_name) {
            (Channel::Action, None) => {
                Err("channel Action requires an action_name".to_string())
            }
            (Channel::Input | Channel::Output, Some(name)) => Err(format!(
                "channel {:?} must not carry an action_name (got {name:?})",
                self.channel
            )),
            _ => Ok(()),
        }
    }
}

/// Build the `SecurityEvent` the engine will be handed.
///
/// Takes an [`EventSpec`] and nothing else. There is no overload, no optional
/// second argument, and no field on `EventSpec` through which ground truth
/// could arrive, so benchmark metadata cannot reach a payload by accident.
pub fn build_event(spec: &EventSpec) -> SecurityEvent {
    let kind = match spec.channel {
        Channel::Input => EventKind::Input,
        Channel::Output => EventKind::Output,
        Channel::Action => EventKind::Action {
            name: spec.action_name.clone().unwrap_or_default(),
        },
    };
    let payload: HashMap<String, AttributedValue> = spec
        .fields
        .iter()
        .map(|f| {
            (
                f.key.clone(),
                AttributedValue {
                    data: Value::from(&f.value),
                    provenance: f.provenance.into(),
                },
            )
        })
        .collect();
    SecurityEvent {
        kind,
        principal_id: spec.principal_id.clone(),
        payload,
    }
}

// ---------------------------------------------------------------------------
// Side B: what the engine must never see.
// ---------------------------------------------------------------------------

/// Ground-truth class.
///
/// Assigned by the case's construction recipe, before the engine is ever run,
/// and never revised after seeing a result. See `docs/DESIGN.md` on why this
/// rule is the single largest bias risk in the benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Class {
    /// Deterministically decidable: sufficient deterministic facts are present
    /// to reach PASS or BLOCK with no semantic reasoning.
    D,
    /// Semantically decidable: no deterministic fact settles it, so a correct
    /// fast path must not pretend to know. Expected outcome is ESCALATE.
    S,
    /// Mixed: semantically ambiguous or adversarial content, plus a
    /// deterministic fact that independently settles the outcome. The fact is
    /// expected to win without semantic reasoning.
    M,
}

/// The outcome the frozen engine is expected to produce for this case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Pass,
    Block,
    Escalate,
}

/// Whether the event is genuinely dangerous, independent of what any engine
/// says about it. This is the axis False SAFE and False BLOCK are scored on;
/// `ExpectedOutcome` is the axis resolution and escalation are scored on. They
/// are deliberately separate: an ESCALATE on a harmful event is a correct
/// deferral, not a miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Safety {
    Safe,
    Harmful,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub class: Class,
    pub expected: ExpectedOutcome,
    pub true_safety: Safety,
    /// For D and M: the single deterministic fact that is supposed to settle
    /// the case (e.g. `amount > 1_000_000`, `tool == "exfiltrate"`). Recorded
    /// so a failure can be inspected without re-deriving intent. `None` for S.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deciding_fact: Option<String>,
    /// Why this case carries this class and expectation. Written at
    /// construction time; a case without a rationale is rejected by the loader.
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_family: Option<String>,
}

/// Which physically separate corpus a case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    /// A. Publicly available external security/agent datasets.
    PublicExternal,
    /// B. Generated deterministic fact cases.
    SyntheticFacts,
    /// C. Separately generated adversarial set. Never used for rule
    /// development, threshold tuning, or engine modification.
    Holdout,
}

/// One corpus line: the two sides, joined only by an id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub source: Source,
    pub event: EventSpec,
    pub ground_truth: GroundTruth,
    /// Upstream dataset, licence, and row identifier for `PublicExternal`
    /// cases; the generator name and seed for the others.
    pub origin: String,
}

// ---------------------------------------------------------------------------
// The ACTION rule set under test.
// ---------------------------------------------------------------------------

/// The `ActionRule` slice the engine is configured with for a benchmark run.
///
/// ACTION results are a property of the engine *and* this rule set - after
/// f664be6 an action with no matching rule escalates by design, so the rule
/// set decides how much of the ACTION channel is even in scope. It is
/// therefore corpus data, versioned and published with the results, not a
/// harness constant. Serialized separately from any case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRuleSpec {
    pub action_name: String,
    pub field: String,
    pub required_provenance: ProvenanceSpec,
    pub comparator: ComparatorSpec,
    pub threshold: ValueSpec,
    pub code: String,
    pub policy_id: String,
    pub reason: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparatorSpec {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl From<ComparatorSpec> for edgeguard::event::Comparator {
    fn from(c: ComparatorSpec) -> Self {
        use edgeguard::event::Comparator as C;
        match c {
            ComparatorSpec::Eq => C::Eq,
            ComparatorSpec::Ne => C::Ne,
            ComparatorSpec::Gt => C::Gt,
            ComparatorSpec::Ge => C::Ge,
            ComparatorSpec::Lt => C::Lt,
            ComparatorSpec::Le => C::Le,
        }
    }
}

impl From<&ActionRuleSpec> for ActionRule {
    fn from(s: &ActionRuleSpec) -> Self {
        ActionRule {
            action_name: s.action_name.clone(),
            field: s.field.clone(),
            required_provenance: s.required_provenance.into(),
            comparator: s.comparator.into(),
            threshold: Value::from(&s.threshold),
            code: s.code.clone(),
            policy_id: s.policy_id.clone(),
            reason: s.reason.clone(),
            retryable: s.retryable,
        }
    }
}
