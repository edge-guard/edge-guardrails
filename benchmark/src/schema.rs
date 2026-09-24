//! Benchmark case schema.
//!
//! # The three-way separation
//!
//! A corpus case is three disjoint things:
//!
//! 1. An [`EventSpec`] - the only thing the engine is ever allowed to see.
//! 2. A [`GroundTruth`] - what the engine must never see.
//! 3. A `policy_environment_id` - a *reference* to a frozen, independently
//!    authored [`crate::policy_env::PolicyEnvironment`]. A case may name an
//!    environment; it may never carry rules of its own. A rule written to make
//!    one case decidable measures the rule author, not the engine.
//!
//! [`build_event`] accepts only the first, so there is no expression in this
//! crate that can place a label, an expected verdict, a D/S/M class, or any
//! other benchmark metadata into a `SecurityEvent`.

use edgeguard::event::{AttributedValue, EventKind, Provenance, SecurityEvent, Value};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

// ---------------------------------------------------------------------------
// Side 1: what the engine sees.
// ---------------------------------------------------------------------------

/// Which of the three contract channels this case exercises.
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
/// them would mean editing the frozen engine. `Map` uses a `BTreeMap` so a
/// corpus file round-trips byte-identically and hashes stably.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSpec {
    pub key: String,
    pub provenance: ProvenanceSpec,
    pub value: ValueSpec,
}

/// Everything the engine is permitted to observe about a case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSpec {
    pub channel: Channel,
    /// Required when `channel == Action`, forbidden otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    pub fields: Vec<FieldSpec>,
}

impl EventSpec {
    pub fn validate(&self) -> Result<(), String> {
        match (self.channel, &self.action_name) {
            (Channel::Action, None) => Err("channel Action requires an action_name".to_string()),
            (Channel::Input | Channel::Output, Some(name)) => Err(format!(
                "channel {:?} must not carry an action_name (got {name:?})",
                self.channel
            )),
            _ => Ok(()),
        }
    }
}

/// Build the `SecurityEvent` the engine will be handed. Takes an
/// [`EventSpec`] and nothing else.
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
// Side 2: what the engine must never see.
// ---------------------------------------------------------------------------

/// Ground-truth class. Frozen before execution; never revised from results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Class {
    /// Deterministically decidable: deterministic facts suffice to reach PASS
    /// or BLOCK with no semantic reasoning.
    D,
    /// Semantically decidable: no deterministic fact settles it, so a correct
    /// fast path must not pretend to know.
    S,
    /// Mixed: semantically ambiguous or adversarial content, plus a
    /// deterministic fact that independently settles the outcome.
    M,
}

/// Which kind of deterministic fact decides a case.
///
/// The axis that keeps EdgeGuard's full thesis measurable: it is a
/// deterministic fast path across content *and* structured action facts, not
/// an action policy evaluator. Reported separately, always.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactDomain {
    /// A fact readable from the content of the event itself.
    Content,
    /// A fact readable from the structured arguments of an action.
    Action,
}

/// Content-fact taxonomy, so CONTENT results are reportable per kind rather
/// than as one undifferentiated bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContentFactKind {
    /// Personally identifying information present in the content.
    Pii,
    /// A credential, key, or token present in the content.
    Secret,
    /// A deterministic literal or structural pattern.
    DeterministicPattern,
    /// Encoded, escaped, or otherwise obfuscated content.
    ObfuscationOrEncoding,
    /// A deterministic content constraint stated by an operator policy.
    PolicyContentRule,
}

/// Action-fact taxonomy, mirroring the structured-fact families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActionFactKind {
    AmountLimit,
    ForbiddenTarget,
    MissingRequiredFact,
    ProvenanceMismatch,
    TypeMismatch,
    StructuredConstraint,
}

/// One deterministic fact that, on its own, settles the security outcome.
///
/// `statement` must be human-auditable and written **about the event**, not
/// about any implementation: an auditor with no knowledge of this codebase must
/// be able to read it, look at the event, and agree. `corpus::validate` rejects
/// statements that name an implementation, a detector, or current behavior -
/// see [`crate::corpus::IMPLEMENTATION_TOKENS`]. A fact whose justification is
/// "the engine has a rule for it" is circular and disqualifies the case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecidingFact {
    pub domain: FactDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<ContentFactKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_kind: Option<ActionFactKind>,
    /// e.g. "the host-authoritative transfer amount is 1,250,000, above the
    /// environment's stated 1,000,000 ceiling".
    pub statement: String,
    /// Where in the event the fact is observable, e.g. `payload.amount`.
    pub observable_at: String,
}

impl DecidingFact {
    pub fn validate(&self) -> Result<(), String> {
        if self.statement.trim().is_empty() {
            return Err("deciding fact statement is required".to_string());
        }
        if self.observable_at.trim().is_empty() {
            return Err("deciding fact observable_at is required".to_string());
        }
        match (self.domain, self.content_kind, self.action_kind) {
            (FactDomain::Content, None, _) => {
                Err("a Content deciding fact requires a content_kind".to_string())
            }
            (FactDomain::Content, _, Some(_)) => {
                Err("a Content deciding fact must not carry an action_kind".to_string())
            }
            (FactDomain::Action, _, None) => {
                Err("an Action deciding fact requires an action_kind".to_string())
            }
            (FactDomain::Action, Some(_), _) => {
                Err("an Action deciding fact must not carry a content_kind".to_string())
            }
            _ => Ok(()),
        }
    }
}

/// Which fact domains decide a case. Independent of [`Class`]: an M case may
/// be decided by a content fact alone (obfuscated text carrying a secret), by
/// an action fact alone (adversarial prose plus an over-limit amount), or by
/// both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CaseShape {
    ContentOnly,
    ActionOnly,
    Mixed,
    /// No deterministic fact decides this case. Only valid for class S.
    NoDeterministicFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Pass,
    Block,
    Escalate,
}

/// Whether the event is genuinely dangerous, independent of any engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Safety {
    Safe,
    Harmful,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub class: Class,
    pub expected: ExpectedOutcome,
    pub true_safety: Safety,
    /// Empty if and only if `class == S`.
    #[serde(default)]
    pub deciding_facts: Vec<DecidingFact>,
    /// Why this case carries this class and expectation.
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_family: Option<String>,
}

impl GroundTruth {
    pub fn shape(&self) -> CaseShape {
        let domains: BTreeSet<FactDomain> = self.deciding_facts.iter().map(|f| f.domain).collect();
        match (
            domains.contains(&FactDomain::Content),
            domains.contains(&FactDomain::Action),
        ) {
            (true, true) => CaseShape::Mixed,
            (true, false) => CaseShape::ContentOnly,
            (false, true) => CaseShape::ActionOnly,
            (false, false) => CaseShape::NoDeterministicFact,
        }
    }

    pub fn content_fact_kinds(&self) -> Vec<ContentFactKind> {
        let set: BTreeSet<_> = self
            .deciding_facts
            .iter()
            .filter_map(|f| f.content_kind)
            .collect();
        set.into_iter().collect()
    }

    pub fn action_fact_kinds(&self) -> Vec<ActionFactKind> {
        let set: BTreeSet<_> = self
            .deciding_facts
            .iter()
            .filter_map(|f| f.action_kind)
            .collect();
        set.into_iter().collect()
    }
}

/// Which physically separate corpus a case came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    PublicExternal,
    SyntheticFacts,
    Holdout,
}

/// What a case is permitted to support.
///
/// Enforced at load time and honoured by the reporter: a `DevelopmentOnly`
/// case never contributes to an external or generalization figure, because the
/// engine's rules and thresholds were developed against it. Its score is a
/// training score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UsageClass {
    /// May support generalization claims.
    ExternalEvaluation,
    /// Previously used for rule or threshold development, or derived from
    /// material that was. Never contributes to generalization claims.
    DevelopmentOnly,
    /// One-shot holdout. Burned for tuning once observed.
    Holdout,
}

/// One corpus line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub source: Source,
    pub usage: UsageClass,
    /// Names a frozen policy environment. Required for `Action`, forbidden
    /// otherwise - the frozen engine consults action rules only on the Action
    /// path. A case may reference an environment; it may never define rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_environment_id: Option<String>,
    pub event: EventSpec,
    pub ground_truth: GroundTruth,
    /// Upstream dataset, licence, and row id for `PublicExternal`; generator
    /// name and seed otherwise.
    pub origin: String,
}
