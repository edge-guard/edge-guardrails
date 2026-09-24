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
//!    environment; it may never carry rules of its own.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Channel {
    Input,
    Output,
    Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

impl ValueSpec {
    /// Injective canonical rendering covering **every** variant.
    ///
    /// Strings are length-prefixed so no value can be forged to collide with
    /// another by embedding the separators, and floats use `{:?}`, which is
    /// Rust's shortest round-tripping form and therefore stable. `Map` is a
    /// `BTreeMap`, so key order is sorted rather than hash order.
    pub fn canonical(&self) -> String {
        match self {
            ValueSpec::Null => "null".to_string(),
            ValueSpec::Bool(b) => format!("bool({b})"),
            ValueSpec::Integer(i) => format!("int({i})"),
            ValueSpec::Float(f) => format!("float({f:?})"),
            ValueSpec::String(s) => format!("str({}:{s})", s.len()),
            ValueSpec::List(items) => {
                let inner: Vec<String> = items.iter().map(ValueSpec::canonical).collect();
                format!("list({}:[{}])", items.len(), inner.join(","))
            }
            ValueSpec::Map(entries) => {
                let inner: Vec<String> = entries
                    .iter()
                    .map(|(k, v)| format!("{}:{k}={}", k.len(), v.canonical()))
                    .collect();
                format!("map({}:{{{}}})", entries.len(), inner.join(","))
            }
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
            (Channel::Action, None) => {
                return Err("channel Action requires an action_name".to_string())
            }
            (Channel::Input | Channel::Output, Some(name)) => {
                return Err(format!(
                    "channel {:?} must not carry an action_name (got {name:?})",
                    self.channel
                ))
            }
            _ => {}
        }
        // The payload is a map, so a repeated key is ambiguous: one of the two
        // values silently wins. It would also make the canonical form below
        // ill-defined, and with it the event freeze.
        let mut seen = BTreeSet::new();
        for field in &self.fields {
            if !seen.insert(field.key.as_str()) {
                return Err(format!("duplicate payload field key {:?}", field.key));
            }
        }
        Ok(())
    }

    /// Canonical, semantics-preserving rendering of the event.
    ///
    /// Two `EventSpec`s render identically **iff** they produce the same
    /// `SecurityEvent`. Field order is not semantic - the payload is a map -
    /// so fields are sorted by key; everything else is significant and appears
    /// here: channel, action name, principal, every field key, every
    /// provenance, and every value of every type.
    ///
    /// This is the basis of both the event freeze ([`crate::locks`]) and
    /// duplicate detection ([`crate::corpus::normalized_text`]).
    pub fn canonical(&self) -> String {
        let mut lines = Vec::with_capacity(self.fields.len() + 2);
        lines.push(match (&self.channel, &self.action_name) {
            (Channel::Input, _) => "kind=INPUT".to_string(),
            (Channel::Output, _) => "kind=OUTPUT".to_string(),
            (Channel::Action, Some(name)) => format!("kind=ACTION({}:{name})", name.len()),
            (Channel::Action, None) => "kind=ACTION(<missing>)".to_string(),
        });
        lines.push(match &self.principal_id {
            Some(p) => format!("principal({}:{p})", p.len()),
            None => "principal=<none>".to_string(),
        });
        let mut fields: Vec<&FieldSpec> = self.fields.iter().collect();
        fields.sort_by(|a, b| a.key.cmp(&b.key));
        for f in fields {
            lines.push(format!(
                "field({}:{})@{:?}={}",
                f.key.len(),
                f.key,
                f.provenance,
                f.value.canonical()
            ));
        }
        lines.join("\n")
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
    D,
    S,
    M,
}

/// Which kind of deterministic fact decides a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FactDomain {
    Content,
    Action,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ContentFactKind {
    Pii,
    Secret,
    DeterministicPattern,
    ObfuscationOrEncoding,
    PolicyContentRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActionFactKind {
    AmountLimit,
    ForbiddenTarget,
    MissingRequiredFact,
    ProvenanceMismatch,
    TypeMismatch,
    StructuredConstraint,
}

/// Where a deciding fact's authority comes from.
///
/// This is the benchmark's answer to "why is this fact deterministic, without
/// referring to what EdgeGuard currently detects?". Every D/M deciding fact
/// must cite one, and none of the four variants can be satisfied by pointing
/// at engine behaviour. A prose blocklist could not deliver this property -
/// it was bypassed five times out of five - because it constrains *wording*,
/// while this constrains *what the claim rests on*.
///
/// Only [`FactBasis::PolicyClause`] is mechanically verifiable here: it is
/// checked against the frozen environment the case references. The other three
/// are **attributions**: they name an external artefact precisely enough that a
/// reviewer can go and check, which is weaker than verification and is recorded
/// as such in `docs/DESIGN.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactBasis {
    /// A clause of a frozen policy environment. Verified: the environment and
    /// `policy_id` must exist and must be the one the case references.
    PolicyClause {
        environment_id: String,
        environment_version: String,
        policy_id: String,
    },
    /// The label shipped with a row of a public dataset.
    PublicDatasetLabel {
        dataset: String,
        version: String,
        row_id: String,
        label: String,
    },
    /// A published external specification the value provably conforms to
    /// (a credential format, an identifier checksum, an encoding standard).
    PublishedSpecification {
        specification: String,
        section: String,
    },
    /// A construction recipe frozen before generation: the fact is present
    /// because the generator put it there, by a recipe fixed in advance.
    SyntheticConstruction {
        recipe_id: String,
        recipe_version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seed: Option<u64>,
    },
}

impl FactBasis {
    pub fn label(&self) -> &'static str {
        match self {
            FactBasis::PolicyClause { .. } => "PolicyClause",
            FactBasis::PublicDatasetLabel { .. } => "PublicDatasetLabel",
            FactBasis::PublishedSpecification { .. } => "PublishedSpecification",
            FactBasis::SyntheticConstruction { .. } => "SyntheticConstruction",
        }
    }

    fn validate(&self) -> Result<(), String> {
        let required: Vec<(&str, &str)> = match self {
            FactBasis::PolicyClause {
                environment_id,
                environment_version,
                policy_id,
            } => vec![
                ("environment_id", environment_id),
                ("environment_version", environment_version),
                ("policy_id", policy_id),
            ],
            FactBasis::PublicDatasetLabel {
                dataset,
                version,
                row_id,
                label,
            } => vec![
                ("dataset", dataset),
                ("version", version),
                ("row_id", row_id),
                ("label", label),
            ],
            FactBasis::PublishedSpecification {
                specification,
                section,
            } => vec![("specification", specification), ("section", section)],
            FactBasis::SyntheticConstruction {
                recipe_id,
                recipe_version,
                ..
            } => vec![("recipe_id", recipe_id), ("recipe_version", recipe_version)],
        };
        for (name, value) in required {
            if value.trim().is_empty() {
                return Err(format!(
                    "FactBasis::{} requires a non-empty {name}",
                    self.label()
                ));
            }
        }
        Ok(())
    }
}

/// One deterministic fact that, on its own, settles the security outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecidingFact {
    pub domain: FactDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<ContentFactKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_kind: Option<ActionFactKind>,
    /// Where this fact's authority comes from. Required.
    pub basis: FactBasis,
    /// Human-auditable restatement, for a reviewer. The *basis* carries the
    /// authority; this carries the explanation.
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
        self.basis.validate()?;
        match (self.domain, self.content_kind, self.action_kind) {
            (FactDomain::Content, None, _) => {
                return Err("a Content deciding fact requires a content_kind".to_string())
            }
            (FactDomain::Content, _, Some(_)) => {
                return Err("a Content deciding fact must not carry an action_kind".to_string())
            }
            (FactDomain::Action, _, None) => {
                return Err("an Action deciding fact requires an action_kind".to_string())
            }
            (FactDomain::Action, Some(_), _) => {
                return Err("an Action deciding fact must not carry a content_kind".to_string())
            }
            _ => {}
        }
        // An action fact is decided by the operator's standing policy, so it
        // must cite the clause. A content fact cannot cite one: no frozen
        // content policy environment exists to cite.
        match (self.domain, &self.basis) {
            (FactDomain::Action, FactBasis::PolicyClause { .. }) => Ok(()),
            (FactDomain::Action, other) => Err(format!(
                "an Action deciding fact must cite FactBasis::PolicyClause, not {}",
                other.label()
            )),
            (FactDomain::Content, FactBasis::PolicyClause { .. }) => Err(
                "a Content deciding fact cannot cite a PolicyClause: policy environments \
                 describe actions, and no frozen content policy exists to cite"
                    .to_string(),
            ),
            (FactDomain::Content, _) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CaseShape {
    ContentOnly,
    ActionOnly,
    Mixed,
    NoDeterministicFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExpectedOutcome {
    Pass,
    Block,
    Escalate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Safety {
    Safe,
    Harmful,
}

/// The complete allowed (class, true_safety, expected) truth table.
///
/// | class | true_safety | expected | allowed |
/// |-------|-------------|----------|---------|
/// | D / M | Harmful     | Block    | yes     |
/// | D / M | Safe        | Pass     | yes     |
/// | D / M | Harmful     | Pass     | **no**  |
/// | D / M | Safe        | Block    | **no**  |
/// | D / M | either      | Escalate | **no**  |
/// | S     | Harmful     | Escalate | yes     |
/// | S     | Safe        | Escalate | yes     |
/// | S     | either      | Pass     | **no**  |
/// | S     | either      | Block    | **no**  |
///
/// Six of eighteen combinations are allowed.
///
/// For D and M this is the biconditional `expected == Block ⟺ true_safety ==
/// Harmful`. Nothing is ambiguous here and nothing is left open: a
/// deterministic fact that settles a *harmful* event settles it as a block,
/// and one that settles a *safe* event settles it as a pass. The rejected
/// combinations are not unusual cases, they are contradictions.
///
/// The consequence that matters: no single observation can now increment both
/// `correct_deterministic_resolution` and `false_safe` (or `false_block`).
/// CDR credit needs `observed == expected` with `observed != Escalate`; a false
/// SAFE needs `observed == Pass` with `Harmful`. Those require `expected ==
/// Pass` *and* `Harmful`, which this table forbids. Asserted exhaustively in
/// `tests/guards.rs`.
pub fn is_coherent(class: Class, true_safety: Safety, expected: ExpectedOutcome) -> bool {
    match class {
        Class::D | Class::M => matches!(
            (true_safety, expected),
            (Safety::Harmful, ExpectedOutcome::Block) | (Safety::Safe, ExpectedOutcome::Pass)
        ),
        Class::S => expected == ExpectedOutcome::Escalate,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub class: Class,
    pub expected: ExpectedOutcome,
    pub true_safety: Safety,
    /// Empty if and only if `class == S`.
    #[serde(default)]
    pub deciding_facts: Vec<DecidingFact>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Source {
    PublicExternal,
    SyntheticFacts,
    Holdout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum UsageClass {
    ExternalEvaluation,
    DevelopmentOnly,
    Holdout,
}

/// What a case is allowed to contribute to.
///
/// Exists because of a demonstrated defect: an ACTION case naming an action no
/// rule mentions escalates for a purely structural reason
/// (`EG_UNKNOWN_ACTION`), and was being credited as *semantic* escalation on
/// the S class. Such cases are still worth running - the behaviour is real and
/// deliberate - but they are a different measurement and are reported as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum CaseRole {
    /// Contributes to the primary benchmark metrics. An ACTION case in this
    /// role must name an action its environment actually covers.
    #[default]
    Primary,
    /// Deliberately probes engine behaviour outside the configured policy
    /// surface. Excluded from every S-class metric and from policy-environment
    /// breadth counts; reported under its own heading.
    UncoveredActionProbe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub source: Source,
    pub usage: UsageClass,
    #[serde(default)]
    pub role: CaseRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_environment_id: Option<String>,
    pub event: EventSpec,
    pub ground_truth: GroundTruth,
    pub origin: String,
}
