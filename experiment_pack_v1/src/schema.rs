//! Raw record schemas for Experiment Pack v1.0, Tracks A / B / C.
//!
//! These types are the *raw* append-only record format. They deliberately
//! carry both the pre-exposure annotation and the observed EdgeGuard result in
//! one record, because a result whose label cannot be traced back to the
//! annotation that existed *before* the engine ran is not auditable.
//!
//! The invariant the type system enforces here is ordering, not content:
//! `label` (pre-exposure) is a required field on construction, and `observed`
//! is an `Option` that starts `None`. A record cannot be built from an engine
//! output; it can only be *completed* by one.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Which corpus partition a case belongs to. Development and holdout are
/// physically separated (Pack §6.5); this field records which side a record
/// came from so a mixed report is detectable after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Partition {
    Development,
    Holdout,
}

/// Where a label came from. Pack §6.2: external labels are preferred and
/// internal annotation must be explicitly marked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelSource {
    /// Carried by the upstream dataset itself.
    External { dataset: String, field: String },
    /// Assigned by a human annotator in this project.
    InternalAnnotation { annotator: String },
    /// Produced by a frozen generator recipe (synthetic).
    GeneratorRecipe { recipe: String, seed: u64 },
}

/// Provenance of one fact, mirroring `edgeguard::event::Provenance` without
/// depending on it, so the record format survives a Core enum change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactProvenance {
    HostAuthoritative,
    ModelProposed,
    UserProvided,
}

/// The observed engine output. Constructed only from a real run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observed {
    /// PASS / BLOCK / ESCALATE as the benchmark-facing three-way result.
    pub verdict: String,
    pub code: String,
    pub reason: String,
    /// `DecidedBy` rendered with `Debug`, verbatim.
    pub decided_by: String,
    /// True when Tier 2 was not consulted.
    pub model_bypassed: bool,
    /// Tier-2 calls attributable to this single event (0 or 1 inline).
    pub tier2_calls: u64,
    /// Whether the terminal decision came from deterministic Core evidence.
    pub locally_resolved: bool,
    pub timing: Timing,
}

/// One case's timing record. Every field is nanoseconds and measured, never
/// estimated. `cold` marks the first observation of a given engine instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    pub native_core_ns: u64,
    pub ffi_boundary_ns: Option<u64>,
    pub adapter_e2e_ns: Option<u64>,
    pub cold: bool,
    pub input_bytes: usize,
    pub rule_count: usize,
}

// ---------------------------------------------------------------------------
// Track A - Action / effect boundary
// ---------------------------------------------------------------------------

/// Pre-exposure deterministic-resolvability label (Pack §3, Track A).
///
/// The distinction that matters for the thesis is D vs S: D asserts the stated
/// facts alone settle the action. Pack §7 forbids labelling a case `D` when
/// that is only true because host state was invented that the source workload
/// does not supply - `deterministic_basis` is where that claim is evidenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionLabel {
    /// Deterministic stated facts are sufficient to permit.
    DPass,
    /// Deterministic stated facts are sufficient to deny.
    DBlock,
    /// Deterministic facts insufficient; semantics/external judgment required.
    S,
    /// Semantic-looking context exists, but an independent deterministic fact
    /// still settles the action.
    M,
}

/// The exact deterministic basis for a D or M label. Pack §7 requires this for
/// every D/M case; a `D` label with an empty basis is a schema error, not a
/// stylistic gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeterministicBasis {
    PolicyClause(String),
    TypedArg(String),
    AuthoritativeStateFact(String),
    IdentityOrOwnershipFact(String),
    Transition(String),
    Limit(String),
    Confirmation(String),
    Provenance(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributedFact {
    pub name: String,
    /// JSON rendering of the typed value, preserving the original type.
    pub value: serde_json::Value,
    pub provenance: FactProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackARecord {
    pub case_id: String,
    pub partition: Partition,
    pub source_dataset: String,
    pub source_version: String,
    pub source_license: String,

    pub action_name: String,
    pub final_typed_args: Vec<AttributedFact>,
    pub principal_id: Option<String>,
    pub resource_id: Option<String>,
    pub host_authoritative_facts: Vec<AttributedFact>,
    pub confirmation_or_attestation: Option<String>,
    pub policy_id: String,
    pub policy_version: String,
    /// Whether this action mutates or is otherwise security-sensitive. Pack §3
    /// excludes trivial read-only calls from the Action headline.
    pub mutating_or_sensitive: bool,

    // --- pre-exposure annotation ------------------------------------------
    pub label: ActionLabel,
    pub label_source: LabelSource,
    pub deterministic_basis: Vec<DeterministicBasis>,
    /// Independently supported ground truth, where it exists. `None` means the
    /// dataset does not establish it - which is NOT the same as "safe".
    pub true_safety: Option<bool>,
    /// Second annotation, required for ambiguous D/S/M (Pack §6.3). Kept even
    /// when it disagrees; disagreements are preserved, never silently resolved.
    pub second_annotation: Option<ActionLabel>,

    // --- post-exposure ----------------------------------------------------
    pub observed: Option<Observed>,
}

// ---------------------------------------------------------------------------
// Track B - Content
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Input,
    Output,
    Rag,
    ToolReturn,
}

/// Content slice (Pack §3, Track B). Slices are reported separately so an easy
/// slice cannot dilute a dangerous one (Pack §6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentSlice {
    ExternalBenign,
    ExternalHarmful,
    /// Benign text that deliberately contains attack-like language.
    HardBenignNegative,
    ObfuscationEncoding,
    /// Semantically malicious with no deterministic signature.
    SemanticNoSignature,
    DeterministicSecretPiiPolicy,
}

/// Ground truth for content. Pack §3: "no malicious label" is never SAFE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTruth {
    Benign,
    Harmful,
    /// The source does not establish safety either way. Counts as neither a
    /// correct PASS nor a False SAFE; it is reported as unresolved.
    Unestablished,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackBRecord {
    pub case_id: String,
    pub partition: Partition,
    pub source_dataset: String,
    pub source_version: String,
    pub source_license: String,
    pub source_record_id: String,

    pub channel: Channel,
    pub slice: ContentSlice,
    /// Raw content, preserved verbatim from the source.
    pub content: String,

    // --- pre-exposure annotation ------------------------------------------
    pub truth: ContentTruth,
    pub label_source: LabelSource,
    pub second_annotation: Option<ContentTruth>,

    // --- post-exposure ----------------------------------------------------
    pub observed: Option<Observed>,
}

// ---------------------------------------------------------------------------
// Track C - Cross-boundary trust / effect
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceTrust {
    Untrusted,
    UserProvided,
    Trusted,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hop {
    pub index: u32,
    pub transformation: String,
    pub derived_value: serde_json::Value,
    /// Whether provenance/lineage survives this hop.
    pub provenance_retained: bool,
}

/// Expected routing outcome, annotated before exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    Pass,
    Block,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrackCRecord {
    pub case_id: String,
    pub partition: Partition,
    /// Pack §7: development scenarios are permitted where no external corpus
    /// exists, but must be marked and never called independent market
    /// evidence. `false` here means exactly that.
    pub externally_sourced: bool,
    pub scenario_shape: String,

    pub source_trust: SourceTrust,
    pub hops: Vec<Hop>,
    pub final_action: String,
    pub expected_enforcement_point: String,
    pub deterministic_facts_available: Vec<AttributedFact>,

    // --- pre-exposure annotation ------------------------------------------
    pub expected: ExpectedOutcome,
    pub label_source: LabelSource,
    /// Hop index at which provenance is expected to be lost, if any.
    pub expected_provenance_loss_hop: Option<u32>,

    // --- post-exposure ----------------------------------------------------
    pub observed: Option<Observed>,
    /// Hop index at which provenance was actually lost, if any.
    pub actual_provenance_loss_hop: Option<u32>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "schema error: {}", self.0)
    }
}

impl TrackARecord {
    /// Pack §7: a D or M label must record the exact deterministic basis. This
    /// is checked mechanically because "we meant to write it down" is how a
    /// deterministic-coverage claim becomes unfalsifiable.
    pub fn validate(&self) -> Result<(), SchemaError> {
        let needs_basis = matches!(
            self.label,
            ActionLabel::DPass | ActionLabel::DBlock | ActionLabel::M
        );
        if needs_basis && self.deterministic_basis.is_empty() {
            return Err(SchemaError(format!(
                "case {}: label {:?} requires a non-empty deterministic_basis",
                self.case_id, self.label
            )));
        }
        if !needs_basis && !self.deterministic_basis.is_empty() {
            return Err(SchemaError(format!(
                "case {}: label S must not carry a deterministic_basis",
                self.case_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(name: &str) -> AttributedFact {
        AttributedFact {
            name: name.into(),
            value: serde_json::json!(10),
            provenance: FactProvenance::HostAuthoritative,
        }
    }

    fn rec(label: ActionLabel, basis: Vec<DeterministicBasis>) -> TrackARecord {
        TrackARecord {
            case_id: "c1".into(),
            partition: Partition::Development,
            source_dataset: "dev".into(),
            source_version: "0".into(),
            source_license: "n/a".into(),
            action_name: "execute_payment".into(),
            final_typed_args: vec![fact("amount")],
            principal_id: None,
            resource_id: None,
            host_authoritative_facts: vec![],
            confirmation_or_attestation: None,
            policy_id: "p".into(),
            policy_version: "1".into(),
            mutating_or_sensitive: true,
            label,
            label_source: LabelSource::InternalAnnotation {
                annotator: "test".into(),
            },
            deterministic_basis: basis,
            true_safety: None,
            second_annotation: None,
            observed: None,
        }
    }

    #[test]
    fn a_d_label_without_a_deterministic_basis_is_rejected() {
        assert!(rec(ActionLabel::DPass, vec![]).validate().is_err());
        assert!(rec(ActionLabel::DBlock, vec![]).validate().is_err());
        assert!(rec(ActionLabel::M, vec![]).validate().is_err());
    }

    #[test]
    fn an_s_label_carrying_a_deterministic_basis_is_rejected() {
        let r = rec(
            ActionLabel::S,
            vec![DeterministicBasis::Limit("amount<=1000".into())],
        );
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_well_formed_d_case_validates() {
        let r = rec(
            ActionLabel::DBlock,
            vec![DeterministicBasis::Limit("amount<=1000".into())],
        );
        assert!(r.validate().is_ok());
    }

    #[test]
    fn records_round_trip_through_json_without_losing_the_annotation() {
        let r = rec(
            ActionLabel::DBlock,
            vec![DeterministicBasis::TypedArg("amount".into())],
        );
        let s = serde_json::to_string(&r).unwrap();
        let back: TrackARecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
        assert!(back.observed.is_none(), "a fresh record has no observation");
    }
}
