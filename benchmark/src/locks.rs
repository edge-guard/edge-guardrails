//! Freeze locks: classification, policy environments, and the holdout burn log.
//!
//! Three things must be fixed *before* a run and provably unchanged after it,
//! or the results describe a moving target:
//!
//! 1. The engine - [`crate::freeze`].
//! 2. Every case: its ground truth **and its event** - [`ClassificationLock`].
//! 3. The policy environments - [`PolicyEnvironmentLock`].
//!
//! And one thing must be recorded because it cannot be prevented: every
//! observation of a holdout version - [`HoldoutBurnLog`].
//!
//! [`FreezeAttestation`] is the chokepoint: it is the only evidence that (2)
//! and (3) were checked, it cannot be constructed without checking them, and
//! [`crate::report::Report`] cannot be built without one.

use crate::schema::CaseRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// SHA-256 over the canonical JSON re-serialization of `value`.
///
/// Serde emits struct fields in declaration order and `BTreeMap` keys sorted,
/// so this is stable across runs and insensitive to source-file formatting: a
/// reformatted corpus is not a changed corpus, and a changed corpus cannot
/// hide behind reformatting.
pub fn digest_of<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("benchmark types are always serializable");
    hex(&Sha256::digest(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Everything about a case whose freeze matters.
///
/// This now includes a digest of the **event itself**, via
/// [`crate::schema::EventSpec::canonical`]. It previously did not, and the
/// gap was demonstrated: a case's entire payload could be replaced - a live
/// credential swapped for a weather question - while class, expectation,
/// safety and id all stayed put, and the lock reported no drift. There is no
/// "typo tolerance" any more, deliberately. If an event must change after the
/// freeze, that is a new case or a new corpus revision, not an invisible edit.
///
/// Because the digest is taken over the *canonical* event, reordering the
/// `fields` array or reformatting the JSON is still not drift: those do not
/// change the `SecurityEvent` the engine receives.
#[derive(Debug, Clone, Serialize)]
struct ClassificationSubject<'a> {
    class: &'a crate::schema::Class,
    expected: &'a crate::schema::ExpectedOutcome,
    expected_escalation_reason: &'a Option<crate::schema::EscalationReason>,
    true_safety: &'a crate::schema::Safety,
    deciding_facts: &'a [crate::schema::DecidingFact],
    policy_environment_id: &'a Option<String>,
    usage: &'a crate::schema::UsageClass,
    role: &'a crate::schema::CaseRole,
    event_canonical: String,
}

pub fn classification_digest(record: &CaseRecord) -> String {
    digest_of(&ClassificationSubject {
        class: &record.ground_truth.class,
        expected: &record.ground_truth.expected,
        expected_escalation_reason: &record.ground_truth.expected_escalation_reason,
        true_safety: &record.ground_truth.true_safety,
        deciding_facts: &record.ground_truth.deciding_facts,
        policy_environment_id: &record.policy_environment_id,
        usage: &record.usage,
        role: &record.role,
        event_canonical: record.event.canonical(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationLock {
    pub engine_commit: String,
    /// case_id -> classification digest.
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClassificationDrift {
    /// A case whose ground truth or event changed after the lock was written.
    Reclassified {
        case_id: String,
    },
    Removed {
        case_id: String,
    },
    Unlocked {
        case_id: String,
    },
}

impl ClassificationLock {
    pub fn build(records: &[CaseRecord]) -> Self {
        Self {
            engine_commit: crate::freeze::FROZEN_COMMIT.to_string(),
            entries: records
                .iter()
                .map(|r| (r.case_id.clone(), classification_digest(r)))
                .collect(),
        }
    }

    pub fn verify(&self, records: &[CaseRecord]) -> Vec<ClassificationDrift> {
        let current: BTreeMap<&str, String> = records
            .iter()
            .map(|r| (r.case_id.as_str(), classification_digest(r)))
            .collect();
        let mut drift = Vec::new();
        for (case_id, locked) in &self.entries {
            match current.get(case_id.as_str()) {
                Some(now) if now == locked => {}
                Some(_) => drift.push(ClassificationDrift::Reclassified {
                    case_id: case_id.clone(),
                }),
                None => drift.push(ClassificationDrift::Removed {
                    case_id: case_id.clone(),
                }),
            }
        }
        for case_id in current.keys() {
            if !self.entries.contains_key(*case_id) {
                drift.push(ClassificationDrift::Unlocked {
                    case_id: (*case_id).to_string(),
                });
            }
        }
        drift
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnvironmentLock {
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyEnvironmentDrift {
    Changed { id: String },
    Removed { id: String },
    Unlocked { id: String },
}

impl PolicyEnvironmentLock {
    pub fn build(digests: BTreeMap<String, String>) -> Self {
        Self { entries: digests }
    }

    pub fn verify(&self, digests: &BTreeMap<String, String>) -> Vec<PolicyEnvironmentDrift> {
        let mut drift = Vec::new();
        for (id, locked) in &self.entries {
            match digests.get(id) {
                Some(now) if now == locked => {}
                Some(_) => drift.push(PolicyEnvironmentDrift::Changed { id: id.clone() }),
                None => drift.push(PolicyEnvironmentDrift::Removed { id: id.clone() }),
            }
        }
        for id in digests.keys() {
            if !self.entries.contains_key(id) {
                drift.push(PolicyEnvironmentDrift::Unlocked { id: id.clone() });
            }
        }
        drift
    }
}

// ---------------------------------------------------------------------------
// The chokepoint.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FreezeFailure {
    Engine(Vec<crate::freeze::DriftedFile>),
    Classification(Vec<ClassificationDrift>),
    PolicyEnvironment(Vec<PolicyEnvironmentDrift>),
    Recipe(Vec<crate::recipe::RecipeDrift>),
    EngineUnreadable(String),
}

/// Proof that the engine, the classification lock, and the policy-environment
/// lock were all verified.
///
/// Its fields are private and there is no public constructor other than
/// [`FreezeAttestation::verify`], so an attestation cannot be fabricated: to
/// hold one is to have passed all three checks. [`crate::report::Report::build`]
/// requires one, which is what makes verification unskippable on the path that
/// produces publishable output.
///
/// **What this does not yet cover.** [`crate::metrics::MetricSet::compute`] is
/// still public and unattested, because unit tests must be able to compute a
/// metric from synthetic observations without a corpus. A future runner must
/// therefore take the attestation at its entry point and thread it through, not
/// merely call `MetricSet::compute` directly. That is the one remaining piece
/// of this invariant, and it is stated in `docs/DESIGN.md` rather than left to
/// be rediscovered.
#[derive(Debug, Clone)]
pub struct FreezeAttestation {
    engine_commit: String,
    case_count: usize,
    environment_digests: BTreeMap<String, String>,
    recipe_digests: BTreeMap<String, String>,
}

impl FreezeAttestation {
    /// The only way to obtain an attestation.
    pub fn verify(
        engine_root: &std::path::Path,
        records: &[CaseRecord],
        classification: &ClassificationLock,
        environments: &PolicyEnvironmentLock,
        environment_digests: &BTreeMap<String, String>,
        recipes: &crate::recipe::RecipeLock,
        recipe_digests: &BTreeMap<String, String>,
    ) -> Result<Self, FreezeFailure> {
        let drifted = crate::freeze::verify(engine_root)
            .map_err(|e| FreezeFailure::EngineUnreadable(e.to_string()))?;
        if !drifted.is_empty() {
            return Err(FreezeFailure::Engine(drifted));
        }
        let class_drift = classification.verify(records);
        if !class_drift.is_empty() {
            return Err(FreezeFailure::Classification(class_drift));
        }
        let env_drift = environments.verify(environment_digests);
        if !env_drift.is_empty() {
            return Err(FreezeFailure::PolicyEnvironment(env_drift));
        }
        let recipe_drift = recipes.verify(recipe_digests);
        if !recipe_drift.is_empty() {
            return Err(FreezeFailure::Recipe(recipe_drift));
        }
        Ok(Self {
            engine_commit: crate::freeze::FROZEN_COMMIT.to_string(),
            case_count: records.len(),
            environment_digests: environment_digests.clone(),
            recipe_digests: recipe_digests.clone(),
        })
    }

    pub fn engine_commit(&self) -> &str {
        &self.engine_commit
    }

    pub fn case_count(&self) -> usize {
        self.case_count
    }

    pub fn environment_digests(&self) -> &BTreeMap<String, String> {
        &self.environment_digests
    }

    pub fn recipe_digests(&self) -> &BTreeMap<String, String> {
        &self.recipe_digests
    }
}

// ---------------------------------------------------------------------------
// Holdout burn log.
// ---------------------------------------------------------------------------

/// One observation of one holdout version.
///
/// A holdout answers one question - does the engine generalise - and answers
/// it once. After a version's results have been seen, that version is
/// **burned**: it may never inform a rule, a threshold, a detector, or a
/// corpus revision, because the people making those decisions have seen its
/// answers. A second look is not forbidden here, because forbidding it is not
/// enforceable; it is *recorded*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldoutObservation {
    pub holdout_version: String,
    pub corpus_digest: String,
    pub engine_commit: String,
    pub observed_at_utc: String,
    pub observation_index: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoldoutBurnLog {
    pub observations: Vec<HoldoutObservation>,
}

impl HoldoutBurnLog {
    pub fn observation_count(&self, holdout_version: &str) -> usize {
        self.observations
            .iter()
            .filter(|o| o.holdout_version == holdout_version)
            .count()
    }

    pub fn is_burned(&self, holdout_version: &str) -> bool {
        self.observation_count(holdout_version) > 0
    }

    pub fn record(
        &mut self,
        holdout_version: &str,
        corpus_digest: &str,
        observed_at_utc: &str,
    ) -> HoldoutObservation {
        let observation = HoldoutObservation {
            holdout_version: holdout_version.to_string(),
            corpus_digest: corpus_digest.to_string(),
            engine_commit: crate::freeze::FROZEN_COMMIT.to_string(),
            observed_at_utc: observed_at_utc.to_string(),
            observation_index: self.observation_count(holdout_version) + 1,
        };
        self.observations.push(observation.clone());
        observation
    }
}
