//! Freeze locks: classification, policy environments, and the holdout burn log.
//!
//! Three things must be fixed *before* a run and provably unchanged after it,
//! or the results describe a moving target:
//!
//! 1. The engine - [`crate::freeze`].
//! 2. The D/S/M classification of every case - [`ClassificationLock`]. A class
//!    revised after seeing results turns the benchmark into a record of what
//!    the engine already does.
//! 3. The policy environments - [`PolicyEnvironmentLock`].
//!
//! And one thing must be recorded because it cannot be prevented: every
//! observation of a holdout version - [`HoldoutBurnLog`].

use crate::schema::CaseRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// SHA-256 over the canonical JSON re-serialization of `value`.
///
/// Serde emits struct fields in declaration order and `BTreeMap` keys in sorted
/// order, so this is stable across runs and insensitive to source-file
/// formatting - a reformatted corpus is not a changed corpus, and a changed
/// corpus cannot hide behind reformatting.
pub fn digest_of<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("benchmark types are always serializable");
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The part of a case whose freeze matters: its ground truth and the policy
/// environment it is evaluated under.
///
/// Deliberately excludes the event payload. Fixing a typo in a prompt is not a
/// reclassification; changing what the case is *claimed to prove* is.
#[derive(Debug, Clone, Serialize)]
struct ClassificationSubject<'a> {
    class: &'a crate::schema::Class,
    expected: &'a crate::schema::ExpectedOutcome,
    true_safety: &'a crate::schema::Safety,
    deciding_facts: &'a [crate::schema::DecidingFact],
    policy_environment_id: &'a Option<String>,
    usage: &'a crate::schema::UsageClass,
}

pub fn classification_digest(record: &CaseRecord) -> String {
    digest_of(&ClassificationSubject {
        class: &record.ground_truth.class,
        expected: &record.ground_truth.expected,
        true_safety: &record.ground_truth.true_safety,
        deciding_facts: &record.ground_truth.deciding_facts,
        policy_environment_id: &record.policy_environment_id,
        usage: &record.usage,
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
    /// A case whose ground truth changed after the lock was written.
    Reclassified { case_id: String },
    /// A case in the lock that is no longer in the corpus.
    Removed { case_id: String },
    /// A case in the corpus that the lock does not cover.
    Unlocked { case_id: String },
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

    /// Every difference between the locked classification and the corpus on
    /// disk. An empty result is the only acceptable state for a scored run.
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
    /// environment id -> digest.
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

/// One observation of one holdout version.
///
/// A holdout answers exactly one question - does the engine generalise - and it
/// answers it once. After a version's results have been seen, that version is
/// **burned**: it may never inform a rule, a threshold, a detector, or a
/// corpus revision, because the people making those decisions have now seen
/// its answers. A second look is not forbidden here, because forbidding it is
/// not enforceable; it is *recorded*, so anyone reading the results knows how
/// many looks there were and can discount accordingly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoldoutObservation {
    pub holdout_version: String,
    pub corpus_digest: String,
    pub engine_commit: String,
    pub observed_at_utc: String,
    /// 1 for the first observation of this version. Anything above 1 means the
    /// version's statistical validity is already degraded.
    pub observation_index: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoldoutBurnLog {
    pub observations: Vec<HoldoutObservation>,
}

impl HoldoutBurnLog {
    /// How many times this holdout version has already been observed.
    pub fn observation_count(&self, holdout_version: &str) -> usize {
        self.observations
            .iter()
            .filter(|o| o.holdout_version == holdout_version)
            .count()
    }

    /// A version that has been observed at least once is burned for tuning.
    pub fn is_burned(&self, holdout_version: &str) -> bool {
        self.observation_count(holdout_version) > 0
    }

    /// Append an observation, assigning its index. Returns the recorded entry
    /// so the caller can surface a repeat look in the report.
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
