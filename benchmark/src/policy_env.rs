//! Frozen policy environments.
//!
//! # Why environments exist
//!
//! If a test case may carry the rule that makes it decidable, the benchmark
//! measures the rule author. The case and the rule would be written together,
//! the rule would fit the case exactly, and every ACTION result would be a
//! tautology.
//!
//! So rules live here instead: a small number of independently authored,
//! versioned, hashed **policy environments**, each describing a plausible
//! operator's standing policy. An environment is frozen before any case is
//! written against it, and a single environment must serve many cases across
//! every class and both safety values - safe and harmful, D, S and M. A case
//! references an environment by id and cannot add to it.
//!
//! An environment is operator configuration, not an engine capability. Writing
//! one adds nothing to the frozen engine: `ActionRule` is a public part of the
//! contract at `f664be6`, and these files only populate it.

use crate::schema::{ProvenanceSpec, ValueSpec};
use edgeguard::event::{ActionRule, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

/// One rule in an environment. Field order is fixed because the environment
/// digest is taken over the canonical re-serialization of this struct.
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
    /// The operator's justification, in business terms. Present so a reader
    /// can audit the environment as a policy rather than reverse-engineer it
    /// from the comparison.
    pub justification: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnvironment {
    pub id: String,
    pub version: String,
    /// What operator this environment represents, in prose.
    pub description: String,
    pub rules: Vec<ActionRuleSpec>,
}

impl PolicyEnvironment {
    /// SHA-256 over the canonical re-serialization of the parsed environment,
    /// not over the file bytes: reformatting the JSON must not appear as a
    /// policy change, and a semantic change must never hide behind formatting.
    pub fn digest(&self) -> String {
        crate::locks::digest_of(self)
    }

    pub fn action_rules(&self) -> Vec<ActionRule> {
        self.rules.iter().map(ActionRule::from).collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("policy environment id is required".to_string());
        }
        if self.version.trim().is_empty() {
            return Err(format!("environment {:?} requires a version", self.id));
        }
        if self.description.trim().is_empty() {
            return Err(format!("environment {:?} requires a description", self.id));
        }
        if self.rules.is_empty() {
            return Err(format!("environment {:?} defines no rules", self.id));
        }
        for rule in &self.rules {
            if rule.justification.trim().is_empty() {
                return Err(format!(
                    "environment {:?}: rule {:?} requires a justification in business terms",
                    self.id, rule.policy_id
                ));
            }
        }
        Ok(())
    }

    /// Action names this environment says anything about.
    ///
    /// Not a registry the engine consults - the frozen engine has no such
    /// notion, and adding one is out of scope. This is for corpus authoring
    /// and reporting only.
    pub fn covered_actions(&self) -> Vec<String> {
        let mut names: Vec<String> = self.rules.iter().map(|r| r.action_name.clone()).collect();
        names.sort();
        names.dedup();
        names
    }
}

#[derive(Debug, Default)]
pub struct PolicyEnvironmentSet {
    environments: BTreeMap<String, PolicyEnvironment>,
}

impl PolicyEnvironmentSet {
    pub fn get(&self, id: &str) -> Option<&PolicyEnvironment> {
        self.environments.get(id)
    }

    pub fn ids(&self) -> Vec<&str> {
        self.environments.keys().map(String::as_str).collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &PolicyEnvironment> {
        self.environments.values()
    }

    pub fn is_empty(&self) -> bool {
        self.environments.is_empty()
    }

    /// Map of environment id to digest, for the freeze lock.
    pub fn digests(&self) -> BTreeMap<String, String> {
        self.environments
            .iter()
            .map(|(id, env)| (id.clone(), env.digest()))
            .collect()
    }
}

#[derive(Debug)]
pub enum PolicyEnvError {
    Io {
        path: PathBuf,
        error: String,
    },
    Parse {
        path: PathBuf,
        error: String,
    },
    Invalid {
        path: PathBuf,
        error: String,
    },
    DuplicateId {
        id: String,
        path: PathBuf,
    },
    /// The file name must match the environment id and version, so a reader
    /// cannot be misled about which environment a path refers to.
    NameMismatch {
        path: PathBuf,
        expected: String,
    },
}

pub fn load_dir(dir: &Path) -> Result<PolicyEnvironmentSet, PolicyEnvError> {
    let mut set = PolicyEnvironmentSet::default();
    let entries = std::fs::read_dir(dir).map_err(|e| PolicyEnvError::Io {
        path: dir.to_path_buf(),
        error: e.to_string(),
    })?;
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();

    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| PolicyEnvError::Io {
            path: path.clone(),
            error: e.to_string(),
        })?;
        let env: PolicyEnvironment =
            serde_json::from_str(&text).map_err(|e| PolicyEnvError::Parse {
                path: path.clone(),
                error: e.to_string(),
            })?;
        env.validate().map_err(|error| PolicyEnvError::Invalid {
            path: path.clone(),
            error,
        })?;
        let expected_stem = format!("{}_{}", env.id, env.version);
        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
        if stem != expected_stem {
            return Err(PolicyEnvError::NameMismatch {
                path: path.clone(),
                expected: format!("{expected_stem}.json"),
            });
        }
        if set.environments.contains_key(&env.id) {
            return Err(PolicyEnvError::DuplicateId {
                id: env.id.clone(),
                path,
            });
        }
        set.environments.insert(env.id.clone(), env);
    }
    Ok(set)
}

/// Minimum breadth an environment must have across the corpus before its
/// ACTION numbers mean anything.
///
/// An environment exercised by three cases from one class is a fixture, not an
/// environment; its per-environment metrics would describe those three cases.
/// Checked once the corpus exists, before any run.
pub const MIN_CASES_PER_ENVIRONMENT: usize = 20;
pub const MIN_CLASSES_PER_ENVIRONMENT: usize = 2;

/// One environment's observed breadth, as counted from a loaded corpus.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentUsage {
    pub cases: usize,
    pub distinct_classes: usize,
    pub has_safe: bool,
    pub has_harmful: bool,
}

impl EnvironmentUsage {
    pub fn shortfalls(&self, id: &str) -> Vec<String> {
        let mut out = Vec::new();
        if self.cases < MIN_CASES_PER_ENVIRONMENT {
            out.push(format!(
                "environment {id:?} is referenced by {} cases, below the {MIN_CASES_PER_ENVIRONMENT} \
                 needed for its per-environment metrics to describe a policy rather than a fixture",
                self.cases
            ));
        }
        if self.distinct_classes < MIN_CLASSES_PER_ENVIRONMENT {
            out.push(format!(
                "environment {id:?} spans {} ground-truth class(es); at least \
                 {MIN_CLASSES_PER_ENVIRONMENT} are required",
                self.distinct_classes
            ));
        }
        if !self.has_safe {
            out.push(format!("environment {id:?} has no safe cases"));
        }
        if !self.has_harmful {
            out.push(format!("environment {id:?} has no harmful cases"));
        }
        out
    }
}
