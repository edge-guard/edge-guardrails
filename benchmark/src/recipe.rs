//! Frozen synthetic construction recipes.
//!
//! # What this prevents
//!
//! Write a recipe, generate cases, look at the results, quietly widen a
//! boundary, regenerate. Nothing in the corpus would record that the second
//! batch came from a different rule than the first, and the benchmark would
//! have been tuned against its own subject without anyone editing the engine.
//!
//! So a recipe is frozen the way a policy environment is: versioned, canonically
//! digested, and locked before a single case is instantiated. A case cites
//! [`crate::schema::FactBasis::SyntheticConstruction`] with a `recipe_id` and
//! `recipe_version`; [`crate::corpus::check_recipe_citations`] refuses a
//! citation that does not resolve, and [`RecipeLock`] refuses a recipe that has
//! changed, vanished, or appeared since the freeze.
//!
//! # What a recipe is not
//!
//! It is not a generation DSL. The predicates are declarative prose, stated as
//! conditions over the **policy clause or published specification** the family
//! rests on, and a versioned [`GeneratorRef`] names the code that reads them.
//! The point is that the boundary is *written down and hashed* before anyone
//! sees a result - not that a machine can execute it.
//!
//! A recipe is authored from a policy clause or a published specification.
//! Never from engine behaviour: "generate examples matching what EdgeGuard
//! detects" is the failure this whole structure exists to prevent, and
//! `tests/guards.rs` checks that this module's own source does not reach into
//! the engine.

use crate::schema::{ActionFactKind, Channel, Class, ContentFactKind, FactBasis, FactDomain};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How seeds are assigned to instantiated cases.
///
/// Recorded in the recipe, and therefore frozen, so that "we regenerated with a
/// luckier seed" is visible rather than silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedPolicy {
    /// One fixed seed for the whole family.
    Fixed { seed: u64 },
    /// Case `i` uses `base_seed + i`, so the sequence is reproducible and a
    /// re-run cannot silently draw different values.
    DerivedFromCaseIndex { base_seed: u64 },
}

/// The code that reads a recipe and emits cases, pinned by version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorRef {
    /// e.g. `generate::synthetic_facts::amount_limit`.
    pub module_path: String,
    pub version: String,
}

/// One frozen family recipe.
///
/// Field order is fixed: the digest is taken over the canonical
/// re-serialization of this struct, so declaration order is part of the
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticRecipe {
    pub recipe_id: String,
    pub recipe_version: String,
    /// The security fact this family tests, in prose.
    pub description: String,
    pub channel: Channel,
    pub domain: FactDomain,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<ContentFactKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_kind: Option<ActionFactKind>,
    /// The independent authority the whole family rests on. For an Action
    /// family this must be a [`FactBasis::PolicyClause`]; cases then cite the
    /// *recipe*, and the chain case -> recipe -> clause is verified.
    pub basis: FactBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_environment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_clause_id: Option<String>,
    /// Which ground-truth classes this family can legitimately produce.
    pub applicable_classes: Vec<Class>,
    /// The condition, over the cited clause or specification, under which a
    /// generated case is SAFE. Stated before generation; frozen.
    pub safe_predicate: String,
    /// The condition under which a generated case is HARMFUL.
    pub harmful_predicate: String,
    /// What is varied across instances (locale, units, field ordering,
    /// encoding depth...). Frozen so the variation space cannot be widened
    /// after seeing results.
    pub variation_dimensions: Vec<String>,
    pub seed_policy: SeedPolicy,
    pub generator: GeneratorRef,
}

impl SyntheticRecipe {
    /// SHA-256 over the canonical re-serialization of the parsed recipe, not
    /// over the file bytes: reformatting the JSON is not a change, and a real
    /// change cannot hide behind reformatting.
    pub fn digest(&self) -> String {
        crate::locks::digest_of(self)
    }

    pub fn key(&self) -> String {
        format!("{}@{}", self.recipe_id, self.recipe_version)
    }

    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("recipe_id", &self.recipe_id),
            ("recipe_version", &self.recipe_version),
            ("description", &self.description),
            ("safe_predicate", &self.safe_predicate),
            ("harmful_predicate", &self.harmful_predicate),
            ("generator.module_path", &self.generator.module_path),
            ("generator.version", &self.generator.version),
        ] {
            if value.trim().is_empty() {
                return Err(format!("recipe requires a non-empty {name}"));
            }
        }
        if self.variation_dimensions.is_empty() {
            return Err(
                "a recipe must state its variation dimensions, even if there is \
                        only one, so the variation space cannot be widened after the freeze"
                    .to_string(),
            );
        }
        if self.applicable_classes.is_empty() {
            return Err("a recipe must state which classes it can produce".to_string());
        }
        // A recipe exists to construct a deciding fact. Class S cases carry no
        // deciding fact and therefore cannot cite a recipe at all.
        if self.applicable_classes.contains(&Class::S) {
            return Err(
                "a recipe cannot produce class S: an S case carries no deciding \
                        fact, so there is nothing for a construction recipe to construct"
                    .to_string(),
            );
        }
        self.basis.validate()?;

        match (self.domain, self.content_kind, self.action_kind) {
            (FactDomain::Content, None, _) => {
                return Err("a Content recipe requires a content_kind".to_string())
            }
            (FactDomain::Content, _, Some(_)) => {
                return Err("a Content recipe must not carry an action_kind".to_string())
            }
            (FactDomain::Action, _, None) => {
                return Err("an Action recipe requires an action_kind".to_string())
            }
            (FactDomain::Action, Some(_), _) => {
                return Err("an Action recipe must not carry a content_kind".to_string())
            }
            _ => {}
        }

        match self.domain {
            FactDomain::Action => {
                if self.channel != Channel::Action {
                    return Err(format!(
                        "an Action recipe must target channel Action, not {:?}",
                        self.channel
                    ));
                }
                let FactBasis::PolicyClause {
                    environment_id,
                    policy_id,
                    ..
                } = &self.basis
                else {
                    return Err(format!(
                        "an Action recipe must rest on FactBasis::PolicyClause, not {}",
                        self.basis.label()
                    ));
                };
                match (&self.policy_environment_id, &self.policy_clause_id) {
                    (Some(env), Some(clause)) if env == environment_id && clause == policy_id => {
                        Ok(())
                    }
                    (Some(_), Some(_)) => Err(
                        "policy_environment_id/policy_clause_id must match the recipe's own \
                         PolicyClause basis"
                            .to_string(),
                    ),
                    _ => Err(
                        "an Action recipe must name policy_environment_id and policy_clause_id"
                            .to_string(),
                    ),
                }
            }
            FactDomain::Content => {
                if matches!(self.basis, FactBasis::PolicyClause { .. }) {
                    return Err("a Content recipe cannot rest on a PolicyClause: no frozen \
                                content policy environment exists to cite"
                        .to_string());
                }
                if self.channel == Channel::Action {
                    return Err("a Content recipe cannot target channel Action: the frozen \
                                engine does not scan content on the action path, so the fact \
                                would be unobservable at its boundary"
                        .to_string());
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct RecipeSet {
    recipes: BTreeMap<String, SyntheticRecipe>,
}

impl RecipeSet {
    /// Looked up by `id@version`, so citing the right id at the wrong version
    /// is a miss rather than a silent match.
    pub fn get(&self, recipe_id: &str, recipe_version: &str) -> Option<&SyntheticRecipe> {
        self.recipes.get(&format!("{recipe_id}@{recipe_version}"))
    }

    pub fn contains_id(&self, recipe_id: &str) -> bool {
        self.recipes.values().any(|r| r.recipe_id == recipe_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SyntheticRecipe> {
        self.recipes.values()
    }

    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    pub fn digests(&self) -> BTreeMap<String, String> {
        self.recipes
            .iter()
            .map(|(k, r)| (k.clone(), r.digest()))
            .collect()
    }

    /// For building a set in tests without touching the filesystem.
    pub fn from_recipes(recipes: Vec<SyntheticRecipe>) -> Result<Self, String> {
        let mut set = RecipeSet::default();
        for recipe in recipes {
            recipe.validate()?;
            if set.recipes.insert(recipe.key(), recipe.clone()).is_some() {
                return Err(format!("duplicate recipe {}", recipe.key()));
            }
        }
        Ok(set)
    }
}

#[derive(Debug)]
pub enum RecipeError {
    Io { path: PathBuf, error: String },
    Parse { path: PathBuf, error: String },
    Invalid { path: PathBuf, error: String },
    Duplicate { key: String, path: PathBuf },
    NameMismatch { path: PathBuf, expected: String },
}

/// Load `recipes/*.json`. An absent or empty directory is not an error: no
/// recipes exist yet, and none may be created before the corpus plan is
/// settled.
pub fn load_dir(dir: &Path) -> Result<RecipeSet, RecipeError> {
    let mut set = RecipeSet::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(set);
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();

    for path in paths {
        let text = std::fs::read_to_string(&path).map_err(|e| RecipeError::Io {
            path: path.clone(),
            error: e.to_string(),
        })?;
        let recipe: SyntheticRecipe =
            serde_json::from_str(&text).map_err(|e| RecipeError::Parse {
                path: path.clone(),
                error: e.to_string(),
            })?;
        recipe.validate().map_err(|error| RecipeError::Invalid {
            path: path.clone(),
            error,
        })?;
        let expected_stem = format!("{}_{}", recipe.recipe_id, recipe.recipe_version);
        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
        if stem != expected_stem {
            return Err(RecipeError::NameMismatch {
                path: path.clone(),
                expected: format!("{expected_stem}.json"),
            });
        }
        if set.recipes.contains_key(&recipe.key()) {
            return Err(RecipeError::Duplicate {
                key: recipe.key(),
                path,
            });
        }
        set.recipes.insert(recipe.key(), recipe);
    }
    Ok(set)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeLock {
    /// `recipe_id@recipe_version` -> digest.
    pub entries: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecipeDrift {
    /// Same id and version, different content: the boundary moved under a
    /// version that claims to be unchanged. The worst of the three.
    Changed {
        key: String,
    },
    Removed {
        key: String,
    },
    /// Present now, absent at the freeze. A new family appearing mid-run is
    /// drift even though nothing existing changed.
    Unlocked {
        key: String,
    },
}

impl RecipeLock {
    pub fn build(digests: BTreeMap<String, String>) -> Self {
        Self { entries: digests }
    }

    pub fn verify(&self, digests: &BTreeMap<String, String>) -> Vec<RecipeDrift> {
        let mut drift = Vec::new();
        for (key, locked) in &self.entries {
            match digests.get(key) {
                Some(now) if now == locked => {}
                Some(_) => drift.push(RecipeDrift::Changed { key: key.clone() }),
                None => drift.push(RecipeDrift::Removed { key: key.clone() }),
            }
        }
        for key in digests.keys() {
            if !self.entries.contains_key(key) {
                drift.push(RecipeDrift::Unlocked { key: key.clone() });
            }
        }
        drift
    }
}
