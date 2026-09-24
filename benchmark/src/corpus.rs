//! Corpus loading, validation, and the leakage lints.

use crate::policy_env::{EnvironmentUsage, PolicyEnvironmentSet};
use crate::schema::{
    build_event, CaseRecord, CaseRole, CaseShape, Channel, Class, Source, UsageClass,
};
use edgeguard::event::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// Payload keys a case may never use: each names benchmark bookkeeping rather
/// than application data, so its presence in a payload is a leak whether or not
/// it was intentional.
pub const RESERVED_PAYLOAD_KEYS: &[&str] = &[
    "case_id",
    "class",
    "expected",
    "expected_outcome",
    "ground_truth",
    "true_safety",
    "attack_family",
    "label",
    "benchmark",
    "deciding_fact",
    "deciding_facts",
    "rationale",
    "source",
    "origin",
    "usage",
    "policy_environment_id",
];

/// Tokens that disqualify a `deciding_fact.statement`.
///
/// A deciding fact must be auditable by someone who has never read this
/// codebase: it states something about the *event*, which an auditor can
/// confirm by looking at the event. "The engine has a rule for this" is
/// circular - it makes the ground truth a function of the implementation, and
/// then the benchmark can only ever confirm what the implementation already
/// does. These tokens are the ways that circularity tends to be written down.
pub const IMPLEMENTATION_TOKENS: &[&str] = &[
    "edgeguard",
    "tier1",
    "tier 1",
    "tier-1",
    "tier2",
    "tier 2",
    "tier-2",
    "eg_",
    "tieredengine",
    "evaluate_action",
    "evaluate_security_event",
    "actionrule",
    "aho-corasick",
    "policy.yaml",
    "deobfuscat",
    "detector",
    "fast path",
    "the engine",
    "has a rule",
    "no rule for",
    "currently",
];

/// Files in this repository that were used for rule or threshold development.
///
/// Any case whose `origin` names one of these is development data by
/// definition and must be marked [`UsageClass::DevelopmentOnly`]. Enforced at
/// load time so the marking cannot be forgotten.
pub const DEVELOPMENT_ONLY_ORIGINS: &[&str] = &[
    "redteam_adaptive.py",
    "corpus_enterprise.py",
    "measure_grey_rate.py",
    "residual_gap_protocol.py",
    "hardcore_redteam.py",
    "comprehensive_test.py",
    "enterprise_audit.py",
    "candidate-flag-rules.yaml",
];

#[derive(Debug)]
pub enum CaseError {
    Parse {
        file: PathBuf,
        line: usize,
        error: String,
    },
    Invalid {
        file: PathBuf,
        line: usize,
        case_id: String,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedCase {
    pub record: CaseRecord,
    pub file: PathBuf,
    pub line: usize,
}

pub fn load_file(path: &Path) -> Result<Vec<LoadedCase>, CaseError> {
    let text = std::fs::read_to_string(path).map_err(|e| CaseError::Parse {
        file: path.to_path_buf(),
        line: 0,
        error: e.to_string(),
    })?;
    let mut out = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        if raw.trim().is_empty() || raw.trim_start().starts_with("//") {
            continue;
        }
        let record: CaseRecord = serde_json::from_str(raw).map_err(|e| CaseError::Parse {
            file: path.to_path_buf(),
            line,
            error: e.to_string(),
        })?;
        validate(&record).map_err(|error| CaseError::Invalid {
            file: path.to_path_buf(),
            line,
            case_id: record.case_id.clone(),
            error,
        })?;
        out.push(LoadedCase {
            record,
            file: path.to_path_buf(),
            line,
        });
    }
    Ok(out)
}

/// Structural and ground-truth coherence checks.
///
/// These reject combinations that contradict the D/S/M definitions, so a
/// miscategorised case is caught when it is written rather than discovered
/// later as a suspicious result.
pub fn validate(record: &CaseRecord) -> Result<(), String> {
    record.event.validate()?;

    if record.ground_truth.rationale.trim().is_empty() {
        return Err(
            "ground_truth.rationale is required: a case whose class cannot be \
                    justified in prose does not belong in the corpus"
                .to_string(),
        );
    }

    // A case references a policy environment; it never defines rules. The
    // schema has no field for a rule, and Action is the only channel on which
    // the frozen engine consults one.
    match (record.event.channel, &record.policy_environment_id) {
        (Channel::Action, None) => {
            return Err("an Action case must reference a frozen policy_environment_id".to_string())
        }
        (Channel::Input | Channel::Output, Some(id)) => {
            return Err(format!(
                "a {:?} case must not reference a policy environment ({id:?}): action rules are \
                 not consulted on the content path",
                record.event.channel
            ))
        }
        _ => {}
    }

    match record.ground_truth.class {
        Class::D | Class::M => {
            if record.ground_truth.deciding_facts.is_empty() {
                return Err(format!(
                    "class {:?} requires at least one deciding_fact citing an \
                     implementation-independent basis",
                    record.ground_truth.class
                ));
            }
        }
        Class::S => {
            if !record.ground_truth.deciding_facts.is_empty() {
                return Err(
                    "class S must not carry a deciding_fact; a case with one is D or M".to_string(),
                );
            }
        }
    }

    // The full (class, true_safety, expected) truth table - see
    // `schema::is_coherent` for the matrix and why only six of eighteen
    // combinations are admissible.
    if !crate::schema::is_coherent(
        record.ground_truth.class,
        record.ground_truth.true_safety,
        record.ground_truth.expected,
    ) {
        return Err(format!(
            "incoherent ground truth: class {:?} with true_safety {:?} cannot expect {:?}. \
             For D and M, expected Block <=> Harmful and expected Pass <=> Safe; S always \
             expects Escalate. A contradictory pair would let one event count as both a \
             correct deterministic decision and a safety error.",
            record.ground_truth.class,
            record.ground_truth.true_safety,
            record.ground_truth.expected
        ));
    }

    for fact in &record.ground_truth.deciding_facts {
        fact.validate()?;
        check_implementation_independence(&fact.statement)?;
    }

    // An Action-domain deciding fact needs an action to be a fact about.
    if record.ground_truth.shape() != CaseShape::ContentOnly
        && record.ground_truth.shape() != CaseShape::NoDeterministicFact
        && record.event.channel != Channel::Action
    {
        return Err(format!(
            "an Action-domain deciding fact requires channel Action, not {:?}",
            record.event.channel
        ));
    }

    check_role(record)?;
    check_usage(record)?;
    check_leakage(record)
}

/// A deciding fact must be auditable without reference to any implementation.
pub fn check_implementation_independence(statement: &str) -> Result<(), String> {
    let lowered = statement.to_lowercase();
    for token in IMPLEMENTATION_TOKENS {
        if lowered.contains(token) {
            return Err(format!(
                "deciding fact statement references an implementation ({token:?}): a fact must be \
                 checkable against the event by an auditor who has never seen this codebase, or \
                 the ground truth becomes a function of the engine it is meant to test"
            ));
        }
    }
    Ok(())
}

/// A probe is an ACTION case by construction, and a primary case may not be
/// one by accident.
///
/// Whether the named action is actually covered by the environment cannot be
/// decided here - this function does not have the environment - so it is
/// settled in [`check_environment_coverage`]. This check is the half that is
/// decidable from the record alone.
pub fn check_role(record: &CaseRecord) -> Result<(), String> {
    match record.role {
        CaseRole::Primary => Ok(()),
        CaseRole::UncoveredActionProbe => {
            if record.event.channel != Channel::Action {
                return Err(format!(
                    "role UncoveredActionProbe is only meaningful on an Action case, not {:?}",
                    record.event.channel
                ));
            }
            if record.ground_truth.class != Class::S {
                return Err(format!(
                    "an UncoveredActionProbe has no deterministic fact available to it, so its \
                     class must be S, not {:?}",
                    record.ground_truth.class
                ));
            }
            Ok(())
        }
    }
}

/// Development-contaminated material may never claim to be external evidence.
pub fn check_usage(record: &CaseRecord) -> Result<(), String> {
    let origin = record.origin.to_lowercase();
    if let Some(hit) = DEVELOPMENT_ONLY_ORIGINS
        .iter()
        .find(|f| origin.contains(&f.to_lowercase()))
    {
        if record.usage != UsageClass::DevelopmentOnly {
            return Err(format!(
                "origin names {hit:?}, which was used for rule or threshold development, so this \
                 case must be marked DevelopmentOnly; a score measured on it is a training score"
            ));
        }
    }
    match (record.source, record.usage) {
        (Source::Holdout, UsageClass::Holdout) => Ok(()),
        (Source::Holdout, other) => Err(format!(
            "a Holdout case must carry UsageClass::Holdout, not {other:?}"
        )),
        (_, UsageClass::Holdout) => {
            Err("UsageClass::Holdout is only valid for Source::Holdout".to_string())
        }
        _ => Ok(()),
    }
}

/// Reject any case whose payload carries benchmark bookkeeping.
///
/// [`build_event`] already makes leakage impossible *structurally* - it accepts
/// only an `EventSpec`, which has no field for ground truth. This catches the
/// remaining route: an author writing a label into a payload by hand.
pub fn check_leakage(record: &CaseRecord) -> Result<(), String> {
    let event = build_event(&record.event);
    let reserved: HashSet<&str> = RESERVED_PAYLOAD_KEYS.iter().copied().collect();

    for (key, attributed) in &event.payload {
        if reserved.contains(key.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "payload key {key:?} is reserved benchmark metadata and must not be visible \
                 to the engine"
            ));
        }
        if let Some(found) = find_needle(&attributed.data, &record.case_id) {
            return Err(format!(
                "payload field {key:?} contains the case id ({found:?}); ground truth must \
                 not be reachable from the event"
            ));
        }
    }

    if let Some(principal) = &event.principal_id {
        if principal.contains(&record.case_id) {
            return Err("principal_id contains the case id".to_string());
        }
    }
    Ok(())
}

fn find_needle(value: &Value, needle: &str) -> Option<String> {
    match value {
        Value::String(s) if s.contains(needle) => Some(s.clone()),
        Value::List(items) => items.iter().find_map(|v| find_needle(v, needle)),
        Value::Map(entries) => entries.values().find_map(|v| find_needle(v, needle)),
        _ => None,
    }
}

pub fn load_dir(dir: &Path) -> Result<Vec<LoadedCase>, CaseError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "jsonl") {
                out.extend(load_file(&path)?);
            }
        }
    }
    out.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    Ok(out)
}

/// Cross-case checks that need the frozen environments.
///
/// Three things are settled here, none of which a single record can decide on
/// its own:
///
/// 1. Every referenced environment exists.
/// 2. Every `PolicyClause` fact cites a clause that actually exists, in the
///    environment the case references. This is what makes an Action-domain
///    ground truth independently checkable rather than a claim about the
///    engine.
/// 3. Action coverage and role agree - a `Primary` ACTION case must name an
///    action its environment covers, and an `UncoveredActionProbe` must not.
///
/// Breadth counts exclude probes, so an environment cannot reach the breadth
/// floor on cases that sit outside its configured surface.
pub fn check_environment_coverage(
    cases: &[LoadedCase],
    environments: &PolicyEnvironmentSet,
) -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let mut usage: BTreeMap<String, (EnvironmentUsage, BTreeSet<Class>)> = BTreeMap::new();

    for case in cases {
        let Some(id) = &case.record.policy_environment_id else {
            continue;
        };
        let Some(env) = environments.get(id) else {
            problems.push(format!(
                "case {:?} references unknown policy environment {id:?}",
                case.record.case_id
            ));
            continue;
        };

        // (2) Every cited policy clause must exist in this environment.
        for fact in &case.record.ground_truth.deciding_facts {
            if let crate::schema::FactBasis::PolicyClause {
                environment_id,
                environment_version,
                policy_id,
            } = &fact.basis
            {
                if environment_id != id {
                    problems.push(format!(
                        "case {:?} cites a clause of environment {environment_id:?} but is \
                         evaluated under {id:?}",
                        case.record.case_id
                    ));
                    continue;
                }
                if environment_version != &env.version {
                    problems.push(format!(
                        "case {:?} cites environment {environment_id:?} version \
                         {environment_version:?}, but the frozen environment is version {:?}",
                        case.record.case_id, env.version
                    ));
                    continue;
                }
                if !env.rules.iter().any(|r| &r.policy_id == policy_id) {
                    problems.push(format!(
                        "case {:?} cites policy clause {policy_id:?}, which does not exist in \
                         environment {id:?}",
                        case.record.case_id
                    ));
                }
            }
        }

        // (3) Coverage and role must agree.
        let covered = case
            .record
            .event
            .action_name
            .as_ref()
            .is_some_and(|name| env.covered_actions().iter().any(|a| a == name));
        match (case.record.role, covered) {
            (CaseRole::Primary, false) => {
                problems.push(format!(
                    "case {:?} is Primary but names action {:?}, which environment {id:?} does \
                     not cover. Escalation would then be caused by the action being unnamed, \
                     not by the case's difficulty. Mark it UncoveredActionProbe to measure that \
                     behaviour separately.",
                    case.record.case_id, case.record.event.action_name
                ));
                continue;
            }
            (CaseRole::UncoveredActionProbe, true) => {
                problems.push(format!(
                    "case {:?} is an UncoveredActionProbe but names action {:?}, which \
                     environment {id:?} does cover",
                    case.record.case_id, case.record.event.action_name
                ));
                continue;
            }
            _ => {}
        }

        // Every referenced environment gets an entry, so its breadth is always
        // assessed. Probes create the entry but increment nothing: an
        // environment referenced only by probes therefore reports a shortfall
        // of zero primary cases, rather than escaping assessment entirely.
        let entry = usage.entry(id.clone()).or_default();
        if case.record.role != CaseRole::Primary {
            continue;
        }
        entry.0.cases += 1;
        entry.1.insert(case.record.ground_truth.class);
        match case.record.ground_truth.true_safety {
            crate::schema::Safety::Safe => entry.0.has_safe = true,
            crate::schema::Safety::Harmful => entry.0.has_harmful = true,
        }
    }

    for (id, (mut counts, classes)) in usage {
        counts.distinct_classes = classes.len();
        problems.extend(counts.shortfalls(&id));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

/// Composition of a loaded corpus, reported alongside every result because
/// several headline metrics - Semantic Work Avoided above all - are functions
/// of this mix as much as of the engine.
#[derive(Debug, Default)]
pub struct Composition {
    pub by_channel: Vec<(Channel, usize)>,
    pub by_class: Vec<(Class, usize)>,
    pub by_shape: Vec<(CaseShape, usize)>,
    pub by_source: Vec<(Source, usize)>,
    pub by_usage: Vec<(UsageClass, usize)>,
    pub total: usize,
}

fn tally<T: Ord + Copy>(mut keys: Vec<T>) -> Vec<(T, usize)> {
    keys.sort_unstable();
    let mut out: Vec<(T, usize)> = Vec::new();
    for key in keys {
        match out.last_mut() {
            Some((k, n)) if *k == key => *n += 1,
            _ => out.push((key, 1)),
        }
    }
    out
}

pub fn composition(cases: &[LoadedCase]) -> Composition {
    Composition {
        by_channel: tally(cases.iter().map(|c| c.record.event.channel).collect()),
        by_class: tally(cases.iter().map(|c| c.record.ground_truth.class).collect()),
        by_shape: tally(
            cases
                .iter()
                .map(|c| c.record.ground_truth.shape())
                .collect(),
        ),
        by_source: tally(cases.iter().map(|c| c.record.source).collect()),
        by_usage: tally(cases.iter().map(|c| c.record.usage).collect()),
        total: cases.len(),
    }
}

/// Canonical representation of a case's event, for duplicate detection between
/// the development corpus and a holdout.
///
/// Delegates to [`crate::schema::EventSpec::canonical`], which covers every
/// `ValueSpec` variant and preserves channel, action name, principal, field
/// names, provenance and values, with fields sorted by key and maps in
/// `BTreeMap` order.
///
/// The previous implementation walked only `ValueSpec::String`, so every
/// structured-only ACTION event - any two payments, whatever their amounts -
/// normalised to the empty string and compared equal. That is fixed.
///
/// What is **not** fixed, and is not fixable without machinery this benchmark
/// has ruled out: this is a lexical representation. Two paraphrases of the same
/// attack are different strings and will not be detected as duplicates. No
/// embedding or model is used, by design; the limitation is recorded in
/// `docs/DESIGN.md` instead of being papered over.
pub fn normalized_text(record: &CaseRecord) -> String {
    record
        .event
        .canonical()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
