//! Corpus loading, validation, and the leakage lint.

use crate::schema::{build_event, CaseRecord, Channel, Class, ExpectedOutcome, Source, ValueSpec};
use edgeguard::event::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Payload keys a case may never use: every one of them names benchmark
/// bookkeeping rather than application data, so their presence in a payload is
/// a leak whether or not it was intentional.
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
    "rationale",
    "source",
    "origin",
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

/// A loaded case, with its origin retained so any error can be traced back to
/// a corpus line without re-scanning the corpus.
#[derive(Debug, Clone)]
pub struct LoadedCase {
    pub record: CaseRecord,
    pub file: PathBuf,
    pub line: usize,
}

/// Read one JSONL corpus file. Every line is validated before it is accepted;
/// a corpus that fails validation is a build failure, not a warning.
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
        let record: CaseRecord =
            serde_json::from_str(raw).map_err(|e| CaseError::Parse {
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
/// These reject class/expectation combinations that contradict the D/S/M
/// definitions. Encoding them here means a miscategorised case is caught when
/// the corpus is written, not discovered later as a suspicious result.
pub fn validate(record: &CaseRecord) -> Result<(), String> {
    record.event.validate()?;

    if record.ground_truth.rationale.trim().is_empty() {
        return Err("ground_truth.rationale is required: a case whose class cannot be \
                    justified in prose does not belong in the corpus"
            .to_string());
    }

    match record.ground_truth.class {
        Class::D | Class::M => {
            if record.ground_truth.expected == ExpectedOutcome::Escalate {
                return Err(format!(
                    "class {:?} means a deterministic fact settles the event, so the expected \
                     outcome cannot be Escalate",
                    record.ground_truth.class
                ));
            }
            if record.ground_truth.deciding_fact.is_none() {
                return Err(format!(
                    "class {:?} requires deciding_fact: the fact that is supposed to settle \
                     the event without semantic reasoning",
                    record.ground_truth.class
                ));
            }
        }
        Class::S => {
            if record.ground_truth.expected != ExpectedOutcome::Escalate {
                return Err("class S means no deterministic fact settles the event, so the \
                            expected outcome must be Escalate"
                    .to_string());
            }
            if record.ground_truth.deciding_fact.is_some() {
                return Err("class S must not carry a deciding_fact; a case with one is M"
                    .to_string());
            }
        }
    }

    check_leakage(record)
}

/// Reject any case whose payload carries benchmark bookkeeping.
///
/// [`build_event`] already makes leakage impossible *structurally* - it accepts
/// only an `EventSpec`, which has no field for ground truth. This catches the
/// remaining route: a corpus author writing a label into a payload key or
/// string value by hand.
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
        if let Some(found) = find_case_id(&attributed.data, &record.case_id) {
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

fn find_case_id(value: &Value, case_id: &str) -> Option<String> {
    match value {
        Value::String(s) if s.contains(case_id) => Some(s.clone()),
        Value::List(items) => items.iter().find_map(|v| find_case_id(v, case_id)),
        Value::Map(entries) => entries.values().find_map(|v| find_case_id(v, case_id)),
        _ => None,
    }
}

/// Load a whole corpus directory tree, skipping anything that is not `.jsonl`.
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

/// Composition of a loaded corpus, reported alongside every result because
/// several headline metrics - Semantic Work Avoided above all - are functions
/// of this mix as much as of the engine.
#[derive(Debug, Default)]
pub struct Composition {
    pub by_channel: Vec<(Channel, usize)>,
    pub by_class: Vec<(Class, usize)>,
    pub by_source: Vec<(Source, usize)>,
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
        by_source: tally(cases.iter().map(|c| c.record.source).collect()),
        total: cases.len(),
    }
}

/// Normalized text of every string a case exposes, for cross-corpus duplicate
/// detection between the development corpus and the holdout.
pub fn normalized_text(record: &CaseRecord) -> String {
    fn walk(v: &ValueSpec, out: &mut String) {
        match v {
            ValueSpec::String(s) => {
                out.push_str(&s.to_lowercase());
                out.push('\u{1}');
            }
            ValueSpec::List(items) => items.iter().for_each(|i| walk(i, out)),
            ValueSpec::Map(entries) => entries.values().for_each(|i| walk(i, out)),
            _ => {}
        }
    }
    let mut out = String::new();
    for field in &record.event.fields {
        walk(&field.value, &mut out);
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}
