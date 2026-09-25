//! The contamination lock (Pack §8 of the execution prompt, §6 of the Pack).
//!
//! The manifest pins everything a Phase-II result depends on. The runner
//! recomputes it at startup and **refuses to run** if it differs from the
//! frozen copy, unless the experiment version is explicitly bumped.
//!
//! The point is not that a manifest makes tampering impossible - it does not.
//! The point is that it makes a changed input *visible*: a result produced
//! against a different corpus, a different Core, or a different metric
//! implementation cannot be silently compared to an earlier one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparatorPin {
    pub name: String,
    pub repository: Option<String>,
    pub version_or_commit: Option<String>,
    pub license: Option<String>,
    pub deployment_model: String,
    pub executable_path: Option<String>,
    /// False when the comparator is a vendor-published figure rather than
    /// something this harness can run. Pack §5: those are never mixed into
    /// direct measured rankings.
    pub executable: bool,
    pub exclusion_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Bumping this is the ONLY sanctioned way to change any pinned input.
    pub experiment_version: String,

    /// Aggregate over the Core's `src/*.rs`, in the Pack's own format:
    /// sha256 of the concatenation of `"{basename}:{sha256}\n"` over the
    /// name-sorted file list.
    pub core_aggregate_sha256: String,
    pub core_files: Vec<FileHash>,
    pub policy_files: Vec<FileHash>,

    /// Harness sources, so a metric-implementation change invalidates results.
    pub harness_files: Vec<FileHash>,
    /// The metric module specifically, called out because Pack §0 permits
    /// repairing a measurement bug only with a version bump and full re-run.
    pub metric_impl_sha256: String,

    pub dataset_files: Vec<FileHash>,
    pub annotation_files: Vec<FileHash>,

    pub comparators: Vec<ComparatorPin>,

    pub seeds: BTreeMap<String, u64>,
    pub environment: BTreeMap<String, String>,
    /// Frozen before any EdgeGuard output is observed (Pack §6.1).
    pub case_inclusion_rules: Vec<String>,
    pub case_exclusion_rules: Vec<String>,
}

/// Same idiom as `benchmark/src/freeze.rs`, so a hash produced here is
/// directly comparable to one produced by the existing benchmark tooling.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hash_file(path: &Path) -> std::io::Result<FileHash> {
    let bytes = std::fs::read(path)?;
    Ok(FileHash {
        path: path.to_string_lossy().into_owned(),
        sha256: hex(&Sha256::digest(&bytes)),
        bytes: bytes.len() as u64,
    })
}

/// The Pack's aggregate formula, reproduced exactly so a recomputed value is
/// directly comparable to the one printed in the Experiment Pack.
pub fn aggregate_src_hash(files: &[FileHash]) -> String {
    let mut named: Vec<(String, &str)> = files
        .iter()
        .map(|f| {
            let base = Path::new(&f.path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| f.path.clone());
            (base, f.sha256.as_str())
        })
        .collect();
    named.sort_by(|a, b| a.0.cmp(&b.0));
    let mut h = Sha256::new();
    for (name, sha) in named {
        h.update(format!("{name}:{sha}\n").as_bytes());
    }
    hex(&h.finalize())
}

/// What went wrong when the live tree does not match the frozen manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockError {
    VersionMismatch { frozen: String, live: String },
    CoreChanged { frozen: String, live: String },
    MetricImplChanged { frozen: String, live: String },
    FileSetChanged { kind: String, details: Vec<String> },
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::VersionMismatch { frozen, live } => write!(
                f,
                "experiment_version differs (frozen {frozen}, live {live}): a changed \
                 input requires an explicit version bump and a re-run from zero"
            ),
            LockError::CoreChanged { frozen, live } => write!(
                f,
                "Core aggregate hash differs (frozen {frozen}, live {live}): every prior \
                 result against this manifest is void, not stale"
            ),
            LockError::MetricImplChanged { frozen, live } => write!(
                f,
                "metric implementation hash differs (frozen {frozen}, live {live})"
            ),
            LockError::FileSetChanged { kind, details } => {
                write!(f, "{kind} file set differs: {}", details.join("; "))
            }
        }
    }
}

fn diff_sets(kind: &str, frozen: &[FileHash], live: &[FileHash]) -> Option<LockError> {
    let f: BTreeMap<_, _> = frozen.iter().map(|x| (&x.path, &x.sha256)).collect();
    let l: BTreeMap<_, _> = live.iter().map(|x| (&x.path, &x.sha256)).collect();
    let mut details = Vec::new();
    for (p, s) in &f {
        match l.get(p) {
            None => details.push(format!("missing: {p}")),
            Some(ls) if ls != s => details.push(format!("changed: {p}")),
            _ => {}
        }
    }
    for p in l.keys() {
        if !f.contains_key(p) {
            details.push(format!("added: {p}"));
        }
    }
    if details.is_empty() {
        None
    } else {
        Some(LockError::FileSetChanged {
            kind: kind.into(),
            details,
        })
    }
}

impl Manifest {
    /// The gate. Returns every difference found, not just the first, so a
    /// mismatched run is diagnosed in one pass.
    pub fn verify_against(&self, live: &Manifest) -> Vec<LockError> {
        let mut errs = Vec::new();
        if self.experiment_version != live.experiment_version {
            errs.push(LockError::VersionMismatch {
                frozen: self.experiment_version.clone(),
                live: live.experiment_version.clone(),
            });
        }
        if self.core_aggregate_sha256 != live.core_aggregate_sha256 {
            errs.push(LockError::CoreChanged {
                frozen: self.core_aggregate_sha256.clone(),
                live: live.core_aggregate_sha256.clone(),
            });
        }
        if self.metric_impl_sha256 != live.metric_impl_sha256 {
            errs.push(LockError::MetricImplChanged {
                frozen: self.metric_impl_sha256.clone(),
                live: live.metric_impl_sha256.clone(),
            });
        }
        for (kind, a, b) in [
            ("core", &self.core_files, &live.core_files),
            ("policy", &self.policy_files, &live.policy_files),
            ("harness", &self.harness_files, &live.harness_files),
            ("dataset", &self.dataset_files, &live.dataset_files),
            ("annotation", &self.annotation_files, &live.annotation_files),
        ] {
            if let Some(e) = diff_sets(kind, a, b) {
                errs.push(e);
            }
        }
        errs
    }

    /// Phase II may begin only when the lock is clean AND there is something
    /// to measure. An empty corpus is not a passing state - it is the reason
    /// the run must not start.
    pub fn ready_for_phase_ii(&self, live: &Manifest) -> Result<(), Vec<String>> {
        let mut problems: Vec<String> = self
            .verify_against(live)
            .into_iter()
            .map(|e| e.to_string())
            .collect();
        if live.dataset_files.is_empty() {
            problems.push("no dataset files are pinned: there is no corpus to execute".into());
        }
        if live.annotation_files.is_empty() {
            problems
                .push("no annotation files are pinned: labels must exist before exposure".into());
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}

/// Hash every regular file under `root` whose extension is in `exts`.
pub fn hash_tree(root: &Path, exts: &[&str]) -> std::io::Result<Vec<FileHash>> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(&dir)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else if exts.is_empty()
                || p.extension()
                    .map(|e| exts.contains(&&*e.to_string_lossy()))
                    .unwrap_or(false)
            {
                out.push(hash_file(&p)?);
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fh(path: &str, sha: &str) -> FileHash {
        FileHash {
            path: path.into(),
            sha256: sha.into(),
            bytes: 1,
        }
    }

    fn base() -> Manifest {
        Manifest {
            experiment_version: "1.0.0".into(),
            core_aggregate_sha256: "aaa".into(),
            core_files: vec![fh("src/tier.rs", "t1")],
            policy_files: vec![fh("policy.yaml", "p1")],
            harness_files: vec![fh("experiment_pack_v1/src/metrics.rs", "m1")],
            metric_impl_sha256: "m1".into(),
            dataset_files: vec![fh("corpus/holdout/a.json", "d1")],
            annotation_files: vec![fh("corpus/holdout/a.labels.json", "l1")],
            comparators: vec![],
            seeds: BTreeMap::new(),
            environment: BTreeMap::new(),
            case_inclusion_rules: vec![],
            case_exclusion_rules: vec![],
        }
    }

    #[test]
    fn an_identical_tree_produces_no_lock_errors() {
        assert!(base().verify_against(&base()).is_empty());
        assert!(base().ready_for_phase_ii(&base()).is_ok());
    }

    #[test]
    fn a_changed_core_voids_the_run() {
        let mut live = base();
        live.core_aggregate_sha256 = "bbb".into();
        live.core_files = vec![fh("src/tier.rs", "t2")];
        let errs = base().verify_against(&live);
        assert!(errs
            .iter()
            .any(|e| matches!(e, LockError::CoreChanged { .. })));
        assert!(base().ready_for_phase_ii(&live).is_err());
    }

    #[test]
    fn a_changed_metric_implementation_is_caught_separately() {
        let mut live = base();
        live.metric_impl_sha256 = "m2".into();
        let errs = base().verify_against(&live);
        assert!(errs
            .iter()
            .any(|e| matches!(e, LockError::MetricImplChanged { .. })));
    }

    #[test]
    fn a_swapped_corpus_file_is_detected() {
        let mut live = base();
        live.dataset_files = vec![fh("corpus/holdout/a.json", "d2")];
        let errs = base().verify_against(&live);
        assert!(errs.iter().any(|e| matches!(
            e, LockError::FileSetChanged { kind, .. } if kind == "dataset")));
    }

    #[test]
    fn an_added_corpus_file_is_detected() {
        let mut live = base();
        live.dataset_files.push(fh("corpus/holdout/b.json", "d9"));
        assert!(!base().verify_against(&live).is_empty());
    }

    #[test]
    fn an_empty_corpus_blocks_phase_two_even_when_the_lock_is_clean() {
        let mut m = base();
        m.dataset_files.clear();
        m.annotation_files.clear();
        // Lock itself is internally consistent...
        assert!(m.verify_against(&m).is_empty());
        // ...but there is nothing to run.
        let err = m.ready_for_phase_ii(&m).unwrap_err();
        assert_eq!(err.len(), 2, "{err:?}");
        assert!(err.iter().any(|e| e.contains("no corpus to execute")));
    }

    #[test]
    fn the_aggregate_formula_matches_the_packs_published_value_shape() {
        // Two files, deterministic order, "{base}:{sha}\n" concatenation.
        let files = vec![fh("x/b.rs", "22"), fh("y/a.rs", "11")];
        let mut h = Sha256::new();
        h.update(b"a.rs:11\nb.rs:22\n");
        assert_eq!(aggregate_src_hash(&files), hex(&h.finalize()));
    }

    #[test]
    fn a_version_bump_is_required_to_change_a_pinned_input() {
        let mut live = base();
        live.dataset_files = vec![fh("corpus/holdout/a.json", "d2")];
        live.experiment_version = "1.1.0".into();
        let errs = base().verify_against(&live);
        // Both the version change and the data change are surfaced; the runner
        // refuses either way, and the operator must acknowledge both.
        assert!(errs
            .iter()
            .any(|e| matches!(e, LockError::VersionMismatch { .. })));
    }
}
