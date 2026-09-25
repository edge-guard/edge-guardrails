//! Kill-Test freeze manifest and Phase-II gate (spec §10).
//!
//! The gate refuses if ANY of: a case, a label, a Core production hash, a
//! comparator version, the metric implementation, or the manifest itself has
//! changed.
//!
//! Production vs test region (spec §1): a Rust file carries its unit tests
//! inline, so a whole-file hash cannot distinguish "the engine changed" from
//! "a test expectation changed". [`production_region_hash`] hashes only the
//! bytes BEFORE the first `#[cfg(test)]` line, and both hashes are pinned, so
//! each kind of change is visible on its own.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    /// Hash of the entire file.
    pub sha256: String,
    /// Hash of the bytes before the first `#[cfg(test)]`, when there is one.
    pub production_region_sha256: Option<String>,
    pub bytes: u64,
}

/// Split a Rust source file at the first `#[cfg(test)]` at column 0 and hash
/// only what precedes it.
pub fn production_region_hash(src: &str) -> Option<String> {
    let mut cut = None;
    let mut offset = 0usize;
    for line in src.split_inclusive('\n') {
        if line.trim_start() == line && line.starts_with("#[cfg(test)]") {
            cut = Some(offset);
            break;
        }
        offset += line.len();
    }
    cut.map(|c| hex(&Sha256::digest(src[..c].as_bytes())))
}

pub fn hash_file(path: &Path) -> std::io::Result<FileHash> {
    let bytes = std::fs::read(path)?;
    let prod = std::str::from_utf8(&bytes)
        .ok()
        .and_then(production_region_hash);
    Ok(FileHash {
        path: path.to_string_lossy().into_owned(),
        sha256: hex(&Sha256::digest(&bytes)),
        production_region_sha256: prod,
        bytes: bytes.len() as u64,
    })
}

pub fn hash_tree(root: &Path, exts: &[&str]) -> std::io::Result<Vec<FileHash>> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if !dir.exists() {
            continue;
        }
        for e in std::fs::read_dir(&dir)? {
            let p = e?.path();
            if p.is_dir() {
                if p.file_name()
                    .map(|n| n == ".git" || n == "target")
                    .unwrap_or(false)
                {
                    continue;
                }
                stack.push(p);
            } else if exts.is_empty()
                || p.extension()
                    .map(|x| exts.contains(&&*x.to_string_lossy()))
                    .unwrap_or(false)
            {
                out.push(hash_file(&p)?);
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparatorPin {
    pub name: String,
    pub repository: Option<String>,
    pub version: Option<String>,
    pub commit: Option<String>,
    pub license: Option<String>,
    pub license_verified_via: Option<String>,
    pub deployment_model: String,
    pub executable: bool,
    /// Whether the comparable subset runs with no network on the hot path.
    pub local_no_network: Option<bool>,
    pub build_status: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetPin {
    pub name: String,
    pub url: Option<String>,
    pub commit: Option<String>,
    pub license: Option<String>,
    pub records: Option<u64>,
    pub label_provenance: String,
    pub commercial_use: String,
    /// Whether the source can support D-PASS / D-BLOCK / M / S labelling
    /// WITHOUT inventing host state (spec §4).
    pub supports_dmsl: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingConfig {
    pub profile: String,
    pub warm_cold_separated: bool,
    pub scale_points: Vec<usize>,
    pub percentiles: Vec<String>,
    pub policy_load_timed_separately: bool,
    pub context_construction_timed_separately: bool,
    pub network_allowed_in_evaluator_timing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub experiment: String,
    pub version: String,
    pub core_branch: String,
    pub core_head: String,
    /// Production-region hashes only — the authority for "Core unchanged".
    pub core_production: Vec<FileHash>,
    pub policy_files: Vec<FileHash>,
    pub harness_files: Vec<FileHash>,
    pub metric_impl_sha256: String,
    pub case_files: Vec<FileHash>,
    pub annotation_files: Vec<FileHash>,
    pub comparators: Vec<ComparatorPin>,
    pub datasets: Vec<DatasetPin>,
    pub inclusion_rules: Vec<String>,
    pub exclusion_rules: Vec<String>,
    pub seeds: BTreeMap<String, u64>,
    pub environment: BTreeMap<String, String>,
    pub timing: TimingConfig,
    pub contamination_policy: Vec<String>,

    // --- substantive readiness, not just hash agreement --------------------
    //
    // A manifest can be internally consistent and still describe an
    // experiment that cannot answer its own question. These three counts are
    // what separate "the lock agrees with itself" from "there is something
    // real to measure", and `ready` refuses on each of them.
    /// Cases flagged `needs_second_annotation` that no INDEPENDENT annotator
    /// has yet adjudicated.
    pub unannotated_cases: u64,
    /// Host-burden cases whose integration/setup figures are still
    /// placeholders rather than measured from a real integration.
    pub placeholder_burden_cases: u64,
    /// Comparators that are pinned and executable but have no adapter wired,
    /// so no verdict can be obtained from them.
    pub comparators_without_adapter: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    CoreProductionChanged(Vec<String>),
    CasesChanged(Vec<String>),
    AnnotationsChanged(Vec<String>),
    MetricImplChanged { frozen: String, live: String },
    ComparatorChanged(Vec<String>),
    VersionChanged { frozen: String, live: String },
    NothingToRun(String),
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::CoreProductionChanged(d) => write!(
                f,
                "EdgeGuard Core PRODUCTION region changed ({}): every prior result is void",
                d.join(", ")
            ),
            GateError::CasesChanged(d) => write!(f, "frozen case files changed ({})", d.join(", ")),
            GateError::AnnotationsChanged(d) => {
                write!(f, "annotation files changed ({})", d.join(", "))
            }
            GateError::MetricImplChanged { frozen, live } => write!(
                f,
                "metric implementation changed (frozen {frozen}, live {live})"
            ),
            GateError::ComparatorChanged(d) => {
                write!(f, "comparator pins changed ({})", d.join(", "))
            }
            GateError::VersionChanged { frozen, live } => {
                write!(
                    f,
                    "experiment version changed (frozen {frozen}, live {live})"
                )
            }
            GateError::NothingToRun(w) => write!(f, "nothing to run: {w}"),
        }
    }
}

fn diff(frozen: &[FileHash], live: &[FileHash], production_only: bool) -> Vec<String> {
    let key = |f: &FileHash| {
        if production_only {
            f.production_region_sha256
                .clone()
                .unwrap_or_else(|| f.sha256.clone())
        } else {
            f.sha256.clone()
        }
    };
    let fm: BTreeMap<_, _> = frozen.iter().map(|f| (f.path.clone(), key(f))).collect();
    let lm: BTreeMap<_, _> = live.iter().map(|f| (f.path.clone(), key(f))).collect();
    let mut out = Vec::new();
    for (p, h) in &fm {
        match lm.get(p) {
            None => out.push(format!("missing {p}")),
            Some(l) if l != h => out.push(format!("changed {p}")),
            _ => {}
        }
    }
    for p in lm.keys() {
        if !fm.contains_key(p) {
            out.push(format!("added {p}"));
        }
    }
    out
}

impl Manifest {
    pub fn gate(&self, live: &Manifest) -> Vec<GateError> {
        let mut errs = Vec::new();
        if self.version != live.version {
            errs.push(GateError::VersionChanged {
                frozen: self.version.clone(),
                live: live.version.clone(),
            });
        }
        let core = diff(&self.core_production, &live.core_production, true);
        if !core.is_empty() {
            errs.push(GateError::CoreProductionChanged(core));
        }
        let cases = diff(&self.case_files, &live.case_files, false);
        if !cases.is_empty() {
            errs.push(GateError::CasesChanged(cases));
        }
        let ann = diff(&self.annotation_files, &live.annotation_files, false);
        if !ann.is_empty() {
            errs.push(GateError::AnnotationsChanged(ann));
        }
        if self.metric_impl_sha256 != live.metric_impl_sha256 {
            errs.push(GateError::MetricImplChanged {
                frozen: self.metric_impl_sha256.clone(),
                live: live.metric_impl_sha256.clone(),
            });
        }
        if self.comparators != live.comparators {
            let mut d = Vec::new();
            for f in &self.comparators {
                match live.comparators.iter().find(|l| l.name == f.name) {
                    None => d.push(format!("missing {}", f.name)),
                    Some(l) if l != f => d.push(format!("changed {}", f.name)),
                    _ => {}
                }
            }
            for l in &live.comparators {
                if !self.comparators.iter().any(|f| f.name == l.name) {
                    d.push(format!("added {}", l.name));
                }
            }
            errs.push(GateError::ComparatorChanged(d));
        }
        errs
    }

    /// Blind execution may begin only when the gate is clean AND there is
    /// something real to measure.
    pub fn ready(&self, live: &Manifest) -> Result<(), Vec<String>> {
        let mut p: Vec<String> = self.gate(live).iter().map(|e| e.to_string()).collect();
        if live.case_files.is_empty() {
            p.push(GateError::NothingToRun("no frozen case files are pinned".into()).to_string());
        }
        if live.comparators.iter().filter(|c| c.executable).count() < 2 {
            p.push(
                "fewer than two executable comparators: a substitution question cannot be \
                 answered against a single system"
                    .into(),
            );
        }
        if live.unannotated_cases > 0 {
            p.push(format!(
                "{} case(s) still await INDEPENDENT second annotation; the harness may flag them \
                 but must not adjudicate them itself",
                live.unannotated_cases
            ));
        }
        if live.placeholder_burden_cases > 0 {
            p.push(format!(
                "{} host-burden case(s) carry placeholder integration figures; host cost must be \
                 measured from a real integration, not defaulted",
                live.placeholder_burden_cases
            ));
        }
        if !live.comparators_without_adapter.is_empty() {
            p.push(format!(
                "executable comparator(s) with no adapter wired: {} - a pinned binary that cannot \
                 be asked for a verdict is not a comparator",
                live.comparators_without_adapter.join(", ")
            ));
        }
        if p.is_empty() {
            Ok(())
        } else {
            Err(p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_production_region_hash_ignores_everything_after_cfg_test() {
        let a = "pub fn f() -> u8 { 1 }\n#[cfg(test)]\nmod t { #[test] fn x() {} }\n";
        let b =
            "pub fn f() -> u8 { 1 }\n#[cfg(test)]\nmod t { #[test] fn y() { assert!(true) } }\n";
        assert_eq!(production_region_hash(a), production_region_hash(b));
        assert!(production_region_hash(a).is_some());
    }

    #[test]
    fn a_production_change_moves_the_production_region_hash() {
        let a = "pub fn f() -> u8 { 1 }\n#[cfg(test)]\nmod t {}\n";
        let b = "pub fn f() -> u8 { 2 }\n#[cfg(test)]\nmod t {}\n";
        assert_ne!(production_region_hash(a), production_region_hash(b));
    }

    #[test]
    fn a_file_with_no_test_module_has_no_separate_production_hash() {
        assert_eq!(production_region_hash("pub fn f() {}\n"), None);
    }

    fn fh(path: &str, whole: &str, prod: Option<&str>) -> FileHash {
        FileHash {
            path: path.into(),
            sha256: whole.into(),
            production_region_sha256: prod.map(|s| s.into()),
            bytes: 1,
        }
    }

    fn base() -> Manifest {
        Manifest {
            experiment: "kill-test".into(),
            version: "1.0.0".into(),
            core_branch: "routing-contract-v0.2".into(),
            core_head: "2d6d75a".into(),
            core_production: vec![fh("src/tier.rs", "whole1", Some("prod1"))],
            policy_files: vec![fh("policy.yaml", "p1", None)],
            harness_files: vec![fh("kill_test_v1/src/metrics.rs", "m1", Some("mp1"))],
            metric_impl_sha256: "m1".into(),
            case_files: vec![fh("cases/t1.json", "c1", None)],
            annotation_files: vec![fh("cases/t1.labels.json", "l1", None)],
            comparators: vec![
                ComparatorPin {
                    name: "Cedar".into(),
                    repository: None,
                    version: Some("4.13.0".into()),
                    commit: None,
                    license: Some("Apache-2.0".into()),
                    license_verified_via: None,
                    deployment_model: "in-process".into(),
                    executable: true,
                    local_no_network: Some(true),
                    build_status: "ok".into(),
                    limitations: vec![],
                },
                ComparatorPin {
                    name: "Handwritten".into(),
                    repository: None,
                    version: None,
                    commit: None,
                    license: None,
                    license_verified_via: None,
                    deployment_model: "in-process".into(),
                    executable: true,
                    local_no_network: Some(true),
                    build_status: "ok".into(),
                    limitations: vec![],
                },
            ],
            datasets: vec![],
            inclusion_rules: vec![],
            exclusion_rules: vec![],
            seeds: BTreeMap::new(),
            environment: BTreeMap::new(),
            timing: TimingConfig {
                profile: "release".into(),
                warm_cold_separated: true,
                scale_points: vec![1, 10, 100, 1000],
                percentiles: vec!["p50".into(), "p95".into(), "p99".into(), "max".into()],
                policy_load_timed_separately: true,
                context_construction_timed_separately: true,
                network_allowed_in_evaluator_timing: false,
            },
            contamination_policy: vec![],
            unannotated_cases: 0,
            placeholder_burden_cases: 0,
            comparators_without_adapter: vec![],
        }
    }

    #[test]
    fn an_identical_manifest_passes_the_gate() {
        assert!(base().gate(&base()).is_empty());
        assert!(base().ready(&base()).is_ok());
    }

    #[test]
    fn a_test_only_core_edit_does_not_trip_the_core_gate() {
        // Whole-file hash moves, production region does not.
        let mut live = base();
        live.core_production = vec![fh("src/tier.rs", "whole2", Some("prod1"))];
        assert!(
            base().gate(&live).is_empty(),
            "a test-only edit must not read as a Core change"
        );
    }

    #[test]
    fn a_real_core_edit_trips_the_core_gate() {
        let mut live = base();
        live.core_production = vec![fh("src/tier.rs", "whole1", Some("prod2"))];
        assert!(base()
            .gate(&live)
            .iter()
            .any(|e| matches!(e, GateError::CoreProductionChanged(_))));
    }

    #[test]
    fn a_changed_case_or_label_trips_the_gate() {
        let mut live = base();
        live.case_files = vec![fh("cases/t1.json", "c2", None)];
        assert!(base()
            .gate(&live)
            .iter()
            .any(|e| matches!(e, GateError::CasesChanged(_))));

        let mut live2 = base();
        live2.annotation_files = vec![fh("cases/t1.labels.json", "l2", None)];
        assert!(base()
            .gate(&live2)
            .iter()
            .any(|e| matches!(e, GateError::AnnotationsChanged(_))));
    }

    #[test]
    fn a_changed_comparator_version_trips_the_gate() {
        let mut live = base();
        live.comparators[0].version = Some("4.14.0".into());
        assert!(base()
            .gate(&live)
            .iter()
            .any(|e| matches!(e, GateError::ComparatorChanged(_))));
    }

    #[test]
    fn a_changed_metric_implementation_trips_the_gate() {
        let mut live = base();
        live.metric_impl_sha256 = "m2".into();
        assert!(base()
            .gate(&live)
            .iter()
            .any(|e| matches!(e, GateError::MetricImplChanged { .. })));
    }

    #[test]
    fn a_single_executable_comparator_is_not_enough_to_answer_substitution() {
        let mut live = base();
        live.comparators.truncate(1);
        assert!(base().ready(&live).is_err());
    }

    #[test]
    fn unannotated_cases_block_execution() {
        let mut live = base();
        live.unannotated_cases = 17;
        let e = base().ready(&live).unwrap_err();
        assert!(
            e.iter()
                .any(|x| x.contains("INDEPENDENT second annotation")),
            "{e:?}"
        );
    }

    #[test]
    fn placeholder_burden_figures_block_execution() {
        let mut live = base();
        live.placeholder_burden_cases = 5;
        let e = base().ready(&live).unwrap_err();
        assert!(
            e.iter()
                .any(|x| x.contains("placeholder integration figures")),
            "{e:?}"
        );
    }

    #[test]
    fn an_executable_comparator_without_an_adapter_blocks_execution() {
        let mut live = base();
        live.comparators_without_adapter = vec!["Jataayu".into()];
        let e = base().ready(&live).unwrap_err();
        assert!(e.iter().any(|x| x.contains("no adapter wired")), "{e:?}");
    }

    #[test]
    fn an_empty_case_set_blocks_execution_even_with_a_clean_gate() {
        let mut m = base();
        m.case_files.clear();
        assert!(m.gate(&m).is_empty());
        assert!(m.ready(&m).is_err());
    }
}
