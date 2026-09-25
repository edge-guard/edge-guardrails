//! Phase-II blind execution runner.
//!
//! This binary exists in Phase I so that the gate is testable before there is
//! anything to run. It does NOT execute a corpus. It computes the live
//! manifest, compares it to the frozen one, and reports whether Phase II may
//! legally begin.
//!
//! It refuses to start when:
//!   * the frozen manifest is missing;
//!   * any pinned input differs without an experiment version bump;
//!   * no dataset/annotation files are pinned (nothing to measure).
//!
//! Usage:
//!   phase2 --check                 verify the lock and report readiness
//!   phase2 --freeze <out.json>     write the live manifest as the frozen one

use edgeguard_experiment_pack_v1::manifest::*;
use edgeguard_experiment_pack_v1::{EXPERIMENT_VERSION, PINNED_CORE_AGGREGATE_SHA256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn repo_root() -> PathBuf {
    // The crate lives at <root>/experiment_pack_v1.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .to_path_buf()
}

fn build_live_manifest() -> std::io::Result<Manifest> {
    let root = repo_root();
    let core_files = hash_tree(&root.join("src"), &["rs"])?;
    let core_aggregate_sha256 = aggregate_src_hash(&core_files);

    let policy_files = {
        let p = root.join("policy.yaml");
        if p.exists() {
            vec![hash_file(&p)?]
        } else {
            vec![]
        }
    };

    let harness_files = hash_tree(&root.join("experiment_pack_v1/src"), &["rs"])?;
    let metric_impl_sha256 = harness_files
        .iter()
        .find(|f| f.path.ends_with("metrics.rs"))
        .map(|f| f.sha256.clone())
        .unwrap_or_else(|| "MISSING".into());

    // Corpus. Both are expected to be EMPTY in Phase I; that is precisely the
    // condition `ready_for_phase_ii` refuses to run on.
    let dataset_files = hash_tree(&root.join("benchmark/corpus/holdout"), &["json", "jsonl"])?;
    let annotation_files = hash_tree(
        &root.join("benchmark/corpus/holdout"),
        &["labels.json", "annotations.json"],
    )?;

    let mut environment = BTreeMap::new();
    environment.insert("arch".into(), std::env::consts::ARCH.into());
    environment.insert("os".into(), std::env::consts::OS.into());
    environment.insert(
        "profile".into(),
        if cfg!(debug_assertions) {
            "debug".into()
        } else {
            "release".into()
        },
    );

    let mut seeds = BTreeMap::new();
    seeds.insert("holdout_generator".into(), 0u64);

    Ok(Manifest {
        experiment_version: EXPERIMENT_VERSION.into(),
        core_aggregate_sha256,
        core_files,
        policy_files,
        harness_files,
        metric_impl_sha256,
        dataset_files,
        annotation_files,
        comparators: comparator_pins(),
        seeds,
        environment,
        case_inclusion_rules: vec![
            "Track A: mutating or security-sensitive actions only; trivial read-only \
             calls excluded from the headline (Pack §3)."
                .into(),
            "Track A: a case may be labelled D only if the SOURCE workload supplies the \
             deterministic basis; inventing host state to reach D is forbidden (Pack §7)."
                .into(),
            "Track B: raw content preserved verbatim; label provenance recorded (Pack §6.2)."
                .into(),
            "Track B: 'no malicious label' is never recorded as SAFE (Pack §3).".into(),
            "Track C: development scenarios permitted where no external corpus exists, \
             but marked externally_sourced=false (Pack §7)."
                .into(),
        ],
        case_exclusion_rules: vec![
            "Any case appearing in benchmark/corpus/dev, verbatim or as a near-duplicate \
             (normalised-text equality or shingle overlap), is excluded from holdout."
                .into(),
            "Any case drawn from the repository's pre-benchmark development scripts \
             (redteam_adaptive.py, corpus_enterprise.py, measure_grey_rate.py, \
             hardcore_redteam.py, comprehensive_test.py, enterprise_audit.py, tests/) \
             is excluded from holdout."
                .into(),
            "No case may be excluded after observing an EdgeGuard output (Pack §6.6).".into(),
        ],
    })
}

/// Comparator pins as assessed in Phase I. `executable: false` entries are
/// recorded so their absence is explicit rather than silently omitted.
fn comparator_pins() -> Vec<ComparatorPin> {
    vec![
        ComparatorPin {
            name: "hand-written deterministic rules baseline".into(),
            repository: None,
            version_or_commit: None,
            license: Some("n/a (written for this experiment)".into()),
            deployment_model: "in-process Rust, same machine".into(),
            executable_path: None,
            executable: true,
            exclusion_reason: None,
        },
        ComparatorPin {
            name: "EdgeGuard Tier2-all".into(),
            repository: None,
            version_or_commit: Some(PINNED_CORE_AGGREGATE_SHA256.into()),
            license: Some("same as Core".into()),
            deployment_model: "in-process, scorer forced on every event".into(),
            executable_path: None,
            // Requires the `onnx` feature and an ORT runtime supplied via
            // ORT_DYLIB_PATH; neither is present in this environment.
            executable: false,
            exclusion_reason: Some(
                "Tier-2 backend not compiled in: the `onnx` feature is off by default and \
                 ORT_DYLIB_PATH is unset. A mock scorer can stand in for ROUTING tests but \
                 must never be reported as semantic quality."
                    .into(),
            ),
        },
        ComparatorPin {
            name: "Cedar".into(),
            repository: Some("https://github.com/cedar-policy/cedar".into()),
            version_or_commit: None,
            license: Some("Apache-2.0".into()),
            deployment_model: "local policy evaluation, in-process".into(),
            executable_path: None,
            executable: false,
            exclusion_reason: Some(
                "Not vendored and not pinned in Phase I; no network acquisition was performed. \
                 Semantics are comparable only for the typed-argument/principal-resource subset."
                    .into(),
            ),
        },
        ComparatorPin {
            name: "OPA".into(),
            repository: Some("https://github.com/open-policy-agent/opa".into()),
            version_or_commit: None,
            license: Some("Apache-2.0".into()),
            deployment_model: "local binary or Go library".into(),
            executable_path: None,
            executable: false,
            exclusion_reason: Some(
                "Not installed in this environment and not acquired in Phase I.".into(),
            ),
        },
        ComparatorPin {
            name: "Jataayu-class deterministic local guard".into(),
            repository: None,
            version_or_commit: None,
            license: None,
            deployment_model: "unknown".into(),
            executable_path: None,
            executable: false,
            exclusion_reason: Some(
                "No public executable implementation was located in Phase I. The Pack's \
                 Jataayu-equivalence test therefore cannot be settled by direct measurement; \
                 it must be argued from capability analysis and labelled as such."
                    .into(),
            ),
        },
        ComparatorPin {
            name: "Lasso (vendor-published figures)".into(),
            repository: None,
            version_or_commit: None,
            license: None,
            deployment_model: "vendor-published; not run here".into(),
            executable_path: None,
            executable: false,
            exclusion_reason: Some(
                "Pack §5: vendor numbers are external reference only and must never be mixed \
                 into direct same-machine measured rankings."
                    .into(),
            ),
        },
    ]
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let live = match build_live_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("could not build the live manifest: {e}");
            return ExitCode::FAILURE;
        }
    };

    let frozen_path = repo_root().join("experiment_pack_v1/FREEZE_MANIFEST.json");

    if args.iter().any(|a| a == "--freeze") {
        let out = args
            .iter()
            .position(|a| a == "--freeze")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or(frozen_path);
        let json = serde_json::to_string_pretty(&live).expect("manifest serializes");
        if let Err(e) = std::fs::write(&out, json) {
            eprintln!("could not write {}: {e}", out.display());
            return ExitCode::FAILURE;
        }
        println!("froze live manifest -> {}", out.display());
        return ExitCode::SUCCESS;
    }

    println!("EdgeGuard Experiment Pack v{EXPERIMENT_VERSION} - Phase II gate\n");
    println!("live Core aggregate : {}", live.core_aggregate_sha256);
    println!("Pack-pinned Core    : {PINNED_CORE_AGGREGATE_SHA256}");
    if live.core_aggregate_sha256 != PINNED_CORE_AGGREGATE_SHA256 {
        println!("  !! Core differs from the Pack's pinned v0.2 tree");
    } else {
        println!("  OK Core matches the Pack's pinned v0.2 tree");
    }
    println!("metric impl sha256  : {}", live.metric_impl_sha256);
    println!("dataset files       : {}", live.dataset_files.len());
    println!("annotation files    : {}", live.annotation_files.len());
    println!(
        "comparators         : {} pinned, {} executable",
        live.comparators.len(),
        live.comparators.iter().filter(|c| c.executable).count()
    );

    let frozen: Option<Manifest> = std::fs::read_to_string(&frozen_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());

    println!();
    match frozen {
        None => {
            println!("FROZEN MANIFEST : absent ({})", frozen_path.display());
            println!("PHASE II        : REFUSED - nothing is frozen yet");
        }
        Some(f) => match f.ready_for_phase_ii(&live) {
            Ok(()) => {
                println!("PHASE II        : PERMITTED - lock verifies and a corpus is present")
            }
            Err(problems) => {
                println!("PHASE II        : REFUSED");
                for p in problems {
                    println!("  - {p}");
                }
            }
        },
    }
    ExitCode::SUCCESS
}
