//! Kill-Test freeze / gate binary.
//!
//!   freeze --emit-cases   write the frozen case JSON files
//!   freeze --freeze       write KILL_TEST_FREEZE_MANIFEST.json
//!   freeze --check        verify the gate and report readiness
//!
//! Never runs a frozen case against EdgeGuard (spec §11).

use edgeguard_kill_test_v1::cases;
use edgeguard_kill_test_v1::manifest::*;
use edgeguard_kill_test_v1::schema::*;
use edgeguard_kill_test_v1::KILL_TEST_VERSION;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent")
        .to_path_buf()
}
fn kt() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn emit_cases() -> std::io::Result<()> {
    let dir = kt().join("cases");
    std::fs::create_dir_all(&dir)?;
    let sets: Vec<(&str, Vec<CaseRecord>)> = vec![
        ("track1_cedar_substitution", cases::cedar_substitution()),
        ("track2_host_burden", cases::host_burden()),
        (
            "track3_jataayu_boundary_taint",
            cases::jataayu_boundary_taint(),
        ),
        ("track4_agt_substitution", cases::agt_substitution()),
    ];
    for (name, set) in &sets {
        for c in set {
            c.validate().unwrap_or_else(|e| panic!("{e}"));
        }
        let p = dir.join(format!("{name}.json"));
        std::fs::write(
            &p,
            serde_json::to_string_pretty(set).expect("cases serialize"),
        )?;
        println!("wrote {} ({} cases)", p.display(), set.len());
    }

    // The independent-review file. Spec §6: this harness flags ambiguous
    // cases but must NOT perform the second annotation and call it
    // independent.
    let need: Vec<&CaseRecord> = sets
        .iter()
        .flat_map(|(_, s)| s.iter())
        .filter(|c| c.needs_second_annotation)
        .collect();
    let review: Vec<serde_json::Value> = need
        .iter()
        .map(|c| {
            serde_json::json!({
                "case_id": c.case_id,
                "track": c.track,
                "action_name": c.action_name,
                "harness_proposed_class": c.expected_class,
                "harness_proposed_verdict": c.expected_verdict,
                "fact_basis": c.fact_basis,
                "host_facts": c.host_facts,
                "notes": c.notes,
                "independent_annotator": serde_json::Value::Null,
                "independent_class": serde_json::Value::Null,
                "independent_verdict": serde_json::Value::Null,
                "agrees_with_harness": serde_json::Value::Null,
                "disagreement_note": serde_json::Value::Null,
            })
        })
        .collect();
    let rp = dir.join("NEEDS_INDEPENDENT_ANNOTATION.json");
    std::fs::write(
        &rp,
        serde_json::to_string_pretty(&review).expect("review serializes"),
    )?;
    println!(
        "wrote {} ({} cases awaiting INDEPENDENT annotation)",
        rp.display(),
        review.len()
    );
    Ok(())
}

fn comparators() -> Vec<ComparatorPin> {
    vec![
        ComparatorPin {
            name: "Cedar".into(),
            repository: Some("https://crates.io/crates/cedar-policy".into()),
            version: Some("4.13.0".into()),
            commit: None,
            license: Some("Apache-2.0".into()),
            license_verified_via: Some("crates.io metadata".into()),
            deployment_model: "in-process Rust library, local only".into(),
            executable: true,
            local_no_network: Some(true),
            build_status: "release build OK; ALLOW and DENY both reproduced on shared facts".into(),
            limitations: vec![
                "Two-valued: Allow/Deny only. Cedar cannot express abstention, so every M/S case \
                 must collapse into one of its two answers. This is a semantic mismatch, recorded \
                 rather than papered over (invariant 12)."
                    .into(),
                "Provenance/trust of a fact is not a first-class Cedar concept; it can only be \
                 passed as ordinary context data."
                    .into(),
            ],
        },
        ComparatorPin {
            name: "Jataayu".into(),
            repository: Some("https://github.com/saikrishnarallabandi/jataayu".into()),
            version: Some("0.3.1".into()),
            commit: Some("bac74dd115c52b83043078877c83fc4fb7141fac".into()),
            license: Some("Apache-2.0".into()),
            license_verified_via: Some("GitHub licenses API".into()),
            deployment_model: "Python package, importable offline (deps: requests, pyyaml)".into(),
            executable: true,
            local_no_network: Some(true),
            build_status:
                "imports offline; EffectBoundary.preview() reproduced ALLOW / DENY / NEEDS_APPROVAL \
                 on throwaway fixtures"
                    .into(),
            limitations: vec![
                "Provenance is binary TRUSTED/UNTRUSTED; EdgeGuard distinguishes three sources. \
                 A fair mapping must be pre-registered."
                    .into(),
                "Authorization is keyed on EFFECT CLASS of the tool (NETWORK/SHELL/FILE_WRITE/...), \
                 not on typed argument values. Limit/threshold cases have no direct expression."
                    .into(),
                "Observed on a throwaway fixture under default config: an unrecognised tool \
                 classifies as READ and returns ALLOW. Pre-registered as a comparator property; \
                 `strict`/`tool_effects` config may change it and the pinned config must be \
                 recorded before the blind run."
                    .into(),
            ],
        },
        ComparatorPin {
            name: "Microsoft Agent Governance Toolkit".into(),
            repository: Some("https://github.com/microsoft/agent-governance-toolkit".into()),
            version: Some("5.0.0".into()),
            commit: Some("3da5a50c5d98c2151a5f69537535f5a71d64ea13".into()),
            license: Some("MIT".into()),
            license_verified_via: Some("GitHub licenses API".into()),
            deployment_model: "Rust workspace (agentmesh), in-process, local".into(),
            executable: true,
            local_no_network: Some(true),
            build_status: "cargo build --release OK (53s, 4 warnings, exit 0)".into(),
            limitations: vec![
                "AGT's own Rust workspace pins cedar-policy =4.13.0 and regorus =0.12.0, so the \
                 AGT and Cedar tracks are NOT independent: AGT embeds the same Cedar build."
                    .into(),
                "PolicyDecision is Allow / Deny / RequiresApproval / RateLimited - a four-valued \
                 result. RequiresApproval is the nearest analogue of ESCALATE and the mapping must \
                 be pre-registered."
                    .into(),
                "policy.rs::evaluate returns Allow when no profile is loaded - a documented \
                 fail-open default. Pre-registered in case T4-AGT-12-FAILMODE."
                    .into(),
            ],
        },
        ComparatorPin {
            name: "Handwritten direct-conditional rules".into(),
            repository: None,
            version: Some("kill_test_v1::adapters::HandwrittenRules".into()),
            commit: None,
            license: Some("n/a (authored here)".into()),
            license_verified_via: None,
            deployment_model: "in-process Rust, same resolved facts".into(),
            executable: true,
            local_no_network: Some(true),
            build_status: "unit-tested".into(),
            limitations: vec![
                "Silently allows any action nobody wrote a branch for. Pre-registered property, \
                 not a discovered result."
                    .into(),
            ],
        },
    ]
}

fn datasets() -> Vec<DatasetPin> {
    vec![
        DatasetPin {
            name: "Agent-SafetyBench".into(),
            url: Some("https://github.com/thu-coai/Agent-SafetyBench".into()),
            commit: Some("74feea8de601b3a1449a93fcf70017fe61556f73".into()),
            license: Some("MIT".into()),
            records: Some(2000),
            label_provenance: "dataset-carried safety labels over 701 environment files".into(),
            commercial_use: "permitted (MIT)".into(),
            supports_dmsl:
                "PARTIAL - carries harm/safety labels for agent behaviour, but supplies no \
                 host-authoritative state (budgets, ownership, delegation), so a D label cannot be \
                 assigned without inventing facts. Usable for M/S and for Content-style slices."
                    .into(),
            status: "acquired and frozen; NOT converted to cases; NOT exposed to EdgeGuard".into(),
        },
        DatasetPin {
            name: "InjecAgent".into(),
            url: Some("https://github.com/uiuc-kang-lab/InjecAgent".into()),
            commit: Some("f19c9f2c79a41046eb13c03c51a24c567a8ffa07".into()),
            license: Some("MIT".into()),
            records: None,
            label_provenance: "attack/injection labels carried per record".into(),
            commercial_use: "permitted (MIT)".into(),
            supports_dmsl:
                "PARTIAL - 'prompt injection present' is NOT the same as a correct EdgeGuard \
                 verdict (spec §4). Supports S and some M; no host state for D."
                    .into(),
            status: "previously acquired in benchmark/corpus_sources; unchanged".into(),
        },
        DatasetPin {
            name: "AgentDojo".into(),
            url: Some("https://github.com/ethz-spylab/agentdojo".into()),
            commit: Some("089ed468cf3ed0322acc66b0211f26d9d90dbf60".into()),
            license: Some("MIT".into()),
            records: None,
            label_provenance: "attack-success labels".into(),
            commercial_use: "permitted (MIT)".into(),
            supports_dmsl:
                "PARTIAL - attack success is not a verdict oracle (spec §4). No host-authoritative \
                 state for D."
                    .into(),
            status: "previously acquired in benchmark/corpus_sources; unchanged".into(),
        },
        DatasetPin {
            name: "AgentGovBench".into(),
            url: Some("https://agenticcontrolplane.com/series/agentgovbench".into()),
            commit: None,
            license: None,
            records: Some(48),
            label_provenance: "vendor-described governance scenarios".into(),
            commercial_use: "unknown - no licence located".into(),
            supports_dmsl: "UNKNOWN".into(),
            status:
                "NOT ACQUIRED - no open repository or licence located; vendor-operated series. \
                 Recorded as unavailable rather than substituted."
                    .into(),
        },
        DatasetPin {
            name: "ToolSafe / TS-Bench".into(),
            url: None,
            commit: None,
            license: None,
            records: None,
            label_provenance: "n/a".into(),
            commercial_use: "n/a".into(),
            supports_dmsl: "n/a".into(),
            status: "NOT FOUND - no source matching this name located in Phase I.5.".into(),
        },
        DatasetPin {
            name: "CrossMCP-Bench".into(),
            url: None,
            commit: None,
            license: None,
            records: None,
            label_provenance: "n/a".into(),
            commercial_use: "n/a".into(),
            supports_dmsl: "n/a".into(),
            status: "NOT FOUND - no source matching this name located in Phase I.5.".into(),
        },
        DatasetPin {
            name: "Agent Action Boundary Benchmark".into(),
            url: None,
            commit: None,
            license: None,
            records: None,
            label_provenance: "n/a".into(),
            commercial_use: "n/a".into(),
            supports_dmsl: "n/a".into(),
            status: "NOT FOUND under this name. Nearest candidates seen in search \
                 (agent-action-safety-benchmark, SafeAgentBench) were not verified or acquired."
                .into(),
        },
    ]
}

fn build_live() -> std::io::Result<Manifest> {
    let r = root();
    let core_production = hash_tree(&r.join("src"), &["rs"])?;
    let policy_files = {
        let p = r.join("policy.yaml");
        if p.exists() {
            vec![hash_file(&p)?]
        } else {
            vec![]
        }
    };
    let harness_files = hash_tree(&kt().join("src"), &["rs"])?;
    let metric_impl_sha256 = harness_files
        .iter()
        .find(|f| f.path.ends_with("metrics.rs"))
        .map(|f| f.sha256.clone())
        .unwrap_or_else(|| "MISSING".into());

    let case_dir = kt().join("cases");
    let all_case_files = hash_tree(&case_dir, &["json"])?;
    let (annotation_files, case_files): (Vec<_>, Vec<_>) = all_case_files
        .into_iter()
        .partition(|f| f.path.contains("NEEDS_INDEPENDENT_ANNOTATION"));

    let mut environment = BTreeMap::new();
    environment.insert("arch".into(), std::env::consts::ARCH.into());
    environment.insert("os".into(), std::env::consts::OS.into());
    environment.insert("profile".into(), "release".into());

    let mut seeds = BTreeMap::new();
    seeds.insert("case_order".into(), 0u64);

    Ok(Manifest {
        experiment: "EdgeGuard Kill-Test".into(),
        version: KILL_TEST_VERSION.into(),
        core_branch: edgeguard_kill_test_v1::CORE_BRANCH.into(),
        core_head: "2d6d75a8f43a7240f63f7dad90f5dcfacb874ced".into(),
        core_production,
        policy_files,
        harness_files,
        metric_impl_sha256,
        case_files,
        annotation_files,
        comparators: comparators(),
        datasets: datasets(),
        inclusion_rules: vec![
            "All 42 frozen cases are authored, development_only, and externally_sourced=false \
             (invariant 13)."
                .into(),
            "Every system receives the SAME host-resolved fact set (spec §3).".into(),
            "A D class requires an explicit fact_basis naming the settling fact (spec §6).".into(),
            "M and S pre-register ESCALATE; no pre-registered semantics allow a terminal local \
             PASS on them (spec §2)."
                .into(),
        ],
        exclusion_rules: vec![
            "No case may be added, removed, reworded, or relabelled after any EdgeGuard output is \
             observed (invariants 5, 6)."
                .into(),
            "Vendor-published comparator numbers are never mixed into same-machine rankings \
             (spec §3)."
                .into(),
            "'Prompt injection present', 'attacker intent' and 'attack success' are never treated \
             as equivalent to a correct EdgeGuard verdict (spec §4)."
                .into(),
        ],
        seeds,
        environment,
        timing: TimingConfig {
            profile: "release".into(),
            warm_cold_separated: true,
            scale_points: vec![1, 10, 100, 1000],
            percentiles: vec!["p50".into(), "p95".into(), "p99".into(), "max".into()],
            policy_load_timed_separately: true,
            context_construction_timed_separately: true,
            network_allowed_in_evaluator_timing: false,
        },
        // Measured from the live tree, not asserted.
        unannotated_cases: {
            let rp = case_dir.join("NEEDS_INDEPENDENT_ANNOTATION.json");
            std::fs::read_to_string(&rp)
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s).ok())
                .map(|v| {
                    v.iter()
                        .filter(|e| {
                            e.get("independent_class")
                                .map(|c| c.is_null())
                                .unwrap_or(true)
                        })
                        .count() as u64
                })
                .unwrap_or(0)
        },
        placeholder_burden_cases: cases::host_burden()
            .iter()
            .filter(|c| c.burden.integration_loc == 0 || c.burden.setup_steps == 0)
            .count() as u64,
        comparators_without_adapter: vec![
            // Pinned, built, sanity-probed - but no verdict-producing adapter
            // is wired into this harness yet, so neither can be asked for a
            // verdict on a frozen case.
            "Jataayu".into(),
            "Microsoft Agent Governance Toolkit".into(),
        ],
        contamination_policy: vec![
            "Frozen cases are NOT run against EdgeGuard in Phase I.5 (spec §11).".into(),
            "Sanity probes use throwaway fixtures only, never a frozen case.".into(),
            "The gate refuses on any change to a case, a label, a Core PRODUCTION-region hash, a \
             comparator pin, the metric implementation, or the manifest."
                .into(),
            "Core test-region edits are visible but do not void results; production-region edits \
             void them."
                .into(),
        ],
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let has = |f: &str| args.iter().any(|a| a == f);

    if has("--emit-cases") {
        if let Err(e) = emit_cases() {
            eprintln!("emit-cases failed: {e}");
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let live = match build_live() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("could not build live manifest: {e}");
            return ExitCode::FAILURE;
        }
    };
    let frozen_path = kt().join("KILL_TEST_FREEZE_MANIFEST.json");

    if has("--freeze") {
        let j = serde_json::to_string_pretty(&live).expect("manifest serializes");
        if let Err(e) = std::fs::write(&frozen_path, j) {
            eprintln!("write failed: {e}");
            return ExitCode::FAILURE;
        }
        println!("froze -> {}", frozen_path.display());
        return ExitCode::SUCCESS;
    }

    println!("EdgeGuard Kill-Test v{KILL_TEST_VERSION} - blind-execution gate\n");
    println!("core branch        : {}", live.core_branch);
    println!("core prod files    : {}", live.core_production.len());
    println!("harness files      : {}", live.harness_files.len());
    println!("metric impl sha256 : {}", live.metric_impl_sha256);
    println!("frozen case files  : {}", live.case_files.len());
    println!("annotation files   : {}", live.annotation_files.len());
    println!(
        "comparators        : {} pinned, {} executable",
        live.comparators.len(),
        live.comparators.iter().filter(|c| c.executable).count()
    );
    println!(
        "datasets           : {} pinned, {} acquired",
        live.datasets.len(),
        live.datasets
            .iter()
            .filter(|d| d.status.starts_with("acquired") || d.status.starts_with("previously"))
            .count()
    );

    let frozen: Option<Manifest> = std::fs::read_to_string(&frozen_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok());
    println!();
    match frozen {
        None => println!(
            "BLIND EXECUTION : REFUSED - no frozen manifest at {}",
            frozen_path.display()
        ),
        Some(f) => match f.ready(&live) {
            Ok(()) => println!("BLIND EXECUTION : PERMITTED"),
            Err(p) => {
                println!("BLIND EXECUTION : REFUSED");
                for x in p {
                    println!("  - {x}");
                }
            }
        },
    }
    ExitCode::SUCCESS
}
