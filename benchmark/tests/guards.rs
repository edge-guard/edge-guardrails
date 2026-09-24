//! Guards that must hold before any result is believable.

use edgeguard_routing_benchmark::corpus::{
    check_implementation_independence, check_leakage, validate, IMPLEMENTATION_TOKENS,
    RESERVED_PAYLOAD_KEYS,
};
use edgeguard_routing_benchmark::locks::{ClassificationLock, PolicyEnvironmentLock};
use edgeguard_routing_benchmark::policy_env;
use edgeguard_routing_benchmark::schema::*;
use edgeguard_routing_benchmark::{freeze, locks};
use std::path::{Path, PathBuf};

fn engine_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("benchmark crate always has a parent directory")
}

fn policy_env_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("policy_env")
}

// --- The freeze -----------------------------------------------------------

#[test]
fn the_frozen_engine_has_not_been_modified() {
    let drifted = freeze::verify(engine_root()).expect("engine files must be readable");
    assert!(
        drifted.is_empty(),
        "EdgeGuard Core is frozen at {}, but these files changed: {:#?}\n\
         Results produced against a modified engine are not comparable.",
        freeze::FROZEN_COMMIT,
        drifted
    );
}

// --- Policy environments --------------------------------------------------

#[test]
fn every_shipped_policy_environment_loads_and_validates() {
    let set = policy_env::load_dir(&policy_env_dir()).expect("policy environments must load");
    assert!(!set.is_empty(), "at least one environment must exist");
    for env in set.iter() {
        assert!(env.validate().is_ok(), "{:?} must validate", env.id);
        assert!(
            !env.covered_actions().is_empty(),
            "{:?} must cover at least one action",
            env.id
        );
    }
}

#[test]
fn a_policy_environment_digest_is_stable_across_reloads() {
    let a = policy_env::load_dir(&policy_env_dir()).unwrap();
    let b = policy_env::load_dir(&policy_env_dir()).unwrap();
    assert_eq!(a.digests(), b.digests());
}

#[test]
fn a_changed_policy_environment_is_caught_by_its_lock() {
    let set = policy_env::load_dir(&policy_env_dir()).unwrap();
    let lock = PolicyEnvironmentLock::build(set.digests());
    assert!(lock.verify(&set.digests()).is_empty(), "unchanged verifies");

    let mut tampered = set.digests();
    if let Some((_, digest)) = tampered.iter_mut().next() {
        *digest = "0".repeat(64);
    }
    assert!(
        !lock.verify(&tampered).is_empty(),
        "a changed environment must be reported as drift"
    );
}

#[test]
fn an_environment_serving_too_few_cases_is_reported() {
    let usage = policy_env::EnvironmentUsage {
        cases: 3,
        distinct_classes: 1,
        has_safe: true,
        has_harmful: false,
    };
    let shortfalls = usage.shortfalls("finance_company");
    assert_eq!(
        shortfalls.len(),
        3,
        "too few cases, too few classes, and no harmful cases: {shortfalls:#?}"
    );
}

// --- Case construction ----------------------------------------------------

fn case(channel: Channel, fields: Vec<FieldSpec>, gt: GroundTruth) -> CaseRecord {
    CaseRecord {
        case_id: "case-0001".to_string(),
        source: Source::SyntheticFacts,
        usage: UsageClass::ExternalEvaluation,
        role: CaseRole::Primary,
        policy_environment_id: (channel == Channel::Action).then(|| "finance_company".to_string()),
        event: EventSpec {
            channel,
            action_name: (channel == Channel::Action).then(|| "execute_payment".to_string()),
            principal_id: None,
            fields,
        },
        ground_truth: gt,
        origin: "test".to_string(),
    }
}

fn text_field(value: &str) -> FieldSpec {
    FieldSpec {
        key: "text".to_string(),
        provenance: ProvenanceSpec::UserProvided,
        value: ValueSpec::String(value.to_string()),
    }
}

fn s_truth() -> GroundTruth {
    GroundTruth {
        class: Class::S,
        expected: ExpectedOutcome::Escalate,
        expected_escalation_reason: Some(EscalationReason::SemanticUncertainty),
        true_safety: Safety::Harmful,
        deciding_facts: vec![],
        rationale: "intent is ambiguous without reading it for meaning".to_string(),
        attack_family: None,
    }
}

fn content_fact() -> DecidingFact {
    DecidingFact {
        domain: FactDomain::Content,
        content_kind: Some(ContentFactKind::Secret),
        action_kind: None,
        basis: FactBasis::PublishedSpecification {
            specification: "AWS access key identifier format".into(),
            section: "AKIA prefix + 16 base32 chars".into(),
        },
        statement: "the message body contains a 40-character AWS secret access key next to its \
                    key id, which an auditor can read directly off the payload"
            .to_string(),
        observable_at: "payload.text".to_string(),
    }
}

fn action_fact() -> DecidingFact {
    DecidingFact {
        domain: FactDomain::Action,
        content_kind: None,
        action_kind: Some(ActionFactKind::AmountLimit),
        basis: FactBasis::PolicyClause {
            environment_id: "finance_company".into(),
            environment_version: "v1".into(),
            policy_id: "finance.payment.delegated_authority".into(),
        },
        statement: "the host-authoritative payment amount is 1,250,000 minor units, above the \
                    1,000,000 delegated authority the operator's policy states"
            .to_string(),
        observable_at: "payload.amount_minor_units".to_string(),
    }
}

// --- Content / Action / Mixed separability --------------------------------

#[test]
fn a_content_only_case_has_content_shape() {
    let gt = GroundTruth {
        class: Class::D,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![content_fact()],
        rationale: "a live credential in the body".to_string(),
        attack_family: None,
    };
    assert_eq!(gt.shape(), CaseShape::ContentOnly);
    assert_eq!(gt.content_fact_kinds(), vec![ContentFactKind::Secret]);
    assert!(gt.action_fact_kinds().is_empty());
    assert!(validate(&case(Channel::Input, vec![text_field("...")], gt)).is_ok());
}

#[test]
fn an_action_only_case_has_action_shape() {
    let gt = GroundTruth {
        class: Class::D,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![action_fact()],
        rationale: "over the delegated authority".to_string(),
        attack_family: None,
    };
    assert_eq!(gt.shape(), CaseShape::ActionOnly);
    assert_eq!(gt.action_fact_kinds(), vec![ActionFactKind::AmountLimit]);
}

#[test]
fn a_case_carrying_both_fact_domains_is_mixed() {
    let gt = GroundTruth {
        class: Class::M,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![content_fact(), action_fact()],
        rationale: "adversarial prose alongside two independently decisive facts".to_string(),
        attack_family: Some("tool_hijack".to_string()),
    };
    assert_eq!(gt.shape(), CaseShape::Mixed);
    assert!(validate(&case(Channel::Action, vec![text_field("...")], gt)).is_ok());
}

#[test]
fn an_m_case_may_be_decided_by_a_content_fact_alone() {
    // Obfuscated, semantically ambiguous content plus a decisive secret.
    let gt = GroundTruth {
        class: Class::M,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![content_fact()],
        rationale: "the surrounding prose is ambiguous, but the credential is not".to_string(),
        attack_family: Some("obfuscated_exfiltration".to_string()),
    };
    assert_eq!(gt.shape(), CaseShape::ContentOnly);
    assert!(validate(&case(Channel::Input, vec![text_field("...")], gt)).is_ok());
}

#[test]
fn an_action_domain_fact_requires_an_action_event() {
    let gt = GroundTruth {
        class: Class::D,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![action_fact()],
        rationale: "structured constraint".to_string(),
        attack_family: None,
    };
    assert!(validate(&case(Channel::Input, vec![text_field("x")], gt)).is_err());
}

// --- Deciding facts must be auditable independently ------------------------

#[test]
fn every_implementation_token_disqualifies_a_deciding_fact() {
    for token in IMPLEMENTATION_TOKENS {
        let statement = format!("this is blocked because {token} says so");
        assert!(
            check_implementation_independence(&statement).is_err(),
            "{token:?} must disqualify a deciding fact statement"
        );
    }
}

#[test]
fn an_implementation_referencing_fact_is_rejected_at_load() {
    let mut fact = action_fact();
    fact.statement = "EdgeGuard currently has a rule for this action".to_string();
    let gt = GroundTruth {
        class: Class::D,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![fact],
        rationale: "circular".to_string(),
        attack_family: None,
    };
    assert!(validate(&case(Channel::Action, vec![], gt)).is_err());
}

#[test]
fn an_event_observable_fact_is_accepted() {
    assert!(check_implementation_independence(
        "the host-authoritative amount is 1,250,000, above the stated 1,000,000 ceiling"
    )
    .is_ok());
}

#[test]
fn a_content_fact_requires_a_content_kind() {
    let mut fact = content_fact();
    fact.content_kind = None;
    assert!(fact.validate().is_err());
}

// --- Policy environments are referenced, never embedded --------------------

#[test]
fn an_action_case_must_reference_a_policy_environment() {
    let gt = GroundTruth {
        class: Class::D,
        expected: ExpectedOutcome::Block,
        expected_escalation_reason: None,
        true_safety: Safety::Harmful,
        deciding_facts: vec![action_fact()],
        rationale: "over the ceiling".to_string(),
        attack_family: None,
    };
    let mut record = case(Channel::Action, vec![], gt);
    record.policy_environment_id = None;
    assert!(validate(&record).is_err());
}

#[test]
fn a_content_case_must_not_reference_a_policy_environment() {
    let mut record = case(Channel::Input, vec![text_field("hello")], s_truth());
    record.policy_environment_id = Some("finance_company".to_string());
    assert!(validate(&record).is_err());
}

// --- Usage class ----------------------------------------------------------

#[test]
fn material_used_for_rule_development_must_be_marked_development_only() {
    let mut record = case(Channel::Input, vec![text_field("hello")], s_truth());
    record.origin = "redteam_adaptive.py row 17".to_string();
    record.usage = UsageClass::ExternalEvaluation;
    assert!(
        validate(&record).is_err(),
        "a case sourced from tuning material may not claim external status"
    );

    record.usage = UsageClass::DevelopmentOnly;
    assert!(validate(&record).is_ok());
}

#[test]
fn a_holdout_usage_class_requires_a_holdout_source() {
    let mut record = case(Channel::Input, vec![text_field("hello")], s_truth());
    record.usage = UsageClass::Holdout;
    assert!(validate(&record).is_err());
}

// --- Classification freeze -------------------------------------------------

#[test]
fn reclassifying_a_case_after_the_lock_is_detected() {
    let original = case(Channel::Input, vec![text_field("hello")], s_truth());
    let lock = ClassificationLock::build(std::slice::from_ref(&original));
    assert!(lock.verify(std::slice::from_ref(&original)).is_empty());

    let mut reclassified = original.clone();
    reclassified.ground_truth.true_safety = Safety::Safe;
    let drift = lock.verify(std::slice::from_ref(&reclassified));
    assert_eq!(
        drift,
        vec![locks::ClassificationDrift::Reclassified {
            case_id: "case-0001".to_string()
        }]
    );
}

#[test]
fn editing_a_payload_after_the_lock_is_now_drift() {
    // This test previously asserted the opposite. The tolerance it protected -
    // "a prose typo is not a reclassification" - turned out to be unbounded:
    // an entire payload could be replaced under a frozen classification with
    // no drift reported. There is no typo exemption now. A payload that must
    // change after the freeze is a new case or a new corpus revision.
    let original = case(
        Channel::Input,
        vec![text_field("teh quick brown fox")],
        s_truth(),
    );
    let lock = ClassificationLock::build(std::slice::from_ref(&original));
    let corrected = case(
        Channel::Input,
        vec![text_field("the quick brown fox")],
        s_truth(),
    );
    assert_eq!(
        lock.verify(std::slice::from_ref(&corrected)),
        vec![locks::ClassificationDrift::Reclassified {
            case_id: "case-0001".to_string()
        }],
        "the event is part of the frozen subject"
    );
}

#[test]
fn reordering_payload_fields_is_not_drift() {
    // Field order is not semantic: the payload becomes a map. Only changes
    // that alter the SecurityEvent the engine receives count as drift.
    let original = case(
        Channel::Input,
        vec![text_field("hello"), int_field_for_order()],
        s_truth(),
    );
    let lock = ClassificationLock::build(std::slice::from_ref(&original));
    let mut reordered = original.clone();
    reordered.event.fields.reverse();
    assert!(lock.verify(std::slice::from_ref(&reordered)).is_empty());
}

fn int_field_for_order() -> FieldSpec {
    FieldSpec {
        key: "counter".to_string(),
        provenance: ProvenanceSpec::HostAuthoritative,
        value: ValueSpec::Integer(7),
    }
}

#[test]
fn a_duplicate_payload_field_key_is_rejected() {
    // Two fields with one key collapse in the payload map, so the canonical
    // form - and therefore the freeze - would be ill-defined.
    let record = case(
        Channel::Input,
        vec![text_field("first"), text_field("second")],
        s_truth(),
    );
    assert!(validate(&record).is_err());
}

#[test]
fn a_case_added_after_the_lock_is_reported_as_unlocked() {
    let locked = case(Channel::Input, vec![text_field("hello")], s_truth());
    let lock = ClassificationLock::build(std::slice::from_ref(&locked));
    let mut added = locked.clone();
    added.case_id = "case-0002".to_string();
    let drift = lock.verify(&[locked, added]);
    assert_eq!(
        drift,
        vec![locks::ClassificationDrift::Unlocked {
            case_id: "case-0002".to_string()
        }]
    );
}

// --- Holdout burn ----------------------------------------------------------

#[test]
fn observing_a_holdout_version_burns_it() {
    let mut log = locks::HoldoutBurnLog::default();
    assert!(!log.is_burned("v1"));
    let first = log.record("v1", "abc", "2026-09-24T00:00:00Z");
    assert_eq!(first.observation_index, 1);
    assert!(log.is_burned("v1"));

    let second = log.record("v1", "abc", "2026-09-25T00:00:00Z");
    assert_eq!(
        second.observation_index, 2,
        "a repeat look must be visible in the record"
    );
    assert!(!log.is_burned("v2"), "burning v1 does not burn v2");
}

// --- Leakage ---------------------------------------------------------------

#[test]
fn a_reserved_payload_key_is_rejected() {
    for key in RESERVED_PAYLOAD_KEYS {
        let record = case(
            Channel::Input,
            vec![FieldSpec {
                key: (*key).to_string(),
                provenance: ProvenanceSpec::UserProvided,
                value: ValueSpec::String("S".to_string()),
            }],
            s_truth(),
        );
        assert!(
            check_leakage(&record).is_err(),
            "payload key {key:?} must be rejected as benchmark metadata"
        );
    }
}

#[test]
fn a_case_id_hidden_in_a_nested_payload_value_is_rejected() {
    let record = case(
        Channel::Input,
        vec![FieldSpec {
            key: "context".to_string(),
            provenance: ProvenanceSpec::UserProvided,
            value: ValueSpec::List(vec![ValueSpec::Map(
                [(
                    "note".to_string(),
                    ValueSpec::String("see case-0001 for the label".to_string()),
                )]
                .into_iter()
                .collect(),
            )]),
        }],
        s_truth(),
    );
    assert!(check_leakage(&record).is_err());
}

#[test]
fn an_ordinary_case_passes_the_leakage_lint() {
    let record = case(
        Channel::Input,
        vec![text_field("please summarise the quarterly report")],
        s_truth(),
    );
    assert!(check_leakage(&record).is_ok());
}

// --- D/S/M coherence -------------------------------------------------------

#[test]
fn an_s_case_may_not_claim_a_deterministic_expectation() {
    let mut record = case(Channel::Input, vec![text_field("ambiguous")], s_truth());
    record.ground_truth.expected = ExpectedOutcome::Block;
    assert!(validate(&record).is_err());
}

#[test]
fn an_s_case_may_not_carry_a_deciding_fact() {
    let mut record = case(Channel::Input, vec![text_field("ambiguous")], s_truth());
    record.ground_truth.deciding_facts = vec![content_fact()];
    assert!(validate(&record).is_err());
}

#[test]
fn a_d_case_may_not_expect_escalation() {
    let record = case(
        Channel::Input,
        vec![text_field("benign")],
        GroundTruth {
            class: Class::D,
            expected: ExpectedOutcome::Escalate,
            expected_escalation_reason: Some(EscalationReason::SemanticUncertainty),
            true_safety: Safety::Safe,
            deciding_facts: vec![content_fact()],
            rationale: "contradictory by construction".to_string(),
            attack_family: None,
        },
    );
    assert!(validate(&record).is_err());
}

#[test]
fn a_d_case_requires_at_least_one_deciding_fact() {
    let record = case(
        Channel::Input,
        vec![text_field("benign")],
        GroundTruth {
            class: Class::D,
            expected: ExpectedOutcome::Pass,
            expected_escalation_reason: None,
            true_safety: Safety::Safe,
            deciding_facts: vec![],
            rationale: "no fact stated".to_string(),
            attack_family: None,
        },
    );
    assert!(validate(&record).is_err());
}

#[test]
fn an_input_case_may_not_carry_an_action_name() {
    let mut record = case(Channel::Input, vec![text_field("hello")], s_truth());
    record.event.action_name = Some("execute_payment".to_string());
    assert!(validate(&record).is_err());
}

#[test]
fn a_case_without_a_rationale_is_rejected() {
    let mut record = case(Channel::Input, vec![text_field("hello")], s_truth());
    record.ground_truth.rationale = "  ".to_string();
    assert!(validate(&record).is_err());
}

#[test]
fn a_case_round_trips_through_json_unchanged() {
    let record = case(
        Channel::Input,
        vec![text_field("please summarise the quarterly report")],
        s_truth(),
    );
    let encoded = serde_json::to_string(&record).unwrap();
    let decoded: CaseRecord = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        serde_json::to_string(&decoded).unwrap(),
        encoded,
        "corpus files must round-trip byte-identically"
    );
}

#[test]
fn the_recipe_module_does_not_reach_into_the_engine() {
    // A recipe is authored from a policy clause or a published specification.
    // "Generate examples matching what EdgeGuard detects" is the failure the
    // whole freeze mechanism exists to prevent, so the module that defines
    // recipes must not be able to consult the engine at all.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/recipe.rs"),
    )
    .expect("recipe module must be readable");
    assert!(
        !source.contains("edgeguard::"),
        "src/recipe.rs must not reference engine types"
    );
    assert!(
        !source.contains("use edgeguard"),
        "src/recipe.rs must not import the engine"
    );
}

#[test]
fn the_recipe_loader_ignores_the_lock_file() {
    // The lock lives beside the recipes it freezes; it is not a recipe and must
    // not be parsed as one.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("recipes");
    assert!(dir.join("recipes.lock.json").exists());
    let recipes = edgeguard_routing_benchmark::recipe::load_dir(&dir).expect("must load");
    assert!(recipes.iter().all(|r| !r.recipe_id.contains("lock")));
}

#[test]
fn the_shipped_recipes_load_and_validate() {
    let recipes = edgeguard_routing_benchmark::recipe::load_dir(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("recipes"),
    )
    .expect("recipes must load");
    for r in recipes.iter() {
        assert!(r.validate().is_ok(), "{} must validate", r.key());
    }
    assert_eq!(recipes.len(), 6, "six recipes were drafted in Phase 1");
}

#[test]
fn the_recipe_lock_matches_the_frozen_recipes() {
    // The freeze is only real if it is checked. Any edit to a recipe, any
    // removal, and any addition must fail here - which is the point: after the
    // lock is written, recipes may not move in response to a benchmark result.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("recipes");
    let recipes = edgeguard_routing_benchmark::recipe::load_dir(&dir).expect("recipes must load");
    let lock: edgeguard_routing_benchmark::recipe::RecipeLock = serde_json::from_str(
        &std::fs::read_to_string(dir.join("recipes.lock.json")).expect("lock must exist"),
    )
    .expect("lock must parse");

    let drift = lock.verify(&recipes.digests());
    assert!(
        drift.is_empty(),
        "recipe drift against the frozen lock: {drift:#?}"
    );
}
