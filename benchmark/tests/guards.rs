//! Guards that must hold before any result is believable.

use edgeguard_routing_benchmark::corpus::{check_leakage, validate, RESERVED_PAYLOAD_KEYS};
use edgeguard_routing_benchmark::freeze;
use edgeguard_routing_benchmark::schema::*;
use std::path::Path;

fn engine_root() -> &'static Path {
    // The frozen engine is the parent of this crate.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("benchmark crate always has a parent directory")
}

#[test]
fn the_frozen_engine_has_not_been_modified() {
    let drifted = freeze::verify(engine_root()).expect("engine files must be readable");
    assert!(
        drifted.is_empty(),
        "EdgeGuard Core is frozen at {}, but these files changed: {:#?}\n\
         Benchmark results produced against a modified engine are not comparable. \
         Either revert the change or re-freeze deliberately.",
        freeze::FROZEN_COMMIT,
        drifted
    );
}

fn case(channel: Channel, fields: Vec<FieldSpec>, gt: GroundTruth) -> CaseRecord {
    CaseRecord {
        case_id: "case-0001".to_string(),
        source: Source::SyntheticFacts,
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
        true_safety: Safety::Harmful,
        deciding_fact: None,
        rationale: "no deterministic fact settles this".to_string(),
        attack_family: None,
    }
}

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

#[test]
fn an_s_case_may_not_claim_a_deterministic_expectation() {
    let mut record = case(Channel::Input, vec![text_field("ambiguous")], s_truth());
    record.ground_truth.expected = ExpectedOutcome::Block;
    assert!(validate(&record).is_err());
}

#[test]
fn an_s_case_may_not_carry_a_deciding_fact() {
    let mut record = case(Channel::Input, vec![text_field("ambiguous")], s_truth());
    record.ground_truth.deciding_fact = Some("amount > 1000000".to_string());
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
            true_safety: Safety::Safe,
            deciding_fact: Some("no rule matches".to_string()),
            rationale: "contradictory by construction".to_string(),
            attack_family: None,
        },
    );
    assert!(validate(&record).is_err());
}

#[test]
fn an_m_case_requires_the_fact_that_is_supposed_to_win() {
    let record = case(
        Channel::Action,
        vec![FieldSpec {
            key: "amount".to_string(),
            provenance: ProvenanceSpec::HostAuthoritative,
            value: ValueSpec::Integer(1_250_000),
        }],
        GroundTruth {
            class: Class::M,
            expected: ExpectedOutcome::Block,
            true_safety: Safety::Harmful,
            deciding_fact: None,
            rationale: "adversarial prose plus an over-limit amount".to_string(),
            attack_family: Some("tool_hijack".to_string()),
        },
    );
    assert!(validate(&record).is_err(), "M without deciding_fact");
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
