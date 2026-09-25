//! Fair adapters. Every system receives the SAME host-resolved facts.
//!
//! "Fair" here has a specific operational meaning (spec §3): the host does the
//! identity/resource/state/provenance resolution ONCE, and each evaluator is
//! handed that same resolved fact set. No evaluator is allowed a private
//! shortcut, and none is charged for work another one got for free. Where a
//! system genuinely cannot express a fact, that is recorded as an expressivity
//! limit rather than papered over (invariant 12).

use crate::schema::*;
use std::time::Instant;

/// The single host-resolved fact set, produced once per case and shared.
#[derive(Debug, Clone)]
pub struct ResolvedFacts {
    pub action_name: String,
    pub principal_id: Option<String>,
    pub resource_id: Option<String>,
    pub facts: Vec<HostFact>,
}

impl ResolvedFacts {
    pub fn from_case(c: &CaseRecord) -> Self {
        ResolvedFacts {
            action_name: c.action_name.clone(),
            principal_id: c
                .host_facts
                .iter()
                .find(|f| f.name == "principal_id")
                .and_then(|f| f.value.as_str().map(|s| s.to_string())),
            resource_id: c
                .host_facts
                .iter()
                .find(|f| f.name == "resource_id")
                .and_then(|f| f.value.as_str().map(|s| s.to_string())),
            facts: c.host_facts.clone(),
        }
    }

    pub fn get(&self, name: &str) -> Option<&HostFact> {
        self.facts.iter().find(|f| f.name == name)
    }

    /// Facts that encode AI-specific trust/provenance rather than ordinary
    /// authorization state. The Cedar-substitution question turns on whether a
    /// comparator can express these at all.
    pub fn ai_specific(&self) -> Vec<&HostFact> {
        self.facts.iter().filter(|f| f.ai_specific).collect()
    }

    pub fn context_bytes(&self) -> u32 {
        serde_json::to_string(&self.facts)
            .map(|s| s.len() as u32)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Invariant 9: what counts as local resolution
// ---------------------------------------------------------------------------

/// A terminal verdict rests on deterministic local evidence only for these
/// stages. `Tier2*` stages - unavailable, failed, shed, deferred, and even a
/// successful model verdict - are NOT local resolution.
pub fn is_locally_resolved(decided_by: &str) -> bool {
    decided_by.starts_with("SizeGuard")
        || decided_by.starts_with("Obfuscation")
        || decided_by.starts_with("Tier1Rule")
        || decided_by.starts_with("Tier1Deterministic")
        || decided_by.starts_with("ActionEvaluator")
        || decided_by.starts_with("Cedar")
        || decided_by.starts_with("Handwritten")
        || decided_by.starts_with("AgtPolicy")
        || decided_by.starts_with("JataayuEffectBoundary")
}

// ---------------------------------------------------------------------------
// EdgeGuard
// ---------------------------------------------------------------------------

/// Build the EdgeGuard ACTION event from the shared facts and evaluate it.
///
/// NOT called on frozen cases in Phase I.5 (spec §11). Exposed so the gate and
/// the self-tests can exercise it on throwaway fixtures.
pub fn edgeguard_action(
    facts: &ResolvedFacts,
    rules: &[edgeguard::event::ActionRule],
) -> (Verdict, String, String, f64) {
    use edgeguard::event::{AttributedValue, EventKind, Provenance, SecurityEvent, Value};
    use std::collections::HashMap;

    let mut payload: HashMap<String, AttributedValue> = HashMap::new();
    for f in &facts.facts {
        payload.insert(
            f.name.clone(),
            AttributedValue {
                data: json_to_value(&f.value),
                provenance: match f.provenance.as_str() {
                    "host_authoritative" => Provenance::HostAuthoritative,
                    "model_proposed" => Provenance::ModelProposed,
                    _ => Provenance::UserProvided,
                },
            },
        );
    }
    let event = SecurityEvent {
        kind: EventKind::Action {
            name: facts.action_name.clone(),
        },
        principal_id: facts.principal_id.clone(),
        payload,
    };

    let t0 = Instant::now();
    let decision = edgeguard::event::evaluate_action(&event, rules);
    let eval_us = t0.elapsed().as_nanos() as f64 / 1000.0;

    let (v, reason) = match decision {
        edgeguard::event::EventDecision::Pass => (Verdict::Pass, "pass".to_string()),
        edgeguard::event::EventDecision::Block { code, reason, .. } => {
            (Verdict::Block, format!("{code}: {reason}"))
        }
        edgeguard::event::EventDecision::Escalate { reason } => (Verdict::Escalate, reason),
    };
    (v, reason, "ActionEvaluator".to_string(), eval_us)
}

/// No coercion: an integer stays an integer. A silent widening at the adapter
/// would move a security verdict outside the engine under test.
pub fn json_to_value(v: &serde_json::Value) -> edgeguard::event::Value {
    use edgeguard::event::Value;
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::Null
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(a) => Value::List(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(o) => Value::Map(
            o.iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Cedar
// ---------------------------------------------------------------------------

/// Cedar evaluation over the same resolved facts.
///
/// Cedar answers a two-valued question (Allow / Deny), so the three-way
/// mapping has to be stated explicitly and pre-registered rather than
/// improvised per case: Cedar `Allow` -> PASS, Cedar `Deny` -> BLOCK. Cedar
/// has **no third value**, which is itself one of the findings the track is
/// designed to surface - there is no way for a Cedar policy to say "the facts
/// do not settle this". `diagnostics` carries the reason.
pub struct CedarEngine {
    policies: cedar_policy::PolicySet,
    entities: cedar_policy::Entities,
    /// Lines of policy text, recorded for the burden metric.
    pub policy_loc: u32,
}

#[derive(Debug)]
pub enum CedarBuildError {
    Policy(String),
    Entities(String),
}

impl CedarEngine {
    pub fn new(policy_src: &str) -> Result<Self, CedarBuildError> {
        let policies: cedar_policy::PolicySet = policy_src
            .parse()
            .map_err(|e| CedarBuildError::Policy(format!("{e:?}")))?;
        let entities = cedar_policy::Entities::empty();
        Ok(CedarEngine {
            policies,
            entities,
            policy_loc: policy_src.lines().filter(|l| !l.trim().is_empty()).count() as u32,
        })
    }

    pub fn with_entities(mut self, json: &str) -> Result<Self, CedarBuildError> {
        self.entities = cedar_policy::Entities::from_json_str(json, None)
            .map_err(|e| CedarBuildError::Entities(format!("{e:?}")))?;
        Ok(self)
    }

    /// Returns (verdict, reason, decided_by, eval_us).
    pub fn evaluate(&self, facts: &ResolvedFacts) -> (Verdict, String, String, f64) {
        use cedar_policy::{Authorizer, Context, Decision, EntityUid, Request};

        let principal: EntityUid = format!(
            "Principal::\"{}\"",
            facts
                .principal_id
                .clone()
                .unwrap_or_else(|| "anonymous".into())
        )
        .parse()
        .expect("well-formed principal uid");
        let action: EntityUid = format!("Action::\"{}\"", facts.action_name)
            .parse()
            .expect("well-formed action uid");
        let resource: EntityUid = format!(
            "Resource::\"{}\"",
            facts
                .resource_id
                .clone()
                .unwrap_or_else(|| "unknown".into())
        )
        .parse()
        .expect("well-formed resource uid");

        // The same facts EdgeGuard receives, presented as Cedar context.
        let ctx_json: serde_json::Value = serde_json::Value::Object(
            facts
                .facts
                .iter()
                .map(|f| (f.name.clone(), f.value.clone()))
                .collect(),
        );
        let context = Context::from_json_value(ctx_json, None).unwrap_or_else(|_| Context::empty());

        let req = Request::new(principal, action, resource, context, None)
            .expect("request builds without a schema");

        let t0 = Instant::now();
        let ans = Authorizer::new().is_authorized(&req, &self.policies, &self.entities);
        let eval_us = t0.elapsed().as_nanos() as f64 / 1000.0;

        let reasons: Vec<String> = ans.diagnostics().reason().map(|p| p.to_string()).collect();
        let v = match ans.decision() {
            Decision::Allow => Verdict::Pass,
            Decision::Deny => Verdict::Block,
        };
        (
            v,
            format!("cedar: {:?} via {:?}", ans.decision(), reasons),
            "Cedar".to_string(),
            eval_us,
        )
    }
}

// ---------------------------------------------------------------------------
// Handwritten direct-conditional comparator (spec §3)
// ---------------------------------------------------------------------------

/// A minimal but competent hand-written rule set over the same facts - the
/// "just write an if-statement" baseline the differentiation claim has to beat.
pub struct HandwrittenRules {
    pub limit: i64,
    /// Counted honestly for the burden metric: the body of `evaluate` below.
    pub integration_loc: u32,
}

impl Default for HandwrittenRules {
    fn default() -> Self {
        HandwrittenRules {
            limit: 1000,
            integration_loc: 18,
        }
    }
}

impl HandwrittenRules {
    pub fn evaluate(&self, facts: &ResolvedFacts) -> (Verdict, String, String, f64) {
        let t0 = Instant::now();
        let v = if facts.action_name == "execute_payment" {
            match facts.get("amount").map(|f| &f.value) {
                Some(serde_json::Value::Number(n)) => {
                    let over = n.as_i64().map(|i| i > self.limit).unwrap_or(true);
                    if over {
                        Verdict::Block
                    } else {
                        Verdict::Pass
                    }
                }
                // Missing or wrong-typed: an if-statement baseline that fails
                // closed is the fair version of this comparator.
                _ => Verdict::Block,
            }
        } else {
            Verdict::Pass
        };
        let eval_us = t0.elapsed().as_nanos() as f64 / 1000.0;
        (v, "handwritten".into(), "Handwritten".into(), eval_us)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(action: &str, amount: i64) -> ResolvedFacts {
        ResolvedFacts {
            action_name: action.into(),
            principal_id: Some("alice".into()),
            resource_id: Some("acct-1".into()),
            facts: vec![HostFact {
                name: "amount".into(),
                value: serde_json::json!(amount),
                provenance: "host_authoritative".into(),
                ai_specific: false,
            }],
        }
    }

    const POLICY: &str = r#"
permit(principal, action, resource)
when { context has amount && context.amount <= 1000 };
"#;

    #[test]
    fn cedar_builds_and_answers_allow_and_deny_on_the_same_facts() {
        let eng = CedarEngine::new(POLICY).expect("policy parses");
        let (allow, r1, by, _) = eng.evaluate(&facts("execute_payment", 10));
        let (deny, _, _, _) = eng.evaluate(&facts("execute_payment", 5000));
        assert_eq!(allow, Verdict::Pass, "{r1}");
        assert_eq!(deny, Verdict::Block);
        assert_eq!(by, "Cedar");
        assert!(eng.policy_loc > 0);
    }

    #[test]
    fn cedar_has_no_third_value_for_insufficient_facts() {
        // The fact the rule needs is simply absent. Cedar cannot say "I do not
        // know"; its default is Deny. Recorded as an expressivity limit, not
        // as a Cedar bug.
        let eng = CedarEngine::new(POLICY).unwrap();
        let mut f = facts("execute_payment", 0);
        f.facts.clear();
        let (v, _, _, _) = eng.evaluate(&f);
        assert!(
            v == Verdict::Block,
            "Cedar collapses 'unknown' into its default decision"
        );
        assert_ne!(v, Verdict::Escalate, "Cedar cannot produce an abstention");
    }

    #[test]
    fn the_handwritten_baseline_fails_closed_on_a_missing_fact() {
        let hw = HandwrittenRules::default();
        let mut f = facts("execute_payment", 10);
        f.facts.clear();
        assert_eq!(hw.evaluate(&f).0, Verdict::Block);
    }

    #[test]
    fn the_handwritten_baseline_answers_the_covered_case() {
        let hw = HandwrittenRules::default();
        assert_eq!(hw.evaluate(&facts("execute_payment", 10)).0, Verdict::Pass);
        assert_eq!(
            hw.evaluate(&facts("execute_payment", 5000)).0,
            Verdict::Block
        );
    }

    #[test]
    fn the_handwritten_baseline_silently_allows_an_uncovered_action() {
        // The thing the "just write an if-statement" baseline actually does on
        // an action nobody wrote a branch for. Pre-registered as a comparator
        // property, not discovered after the fact.
        let hw = HandwrittenRules::default();
        assert_eq!(
            hw.evaluate(&facts("delete_all_backups", 0)).0,
            Verdict::Pass
        );
    }

    #[test]
    fn every_comparator_stage_counts_as_local_resolution_but_no_tier2_stage_does() {
        for s in [
            "Cedar",
            "Handwritten",
            "AgtPolicy",
            "JataayuEffectBoundary",
            "ActionEvaluator",
        ] {
            assert!(is_locally_resolved(s), "{s}");
        }
        for s in [
            "Tier2Unavailable",
            "Tier2Failed { error: \"x\" }",
            "Tier2ShedByBreaker",
            "Tier2Deferred",
            "Tier2Model { model: \"m\" }",
            "Tier1NoSignal",
        ] {
            assert!(!is_locally_resolved(s), "{s}");
        }
    }

    #[test]
    fn the_adapter_does_not_coerce_an_integer_into_a_float() {
        use edgeguard::event::Value;
        assert_eq!(json_to_value(&serde_json::json!(10)), Value::Integer(10));
        assert_eq!(json_to_value(&serde_json::json!(10.5)), Value::Float(10.5));
    }
}
