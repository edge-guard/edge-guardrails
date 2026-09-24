//! Baseline routers to compare the frozen engine against.
//!
//! # No fake substitutes
//!
//! Three of the four baselines need something this repository does not ship:
//! a semantic model, or a third-party CPU guard. Where that dependency is
//! absent, the baseline reports [`Availability::Unavailable`] with a reason and
//! is **omitted from the comparison**. It is never approximated by a keyword
//! list standing in for a model, or by a hand-tuned imitation of a competitor.
//! A benchmark that fabricates its own competitors measures nothing, and a
//! plausible-looking stand-in is worse than an empty cell because a reader
//! cannot tell it apart from a measurement.

use crate::policy_env::ActionRuleSpec;
use edgeguard::event::{ActionRule, EventDecision, SecurityEvent};

#[derive(Debug, Clone)]
pub enum Availability {
    Available,
    /// Carries the reason verbatim into the report, so an empty cell always
    /// says why it is empty.
    Unavailable {
        reason: String,
    },
}

/// What one routed event cost, in units the cascade comparison needs.
///
/// Semantic evaluations are counted, not timed, here: their wall cost is
/// measured once per backend and applied in the comparison, so a missing
/// backend cannot silently contribute zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoutingCost {
    pub deterministic_evaluations: usize,
    pub semantic_evaluations: usize,
}

pub struct Routed {
    pub decision: EventDecision,
    pub cost: RoutingCost,
}

pub trait Router {
    fn name(&self) -> &str;

    fn availability(&self) -> Availability;

    /// Only called when [`Router::availability`] is [`Availability::Available`].
    fn route(&self, event: &SecurityEvent) -> Routed;
}

/// A semantic tier. Deliberately left unimplemented in this crate.
///
/// Supplying one is an operator decision: it needs `--features onnx`, an ONNX
/// Runtime shared library, and a model. Until an implementation is injected,
/// every baseline that depends on semantic evaluation reports as unavailable.
pub trait SemanticBackend {
    fn name(&self) -> &str;
    fn evaluate(&self, event: &SecurityEvent) -> EventDecision;
}

/// Baseline 2's deterministic half, and the primary subject of the benchmark:
/// the frozen engine alone, with no semantic tier behind it.
pub struct FrozenEdgeGuard {
    engine: edgeguard::tier::TieredEngine,
    rules: Vec<ActionRule>,
}

impl FrozenEdgeGuard {
    pub fn new(engine: edgeguard::tier::TieredEngine, rules: &[ActionRuleSpec]) -> Self {
        Self {
            engine,
            rules: rules.iter().map(ActionRule::from).collect(),
        }
    }

    /// The single call the latency measurement wraps. Kept separate from
    /// [`Router::route`] so the timed region contains exactly one engine call
    /// and no trait dispatch or cost bookkeeping.
    #[inline]
    pub fn decide(&self, event: &SecurityEvent) -> EventDecision {
        edgeguard::event::evaluate_security_event(&self.engine, event, &self.rules)
    }
}

impl Router for FrozenEdgeGuard {
    fn name(&self) -> &str {
        "frozen_edgeguard"
    }

    fn availability(&self) -> Availability {
        Availability::Available
    }

    fn route(&self, event: &SecurityEvent) -> Routed {
        Routed {
            decision: self.decide(event),
            cost: RoutingCost {
                deterministic_evaluations: 1,
                semantic_evaluations: 0,
            },
        }
    }
}

/// Baseline 1: semantic security on every event.
pub struct SemanticOnEvery<B: SemanticBackend> {
    pub backend: Option<B>,
}

impl<B: SemanticBackend> Router for SemanticOnEvery<B> {
    fn name(&self) -> &str {
        "semantic_on_every_event"
    }

    fn availability(&self) -> Availability {
        match &self.backend {
            Some(_) => Availability::Available,
            None => Availability::Unavailable {
                reason: "no SemanticBackend supplied; requires --features onnx, an ONNX \
                         Runtime shared library via ORT_DYLIB_PATH, and a model"
                    .to_string(),
            },
        }
    }

    fn route(&self, event: &SecurityEvent) -> Routed {
        let backend = self
            .backend
            .as_ref()
            .expect("route called on an unavailable baseline");
        Routed {
            decision: backend.evaluate(event),
            cost: RoutingCost {
                deterministic_evaluations: 0,
                semantic_evaluations: 1,
            },
        }
    }
}

/// Baseline 2: the cascade under test - frozen EdgeGuard, semantic tier
/// consulted only on ESCALATE.
pub struct EdgeGuardThenSemantic<B: SemanticBackend> {
    pub edgeguard: FrozenEdgeGuard,
    pub backend: Option<B>,
}

impl<B: SemanticBackend> Router for EdgeGuardThenSemantic<B> {
    fn name(&self) -> &str {
        "frozen_edgeguard_then_semantic_on_escalate"
    }

    fn availability(&self) -> Availability {
        match &self.backend {
            Some(_) => Availability::Available,
            None => Availability::Unavailable {
                reason: "no SemanticBackend supplied for the ESCALATE leg; the deterministic \
                         half is reported separately as `frozen_edgeguard`"
                    .to_string(),
            },
        }
    }

    fn route(&self, event: &SecurityEvent) -> Routed {
        let first = self.edgeguard.decide(event);
        match first {
            EventDecision::Escalate { .. } => {
                let backend = self
                    .backend
                    .as_ref()
                    .expect("route called on an unavailable baseline");
                Routed {
                    decision: backend.evaluate(event),
                    cost: RoutingCost {
                        deterministic_evaluations: 1,
                        semantic_evaluations: 1,
                    },
                }
            }
            decided => Routed {
                decision: decided,
                cost: RoutingCost {
                    deterministic_evaluations: 1,
                    semantic_evaluations: 0,
                },
            },
        }
    }
}

/// A baseline that is named in the comparison but cannot be measured here.
///
/// Baseline 3 (simple deterministic rules into a semantic tier) and baseline 4
/// (a fast third-party CPU guard) both sit behind dependencies this repository
/// does not ship. Representing them this way is deliberate: the report lists
/// them with the reason they were not run, rather than omitting them silently
/// or filling the row with something written here to look like them.
pub struct UnconfiguredBaseline {
    pub name: &'static str,
    pub reason: &'static str,
}

impl Router for UnconfiguredBaseline {
    fn name(&self) -> &str {
        self.name
    }

    fn availability(&self) -> Availability {
        Availability::Unavailable {
            reason: self.reason.to_string(),
        }
    }

    fn route(&self, _event: &SecurityEvent) -> Routed {
        unreachable!("an unavailable baseline is never routed; the runner checks availability")
    }
}

/// Baseline 3, pending a simple-rules implementation and a semantic backend.
pub fn simple_rules_then_semantic() -> UnconfiguredBaseline {
    UnconfiguredBaseline {
        name: "simple_deterministic_rules_then_semantic",
        reason: "requires both a published simple-rule set (authored separately, so it is not \
                 reverse-engineered from EdgeGuard's behavior) and a SemanticBackend",
    }
}

/// Baseline 4, pending a real third-party guard.
pub fn fast_cpu_guard() -> UnconfiguredBaseline {
    UnconfiguredBaseline {
        name: "fast_cpu_guard",
        reason: "requires a real third-party CPU guard installed locally; no substitute is \
                 implemented, since an imitation would measure this repository, not the product",
    }
}
