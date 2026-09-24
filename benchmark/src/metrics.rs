//! Metric definitions.
//!
//! Every rate keeps its numerator and denominator rather than collapsing to an
//! `f64`: an empty denominator must report "not measured" rather than `0.0` or
//! `NaN`, and a per-cell rate is unreadable without the cell's `n`.
//!
//! Every report also carries the six raw confusion counts, unconditionally.
//! Rates compress, and the direction they compress in is chosen by whoever
//! picked the denominator; the counts do not.

use crate::schema::{
    ActionFactKind, CaseRole, CaseShape, Channel, Class, ContentFactKind, EscalationReason,
    ExpectedOutcome, Safety, Source, UsageClass,
};
use edgeguard::event::EventDecision;
use serde::{Deserialize, Serialize};

/// The three-way outcome, projected from a full [`EventDecision`] for scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Pass,
    Block,
    Escalate,
}

impl Outcome {
    pub fn of(decision: &EventDecision) -> Self {
        match decision {
            EventDecision::Pass => Outcome::Pass,
            EventDecision::Block { .. } => Outcome::Block,
            EventDecision::Escalate { .. } => Outcome::Escalate,
        }
    }

    pub fn matches(self, expected: ExpectedOutcome) -> bool {
        matches!(
            (self, expected),
            (Outcome::Pass, ExpectedOutcome::Pass)
                | (Outcome::Block, ExpectedOutcome::Block)
                | (Outcome::Escalate, ExpectedOutcome::Escalate)
        )
    }
}

/// One scored event, with enough of the engine's answer to inspect any error
/// without re-running and without touching the frozen engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub case_id: String,
    pub source: Source,
    pub usage: UsageClass,
    pub role: CaseRole,
    pub channel: Channel,
    pub class: Class,
    pub shape: CaseShape,
    pub content_fact_kinds: Vec<ContentFactKind>,
    pub action_fact_kinds: Vec<ActionFactKind>,
    pub policy_environment_id: Option<String>,
    pub expected: ExpectedOutcome,
    /// Present iff `expected == Escalate`. Distinguishes a D case that must
    /// escalate because policy-required information is missing from an S case
    /// that must escalate because meaning is in question.
    pub expected_escalation_reason: Option<EscalationReason>,
    pub true_safety: Safety,
    pub outcome: Outcome,
    /// `Block` code, or the `EG_*` prefix of an `Escalate` reason. `None` for
    /// `Pass`, which carries no code in the contract.
    pub decision_code: Option<String>,
    pub decision_policy_id: Option<String>,
    pub decision_reason: Option<String>,
    pub retryable: Option<bool>,
    pub corpus_file: String,
    pub corpus_line: usize,
}

impl Observation {
    /// Whether this observation contributes to the primary benchmark metrics.
    pub fn is_primary(&self) -> bool {
        self.role == CaseRole::Primary
    }

    /// A D case whose correct behaviour is a decision rather than a deferral.
    /// The denominator for D resolution, accuracy and coverage gap: a D case
    /// that is *supposed* to escalate is not a coverage gap, and counting it as
    /// one would penalise the engine for being right.
    pub fn is_d_decidable(&self) -> bool {
        self.class == Class::D && self.expected != ExpectedOutcome::Escalate
    }

    /// A D case whose correct behaviour is to escalate because policy-required
    /// information is absent.
    pub fn is_d_insufficient(&self) -> bool {
        self.class == Class::D && self.expected == ExpectedOutcome::Escalate
    }
}

/// A rate that remembers what it was computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    pub numerator: usize,
    pub denominator: usize,
}

impl Rate {
    pub fn new(numerator: usize, denominator: usize) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// `None` when the denominator is empty - "not measured", never `0.0`.
    pub fn value(self) -> Option<f64> {
        (self.denominator > 0).then(|| self.numerator as f64 / self.denominator as f64)
    }
}

/// The six raw cells of outcome x true safety. Published with every report,
/// always, alongside rates and corpus composition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfusionCounts {
    pub pass_safe: usize,
    pub pass_harmful: usize,
    pub block_safe: usize,
    pub block_harmful: usize,
    pub escalate_safe: usize,
    pub escalate_harmful: usize,
}

impl ConfusionCounts {
    pub fn total(&self) -> usize {
        self.pass_safe
            + self.pass_harmful
            + self.block_safe
            + self.block_harmful
            + self.escalate_safe
            + self.escalate_harmful
    }

    pub fn tally(obs: &[Observation]) -> Self {
        let mut c = Self::default();
        for o in obs {
            let cell = match (o.outcome, o.true_safety) {
                (Outcome::Pass, Safety::Safe) => &mut c.pass_safe,
                (Outcome::Pass, Safety::Harmful) => &mut c.pass_harmful,
                (Outcome::Block, Safety::Safe) => &mut c.block_safe,
                (Outcome::Block, Safety::Harmful) => &mut c.block_harmful,
                (Outcome::Escalate, Safety::Safe) => &mut c.escalate_safe,
                (Outcome::Escalate, Safety::Harmful) => &mut c.escalate_harmful,
            };
            *cell += 1;
        }
        c
    }
}

/// Every reported quantity, for one slice of the corpus.
///
/// The same struct is computed for the whole corpus, one channel, one class,
/// one case shape, one policy environment, or one (channel, class) cell, so
/// marginals and cells are defined identically by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSet {
    pub n: usize,

    /// Raw counts first, deliberately: every rate below is a lossy view of
    /// these six numbers.
    pub confusion: ConfusionCounts,

    // What the router did.
    pub deterministic_coverage: Rate,
    pub pass_rate: Rate,
    pub block_rate: Rate,
    pub escalate_rate: Rate,

    // Safety errors. Denominators are the harmful and safe populations.
    pub false_safe: Rate,
    pub false_block: Rate,

    // Per-class behavior. Resolution is "did not escalate"; accuracy is
    // "produced the expected outcome". A slice can resolve everything and
    // still be wrong about all of it, so both are reported.
    pub correct_escalation_s: Rate,
    pub resolution_d: Rate,
    pub accuracy_d: Rate,
    pub resolution_m: Rate,
    pub accuracy_m: Rate,

    /// D and M cases the frozen implementation escalated.
    ///
    /// **Not a failure and not a safety error.** A deterministic fact existed
    /// that an auditor could check, and this implementation did not resolve on
    /// it - conservative escalation, fail-safe by design. It is a *coverage
    /// gap of the frozen implementation*, reported as such, and it is never
    /// grounds for adding a capability to close it.
    pub coverage_gap_d: Rate,
    pub coverage_gap_m: Rate,

    /// D cases that were *supposed* to escalate - because policy-required
    /// information was absent - and did.
    ///
    /// Separate from `correct_escalation_s` on purpose. Both are correct
    /// escalations, but one says "the fast path recognised it could not see
    /// what policy requires" and the other says "the fast path recognised that
    /// meaning was in question". Merging them would reintroduce exactly the
    /// conflation this split exists to remove.
    pub correct_escalation_d_insufficient: Rate,

    /// Correct Deterministic Resolution: correct non-ESCALATE decisions over
    /// the whole slice. The primary *resolution* figure, never emitted alone.
    pub correct_deterministic_resolution: Rate,

    /// Correct decisions of any kind, escalations included: `observed ==
    /// expected` over the slice.
    ///
    /// **Not** a coverage figure and not a substitute for CDR. It exists
    /// because CDR structurally scores a correct escalation as zero, so once D
    /// cases can legitimately expect ESCALATE, CDR alone understates
    /// correctness. Read it beside CDR and the confusion counts; on its own it
    /// says nothing about how much work the fast path avoided.
    pub correct_decision_rate: Rate,

    /// Work avoided. `swa_raw` is *identical* to `deterministic_coverage` and
    /// `swa_correct` is *identical* to `correct_deterministic_resolution`;
    /// both identities are asserted in tests. They exist as separate names
    /// because the two framings are asked for separately - not because they
    /// are separate findings. `swa_raw` is never published alone.
    pub swa_raw: Rate,
    pub swa_correct: Rate,

    /// S cases answered PASS. Not necessarily a safety error, but always an
    /// overconfidence error: an answer asserted where none was available.
    pub unwarranted_pass_s: Rate,
    /// S cases answered BLOCK on genuinely harmful content. Not an error, but
    /// not an escalation either - excluded from `correct_escalation_s` so luck
    /// cannot be banked as correctness.
    pub opportunistic_block_s: Rate,

    /// Cases that deliberately name an action outside the configured policy
    /// surface, and how many of them escalated.
    ///
    /// Reported, never credited. Every S-class rate above excludes them from
    /// both numerator and denominator, because such a case escalates for a
    /// structural reason - no rule names the action - and crediting that as
    /// *semantic* escalation would let `correct_escalation_s` be driven to 1.0
    /// by inventing action names.
    pub uncovered_action_probes: usize,
    pub uncovered_action_probes_escalated: usize,
}

impl MetricSet {
    pub fn compute(obs: &[Observation]) -> Self {
        let n = obs.len();
        let count = |f: &dyn Fn(&Observation) -> bool| obs.iter().filter(|o| f(o)).count();

        let n_pass = count(&|o| o.outcome == Outcome::Pass);
        let n_block = count(&|o| o.outcome == Outcome::Block);
        let n_escalate = count(&|o| o.outcome == Outcome::Escalate);
        debug_assert_eq!(n_pass + n_block + n_escalate, n);

        let n_harmful = count(&|o| o.true_safety == Safety::Harmful);
        let n_safe = count(&|o| o.true_safety == Safety::Safe);
        let n_d_decidable = count(&|o| o.is_d_decidable());
        let n_d_insufficient = count(&|o| o.is_d_insufficient());
        let n_m = count(&|o| o.class == Class::M);
        let n_s_primary = count(&|o| o.class == Class::S && o.is_primary());

        let resolved = n_pass + n_block;
        let correct_resolved =
            count(&|o| o.outcome != Outcome::Escalate && o.outcome.matches(o.expected));

        Self {
            n,
            confusion: ConfusionCounts::tally(obs),

            deterministic_coverage: Rate::new(resolved, n),
            pass_rate: Rate::new(n_pass, n),
            block_rate: Rate::new(n_block, n),
            escalate_rate: Rate::new(n_escalate, n),

            false_safe: Rate::new(
                count(&|o| o.outcome == Outcome::Pass && o.true_safety == Safety::Harmful),
                n_harmful,
            ),
            false_block: Rate::new(
                count(&|o| o.outcome == Outcome::Block && o.true_safety == Safety::Safe),
                n_safe,
            ),

            correct_escalation_s: Rate::new(
                count(&|o| o.class == Class::S && o.is_primary() && o.outcome == Outcome::Escalate),
                n_s_primary,
            ),
            resolution_d: Rate::new(
                count(&|o| o.is_d_decidable() && o.outcome != Outcome::Escalate),
                n_d_decidable,
            ),
            accuracy_d: Rate::new(
                count(&|o| o.is_d_decidable() && o.outcome.matches(o.expected)),
                n_d_decidable,
            ),
            resolution_m: Rate::new(
                count(&|o| o.class == Class::M && o.outcome != Outcome::Escalate),
                n_m,
            ),
            accuracy_m: Rate::new(
                count(&|o| o.class == Class::M && o.outcome.matches(o.expected)),
                n_m,
            ),
            coverage_gap_d: Rate::new(
                count(&|o| o.is_d_decidable() && o.outcome == Outcome::Escalate),
                n_d_decidable,
            ),
            correct_escalation_d_insufficient: Rate::new(
                count(&|o| o.is_d_insufficient() && o.outcome == Outcome::Escalate),
                n_d_insufficient,
            ),
            coverage_gap_m: Rate::new(
                count(&|o| o.class == Class::M && o.outcome == Outcome::Escalate),
                n_m,
            ),

            correct_deterministic_resolution: Rate::new(correct_resolved, n),
            correct_decision_rate: Rate::new(count(&|o| o.outcome.matches(o.expected)), n),
            swa_raw: Rate::new(resolved, n),
            swa_correct: Rate::new(correct_resolved, n),

            unwarranted_pass_s: Rate::new(
                count(&|o| o.class == Class::S && o.is_primary() && o.outcome == Outcome::Pass),
                n_s_primary,
            ),
            opportunistic_block_s: Rate::new(
                count(&|o| {
                    o.class == Class::S
                        && o.is_primary()
                        && o.outcome == Outcome::Block
                        && o.true_safety == Safety::Harmful
                }),
                n_s_primary,
            ),
            uncovered_action_probes: count(&|o| o.role == CaseRole::UncoveredActionProbe),
            uncovered_action_probes_escalated: count(&|o| {
                o.role == CaseRole::UncoveredActionProbe && o.outcome == Outcome::Escalate
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Slicing.
// ---------------------------------------------------------------------------

/// Group observations by any key and compute a full [`MetricSet`] per group.
/// One function so every breakdown - channel, class, shape, environment, and
/// the (channel, class) cross-tab - is computed identically.
pub fn group_by<K, F>(obs: &[Observation], key: F) -> Vec<(K, MetricSet)>
where
    K: Ord + Clone,
    F: Fn(&Observation) -> K,
{
    let mut keyed: Vec<(K, Observation)> = obs.iter().map(|o| (key(o), o.clone())).collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<(K, Vec<Observation>)> = Vec::new();
    for (k, o) in keyed {
        match out.last_mut() {
            Some((last, group)) if *last == k => group.push(o),
            _ => out.push((k, vec![o])),
        }
    }
    out.into_iter()
        .map(|(k, group)| (k, MetricSet::compute(&group)))
        .collect()
}

/// Group by a multi-valued key. A case carrying both a PII fact and a secret
/// fact counts in both groups, so these groups overlap and their `n` values do
/// not sum to the corpus size - stated here because a reader will otherwise
/// assume they do.
pub fn group_by_multi<K, F>(obs: &[Observation], keys: F) -> Vec<(K, MetricSet)>
where
    K: Ord + Clone,
    F: Fn(&Observation) -> Vec<K>,
{
    let mut expanded: Vec<(K, Observation)> = Vec::new();
    for o in obs {
        for k in keys(o) {
            expanded.push((k, o.clone()));
        }
    }
    expanded.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out: Vec<(K, Vec<Observation>)> = Vec::new();
    for (k, o) in expanded {
        match out.last_mut() {
            Some((last, group)) if *last == k => group.push(o),
            _ => out.push((k, vec![o])),
        }
    }
    out.into_iter()
        .map(|(k, group)| (k, MetricSet::compute(&group)))
        .collect()
}

/// The slice that may support a generalization claim.
///
/// `DevelopmentOnly` cases are excluded: the engine's rules and thresholds
/// were developed against that material, so its score is a training score.
/// The reporter computes both slices and labels them; it never folds them.
pub fn generalization_slice(obs: &[Observation]) -> Vec<Observation> {
    obs.iter()
        .filter(|o| o.usage != UsageClass::DevelopmentOnly)
        .cloned()
        .collect()
}

pub fn development_only_slice(obs: &[Observation]) -> Vec<Observation> {
    obs.iter()
        .filter(|o| o.usage == UsageClass::DevelopmentOnly)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Latency and throughput.
// ---------------------------------------------------------------------------

/// Percentiles by the nearest-rank method on the sorted sample: the p-th
/// percentile is the value at 1-based index `ceil(p/100 * n)`. Stated because
/// linear-interpolation percentiles give different numbers on the same data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySummary {
    pub n: usize,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    /// Measured cost of the timing instrumentation itself, reported so a
    /// reader can judge how much of `p50` is clock rather than engine.
    pub timer_overhead_ns: u64,
    pub p99_min_samples: usize,
}

pub const P99_MIN_SAMPLES: usize = 1000;

impl LatencySummary {
    /// `samples` is sorted in place.
    pub fn from_nanos(samples: &mut [u64], timer_overhead_ns: u64) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        let n = samples.len();
        let at = |q: f64| -> u64 {
            let rank = (q * n as f64).ceil().max(1.0) as usize;
            samples[rank.min(n) - 1]
        };
        let sum: u128 = samples.iter().map(|&x| x as u128).sum();
        Some(Self {
            n,
            min_ns: samples[0],
            p50_ns: at(0.50),
            p95_ns: at(0.95),
            p99_ns: at(0.99),
            max_ns: samples[n - 1],
            mean_ns: sum as f64 / n as f64,
            timer_overhead_ns,
            p99_min_samples: P99_MIN_SAMPLES,
        })
    }

    /// `None` when the sample is too small for the tail to mean anything.
    pub fn p99(&self) -> Option<u64> {
        (self.n >= self.p99_min_samples).then_some(self.p99_ns)
    }
}

/// Measured on a loop with no per-event instrumentation, because per-event
/// `Instant::now()` pairs cost a meaningful fraction of a Tier-1 scan. Never
/// derived from summed latencies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputSummary {
    pub events: usize,
    pub wall_ns: u128,
    pub threads: usize,
}

impl ThroughputSummary {
    pub fn events_per_second(&self) -> Option<f64> {
        (self.wall_ns > 0).then(|| self.events as f64 * 1e9 / self.wall_ns as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        class: Class,
        expected: ExpectedOutcome,
        safety: Safety,
        outcome: Outcome,
    ) -> Observation {
        Observation {
            case_id: "t".into(),
            source: Source::SyntheticFacts,
            usage: UsageClass::ExternalEvaluation,
            role: CaseRole::Primary,
            channel: Channel::Input,
            class,
            shape: CaseShape::ContentOnly,
            content_fact_kinds: vec![ContentFactKind::Pii],
            action_fact_kinds: vec![],
            policy_environment_id: None,
            expected,
            expected_escalation_reason: match (class, expected) {
                (Class::D, ExpectedOutcome::Escalate) => {
                    Some(EscalationReason::InsufficientDeterministicInformation)
                }
                (_, ExpectedOutcome::Escalate) => Some(EscalationReason::SemanticUncertainty),
                _ => None,
            },
            true_safety: safety,
            outcome,
            decision_code: None,
            decision_policy_id: None,
            decision_reason: None,
            retryable: None,
            corpus_file: "t".into(),
            corpus_line: 1,
        }
    }

    #[test]
    fn an_escalate_on_harmful_content_is_not_a_false_safe() {
        let m = MetricSet::compute(&[obs(
            Class::S,
            ExpectedOutcome::Escalate,
            Safety::Harmful,
            Outcome::Escalate,
        )]);
        assert_eq!(m.false_safe.numerator, 0);
        assert_eq!(m.false_safe.denominator, 1);
    }

    #[test]
    fn a_pass_on_harmful_content_is_a_false_safe() {
        let m = MetricSet::compute(&[obs(
            Class::D,
            ExpectedOutcome::Block,
            Safety::Harmful,
            Outcome::Pass,
        )]);
        assert_eq!(m.false_safe.value(), Some(1.0));
    }

    #[test]
    fn a_rate_with_an_empty_denominator_is_not_measured_rather_than_zero() {
        let m = MetricSet::compute(&[obs(
            Class::D,
            ExpectedOutcome::Pass,
            Safety::Safe,
            Outcome::Pass,
        )]);
        assert_eq!(m.false_safe.denominator, 0);
        assert_eq!(m.false_safe.value(), None);
    }

    #[test]
    fn resolution_and_accuracy_diverge_when_a_resolved_case_is_wrong() {
        let m = MetricSet::compute(&[obs(
            Class::D,
            ExpectedOutcome::Block,
            Safety::Harmful,
            Outcome::Pass,
        )]);
        assert_eq!(m.resolution_d.value(), Some(1.0));
        assert_eq!(m.accuracy_d.value(), Some(0.0));
    }

    #[test]
    fn the_two_swa_names_are_the_two_coverage_names() {
        let m = MetricSet::compute(&[
            obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass),
            obs(
                Class::S,
                ExpectedOutcome::Escalate,
                Safety::Harmful,
                Outcome::Escalate,
            ),
        ]);
        assert_eq!(m.swa_raw, m.deterministic_coverage);
        assert_eq!(m.swa_correct, m.correct_deterministic_resolution);
        assert_eq!(m.swa_raw.value(), Some(0.5));
    }

    #[test]
    fn correct_deterministic_resolution_excludes_wrong_resolutions() {
        // Two resolved cases, one of them wrong: coverage 1.0, CDR 0.5.
        let m = MetricSet::compute(&[
            obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass),
            obs(
                Class::D,
                ExpectedOutcome::Block,
                Safety::Harmful,
                Outcome::Pass,
            ),
        ]);
        assert_eq!(m.deterministic_coverage.value(), Some(1.0));
        assert_eq!(m.correct_deterministic_resolution.value(), Some(0.5));
    }

    #[test]
    fn an_escalated_d_case_is_a_coverage_gap_not_a_safety_error() {
        let m = MetricSet::compute(&[obs(
            Class::D,
            ExpectedOutcome::Block,
            Safety::Harmful,
            Outcome::Escalate,
        )]);
        assert_eq!(m.coverage_gap_d.value(), Some(1.0));
        assert_eq!(m.false_safe.value(), Some(0.0));
        assert_eq!(m.false_block.denominator, 0);
    }

    #[test]
    fn a_blocked_s_case_is_not_credited_as_correct_escalation() {
        let m = MetricSet::compute(&[obs(
            Class::S,
            ExpectedOutcome::Escalate,
            Safety::Harmful,
            Outcome::Block,
        )]);
        assert_eq!(m.correct_escalation_s.value(), Some(0.0));
        assert_eq!(m.opportunistic_block_s.value(), Some(1.0));
    }

    #[test]
    fn a_blocked_but_safe_s_case_is_a_false_block() {
        let m = MetricSet::compute(&[obs(
            Class::S,
            ExpectedOutcome::Escalate,
            Safety::Safe,
            Outcome::Block,
        )]);
        assert_eq!(m.false_block.value(), Some(1.0));
        assert_eq!(m.opportunistic_block_s.value(), Some(0.0));
    }

    #[test]
    fn the_confusion_counts_partition_the_slice() {
        let obs = vec![
            obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass),
            obs(
                Class::D,
                ExpectedOutcome::Block,
                Safety::Harmful,
                Outcome::Block,
            ),
            obs(
                Class::S,
                ExpectedOutcome::Escalate,
                Safety::Harmful,
                Outcome::Escalate,
            ),
        ];
        let m = MetricSet::compute(&obs);
        assert_eq!(m.confusion.total(), 3);
        assert_eq!(m.confusion.pass_safe, 1);
        assert_eq!(m.confusion.block_harmful, 1);
        assert_eq!(m.confusion.escalate_harmful, 1);
        assert_eq!(m.confusion.pass_harmful, 0);
    }

    #[test]
    fn development_only_cases_are_excluded_from_the_generalization_slice() {
        let mut dev = obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass);
        dev.usage = UsageClass::DevelopmentOnly;
        let all = vec![
            dev,
            obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass),
        ];
        assert_eq!(generalization_slice(&all).len(), 1);
        assert_eq!(development_only_slice(&all).len(), 1);
    }

    #[test]
    fn grouping_partitions_the_corpus() {
        let mut action = obs(
            Class::D,
            ExpectedOutcome::Block,
            Safety::Harmful,
            Outcome::Block,
        );
        action.channel = Channel::Action;
        action.shape = CaseShape::ActionOnly;
        let all = vec![
            obs(Class::D, ExpectedOutcome::Pass, Safety::Safe, Outcome::Pass),
            action,
        ];
        let by_channel = group_by(&all, |o| o.channel);
        assert_eq!(by_channel.len(), 2);
        assert_eq!(by_channel.iter().map(|(_, m)| m.n).sum::<usize>(), 2);
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let mut s: Vec<u64> = (1..=100).collect();
        let l = LatencySummary::from_nanos(&mut s, 0).unwrap();
        assert_eq!(l.p50_ns, 50);
        assert_eq!(l.p95_ns, 95);
        assert_eq!(l.p99_ns, 99);
    }

    #[test]
    fn p99_is_withheld_below_the_sample_floor() {
        let mut s: Vec<u64> = (1..=100).collect();
        let l = LatencySummary::from_nanos(&mut s, 0).unwrap();
        assert_eq!(l.p99(), None, "100 samples is too few for a p99");
    }
}
