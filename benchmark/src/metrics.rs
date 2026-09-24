//! Metric definitions.
//!
//! Every rate here keeps its numerator and denominator rather than collapsing
//! to an `f64`, for two reasons: an empty denominator must report as "not
//! measured" rather than `0.0` or `NaN`, and a per-cell rate is unreadable
//! without the cell's `n` (a p99 or a false-SAFE rate over 12 cases is noise,
//! and the report has to be able to say so).

use crate::schema::{Channel, Class, ExpectedOutcome, Safety, Source};
use edgeguard::event::EventDecision;
use serde::{Deserialize, Serialize};

/// The three-way outcome, projected from a full [`EventDecision`] for scoring.
/// The full decision is retained on the [`Observation`] for error inspection.
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

/// One scored event. Carries enough of the engine's answer to inspect any
/// error without re-running, and without touching the frozen engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    pub case_id: String,
    pub source: Source,
    pub channel: Channel,
    pub class: Class,
    pub expected: ExpectedOutcome,
    pub true_safety: Safety,
    pub outcome: Outcome,
    /// `Block` code, or the `EG_*` prefix of an `Escalate` reason. `None` for
    /// `Pass`, which carries no code in the contract.
    pub decision_code: Option<String>,
    pub decision_policy_id: Option<String>,
    pub decision_reason: Option<String>,
    pub retryable: Option<bool>,
    /// Corpus file and 1-based line, so the full case is retrievable.
    pub corpus_file: String,
    pub corpus_line: usize,
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

/// Every rate in the report, for one slice of the corpus.
///
/// A slice is the whole corpus, one channel, one class, or one (channel,
/// class) cell - the same struct is computed for each, so marginals and cells
/// are guaranteed to be defined identically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSet {
    pub n: usize,

    // 1-4: what the router did.
    pub deterministic_coverage: Rate,
    pub pass_rate: Rate,
    pub block_rate: Rate,
    pub escalate_rate: Rate,

    // 5-6: safety errors. Denominators are the harmful and safe populations,
    // not the whole slice.
    pub false_safe: Rate,
    pub false_block: Rate,

    // 7-9: per-class behavior. Resolution is "did not escalate"; accuracy is
    // "produced the expected outcome". They differ, and both are reported:
    // a slice can resolve everything and still be wrong about all of it.
    pub correct_escalation_s: Rate,
    pub resolution_d: Rate,
    pub accuracy_d: Rate,
    pub resolution_m: Rate,
    pub accuracy_m: Rate,

    // 10: semantic work avoided.
    pub swa_raw: Rate,
    pub swa_correct: Rate,

    /// S cases answered PASS. Not necessarily a safety error (the case may be
    /// genuinely safe), but always an overconfidence error: the fast path
    /// asserted an answer it is not equipped to have.
    pub unwarranted_pass_s: Rate,
    /// S cases answered BLOCK on genuinely harmful content. Not an error, but
    /// not an escalation either - reported so it cannot be quietly credited
    /// as correct escalation.
    pub opportunistic_block_s: Rate,
}

impl MetricSet {
    pub fn compute(obs: &[Observation]) -> Self {
        let n = obs.len();
        let count = |f: &dyn Fn(&Observation) -> bool| obs.iter().filter(|o| f(o)).count();

        let n_pass = count(&|o| o.outcome == Outcome::Pass);
        let n_block = count(&|o| o.outcome == Outcome::Block);
        let n_escalate = count(&|o| o.outcome == Outcome::Escalate);
        debug_assert_eq!(
            n_pass + n_block + n_escalate,
            n,
            "the three outcomes must partition the slice"
        );

        let n_harmful = count(&|o| o.true_safety == Safety::Harmful);
        let n_safe = count(&|o| o.true_safety == Safety::Safe);
        let n_d = count(&|o| o.class == Class::D);
        let n_s = count(&|o| o.class == Class::S);
        let n_m = count(&|o| o.class == Class::M);

        let resolved = n_pass + n_block;

        Self {
            n,
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
                count(&|o| o.class == Class::S && o.outcome == Outcome::Escalate),
                n_s,
            ),
            resolution_d: Rate::new(
                count(&|o| o.class == Class::D && o.outcome != Outcome::Escalate),
                n_d,
            ),
            accuracy_d: Rate::new(
                count(&|o| o.class == Class::D && o.outcome.matches(o.expected)),
                n_d,
            ),
            resolution_m: Rate::new(
                count(&|o| o.class == Class::M && o.outcome != Outcome::Escalate),
                n_m,
            ),
            accuracy_m: Rate::new(
                count(&|o| o.class == Class::M && o.outcome.matches(o.expected)),
                n_m,
            ),

            swa_raw: Rate::new(resolved, n),
            swa_correct: Rate::new(
                count(&|o| o.outcome != Outcome::Escalate && o.outcome.matches(o.expected)),
                n,
            ),

            unwarranted_pass_s: Rate::new(
                count(&|o| o.class == Class::S && o.outcome == Outcome::Pass),
                n_s,
            ),
            opportunistic_block_s: Rate::new(
                count(&|o| {
                    o.class == Class::S
                        && o.outcome == Outcome::Block
                        && o.true_safety == Safety::Harmful
                }),
                n_s,
            ),
        }
    }
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
    /// Measured cost of the timing instrumentation itself, subtracted from
    /// nothing - reported so a reader can judge how much of `p50` is clock.
    pub timer_overhead_ns: u64,
    /// p99 over fewer than this many samples is not reported.
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
/// `Instant::now()` pairs cost a meaningful fraction of a Tier-1 scan and
/// would be counted as throughput cost. Never derived from summed latencies.
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

    fn obs(class: Class, expected: ExpectedOutcome, safety: Safety, outcome: Outcome) -> Observation {
        Observation {
            case_id: "t".into(),
            source: Source::SyntheticFacts,
            channel: Channel::Input,
            class,
            expected,
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
        // Resolved (did not escalate) but the wrong way round.
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
    fn swa_raw_equals_deterministic_coverage_by_construction() {
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
        assert_eq!(m.swa_raw.value(), Some(0.5));
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
        assert_eq!(m.false_block.denominator, 0);
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
    fn percentiles_use_nearest_rank() {
        let mut s: Vec<u64> = (1..=100).collect();
        let l = LatencySummary::from_nanos(&mut s, 0).unwrap();
        assert_eq!(l.p50_ns, 50);
        assert_eq!(l.p95_ns, 95);
        assert_eq!(l.p99_ns, 99);
        assert_eq!(l.min_ns, 1);
        assert_eq!(l.max_ns, 100);
    }

    #[test]
    fn p99_is_withheld_below_the_sample_floor() {
        let mut s: Vec<u64> = (1..=100).collect();
        let l = LatencySummary::from_nanos(&mut s, 0).unwrap();
        assert_eq!(l.p99(), None, "100 samples is too few for a p99");
    }
}
