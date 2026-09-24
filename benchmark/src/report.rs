//! The reporting contract.
//!
//! # Why this type exists
//!
//! Two demonstrated hazards are reporting hazards, not engine defects, and no
//! amount of documentation removes them:
//!
//! - Aggregate CDR moved from 0.90 to 0.20 across two corpora whose *per-class
//!   behaviour was byte-identical and perfect*. CDR is as much a statement
//!   about corpus composition as about the engine.
//! - Aggregate false-SAFE fell from 0.500 to 0.005 while the number of missed
//!   harmful events stayed at exactly 5, purely by adding correctly-blocked
//!   harmful ACTION events to the denominator.
//!
//! Neither number is wrong. Both are misleading alone. So this module removes
//! the option of quoting them alone: a [`Report`] is built in one call, always
//! carries its composition and its slices, and every rendering path emits the
//! raw numerator/denominator counts beside every rate.
//!
//! Aggregates are **not** deleted, and no weighted "universal" CDR is invented
//! to paper over the mix dependence - a weighting would just hide the choice of
//! mix inside a constant.

use crate::corpus::Composition;
use crate::locks::FreezeAttestation;
use crate::metrics::{group_by, group_by_multi, MetricSet, Observation};
use crate::schema::{ActionFactKind, CaseShape, Channel, Class, ContentFactKind, UsageClass};

/// A complete benchmark result. There is no partial constructor.
///
/// Building one requires a [`FreezeAttestation`], which cannot be obtained
/// without verifying the engine hashes, the classification lock and the
/// policy-environment lock. That is the chokepoint: publishable output is
/// unreachable without verification, rather than relying on a caller
/// remembering to call `verify()`.
pub struct Report {
    pub engine_commit: String,
    pub composition: Composition,

    /// Present, never sufficient. Every renderer in this module emits it only
    /// alongside `by_class`, `by_channel` and the composition.
    pub aggregate: MetricSet,

    pub by_class: Vec<(Class, MetricSet)>,
    pub by_channel: Vec<(Channel, MetricSet)>,
    pub by_shape: Vec<(CaseShape, MetricSet)>,
    pub by_policy_environment: Vec<(String, MetricSet)>,
    /// Overlapping groups: a case carrying two fact kinds appears twice, so
    /// these `n` do not sum to the corpus size.
    pub by_content_fact_kind: Vec<(ContentFactKind, MetricSet)>,
    pub by_action_fact_kind: Vec<(ActionFactKind, MetricSet)>,
    pub channel_class_cross_tab: Vec<((Channel, Class), MetricSet)>,

    /// Computed separately and never folded into the aggregate: the engine's
    /// rules and thresholds were developed against this material, so its score
    /// is a training score.
    pub development_only: MetricSet,
    pub generalization: MetricSet,
}

impl Report {
    pub fn build(
        attestation: &FreezeAttestation,
        composition: Composition,
        observations: &[Observation],
    ) -> Self {
        Self {
            engine_commit: attestation.engine_commit().to_string(),
            composition,
            aggregate: MetricSet::compute(observations),
            by_class: group_by(observations, |o| o.class),
            by_channel: group_by(observations, |o| o.channel),
            by_shape: group_by(observations, |o| o.shape),
            by_policy_environment: group_by(observations, |o| {
                o.policy_environment_id
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string())
            }),
            by_content_fact_kind: group_by_multi(observations, |o| o.content_fact_kinds.clone()),
            by_action_fact_kind: group_by_multi(observations, |o| o.action_fact_kinds.clone()),
            channel_class_cross_tab: group_by(observations, |o| (o.channel, o.class)),
            development_only: MetricSet::compute(&crate::metrics::development_only_slice(
                observations,
            )),
            generalization: MetricSet::compute(&crate::metrics::generalization_slice(observations)),
        }
    }

    /// The mandatory framing for Correct Deterministic Resolution.
    ///
    /// CDR is never emitted by this crate without the corpus composition that
    /// produced it and without the disclaimer below, because the same engine
    /// behaviour yields wildly different CDRs on different mixes.
    pub fn cdr_statement(&self) -> String {
        let cdr = &self.aggregate.correct_deterministic_resolution;
        let mut out = String::new();
        out.push_str(&format!(
            "Correct Deterministic Resolution = {}/{} ({})\n",
            cdr.numerator,
            cdr.denominator,
            match cdr.value() {
                Some(v) => format!("{v:.4}"),
                None => "not measured".to_string(),
            }
        ));
        out.push_str(
            "  corpus composition (CDR is a function of this mix as much as of the engine):\n",
        );
        out.push_str(&format!(
            "    by class:   {:?}\n",
            self.composition.by_class
        ));
        out.push_str(&format!(
            "    by channel: {:?}\n",
            self.composition.by_channel
        ));
        out.push_str(&format!(
            "    by shape:   {:?}\n",
            self.composition.by_shape
        ));
        out.push_str(
            "  CDR is corpus-mix-dependent and is NOT an estimate of how much production\n\
             \x20 traffic would bypass a semantic tier. Two corpora with identical per-class\n\
             \x20 engine behaviour can differ by tens of points. Compare CDR only within one\n\
             \x20 corpus, and read it beside the per-class slices below.\n",
        );
        out.push_str(&format!(
            "  correct escalations, by why escalation was right:\n    \
             D / information policy requires was absent: {}/{}\n    \
             S / meaning was in question:               {}/{}\n",
            self.aggregate.correct_escalation_d_insufficient.numerator,
            self.aggregate.correct_escalation_d_insufficient.denominator,
            self.aggregate.correct_escalation_s.numerator,
            self.aggregate.correct_escalation_s.denominator
        ));
        for (class, m) in &self.by_class {
            out.push_str(&format!(
                "    class {class:?}: n={} resolution={:?} accuracy={:?}\n",
                m.n,
                match class {
                    Class::D => m.resolution_d.value(),
                    Class::M => m.resolution_m.value(),
                    Class::S => m.correct_escalation_s.value(),
                },
                match class {
                    Class::D => m.accuracy_d.value(),
                    Class::M => m.accuracy_m.value(),
                    Class::S => m.correct_escalation_s.value(),
                }
            ));
        }
        out
    }

    /// The mandatory framing for false SAFE and false BLOCK.
    ///
    /// Absolute counts first, because the rate's denominator is a corpus
    /// choice: adding correctly-handled harmful events shrinks the rate without
    /// changing a single missed event. Per-channel figures follow, because a
    /// content miss diluted by action volume is invisible in the aggregate.
    pub fn safety_statement(&self) -> String {
        let c = &self.aggregate.confusion;
        let mut out =
            String::from("Safety (absolute counts first - rates have chosen denominators)\n");
        out.push_str(&format!(
            "  confusion: pass_safe={} pass_harmful={} block_safe={} block_harmful={} \
             escalate_safe={} escalate_harmful={}\n",
            c.pass_safe,
            c.pass_harmful,
            c.block_safe,
            c.block_harmful,
            c.escalate_safe,
            c.escalate_harmful
        ));
        out.push_str(&format!(
            "  MISSED HARMFUL EVENTS (false SAFE, absolute) = {}\n",
            self.aggregate.false_safe.numerator
        ));
        out.push_str(&format!(
            "  aggregate false_safe  = {}/{}   aggregate false_block = {}/{}\n",
            self.aggregate.false_safe.numerator,
            self.aggregate.false_safe.denominator,
            self.aggregate.false_block.numerator,
            self.aggregate.false_block.denominator
        ));
        out.push_str("  per channel (an aggregate rate can fall while a channel is unchanged):\n");
        for (channel, m) in &self.by_channel {
            out.push_str(&format!(
                "    {channel:?}: n={} false_safe={}/{} false_block={}/{}\n",
                m.n,
                m.false_safe.numerator,
                m.false_safe.denominator,
                m.false_block.numerator,
                m.false_block.denominator
            ));
        }
        out
    }

    /// Probe cases, reported under their own heading and credited nowhere.
    pub fn probe_statement(&self) -> String {
        format!(
            "Uncovered-action probes: {} case(s), {} escalated.\n  \
             Excluded from every S-class metric. These escalate because no rule names the \
             action, which is a structural fact about the configured policy, not evidence \
             that the fast path recognised semantic difficulty.\n",
            self.aggregate.uncovered_action_probes,
            self.aggregate.uncovered_action_probes_escalated
        )
    }

    /// The full report. This is the only rendering intended for publication,
    /// and it is not decomposable into a single headline number.
    pub fn render(&self) -> String {
        let mut out = format!(
            "EdgeGuard Routing Benchmark v0.1\nengine: {}\ncases: {}\n\n",
            self.engine_commit, self.composition.total
        );
        out.push_str(&self.cdr_statement());
        out.push('\n');
        out.push_str(&self.safety_statement());
        out.push('\n');
        out.push_str(&self.probe_statement());
        out.push('\n');
        out.push_str("Slices (numerator/denominator, never bare rates)\n");
        for (label, groups) in [
            ("by shape", &self.by_shape as &dyn RenderGroups),
            ("by channel x class", &self.channel_class_cross_tab),
            ("by policy environment", &self.by_policy_environment),
            (
                "by content fact kind (OVERLAPPING groups)",
                &self.by_content_fact_kind,
            ),
            (
                "by action fact kind (OVERLAPPING groups)",
                &self.by_action_fact_kind,
            ),
        ] {
            out.push_str(&format!("  {label}:\n"));
            out.push_str(&groups.render());
        }
        out.push_str(&format!(
            "\nUsage split (never folded):\n  generalization slice: n={}\n  \
             DevelopmentOnly slice: n={} (training score - excluded from generalization claims)\n",
            self.generalization.n, self.development_only.n
        ));
        out
    }
}

/// Renders any grouped slice with explicit counts.
trait RenderGroups {
    fn render(&self) -> String;
}

impl<K: std::fmt::Debug> RenderGroups for Vec<(K, MetricSet)> {
    fn render(&self) -> String {
        let mut out = String::new();
        for (key, m) in self {
            out.push_str(&format!(
                "    {key:?}: n={} coverage={}/{} CDR={}/{} false_safe={}/{} false_block={}/{}\n",
                m.n,
                m.deterministic_coverage.numerator,
                m.deterministic_coverage.denominator,
                m.correct_deterministic_resolution.numerator,
                m.correct_deterministic_resolution.denominator,
                m.false_safe.numerator,
                m.false_safe.denominator,
                m.false_block.numerator,
                m.false_block.denominator,
            ));
        }
        out
    }
}

/// What the frozen policy environments actually exercise.
///
/// Published with every ACTION result. The benchmark's ACTION coverage is
/// narrow, and stating the narrowness precisely is the alternative to widening
/// it - which would mean expanding policy capability to improve a score.
pub const POLICY_ENVIRONMENT_SCOPE: &str = "\
Frozen policy environments exercise ONLY:
  comparators:  Eq, Gt, Ne            (Ge, Lt, Le unexercised)
  value types:  Bool, Integer, String (Null, Float, List, Map unexercised)
  provenance:   HostAuthoritative required by every rule
                (no rule requires ModelProposed or UserProvided)
  structure:    single-field scalar constraints only
                no nested, compound, or multi-field policy logic exists -
                ActionRule is (one action, one field, one comparator, one threshold)
Consequences a reader must not overlook:
  - This benchmark does NOT validate arbitrary enterprise authorization logic.
  - The Float ordering path and the Eq/Ne discriminant gate over List/Map are
    unreachable from any ACTION case.
  - ActionFactKind::TypeMismatch is exercised only against Bool/Integer/String.
Policy capability was deliberately NOT expanded to widen this surface.";

/// Usage slices a reader must keep apart.
pub fn usage_caveat(usage: UsageClass) -> &'static str {
    match usage {
        UsageClass::ExternalEvaluation => "may support generalization claims",
        UsageClass::DevelopmentOnly => {
            "training score - the engine was developed against this material"
        }
        UsageClass::Holdout => "one-shot; burned for tuning once observed",
    }
}
