//! The slow-path worker: where deferred prompts actually get scored.
//!
//! # What it does
//!
//! Drains [`crate::deferred::DeferredQueue`], scores each parked prompt with a
//! [`crate::semantic::SemanticScorer`], writes the **classification** to the
//! audit outbox, and deletes the row. It is the consumer half of the
//! Fast-Path/Slow-Path split, and the only component that needs the `onnx`
//! feature - the deterministic tier never links a model.
//!
//! # The privacy boundary runs straight through this module
//!
//! It is the one place that holds prompt text and an outbox handle at the same
//! time, which makes it the only place the two stores could be confused. So:
//!
//! * the prompt goes to the scorer and nowhere else;
//! * what reaches [`crate::audit_queue::AuditQueue`] is a category -
//!   `SEMANTIC_93`, the same shape `tier::audit_label` already produces - never
//!   the text, never the matched span, never a fragment;
//! * the row is DELETED on completion, not marked done, so a scored prompt
//!   stops existing.
//!
//! A test asserts the audit label for a payload containing a distinctive
//! string does not contain that string. That is a cheap check for the failure
//! that would matter most.
//!
//! # Failure handling
//!
//! Scoring can fail for two very different reasons and they are not treated
//! alike:
//!
//! * **absent** ([`crate::semantic::ScorerError::is_absent`]) - no model is
//!   configured, or the backend was compiled out. Retrying is pointless and
//!   the work will never succeed, so the item is completed with an
//!   `unavailable` category rather than cycled forever;
//! * **failed** - a real error. The item is released for another attempt, up
//!   to `max_attempts`, after which it is dropped with a `poison` category.
//!   Without that ceiling one malformed prompt would be redelivered until its
//!   TTL expired, burning the whole worker on it.
//!
//! Either way an audit record is written. A deferred prompt that silently
//! disappears is worse than one that is scored wrong: the first is invisible,
//! the second is measurable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::audit_queue::AuditQueue;
use crate::deferred::{DeferredError, DeferredItem, DeferredWorker};
use crate::semantic::SemanticScorer;

/// What the worker concluded about one parked prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Scored, and the model considered it benign.
    Benign,
    /// Scored, and the model's confidence reached `flag_threshold`.
    Suspicious,
    /// Scored, and the model's confidence reached `block_threshold`.
    Malicious,
    /// No model available. Terminal - retrying cannot help.
    Unavailable,
    /// Scoring failed; the item was released for another attempt.
    Retried,
    /// Scoring failed `max_attempts` times. Dropped.
    Poison,
}

impl Outcome {
    /// The category written to the audit trail.
    ///
    /// A label, never a value - this string leaves the device.
    fn label(self, malicious: f32) -> String {
        match self {
            Outcome::Benign | Outcome::Suspicious | Outcome::Malicious => {
                format!("SEMANTIC_{:.0}", malicious * 100.0)
            }
            Outcome::Unavailable => "TIER2_UNAVAILABLE".to_string(),
            Outcome::Retried => "TIER2_RETRY".to_string(),
            Outcome::Poison => "TIER2_POISON".to_string(),
        }
    }

    fn code(self) -> u32 {
        match self {
            Outcome::Benign => crate::codes::SAFE,
            Outcome::Suspicious | Outcome::Malicious => crate::codes::SEMANTIC,
            _ => crate::codes::GREY_NO_SEMANTIC,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlowPathStats {
    pub claimed: u64,
    pub benign: u64,
    pub suspicious: u64,
    pub malicious: u64,
    pub unavailable: u64,
    pub retried: u64,
    pub poison: u64,
}

impl SlowPathStats {
    /// Items the model actually rendered a verdict on.
    pub fn scored(&self) -> u64 {
        self.benign + self.suspicious + self.malicious
    }

    fn record(&mut self, o: Outcome) {
        match o {
            Outcome::Benign => self.benign += 1,
            Outcome::Suspicious => self.suspicious += 1,
            Outcome::Malicious => self.malicious += 1,
            Outcome::Unavailable => self.unavailable += 1,
            Outcome::Retried => self.retried += 1,
            Outcome::Poison => self.poison += 1,
        }
    }

    fn merge(&mut self, o: SlowPathStats) {
        self.claimed += o.claimed;
        self.benign += o.benign;
        self.suspicious += o.suspicious;
        self.malicious += o.malicious;
        self.unavailable += o.unavailable;
        self.retried += o.retried;
        self.poison += o.poison;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SlowPathConfig {
    /// Items taken per claim.
    pub batch_size: usize,
    /// `p(malicious)` at or above which the outcome is `Malicious`.
    pub block_threshold: f32,
    /// `p(malicious)` at or above which the outcome is `Suspicious`.
    pub flag_threshold: f32,
    /// Give up on an item after this many failed scoring attempts.
    pub max_attempts: u32,
    /// How long `run_forever` sleeps when the queue came back empty.
    pub idle_sleep: Duration,
}

impl Default for SlowPathConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            // Matched to TierConfig's inline thresholds on purpose: the same
            // prompt must not get a different answer because it happened to be
            // scored out of band rather than inline.
            block_threshold: 0.90,
            flag_threshold: 0.60,
            max_attempts: 3,
            idle_sleep: Duration::from_millis(250),
        }
    }
}

/// Drains the deferred queue and scores what it finds.
pub struct SlowPathWorker {
    queue: DeferredWorker,
    scorer: Arc<dyn SemanticScorer>,
    audit: Option<Arc<AuditQueue>>,
    cfg: SlowPathConfig,
}

impl std::fmt::Debug for SlowPathWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never derive here: this type holds a queue of prompt text, and a
        // derived formatter would be one `dbg!` away from printing it.
        f.debug_struct("SlowPathWorker")
            .field("scorer", &self.scorer.name())
            .field("batch_size", &self.cfg.batch_size)
            .finish_non_exhaustive()
    }
}

impl SlowPathWorker {
    pub fn new(
        queue: DeferredWorker,
        scorer: Arc<dyn SemanticScorer>,
        cfg: SlowPathConfig,
    ) -> Self {
        Self {
            queue,
            scorer,
            audit: None,
            cfg,
        }
    }

    /// Attach the audit outbox.
    ///
    /// Optional so the worker can be exercised without a trail, but a
    /// deployment without one is scoring prompts and telling nobody - the
    /// verdicts exist only in the process that computed them.
    pub fn with_audit(mut self, audit: Arc<AuditQueue>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn scorer_name(&self) -> &str {
        self.scorer.name()
    }

    /// Claim one batch, score it, and report what happened.
    ///
    /// Returns `claimed: 0` when the queue is empty, which is how
    /// `run_forever` knows to idle.
    pub fn run_once(&mut self) -> Result<SlowPathStats, DeferredError> {
        // `.max(1)` mirrors the channel-depth clamp in `deferred`: a zero
        // batch size otherwise makes the worker a permanent no-op that never
        // says why.
        let items = self.queue.claim(self.cfg.batch_size.max(1))?;
        let mut stats = SlowPathStats {
            claimed: items.len() as u64,
            ..SlowPathStats::default()
        };
        for item in items {
            let outcome = self.process(&item)?;
            stats.record(outcome);
        }
        Ok(stats)
    }

    fn process(&mut self, item: &DeferredItem) -> Result<Outcome, DeferredError> {
        let started = Instant::now();
        let (outcome, malicious) = match self.scorer.score(&item.prompt) {
            Ok(score) => {
                let o = if score.malicious >= self.cfg.block_threshold {
                    Outcome::Malicious
                } else if score.malicious >= self.cfg.flag_threshold {
                    Outcome::Suspicious
                } else {
                    Outcome::Benign
                };
                (o, score.malicious)
            }
            Err(e) if e.is_absent() => {
                // Terminal: no model is coming. Cycling the item until its TTL
                // expires would burn the worker and still lose the prompt.
                (Outcome::Unavailable, 0.0)
            }
            Err(_) if item.attempts < self.cfg.max_attempts => {
                // Release BEFORE the audit write: if the process dies between
                // the two, a visible row is recoverable but a swallowed one is
                // not.
                self.queue.release(item.id)?;
                self.audit(Outcome::Retried, 0.0, started.elapsed());
                return Ok(Outcome::Retried);
            }
            Err(_) => (Outcome::Poison, 0.0),
        };

        self.audit(outcome, malicious, started.elapsed());
        // Deleted, not marked done. The prompt stops existing once the work
        // does - see the deferred module's retention rules.
        self.queue.complete(item.id)?;
        Ok(outcome)
    }

    /// Write the classification - and only the classification - to the trail.
    fn audit(&self, outcome: Outcome, malicious: f32, took: Duration) {
        let Some(audit) = self.audit.as_deref() else {
            return;
        };
        audit.log(
            unix_now(),
            outcome.code(),
            // A category. The prompt is deliberately not in scope here: this
            // record is shipped off the device.
            &outcome.label(malicious),
            "tier2_deferred_scored",
            took.as_micros() as u64,
        );
    }

    /// Drain until `stop` is set, idling when the queue is empty.
    pub fn run_until(&mut self, stop: Arc<AtomicBool>) -> SlowPathStats {
        let mut total = SlowPathStats::default();
        while !stop.load(Ordering::Relaxed) {
            match self.run_once() {
                Ok(s) if s.claimed == 0 => std::thread::sleep(self.cfg.idle_sleep),
                Ok(s) => total.merge(s),
                Err(e) => {
                    // A database error here is an availability problem for the
                    // slow path only; the fast path is untouched. Back off
                    // rather than spin.
                    eprintln!("[EdgeGuard] slow path: {e}");
                    std::thread::sleep(self.cfg.idle_sleep);
                }
            }
        }
        total
    }

    /// Drain everything currently claimable, then stop. Bounded so a test or
    /// a batch job cannot loop forever on a queue that keeps refilling.
    pub fn drain(&mut self, max_batches: usize) -> Result<SlowPathStats, DeferredError> {
        let mut total = SlowPathStats::default();
        for _ in 0..max_batches {
            let s = self.run_once()?;
            if s.claimed == 0 {
                break;
            }
            total.merge(s);
        }
        Ok(total)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred::{DeferredConfig, DeferredQueue, Interim};
    use crate::semantic::{ScorerError, ScorerStats, SemanticScore, SemanticScorer};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    // --- a scorer the test dictates -----------------------------------------

    struct Scripted {
        score: f32,
        fail: bool,
        absent: bool,
        seen: Arc<Mutex<Vec<String>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Scripted {
        fn new(score: f32) -> Arc<Self> {
            Arc::new(Self {
                score,
                fail: false,
                absent: false,
                seen: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(Self {
                score: 0.0,
                fail: true,
                absent: false,
                seen: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
        fn absent() -> Arc<Self> {
            Arc::new(Self {
                score: 0.0,
                fail: false,
                absent: true,
                seen: Arc::new(Mutex::new(Vec::new())),
                calls: Arc::new(AtomicUsize::new(0)),
            })
        }
    }

    impl SemanticScorer for Scripted {
        fn score(&self, text: &str) -> Result<SemanticScore, ScorerError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.seen.lock().unwrap().push(text.to_string());
            if self.absent {
                return Err(ScorerError::NotConfigured);
            }
            if self.fail {
                return Err(ScorerError::Inference("scripted failure".into()));
            }
            Ok(SemanticScore {
                malicious: self.score,
                latency: Duration::from_micros(10),
                tokens: 8,
                truncated: false,
            })
        }
        fn name(&self) -> &str {
            "scripted"
        }
        fn stats(&self) -> ScorerStats {
            ScorerStats::default()
        }
    }

    // --- fixtures ------------------------------------------------------------

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "eg_slowpath_{}_{}_{}.db",
            name,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        p
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            for ext in ["-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0.display(), ext));
            }
        }
    }

    /// Park prompts and wait for the writer thread to land them.
    fn park(path: &PathBuf, prompts: &[&str]) -> DeferredQueue {
        let q = DeferredQueue::open(path, DeferredConfig::default()).unwrap();
        for p in prompts {
            q.submit(p, 211, "tier1_rule", 0, Interim::ServeAndMark);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if q.stats().persisted >= prompts.len() as u64 {
                return q;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("prompts never persisted");
    }

    fn worker(path: &PathBuf, scorer: Arc<dyn SemanticScorer>) -> SlowPathWorker {
        let w = DeferredWorker::open(path, DeferredConfig::default()).unwrap();
        SlowPathWorker::new(w, scorer, SlowPathConfig::default())
    }

    // --- the privacy boundary ------------------------------------------------

    #[test]
    fn the_audit_trail_never_receives_the_prompt() {
        // The check that matters most in this module: it is the only place
        // holding prompt text and an outbox handle at once, and the outbox is
        // shipped off the device.
        let dpath = tmp("privacy");
        let apath = tmp("privacy_audit");
        let _g1 = Tmp(dpath.clone());
        let _g2 = Tmp(apath.clone());

        const CANARY: &str = "ZZQUUXCANARY7788";
        let q = park(&dpath, &[&format!("please {CANARY} do the thing")]);

        let audit = Arc::new(crate::audit_queue::AuditQueue::open(
            &apath,
            Default::default(),
        ));
        let mut w = worker(&dpath, Scripted::new(0.95)).with_audit(Arc::clone(&audit));
        let stats = w.run_once().unwrap();
        assert_eq!(stats.malicious, 1);

        // Let the outbox writer flush, then read every byte it stored.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut blob = String::new();
        while Instant::now() < deadline {
            if let Ok(c) = rusqlite::Connection::open(&apath) {
                if let Ok(mut st) = c.prepare("SELECT label, decided_by FROM audit_outbox") {
                    if let Ok(rows) = st.query_map([], |r| {
                        Ok(format!(
                            "{} {}",
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?
                        ))
                    }) {
                        blob = rows.filter_map(|r| r.ok()).collect::<Vec<_>>().join("|");
                    }
                }
            }
            if !blob.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!blob.is_empty(), "no audit record was written");
        assert!(
            !blob.contains(CANARY),
            "prompt text reached the outbox: {blob:?}"
        );
        assert!(blob.contains("SEMANTIC_95"), "got {blob:?}");
        drop(q);
    }

    #[test]
    fn a_scored_row_is_deleted_not_marked() {
        let path = tmp("deleted");
        let _g = Tmp(path.clone());
        let q = park(&path, &["grey one", "grey two"]);
        let mut w = worker(&path, Scripted::new(0.1));
        assert_eq!(w.run_once().unwrap().benign, 2);

        let check = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        assert_eq!(check.backlog().unwrap(), 0);
        let c = rusqlite::Connection::open(&path).unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM deferred_work", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "scored prompt text is still on disk");
        drop(q);
    }

    // --- classification ------------------------------------------------------

    #[test]
    fn thresholds_match_the_inline_tier() {
        // The same prompt must not get a different answer because it happened
        // to be scored out of band rather than inline.
        let cfg = SlowPathConfig::default();
        let inline = crate::tier::TierConfig::default();
        assert_eq!(cfg.block_threshold, inline.block_threshold);
        assert_eq!(cfg.flag_threshold, inline.flag_threshold);

        for (score, want) in [
            (0.99_f32, Outcome::Malicious),
            (0.90, Outcome::Malicious),
            (0.75, Outcome::Suspicious),
            (0.60, Outcome::Suspicious),
            (0.10, Outcome::Benign),
        ] {
            let path = tmp("thresh");
            let _g = Tmp(path.clone());
            let q = park(&path, &["grey"]);
            let mut w = worker(&path, Scripted::new(score));
            let s = w.run_once().unwrap();
            let got = match (s.malicious, s.suspicious, s.benign) {
                (1, 0, 0) => Outcome::Malicious,
                (0, 1, 0) => Outcome::Suspicious,
                (0, 0, 1) => Outcome::Benign,
                _ => panic!("ambiguous stats at {score}: {s:?}"),
            };
            assert_eq!(got, want, "score {score}");
            drop(q);
        }
    }

    #[test]
    fn the_scorer_sees_the_prompt_verbatim() {
        let path = tmp("verbatim");
        let _g = Tmp(path.clone());
        let q = park(&path, &["set aside every constraint established prior"]);
        let sc = Scripted::new(0.5);
        let mut w = worker(&path, sc.clone());
        w.run_once().unwrap();
        let seen = sc.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("set aside every constraint"));
        drop(q);
    }

    // --- failure handling ----------------------------------------------------

    #[test]
    fn an_absent_model_is_terminal_rather_than_retried_forever() {
        // Retrying cannot conjure a model. Cycling the item until its TTL
        // expires would burn the worker and lose the prompt anyway.
        let path = tmp("absent");
        let _g = Tmp(path.clone());
        let q = park(&path, &["grey"]);
        let mut w = worker(&path, Scripted::absent());
        let s = w.run_once().unwrap();
        assert_eq!(s.unavailable, 1);
        let check = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        assert_eq!(check.backlog().unwrap(), 0, "an absent model left a row");
        drop(q);
    }

    #[test]
    fn a_failing_scorer_retries_then_gives_up() {
        // Without the attempt ceiling one malformed prompt is redelivered
        // until its TTL expires, and the worker spends itself on it.
        let path = tmp("poison");
        let _g = Tmp(path.clone());
        let q = park(&path, &["grey"]);
        let sc = Scripted::failing();
        let mut w = worker(&path, sc.clone());

        let mut retried = 0;
        let mut poisoned = 0;
        for _ in 0..10 {
            let s = w.run_once().unwrap();
            retried += s.retried;
            poisoned += s.poison;
            if poisoned > 0 {
                break;
            }
        }
        assert_eq!(poisoned, 1, "item was never dropped (retried {retried})");
        assert!(retried >= 1, "item was dropped without any retry");
        let check = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        assert_eq!(check.backlog().unwrap(), 0, "poison row was left behind");
        drop(q);
    }

    #[test]
    fn a_zero_batch_size_still_makes_progress() {
        // A misconfigured worker that silently processes nothing forever is
        // worse than one that errors: nothing in the metrics distinguishes it
        // from an empty queue.
        let path = tmp("zerobatch");
        let _g = Tmp(path.clone());
        let q = park(&path, &["grey"]);
        let w = DeferredWorker::open(&path, DeferredConfig::default()).unwrap();
        let mut sp = SlowPathWorker::new(
            w,
            Scripted::new(0.1),
            SlowPathConfig {
                batch_size: 0,
                ..SlowPathConfig::default()
            },
        );
        assert_eq!(sp.run_once().unwrap().claimed, 1);
        drop(q);
    }

    #[test]
    fn an_empty_queue_reports_nothing_claimed() {
        let path = tmp("empty");
        let _g = Tmp(path.clone());
        let q = DeferredQueue::open(&path, DeferredConfig::default()).unwrap();
        let mut w = worker(&path, Scripted::new(0.5));
        assert_eq!(w.run_once().unwrap(), SlowPathStats::default());
        drop(q);
    }

    #[test]
    fn drain_is_bounded_and_processes_every_batch() {
        let path = tmp("drain");
        let _g = Tmp(path.clone());
        let prompts: Vec<String> = (0..70).map(|i| format!("grey {i}")).collect();
        let refs: Vec<&str> = prompts.iter().map(|s| s.as_str()).collect();
        let q = park(&path, &refs);
        let mut w = worker(&path, Scripted::new(0.1));
        let s = w.drain(10).unwrap();
        assert_eq!(s.claimed, 70);
        assert_eq!(s.benign, 70);
        drop(q);
    }

    #[test]
    fn a_worker_without_an_audit_sink_still_scores() {
        let path = tmp("noaudit");
        let _g = Tmp(path.clone());
        let q = park(&path, &["grey"]);
        let mut w = worker(&path, Scripted::new(0.95));
        assert_eq!(w.run_once().unwrap().malicious, 1);
        drop(q);
    }

    #[test]
    fn debug_never_prints_a_prompt() {
        // A derived Debug on this type would be one `dbg!` away from printing
        // the queue it holds.
        let path = tmp("dbg");
        let _g = Tmp(path.clone());
        let q = park(&path, &["ZZSECRETPROMPT"]);
        let w = worker(&path, Scripted::new(0.5));
        let rendered = format!("{w:?}");
        assert!(!rendered.contains("ZZSECRETPROMPT"), "{rendered}");
        assert!(rendered.contains("scripted"));
        drop(q);
    }
}
