//! Latching guardrail for token-by-token LLM output.
//!
//! # The failure this exists to prevent
//!
//! Streaming output cannot be scanned as one string, because by the time the
//! last token arrives the first ones have already been sent to the user. So a
//! bounded rolling window is scanned after every token, which catches a
//! payload as soon as it becomes visible even when it is split across tokens.
//!
//! The window is also the problem. A secret is detected while it sits inside
//! the window, and then the window scrolls, and the scanner reports the stream
//! as clean again:
//!
//! ```text
//! token  5  BLOCK  "s your key: AKIAIOSFODNN7EXAMPLE"
//! token  8  BLOCK  " AKIAIOSFODNN7EXAMPLE. Now some "
//! token 27  SAFE   "ely and keeps going for a while."   <- the stream forgot
//! ```
//!
//! A caller that gates on the most recent verdict — which is the obvious way
//! to use a streaming API, and what the shipped examples do — therefore
//! forwards a response whose secret was detected and then forgotten. The
//! detection worked perfectly and the outcome was a leak.
//!
//! # The latch
//!
//! Once a stream trips, it stays tripped. [`StreamScanner`] keeps the first
//! violation and reports it for every subsequent token, regardless of what the
//! window currently holds. Only [`StreamScanner::reset`] clears it, and that
//! means "a new stream starts here" rather than "forget what you saw".
//!
//! The latch is deliberately monotonic. There is no timeout and no decay: a
//! secret that was emitted was emitted, and no amount of subsequent
//! well-behaved output makes it un-emitted.
//!
//! # Audit behaviour
//!
//! Re-scanning the window on every token means the same violation is
//! re-detected on every token until it scrolls out. Routing that through
//! [`SecurityEngine::scan`] wrote an audit record each time, so one leaked key
//! produced one row per token — hundreds, at the default window size — all
//! identical. This records **one row per distinct violation code per stream**
//! instead, via [`SecurityEngine::scan_without_audit`] plus an explicit audit
//! on first sight.

use std::sync::Arc;

use crate::{ScanResult, SecurityEngine};

/// Largest rolling window, in characters.
///
/// Bounded for a specific reason rather than for tidiness: the window is
/// handed to the scanner, and the scanner refuses anything over
/// [`crate::MAX_SCAN_BYTES`] with a "payload too large" verdict. An unbounded
/// window would therefore eventually make a perfectly ordinary stream *latch*
/// on the size guard — a false positive that permanently blocks a benign
/// response. Capping the window keeps it comfortably inside the scan limit
/// even when every character is 4 bytes of UTF-8.
pub const MAX_WINDOW_CHARS: usize = 65_536;

/// Distinct violation codes remembered per stream. A cap, so a hostile stream
/// cannot grow this without bound.
const MAX_TRACKED_CODES: usize = 32;

/// The verdict for one token.
///
/// The first four fields carry the same meaning as [`ScanResult`], so a caller
/// already written against the scan API reads this the same way.
#[derive(Debug, Clone)]
pub struct StreamVerdict {
    /// `false` for every token after the stream trips, whatever the window
    /// currently holds. **This is the field to gate on.**
    pub is_safe: bool,
    pub violation_code: u32,
    pub reason: String,
    pub matched_pattern: String,
    /// `true` when this verdict comes from the latch rather than from the
    /// current window — i.e. the violation has already scrolled out of view.
    pub latched: bool,
    /// `true` only on the token that tripped the stream, so a caller can log
    /// or alert exactly once without de-duplicating.
    pub just_tripped: bool,
    /// Tokens whose window contained a violation. Not a count of distinct
    /// secrets: one secret is re-detected on every token until it scrolls out.
    pub violation_tokens: u64,
}

/// A rolling-window guard over one stream, with a latch.
///
/// Construct one per response. Feed it every token as it is generated, and
/// stop the stream on the first verdict whose `is_safe` is `false`.
pub struct StreamScanner {
    engine: Arc<SecurityEngine>,
    window: String,
    /// Tracked incrementally: `chars().count()` on the whole window per token
    /// would make every token cost a pass over the window for nothing.
    window_chars: usize,
    max_chars: usize,
    /// The first violation seen. Once set, never cleared except by `reset`.
    latch: Option<ScanResult>,
    violation_tokens: u64,
    tokens: u64,
    codes_seen: Vec<u32>,
}

impl StreamScanner {
    /// `window_chars` is clamped to `1..=MAX_WINDOW_CHARS`.
    ///
    /// The window must be at least as long as the longest payload that has to
    /// be recognised as a contiguous string: a window of 8 characters cannot
    /// see a 20-character API key however many tokens it is fed.
    pub fn new(engine: Arc<SecurityEngine>, window_chars: usize) -> Self {
        Self {
            engine,
            window: String::new(),
            window_chars: 0,
            max_chars: window_chars.clamp(1, MAX_WINDOW_CHARS),
            latch: None,
            violation_tokens: 0,
            tokens: 0,
            codes_seen: Vec::new(),
        }
    }

    /// Feed one generated token and get the verdict for the stream so far.
    pub fn feed_token(&mut self, token: &str) -> StreamVerdict {
        self.tokens += 1;
        self.window.push_str(token);
        self.window_chars += token.chars().count();

        if self.window_chars > self.max_chars {
            let excess = self.window_chars - self.max_chars;
            // Drain from the front in place. The previous
            // `chars().skip(n).collect()` allocated a fresh `String` on every
            // token once the window was full.
            let cut = self
                .window
                .char_indices()
                .nth(excess)
                .map(|(i, _)| i)
                .unwrap_or(self.window.len());
            self.window.drain(..cut);
            self.window_chars -= excess;
        }

        // Deliberately the non-auditing scan: this same window is scanned
        // again on the very next token, and a violation inside it would
        // otherwise be recorded once per token for as long as it stays
        // visible.
        let res = self.engine.scan_without_audit(&self.window);

        let mut just_tripped = false;
        if !res.is_safe {
            self.violation_tokens += 1;
            let is_new_code = !self.codes_seen.contains(&res.violation_code);
            if is_new_code && self.codes_seen.len() < MAX_TRACKED_CODES {
                self.codes_seen.push(res.violation_code);
            }
            // One audit row per distinct violation code per stream: a second
            // secret of a different kind is still recorded, a re-sighting of
            // the same one is not.
            if is_new_code {
                self.engine.audit(&res);
            }
            if self.latch.is_none() {
                self.latch = Some(res.clone());
                just_tripped = true;
            }
        }

        match &self.latch {
            Some(first) => StreamVerdict {
                is_safe: false,
                violation_code: first.violation_code,
                reason: first.reason.clone(),
                matched_pattern: first.matched_pattern.clone(),
                // The verdict is latched whenever the current window is clean
                // but the stream has already tripped.
                latched: res.is_safe,
                just_tripped,
                violation_tokens: self.violation_tokens,
            },
            None => StreamVerdict {
                is_safe: true,
                violation_code: crate::codes::SAFE,
                reason: res.reason,
                matched_pattern: String::new(),
                latched: false,
                just_tripped: false,
                violation_tokens: 0,
            },
        }
    }

    /// Begin a new stream: clears the window, the latch and the counters.
    ///
    /// The only way to clear the latch, and named for what it means. A stream
    /// does not get to un-see a secret; a *new* stream simply has not seen one
    /// yet.
    pub fn reset(&mut self) {
        self.window.clear();
        self.window_chars = 0;
        self.latch = None;
        self.violation_tokens = 0;
        self.tokens = 0;
        self.codes_seen.clear();
    }

    /// `true` once this stream has tripped.
    pub fn is_latched(&self) -> bool {
        self.latch.is_some()
    }

    /// The violation that tripped the stream, if any.
    pub fn latched_violation(&self) -> Option<&ScanResult> {
        self.latch.as_ref()
    }

    /// Distinct violation codes seen in this stream, in order of first sight.
    pub fn codes_seen(&self) -> &[u32] {
        &self.codes_seen
    }

    pub fn tokens_fed(&self) -> u64 {
        self.tokens
    }

    /// The current rolling window. Diagnostics only.
    pub fn window(&self) -> &str {
        &self.window
    }

    pub fn window_capacity_chars(&self) -> usize {
        self.max_chars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Arc<SecurityEngine> {
        Arc::new(SecurityEngine::without_policy(vec![], None))
    }

    fn scanner(window: usize) -> StreamScanner {
        StreamScanner::new(engine(), window)
    }

    /// Tokens that push a secret out of a 32-character window and then keep
    /// going with entirely innocuous text.
    const LEAK_THEN_FILLER: &[&str] = &[
        "Here ",
        "is ",
        "your ",
        "key: ",
        "AKIA",
        "IOSFODNN7EXAMPLE",
        ". ",
        "Now ",
        "some ",
        "perfectly ",
        "ordinary ",
        "filler ",
        "text ",
        "that ",
        "pushes ",
        "the ",
        "secret ",
        "out ",
        "of ",
        "the ",
        "window ",
        "entirely ",
        "and ",
        "keeps ",
        "going ",
        "for ",
        "a ",
        "while.",
    ];

    // The blocker. Before the latch, the final verdict here was `is_safe:
    // true` and a caller gating on it forwarded a response containing a live
    // credential.
    #[test]
    fn a_secret_stays_flagged_after_it_scrolls_out_of_the_window() {
        let mut s = scanner(32);
        let mut last = None;
        for t in LEAK_THEN_FILLER {
            last = Some(s.feed_token(t));
        }
        let v = last.unwrap();
        assert!(
            !v.is_safe,
            "the stream forgot a secret it had already detected"
        );
        assert_eq!(v.violation_code, crate::codes::PII_AWS_KEY);
        assert!(
            v.latched,
            "the window is clean by now, so the verdict must come from the latch"
        );
        assert!(s.is_latched());
        // And the window really has scrolled past it - the latch is doing the
        // work, not a lucky window boundary.
        assert!(
            !s.window().contains("AKIA"),
            "window still holds the secret: {:?}",
            s.window()
        );
    }

    #[test]
    fn the_latch_holds_for_an_arbitrarily_long_clean_tail() {
        let mut s = scanner(64);
        for t in ["leak ", "AKIAIOSFODNN7EXAMPLE", " done"] {
            s.feed_token(t);
        }
        assert!(s.is_latched());
        for i in 0..5_000 {
            let v = s.feed_token("perfectly ordinary prose ");
            assert!(!v.is_safe, "stream un-latched after {} clean tokens", i);
        }
    }

    #[test]
    fn a_clean_stream_never_latches() {
        let mut s = scanner(64);
        for t in [
            "The ",
            "quarterly ",
            "report ",
            "looks ",
            "fine ",
            "and ",
            "margins ",
            "held ",
            "steady ",
            "across ",
            "every ",
            "region.",
        ] {
            let v = s.feed_token(t);
            assert!(
                v.is_safe,
                "clean token {:?} tripped the stream: {}",
                t, v.reason
            );
            assert!(!v.latched);
            assert!(!v.just_tripped);
        }
        assert!(!s.is_latched());
        assert!(s.codes_seen().is_empty());
    }

    #[test]
    fn just_tripped_fires_exactly_once_for_one_secret() {
        let mut s = scanner(32);
        let trips: usize = LEAK_THEN_FILLER
            .iter()
            .map(|t| s.feed_token(t))
            .filter(|v| v.just_tripped)
            .count();
        assert_eq!(
            trips, 1,
            "a caller alerting on just_tripped would alert {} times",
            trips
        );
    }

    #[test]
    fn reset_begins_a_new_stream_and_is_the_only_thing_that_clears_the_latch() {
        let mut s = scanner(32);
        for t in LEAK_THEN_FILLER {
            s.feed_token(t);
        }
        assert!(s.is_latched());

        s.reset();
        assert!(!s.is_latched());
        assert_eq!(s.window(), "");
        assert!(s.codes_seen().is_empty());
        assert_eq!(s.tokens_fed(), 0);

        let v = s.feed_token("a perfectly ordinary new response");
        assert!(v.is_safe, "a reset stream must start clean");
    }

    #[test]
    fn a_secret_split_across_many_tokens_is_still_caught() {
        // The original reason the rolling window exists: no single token
        // contains the key.
        let mut s = scanner(64);
        let mut tripped = false;
        for t in [
            "Here ", "is ", "your ", "key: ", "AK", "IA", "IOSF", "ODNN", "7EXA", "MPLE",
        ] {
            if s.feed_token(t).just_tripped {
                tripped = true;
            }
        }
        assert!(tripped, "a key split across tokens was not detected");
        assert_eq!(s.codes_seen(), &[crate::codes::PII_AWS_KEY]);
    }

    // The audit-amplification fix. One leak must not produce one row per
    // token for as long as it stays inside the window.
    #[test]
    fn one_leak_writes_one_audit_row_not_one_per_token() {
        let eng = engine();
        let mut s = StreamScanner::new(Arc::clone(&eng), 64);
        for t in LEAK_THEN_FILLER {
            s.feed_token(t);
        }
        // Several tokens saw the violation...
        assert!(
            s.violation_tokens_for_test() > 1,
            "the window should have re-detected the secret on several tokens"
        );
        // ...but only one record was offered to the trail.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let stats = eng.audit_stats();
        assert_eq!(
            stats.enqueued, 1,
            "one leaked key produced {} audit rows",
            stats.enqueued
        );
    }

    #[test]
    fn two_different_secrets_are_both_recorded() {
        let eng = engine();
        let mut s = StreamScanner::new(Arc::clone(&eng), 48);
        for t in [
            "key AKIAIOSFODNN7EXAMPLE then ",
            "filler ",
            "filler ",
            "filler ",
            "filler ",
            "filler ",
            "card 4532-0150-0000-0007",
        ] {
            s.feed_token(t);
        }
        assert!(s.codes_seen().contains(&crate::codes::PII_AWS_KEY));
        assert!(s.codes_seen().contains(&crate::codes::PII_CREDIT_CARD));
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(eng.audit_stats().enqueued, 2);
        // The latch still reports the FIRST violation, so the verdict is
        // stable for the life of the stream.
        assert_eq!(
            s.latched_violation().unwrap().violation_code,
            crate::codes::PII_AWS_KEY
        );
    }

    #[test]
    fn the_window_never_grows_past_its_capacity() {
        let mut s = scanner(100);
        for _ in 0..2_000 {
            s.feed_token("some streamed output ");
        }
        assert!(
            s.window().chars().count() <= 100,
            "window grew to {}",
            s.window().chars().count()
        );
        assert!(s.window().len() < 1024);
    }

    // An unbounded window would eventually exceed the scan size limit and
    // latch the stream on "payload too large" - a permanent false positive on
    // a benign response.
    // Two separable properties, tested separately so neither needs to scan a
    // 64K window tens of thousands of times.
    #[test]
    fn an_absurd_window_size_is_clamped_to_the_cap() {
        let s = StreamScanner::new(engine(), usize::MAX);
        assert_eq!(s.window_capacity_chars(), MAX_WINDOW_CHARS);
        let tiny = StreamScanner::new(engine(), 0);
        assert_eq!(
            tiny.window_capacity_chars(),
            1,
            "a zero window must still be usable"
        );
    }

    #[test]
    fn a_stream_longer_than_the_scan_limit_never_trips_the_size_guard() {
        // Total output far exceeds MAX_SCAN_BYTES; the window must not
        // accumulate it, or an ordinary long response would latch on
        // "payload too large" and be blocked for the rest of the stream.
        let mut s = scanner(256);
        let chunk = "ordinary streamed prose that is entirely unremarkable ";
        let rounds = crate::MAX_SCAN_BYTES / chunk.len() + 1_000;
        for _ in 0..rounds {
            let v = s.feed_token(chunk);
            assert!(
                v.violation_code != crate::codes::PAYLOAD_TOO_LARGE,
                "the rolling window tripped the size guard"
            );
        }
        assert!(s.tokens_fed() as usize * chunk.len() > crate::MAX_SCAN_BYTES);
        assert!(!s.is_latched());
        assert!(s.window().chars().count() <= 256);
    }

    #[test]
    fn a_multibyte_window_is_trimmed_on_character_boundaries() {
        // Draining by byte offset must not split a UTF-8 sequence.
        let mut s = scanner(8);
        for _ in 0..50 {
            let v = s.feed_token("日本語テキスト");
            assert!(v.is_safe);
            assert!(s.window().chars().count() <= 8);
        }
        // Still valid UTF-8, by construction - `window()` returns `&str`.
        assert!(!s.window().is_empty());
    }

    #[test]
    fn an_injection_in_the_stream_latches_just_like_a_secret() {
        let mut s = scanner(40);
        for t in ["Sure. ", "ignore previous instructions", " and continue"] {
            s.feed_token(t);
        }
        assert!(s.is_latched());
        for _ in 0..200 {
            assert!(!s.feed_token("harmless tail ").is_safe);
        }
    }
}

#[cfg(test)]
impl StreamScanner {
    fn violation_tokens_for_test(&self) -> u64 {
        self.violation_tokens
    }
}
