//! Timing methodology for Pack §4 (Speed).
//!
//! Three layers are measured *separately* and never summed into one number:
//!
//! 1. `native_core_ns`  - `TieredEngine::inspect` with a caller-owned scratch.
//! 2. `ffi_boundary_ns` - the same decision through the C ABI.
//! 3. `adapter_e2e_ns`  - final typed args in, verdict back to the host.
//!
//! Warm and cold are separated because the first observation on an engine
//! instance pays for lazy initialisation, and reporting a blended p50 hides
//! exactly the number an integrator feels on their first request.
//!
//! No network or DB fetch may occur inside a timed region. Host-supplied facts
//! are the architecture under test (Pack §4), so a harness that fetched a fact
//! mid-measurement would be measuring a different system.

use std::time::{Duration, Instant};

/// Percentile summary over a set of observations, in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub n: usize,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub total_ns: u64,
}

impl Summary {
    /// Nearest-rank percentiles on an owned, sorted copy.
    ///
    /// Nearest-rank rather than interpolation: an interpolated p99 reports a
    /// latency that no request actually experienced, which is the wrong thing
    /// to put in a security-routing budget.
    pub fn from_nanos(mut samples: Vec<u64>) -> Option<Summary> {
        if samples.is_empty() {
            return None;
        }
        samples.sort_unstable();
        let n = samples.len();
        let rank = |p: f64| -> u64 {
            let idx = ((p * n as f64).ceil() as usize).max(1).min(n) - 1;
            samples[idx]
        };
        Some(Summary {
            n,
            p50_ns: rank(0.50),
            p95_ns: rank(0.95),
            p99_ns: rank(0.99),
            max_ns: samples[n - 1],
            total_ns: samples.iter().sum(),
        })
    }

    /// Observations per second, derived from the measured total only.
    pub fn throughput_per_sec(&self) -> f64 {
        if self.total_ns == 0 {
            return f64::NAN;
        }
        self.n as f64 * 1_000_000_000.0 / self.total_ns as f64
    }
}

/// One timed scale point: how many rules/checks were live during the run.
#[derive(Debug, Clone)]
pub struct ScalePoint {
    pub label: String,
    pub rule_count: usize,
    pub input_bytes: usize,
    pub cold: Option<Summary>,
    pub warm: Option<Summary>,
}

/// Pack §4 requires at least 1, 10, 100, and one larger realistic check count.
pub const REQUIRED_SCALE_POINTS: &[usize] = &[1, 10, 100, 1000];

/// Time `f` `iters` times, returning cold (first observation) separately from
/// the warm remainder.
///
/// `f` must perform no I/O. The closure is called once before measurement
/// begins only when `warmup` is true - which is how a *warm* series is
/// produced; a cold series passes `warmup: false` and uses the first sample.
pub fn measure<F: FnMut()>(
    mut f: F,
    iters: usize,
    warmup: bool,
) -> (Option<Summary>, Option<Summary>) {
    if warmup {
        f();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        f();
        samples.push(t0.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }
    if warmup {
        (None, Summary::from_nanos(samples))
    } else {
        let cold = samples.first().copied().map(|s| Summary {
            n: 1,
            p50_ns: s,
            p95_ns: s,
            p99_ns: s,
            max_ns: s,
            total_ns: s,
        });
        (cold, Summary::from_nanos(samples[1..].to_vec()))
    }
}

/// The environment a timing run was produced on. Reported with every timing
/// table, because a latency figure without its machine is not a measurement.
#[derive(Debug, Clone)]
pub struct Environment {
    pub cpu: String,
    pub arch: String,
    pub os: String,
    pub rustc: String,
    pub profile: String,
    pub logical_cores: usize,
}

impl Environment {
    /// Captured from the build/runtime rather than typed in by hand where the
    /// value is knowable; the rest is supplied by the caller from the freeze
    /// manifest so it cannot silently drift from what was recorded there.
    pub fn render(&self) -> String {
        format!(
            "{} ({} cores) / {} / {} / rustc {} / profile {}",
            self.cpu, self.logical_cores, self.arch, self.os, self.rustc, self.profile
        )
    }
}

/// Guard against a timed region that performed I/O.
///
/// This cannot detect every syscall; what it does is make a *deliberate*
/// violation loud. Harness code that needs a fact must take it from the
/// pre-loaded record, and this asserts the elapsed time is consistent with
/// that - a hot-path decision that took longer than `bound` is treated as
/// evidence the measurement is contaminated rather than as a slow decision.
pub fn assert_no_io(elapsed: Duration, bound: Duration, what: &str) -> Result<(), String> {
    if elapsed > bound {
        return Err(format!(
            "{what}: timed region took {elapsed:?}, over the {bound:?} bound - \
             a deterministic hot path should not; suspect I/O inside the measurement"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_nearest_rank_and_report_real_observations() {
        let s = Summary::from_nanos((1..=100).collect()).unwrap();
        assert_eq!(s.n, 100);
        assert_eq!(s.p50_ns, 50);
        assert_eq!(s.p95_ns, 95);
        assert_eq!(s.p99_ns, 99);
        assert_eq!(s.max_ns, 100);
    }

    #[test]
    fn an_empty_series_has_no_summary_rather_than_a_zero_one() {
        assert!(Summary::from_nanos(vec![]).is_none());
    }

    #[test]
    fn a_single_sample_reports_itself_at_every_percentile() {
        let s = Summary::from_nanos(vec![42]).unwrap();
        assert_eq!((s.p50_ns, s.p95_ns, s.p99_ns, s.max_ns), (42, 42, 42, 42));
    }

    #[test]
    fn throughput_is_derived_only_from_measured_time() {
        let s = Summary::from_nanos(vec![1_000_000; 1000]).unwrap();
        // 1000 observations of 1 ms = 1000 per second.
        assert!((s.throughput_per_sec() - 1000.0).abs() < 1e-6);
    }

    #[test]
    fn cold_is_reported_separately_from_warm() {
        let mut n = 0u64;
        let (cold, warm) = measure(|| n += 1, 10, false);
        assert_eq!(cold.unwrap().n, 1, "cold is the first observation alone");
        assert_eq!(warm.unwrap().n, 9, "warm excludes it");
        assert_eq!(n, 10);
    }

    #[test]
    fn a_warm_series_pays_for_a_warmup_call_outside_the_measurement() {
        let mut n = 0u64;
        let (cold, warm) = measure(|| n += 1, 5, true);
        assert!(cold.is_none());
        assert_eq!(warm.unwrap().n, 5);
        assert_eq!(n, 6, "5 measured + 1 warmup");
    }

    #[test]
    fn the_required_scale_points_cover_the_packs_minimum() {
        assert!(REQUIRED_SCALE_POINTS.contains(&1));
        assert!(REQUIRED_SCALE_POINTS.contains(&10));
        assert!(REQUIRED_SCALE_POINTS.contains(&100));
        assert!(REQUIRED_SCALE_POINTS.iter().any(|&n| n > 100));
    }

    #[test]
    fn an_overlong_hot_path_is_flagged_as_contaminated() {
        let r = assert_no_io(Duration::from_millis(50), Duration::from_millis(1), "tier1");
        assert!(r.is_err());
        assert!(assert_no_io(Duration::from_micros(5), Duration::from_millis(1), "tier1").is_ok());
    }
}
