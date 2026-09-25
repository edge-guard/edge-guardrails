//! EdgeGuard Experiment Pack v1.0 harness.
//!
//! Built OUTSIDE the production Core. The Core is a path dependency and is
//! never edited for measurement convenience.
//!
//! Phase discipline (Pack §7):
//!
//! * **Phase I** - freeze implementation, datasets, labels, comparators,
//!   metrics, harness. Repair measurement bugs only. This crate is the Phase-I
//!   deliverable.
//! * **Phase II** - one blind execution against the frozen holdout.
//!   [`bin/phase2`] refuses to start unless the contamination lock verifies
//!   AND a corpus actually exists.
//! * **Phase III** - decision report. No code changes before sign-off.
//!
//! Nothing in this crate may select, filter, reorder, or relabel a case on the
//! basis of an observed EdgeGuard output.

pub mod adapter;
pub mod manifest;
pub mod metrics;
pub mod results;
pub mod schema;
pub mod timing;

/// Experiment version. Pack §0: any change to a pinned input requires bumping
/// this and re-running from zero.
pub const EXPERIMENT_VERSION: &str = "1.0.0";

/// The Core the Pack pins for this experiment (Pack §2).
pub const PINNED_CORE_AGGREGATE_SHA256: &str =
    "e6fd1a5379a62ec065eaedbd06875493c66816526a4f2a42d5610cd3d184cfa8";
