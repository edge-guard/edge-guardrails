//! Routing Benchmark v0.1 harness for EdgeGuard Core, frozen at
//! [`freeze::FROZEN_COMMIT`].
//!
//! This crate evaluates the engine as a **selective classifier**: a router
//! whose three outcomes are PASS, BLOCK, and ESCALATE, where ESCALATE is an
//! explicit refusal to answer rather than a verdict. Scoring it as if it were
//! a binary classifier - collapsing ESCALATE into either PASS or BLOCK - would
//! measure something the engine does not claim to be.
//!
//! # Layout
//!
//! - [`schema`] - the two disjoint sides of a case: what the engine sees, and
//!   the ground truth it must never see.
//! - [`corpus`] - loading, coherence validation, and the leakage lint.
//! - [`metrics`] - every rate and percentile, with explicit denominators.
//! - [`baselines`] - the routers under comparison, including the ones that
//!   report as unavailable rather than being imitated.
//! - [`freeze`] - verification that the engine has not moved.
//!
//! The corpus itself, the case generators, and the runner are added after the
//! design in `docs/DESIGN.md` is reviewed. Nothing in this crate may require
//! an edit to the frozen engine.

pub mod baselines;
pub mod corpus;
pub mod freeze;
pub mod metrics;
pub mod schema;
