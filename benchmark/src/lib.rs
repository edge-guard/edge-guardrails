//! Routing Benchmark v0.1 harness for EdgeGuard Core, frozen at
//! [`freeze::FROZEN_COMMIT`].
//!
//! This crate evaluates the engine as a **selective classifier**: a router
//! whose three outcomes are PASS, BLOCK, and ESCALATE, where ESCALATE is an
//! explicit refusal to answer rather than a verdict. Scoring it as a binary
//! classifier - collapsing ESCALATE into PASS or BLOCK - would measure
//! something the engine does not claim to be.
//!
//! It measures the engine across all three channels. EdgeGuard is a
//! deterministic fast path over **content facts** (INPUT/OUTPUT) and
//! **structured action facts** (ACTION), so those are separately reported and
//! neither is allowed to stand in for the whole. See `docs/DESIGN.md`, which
//! keeps the architectural thesis, the frozen implementation, and future
//! potential in three explicitly separate sections.
//!
//! # Layout
//!
//! - [`schema`] - what the engine sees, and the ground truth it never sees.
//! - [`policy_env`] - frozen, independently authored ACTION policy
//!   environments. A case references one; a case never defines rules.
//! - [`corpus`] - loading, coherence validation, and the leakage lints.
//! - [`recipe`] - frozen synthetic construction recipes.
//! - [`locks`] - classification, policy-environment, recipe, and holdout-burn
//!   freezes, plus the verification chokepoint.
//! - [`metrics`] - raw confusion counts, every rate, and the percentiles.
//! - [`report`] - the reporting contract: aggregates are never emitted alone,
//!   and a report cannot be built without a [`locks::FreezeAttestation`].
//! - [`baselines`] - routers under comparison, including the ones that report
//!   as unavailable rather than being imitated.
//! - [`freeze`] - verification that the engine has not moved.
//!
//! The corpus, the generators, and the runner follow the design review.
//! Nothing here may require an edit to the frozen engine.

pub mod baselines;
pub mod corpus;
pub mod freeze;
pub mod locks;
pub mod metrics;
pub mod policy_env;
pub mod recipe;
pub mod report;
pub mod schema;
