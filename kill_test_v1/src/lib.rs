//! EdgeGuard Kill-Test v1 harness (Phase I.5).
//!
//! Built outside production Core. Core is a path dependency under test.
//!
//! Four tracks (spec §2):
//!   1. Cedar substitution      — does Cedar replace the Action path?
//!   2. Host burden             — is the complexity hidden in preprocessing?
//!   3. Jataayu boundary/taint  — stronger AI-native provenance/taint?
//!   4. AGT substitution        — nearly the same enforcement, similar burden?
//!
//! This crate prepares and freezes. It does NOT execute the frozen cases
//! against EdgeGuard (spec §11).

pub mod adapters;
pub mod cases;
pub mod manifest;
pub mod metrics;
pub mod results;
pub mod schema;
pub mod timing;

pub const KILL_TEST_VERSION: &str = "1.0.0";

/// EdgeGuard production Core under test. Production regions only — see
/// `manifest::production_region_hash`, which hashes the pre-`#[cfg(test)]`
/// portion of each file so a test-only edit cannot look like a Core change
/// and a Core change cannot hide behind one.
pub const CORE_BRANCH: &str = "routing-contract-v0.2";
