//! The freeze guard.
//!
//! EdgeGuard Core is frozen for Routing Benchmark v0.1 at
//! [`FROZEN_COMMIT`]. Results are only meaningful if the engine that produced
//! them is that engine, so the harness verifies it rather than trusting it.
//!
//! The check hashes engine *files*, not the repository HEAD, because HEAD
//! moves every time the benchmark itself is committed. Any edit to a scanner
//! source, the rule graph, the event contract, or the shipped policy changes a
//! hash here and fails the run with the file named.

use sha2::{Digest, Sha256};
use std::path::Path;

pub const FROZEN_COMMIT: &str = "f664be6af727a5a1fa8f66e9e2ad07c109263acb";

/// SHA-256 of every engine file, as of [`FROZEN_COMMIT`].
pub const FROZEN_ENGINE_FILES: &[(&str, &str)] = &[
    (
        "src/audit_queue.rs",
        "48a7dd59ecb6006984a17a8aaced03893d132bccbf59b7a2f52dc3c3d0f6cd95",
    ),
    (
        "src/codes.rs",
        "6fa4aeee4a6750a84e6ef667f6de37a94fdb4fa9719ca7ba687afbf821cef7c6",
    ),
    (
        "src/deferred.rs",
        "2f3cbe386ad228a64118a89343b116023d5da8fec0b68d73f35a58da427c787e",
    ),
    (
        "src/deobfuscate.rs",
        "400b5b890b2c2becb360fd57b84b75f629dfcaf3bbf736da146d0ed2f9245daf",
    ),
    (
        "src/event.rs",
        "09786cd145c17c56aef95cf7d5cb4b69938fb3cd397a2970bccc1c485ba0d50c",
    ),
    (
        "src/ffi.rs",
        "1ed40b034ea46dad3d8e607c2e908425d66f0d68ff3d0264258abe6f4b61e632",
    ),
    (
        "src/graph.rs",
        "f3f3729923f6bc4e39a0687ccc1f45e4c9047bf2cfaccda32720ad62f4bde986",
    ),
    (
        "src/lib.rs",
        "3b50f57db80495c472cd3ea504e6f16137569e65d8e60c2e966bb3dd2ef2372d",
    ),
    (
        "src/semantic.rs",
        "76217619b0e3397add0593e188ce6089a2fb92a694d99a2455a8a17c738dc2b7",
    ),
    (
        "src/signing.rs",
        "770058316ad7a5296bca574a2838cbd02df7c3356acebef43d073393b51a4a75",
    ),
    (
        "src/slowpath.rs",
        "332c63c47d810bf4d5448eaa5939871bb33c4474d52bf6c6e7515de8b57b9e4b",
    ),
    (
        "src/stream.rs",
        "e9c28a3238098cd29e024e1b4a09f0042ce852e6d83dd021e69355b5f404fed2",
    ),
    (
        "src/tier.rs",
        "dd15f6cd69553e77a1fad69d22efd4f613dab936f6ae0d673f2bfcb00d9ee444",
    ),
    (
        "policy.yaml",
        "26189e168dad02e467edd14e812721f54e9433a3796bcd34aafc088a20f203f2",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug)]
pub struct DriftedFile {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// `engine_root` is the directory holding the frozen engine (the parent of
/// this crate). Returns every file whose content no longer matches the freeze.
pub fn verify(engine_root: &Path) -> Result<Vec<DriftedFile>, std::io::Error> {
    let mut drifted = Vec::new();
    for (rel, expected) in FROZEN_ENGINE_FILES {
        let bytes = std::fs::read(engine_root.join(rel))?;
        let actual = hex(&Sha256::digest(&bytes));
        if actual != *expected {
            drifted.push(DriftedFile {
                path: (*rel).to_string(),
                expected: (*expected).to_string(),
                actual,
            });
        }
    }
    Ok(drifted)
}
