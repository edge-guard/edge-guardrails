//! Cryptographically signed policy distribution.
//!
//! # The gap this closes
//!
//! Until now [`crate::PolicyEngine`] watched a file's mtime and recompiled
//! whatever it found there. That makes *write access to one path* equivalent
//! to *full control of the guardrail*: an attacker who can drop a file can
//! ship `rules: []` and silently disable every policy, or add a
//! `Custom Pattern` that allowlists their own payload. On an edge device the
//! filesystem is the least defensible surface there is — a shared volume, a
//! sidecar with a bad mount, a compromised updater, an NFS export.
//!
//! The engine therefore must not trust the *location* a policy came from. It
//! trusts a **signature over the policy bytes**, made by a key the device was
//! provisioned with out of band.
//!
//! # Threat model
//!
//! The attacker is assumed to have:
//!
//! * full read access to the device, including this source and the bundle
//!   format — there is no security here from obscurity;
//! * write access to the policy path and to anything else on disk that is
//!   not the pinned trust store;
//! * the ability to observe, record, drop, delay and replay every policy
//!   bundle that has ever legitimately been served to any device.
//!
//! The attacker is assumed **not** to hold a private signing key.
//!
//! Each of the checks below exists because one specific attack from that list
//! defeats a design without it:
//!
//! | attack | check |
//! |---|---|
//! | forge a bundle | Ed25519 signature over the canonical header |
//! | tamper with the payload, keep the header | payload SHA-256 bound into the signed header |
//! | re-sign with an attacker key | `key_id` must resolve in the pinned [`TrustStore`] |
//! | replay an old, weaker, genuinely signed bundle | monotonic [`Sequence`] high-water mark |
//! | keep a revoked key alive | explicit revocation list, checked before use |
//! | serve tenant A's bundle to tenant B | `tenant` bound into the signed header |
//! | hold a valid bundle back forever | `not_after` expiry, so staleness is bounded |
//! | reuse a signature from another protocol | domain separation string in the signed input |
//! | truncate/extend a field to shift the parse | every signed field is length-prefixed |
//!
//! # Why not detached signatures over the raw YAML
//!
//! Because "the bytes" is not enough. A signature that covers only the rules
//! cannot express *which tenant they are for*, *which key signed them*,
//! *when they stop being valid*, or *what order they go in* — and those four
//! are where the interesting attacks live. The header is the security
//! boundary; the payload is just cargo.
//!
//! # Wire format
//!
//! Deliberately line-oriented UTF-8 rather than a binary or JSON encoding:
//! it survives copy/paste into a ticket, diffs legibly in review, and — most
//! importantly — has no canonicalization ambiguity to argue about, because
//! the bytes that get signed are *not* these lines (see
//! [`BundleHeader::signing_input`]).
//!
//! ```text
//! edgeguard-bundle/1
//! key-id: prod-signer-2026
//! bundle-id: 0f3c...
//! tenant: acme-corp
//! sequence: 42
//! not-before: 1758153600
//! not-after: 1789689600
//! payload-sha256: 9f86d081...
//! payload-len: 1024
//! signature: 3045...
//!
//! <payload bytes>
//! ```

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Bumped only for a change that alters what is signed. A verifier that does
/// not recognize the version refuses the bundle rather than guessing.
pub const BUNDLE_VERSION: &str = "edgeguard-bundle/1";

/// Domain separation tag, mixed into every signature.
///
/// Without it, a signature this key made over some *other* protocol's message
/// could be replayed as a policy bundle if the byte strings ever collided.
/// With it, an EdgeGuard signature is only ever valid as an EdgeGuard
/// signature, even for an operator who reuses one key across systems (which
/// they should not, and will).
const DOMAIN: &[u8] = b"edgeguard.policy-bundle.v1";

/// A bundle is refused if its own declared lifetime is longer than this.
///
/// An attacker who compromises a signing key for ten minutes should not be
/// able to mint a bundle that is still accepted in 2040. Capping the window
/// at the verifier turns key compromise into a bounded incident.
pub const MAX_VALIDITY_WINDOW_SECS: u64 = 400 * 24 * 60 * 60; // ~13 months

/// Largest payload a bundle may carry. Policy files are kilobytes; anything
/// approaching this is an attempt to make the verifier itself the DoS.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Largest header a bundle may carry, so a malformed stream cannot be read
/// line by line forever looking for the blank separator.
const MAX_HEADER_BYTES: usize = 8 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a bundle was refused.
///
/// Deliberately granular. An operator whose rollout is being rejected needs
/// to know whether they have a clock problem, a key problem or an attack, and
/// collapsing all of these into "invalid signature" is how a real outage gets
/// misdiagnosed as a breach — and how a real breach gets misdiagnosed as a
/// clock problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Malformed(String),
    UnsupportedVersion(String),
    TooLarge {
        field: &'static str,
        len: usize,
        limit: usize,
    },
    UnknownKey(String),
    RevokedKey(String),
    BadSignature,
    PayloadDigestMismatch,
    NotYetValid {
        not_before: u64,
        now: u64,
    },
    Expired {
        not_after: u64,
        now: u64,
    },
    ValidityWindowTooLong {
        secs: u64,
        limit: u64,
    },
    /// A genuinely signed bundle that is older than one already applied —
    /// i.e. a downgrade attempt, not a corruption.
    Rollback {
        offered: u64,
        applied: u64,
    },
    WrongTenant {
        expected: String,
        found: String,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use BundleError::*;
        match self {
            Malformed(m) => write!(f, "malformed bundle: {}", m),
            UnsupportedVersion(v) => write!(f, "unsupported bundle version '{}'", v),
            TooLarge { field, len, limit } => {
                write!(f, "{} is {} bytes, limit is {}", field, len, limit)
            }
            UnknownKey(k) => write!(f, "signing key '{}' is not in the trust store", k),
            RevokedKey(k) => write!(f, "signing key '{}' has been revoked", k),
            BadSignature => write!(f, "signature verification failed"),
            PayloadDigestMismatch => write!(f, "payload does not match the signed digest"),
            NotYetValid { not_before, now } => {
                write!(f, "bundle is not valid until {} (now {})", not_before, now)
            }
            Expired { not_after, now } => {
                write!(f, "bundle expired at {} (now {})", not_after, now)
            }
            ValidityWindowTooLong { secs, limit } => {
                write!(
                    f,
                    "validity window of {}s exceeds the {}s maximum",
                    secs, limit
                )
            }
            Rollback { offered, applied } => write!(
                f,
                "rollback refused: bundle sequence {} is not newer than the applied sequence {}",
                offered, applied
            ),
            WrongTenant { expected, found } => {
                write!(
                    f,
                    "bundle is for tenant '{}', this device is '{}'",
                    found, expected
                )
            }
        }
    }
}

impl std::error::Error for BundleError {}

// ---------------------------------------------------------------------------
// Hex, without a dependency
// ---------------------------------------------------------------------------

fn to_hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for pair in b.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Some(out)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// The signed part of a bundle. Everything security-relevant lives here;
/// the payload is authenticated only through `payload_sha256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleHeader {
    pub key_id: String,
    /// Opaque unique id for this bundle, for correlating device logs with the
    /// control plane. Signed so it cannot be rewritten in transit.
    pub bundle_id: String,
    /// Which tenant this policy belongs to. Signed, so a bundle legitimately
    /// issued to one customer cannot be replayed onto another's fleet.
    pub tenant: String,
    /// Monotonic per-tenant counter. The anti-rollback primitive.
    pub sequence: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub payload_sha256: [u8; 32],
    pub payload_len: usize,
}

impl BundleHeader {
    /// The exact byte string an Ed25519 signature is computed over.
    ///
    /// Not the serialized text above. Two properties matter and the text form
    /// has neither:
    ///
    /// 1. **No canonicalization ambiguity.** Whitespace, field order, line
    ///    endings and duplicate keys are all things a text parser has to have
    ///    an opinion about, and any disagreement between the signer's opinion
    ///    and the verifier's is a signature bypass. Here the signer and the
    ///    verifier both build this buffer from *parsed, typed* fields, so
    ///    there is exactly one byte string per logical header.
    ///
    /// 2. **No field-boundary confusion.** Every variable-length field is
    ///    preceded by its length as a fixed 8-byte big-endian integer. Without
    ///    that, `tenant="ab"`+`bundle_id="c"` and `tenant="a"`+`bundle_id="bc"`
    ///    concatenate to the same bytes, and an attacker who controls one
    ///    field can borrow characters from its neighbour while keeping the
    ///    signature valid. This is the classic length-extension-style
    ///    confusion, and length prefixes are the standard answer.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        let mut put = |bytes: &[u8]| {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        };
        put(DOMAIN);
        put(BUNDLE_VERSION.as_bytes());
        put(self.key_id.as_bytes());
        put(self.bundle_id.as_bytes());
        put(self.tenant.as_bytes());
        put(&self.sequence.to_be_bytes());
        put(&self.not_before.to_be_bytes());
        put(&self.not_after.to_be_bytes());
        put(&self.payload_sha256);
        put(&(self.payload_len as u64).to_be_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// Trust store
// ---------------------------------------------------------------------------

/// The device's pinned set of acceptable signers.
///
/// Provisioned out of band — baked into the image, injected by the
/// orchestrator, or held in a TPM/Secure Enclave-backed file. It is the one
/// piece of state whose integrity the whole scheme rests on, so it is
/// deliberately *not* something the policy channel can modify: a bundle can
/// never add a key. Rotation is an out-of-band operation, on purpose, because
/// a channel that can add its own signers authenticates nothing.
#[derive(Debug, Default, Clone)]
pub struct TrustStore {
    keys: HashMap<String, VerifyingKey>,
    revoked: HashMap<String, String>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a signer. `public_key` is 32 raw Ed25519 bytes, hex-encoded.
    pub fn add_key_hex(&mut self, key_id: &str, public_key_hex: &str) -> Result<(), BundleError> {
        let raw = from_hex(public_key_hex.trim())
            .ok_or_else(|| BundleError::Malformed("public key is not valid hex".into()))?;
        let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            BundleError::Malformed(format!("public key must be 32 bytes, got {}", raw.len()))
        })?;
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| BundleError::Malformed(format!("invalid Ed25519 public key: {}", e)))?;
        self.keys.insert(key_id.to_string(), vk);
        Ok(())
    }

    pub fn add_key(&mut self, key_id: &str, key: VerifyingKey) {
        self.keys.insert(key_id.to_string(), key);
    }

    /// Revoke a signer. Revocation is checked *before* the signature, so a
    /// revoked key cannot spend CPU on verification, and it wins over
    /// presence in `keys` — removing the key entry is not required, which
    /// matters because an operator who deletes a key by mistake would
    /// otherwise silently re-enable it on the next provisioning run.
    pub fn revoke(&mut self, key_id: &str, reason: &str) {
        self.revoked.insert(key_id.to_string(), reason.to_string());
    }

    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked.contains_key(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn resolve(&self, key_id: &str) -> Result<&VerifyingKey, BundleError> {
        if self.revoked.contains_key(key_id) {
            return Err(BundleError::RevokedKey(key_id.to_string()));
        }
        self.keys
            .get(key_id)
            .ok_or_else(|| BundleError::UnknownKey(key_id.to_string()))
    }

    /// Load from a simple `key_id <space> hex` file, one per line, `#`
    /// comments, and `!revoked` in place of the key to mark a revocation.
    ///
    /// A text format on purpose: the trust store is the thing an auditor will
    /// ask to see, and it should be readable without tooling.
    pub fn from_file(path: &Path) -> Result<Self, BundleError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            BundleError::Malformed(format!(
                "cannot read trust store '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::from_str_repr(&raw)
    }

    pub fn from_str_repr(raw: &str) -> Result<Self, BundleError> {
        let mut store = Self::new();
        for (n, line) in raw.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let id = parts.next().ok_or_else(|| {
                BundleError::Malformed(format!("trust store line {}: missing key id", n + 1))
            })?;
            let val = parts.next().ok_or_else(|| {
                BundleError::Malformed(format!("trust store line {}: missing key material", n + 1))
            })?;
            if val == "!revoked" {
                store.revoke(id, parts.next().unwrap_or("unspecified"));
            } else {
                store.add_key_hex(id, val)?;
            }
        }
        Ok(store)
    }
}

// ---------------------------------------------------------------------------
// Anti-rollback
// ---------------------------------------------------------------------------

/// The highest bundle sequence this device has ever *applied*.
///
/// Without this, every check above still passes for a bundle that was
/// genuinely signed six months ago — and an attacker who recorded that
/// bundle can pin the fleet to it forever, which is a complete policy
/// downgrade using nothing but valid signatures. Monotonicity is what turns
/// "this bundle is authentic" into "this bundle is current".
///
/// Deliberately advanced only on *successful application*, not on successful
/// verification: a bundle that verifies but then fails to compile must not
/// burn a sequence number, or a single malformed-but-signed release would
/// permanently lock the device out of every subsequent one.
#[derive(Debug)]
pub struct Sequence {
    applied: AtomicU64,
    path: Option<std::path::PathBuf>,
}

impl Sequence {
    pub fn in_memory() -> Self {
        Self {
            applied: AtomicU64::new(0),
            path: None,
        }
    }

    /// Persist the high-water mark, so a reboot does not reopen the rollback
    /// window. A missing or unreadable file starts at zero rather than
    /// failing: a device that cannot read its own marker must still boot with
    /// *some* policy, and starting at zero is the fail-open that matters
    /// least here — it accepts a replay once, and then is monotonic again.
    pub fn at_path(path: impl Into<std::path::PathBuf>) -> Self {
        let path = path.into();
        let applied = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Self {
            applied: AtomicU64::new(applied),
            path: Some(path),
        }
    }

    pub fn applied(&self) -> u64 {
        self.applied.load(Ordering::Acquire)
    }

    fn check(&self, offered: u64) -> Result<(), BundleError> {
        let applied = self.applied();
        if offered <= applied {
            return Err(BundleError::Rollback { offered, applied });
        }
        Ok(())
    }

    /// Record a successful application. Writes through to disk before
    /// returning so a crash between "policy live" and "sequence recorded"
    /// leaves the device accepting a replay, rather than rejecting the very
    /// bundle it is already running.
    pub fn commit(&self, sequence: u64) {
        self.applied.fetch_max(sequence, Ordering::AcqRel);
        if let Some(p) = &self.path {
            // Write-and-rename, so a torn write cannot leave a truncated
            // number that parses as something smaller.
            let tmp = p.with_extension("tmp");
            if std::fs::write(&tmp, self.applied().to_string()).is_ok() {
                let _ = std::fs::rename(&tmp, p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verification policy
// ---------------------------------------------------------------------------

/// What this device requires of a bundle beyond the signature itself.
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
    /// Refuse bundles addressed to any other tenant. `None` disables the
    /// check, which is only correct for a single-tenant build.
    pub expect_tenant: Option<String>,
    /// Enforce `not_before` / `not_after`.
    ///
    /// Settable because an edge device without an RTC or NTP genuinely may
    /// not know the time at boot, and a guardrail that refuses all policy
    /// because the clock says 1970 has failed more completely than one that
    /// accepts a stale bundle. Turning it off makes [`Sequence`] the only
    /// freshness control, which is why `Sequence` is not optional.
    pub enforce_time: bool,
    /// Tolerance for clock skew between signer and device, in seconds.
    pub clock_skew_secs: u64,
    pub max_validity_window_secs: u64,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        Self {
            expect_tenant: None,
            enforce_time: true,
            clock_skew_secs: 300,
            max_validity_window_secs: MAX_VALIDITY_WINDOW_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------

/// A parsed, **not yet verified** bundle.
///
/// The type deliberately does not hand out `payload` until
/// [`Self::verify`] has run: parsing is a pure syntax operation on attacker
/// controlled bytes, and the only thing standing between it and the rule
/// compiler is that you cannot get the payload out of this struct without
/// passing a [`TrustStore`].
#[derive(Debug, Clone)]
pub struct SignedBundle {
    header: BundleHeader,
    signature: Signature,
    payload: Vec<u8>,
}

/// A bundle that has passed every check. Holding one is the proof.
#[derive(Debug, Clone)]
pub struct VerifiedBundle {
    pub header: BundleHeader,
    payload: Vec<u8>,
}

impl VerifiedBundle {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// The payload as text. `None` if it is not valid UTF-8 — a YAML rule
    /// group that is not UTF-8 is malformed no matter who signed it.
    pub fn payload_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
    pub fn sequence(&self) -> u64 {
        self.header.sequence
    }
}

impl SignedBundle {
    /// Build and sign a bundle. Used by the control plane and by tests; a
    /// device only ever *verifies*.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        signing_key: &SigningKey,
        key_id: &str,
        bundle_id: &str,
        tenant: &str,
        sequence: u64,
        not_before: u64,
        not_after: u64,
        payload: Vec<u8>,
    ) -> Result<Self, BundleError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(BundleError::TooLarge {
                field: "payload",
                len: payload.len(),
                limit: MAX_PAYLOAD_BYTES,
            });
        }
        let header = BundleHeader {
            key_id: key_id.to_string(),
            bundle_id: bundle_id.to_string(),
            tenant: tenant.to_string(),
            sequence,
            not_before,
            not_after,
            payload_sha256: sha256(&payload),
            payload_len: payload.len(),
        };
        let signature = signing_key.sign(&header.signing_input());
        Ok(Self {
            header,
            signature,
            payload,
        })
    }

    pub fn header(&self) -> &BundleHeader {
        &self.header
    }

    /// Serialize to the on-the-wire text form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let h = &self.header;
        let mut out = format!(
            "{}\nkey-id: {}\nbundle-id: {}\ntenant: {}\nsequence: {}\nnot-before: {}\nnot-after: {}\npayload-sha256: {}\npayload-len: {}\nsignature: {}\n\n",
            BUNDLE_VERSION,
            h.key_id,
            h.bundle_id,
            h.tenant,
            h.sequence,
            h.not_before,
            h.not_after,
            to_hex(&h.payload_sha256),
            h.payload_len,
            to_hex(&self.signature.to_bytes()),
        )
        .into_bytes();
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse without verifying. Every length is bounded before anything is
    /// allocated for it, so a hostile stream cannot make the parser the
    /// denial of service.
    pub fn parse(raw: &[u8]) -> Result<Self, BundleError> {
        // Locate the blank line ending the header, within a bounded prefix.
        let search_limit = raw.len().min(MAX_HEADER_BYTES);
        let sep = raw[..search_limit]
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or_else(|| {
                BundleError::Malformed(format!(
                    "no header terminator within the first {} bytes",
                    search_limit
                ))
            })?;
        let header_txt = std::str::from_utf8(&raw[..sep])
            .map_err(|_| BundleError::Malformed("header is not valid UTF-8".into()))?;
        let payload = raw[sep + 2..].to_vec();

        let mut lines = header_txt.lines();
        let version = lines
            .next()
            .ok_or_else(|| BundleError::Malformed("empty header".into()))?
            .trim();
        if version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion(version.to_string()));
        }

        let mut fields: HashMap<&str, &str> = HashMap::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line.split_once(':').ok_or_else(|| {
                BundleError::Malformed(format!("header line '{}' has no ':'", line))
            })?;
            // Reject duplicates rather than last-wins. A parser that silently
            // takes the last value lets an attacker prepend a field the signer
            // never wrote and have a lenient reader elsewhere see a different
            // one - the classic request-smuggling shape, applied to a config.
            if fields.insert(k.trim(), v.trim()).is_some() {
                return Err(BundleError::Malformed(format!(
                    "duplicate header field '{}'",
                    k.trim()
                )));
            }
        }

        let need = |k: &'static str| -> Result<&str, BundleError> {
            fields
                .get(k)
                .copied()
                .ok_or_else(|| BundleError::Malformed(format!("missing header field '{}'", k)))
        };
        let need_u64 = |k: &'static str| -> Result<u64, BundleError> {
            need(k)?.parse::<u64>().map_err(|_| {
                BundleError::Malformed(format!("header field '{}' is not a number", k))
            })
        };

        let digest_hex = need("payload-sha256")?;
        let digest: [u8; 32] = from_hex(digest_hex)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| BundleError::Malformed("payload-sha256 is not 32 hex bytes".into()))?;

        let sig_bytes: [u8; 64] = from_hex(need("signature")?)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| BundleError::Malformed("signature is not 64 hex bytes".into()))?;

        let payload_len = need_u64("payload-len")? as usize;
        if payload_len > MAX_PAYLOAD_BYTES {
            return Err(BundleError::TooLarge {
                field: "payload-len",
                len: payload_len,
                limit: MAX_PAYLOAD_BYTES,
            });
        }
        // The declared length must match what actually arrived. Checked here,
        // before verification, so a truncated or padded stream is a parse
        // error rather than a confusing digest mismatch.
        if payload_len != payload.len() {
            return Err(BundleError::Malformed(format!(
                "payload-len says {} bytes but {} arrived",
                payload_len,
                payload.len()
            )));
        }

        Ok(Self {
            header: BundleHeader {
                key_id: need("key-id")?.to_string(),
                bundle_id: need("bundle-id")?.to_string(),
                tenant: need("tenant")?.to_string(),
                sequence: need_u64("sequence")?,
                not_before: need_u64("not-before")?,
                not_after: need_u64("not-after")?,
                payload_sha256: digest,
                payload_len,
            },
            signature: Signature::from_bytes(&sig_bytes),
            payload,
        })
    }

    /// Run every check. The only way to obtain the payload.
    ///
    /// Order matters and is not arbitrary: the cheap, non-cryptographic
    /// refusals (unknown key, revoked key, oversize) run first so an attacker
    /// cannot make the device burn Ed25519 verifications by spraying garbage;
    /// the signature check runs before the *semantic* checks (time, sequence,
    /// tenant) so those are never decided on attacker-controlled values that
    /// have not yet been authenticated.
    pub fn verify(
        self,
        trust: &TrustStore,
        seq: &Sequence,
        policy: &VerifyPolicy,
    ) -> Result<VerifiedBundle, BundleError> {
        let vk = trust.resolve(&self.header.key_id)?;

        // Authenticate before believing anything in the header.
        vk.verify(&self.header.signing_input(), &self.signature)
            .map_err(|_| BundleError::BadSignature)?;

        // The signature covers the digest, not the bytes, so this is the step
        // that actually binds the payload to the header.
        if sha256(&self.payload) != self.header.payload_sha256 {
            return Err(BundleError::PayloadDigestMismatch);
        }

        // --- from here on the header is trusted ---------------------------
        if let Some(expected) = &policy.expect_tenant {
            if expected != &self.header.tenant {
                return Err(BundleError::WrongTenant {
                    expected: expected.clone(),
                    found: self.header.tenant.clone(),
                });
            }
        }

        let window = self.header.not_after.saturating_sub(self.header.not_before);
        if window > policy.max_validity_window_secs {
            return Err(BundleError::ValidityWindowTooLong {
                secs: window,
                limit: policy.max_validity_window_secs,
            });
        }

        if policy.enforce_time {
            let now = now_unix();
            let skew = policy.clock_skew_secs;
            if now + skew < self.header.not_before {
                return Err(BundleError::NotYetValid {
                    not_before: self.header.not_before,
                    now,
                });
            }
            if self.header.not_after != 0 && now > self.header.not_after + skew {
                return Err(BundleError::Expired {
                    not_after: self.header.not_after,
                    now,
                });
            }
        }

        seq.check(self.header.sequence)?;

        Ok(VerifiedBundle {
            header: self.header,
            payload: self.payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Device-side loader
// ---------------------------------------------------------------------------

/// Everything a device needs to accept a policy bundle from disk.
///
/// The point of the type is that there is no constructor that skips the trust
/// store. A deployment either provisions one or does not load signed policy;
/// there is deliberately no "verification off" flag, because that flag is
/// always the one that ends up set in production.
pub struct SignedRuleSource {
    trust: TrustStore,
    sequence: Sequence,
    policy: VerifyPolicy,
}

impl SignedRuleSource {
    pub fn new(trust: TrustStore, sequence: Sequence, policy: VerifyPolicy) -> Self {
        Self {
            trust,
            sequence,
            policy,
        }
    }

    /// Provision from files: a pinned trust store and a persisted sequence
    /// high-water mark.
    pub fn from_paths(
        trust_store_path: &Path,
        sequence_path: &Path,
        policy: VerifyPolicy,
    ) -> Result<Self, BundleError> {
        let trust = TrustStore::from_file(trust_store_path)?;
        if trust.is_empty() {
            return Err(BundleError::Malformed(format!(
                "trust store '{}' contains no usable keys - refusing to start a signed \
                 policy source that could never accept anything",
                trust_store_path.display()
            )));
        }
        Ok(Self::new(trust, Sequence::at_path(sequence_path), policy))
    }

    pub fn applied_sequence(&self) -> u64 {
        self.sequence.applied()
    }

    /// Read, verify and accept a bundle.
    ///
    /// The sequence is committed **only after** `accept` has signalled that
    /// the payload was successfully put into service. A bundle that verifies
    /// but fails to compile must not consume a sequence number, or one bad
    /// release permanently locks the device out of every later one.
    pub fn load_and_apply<T, E, F>(&self, bundle_path: &Path, accept: F) -> Result<T, LoadError<E>>
    where
        F: FnOnce(&VerifiedBundle) -> Result<T, E>,
    {
        let raw = std::fs::read(bundle_path).map_err(|e| {
            LoadError::Bundle(BundleError::Malformed(format!(
                "cannot read bundle '{}': {}",
                bundle_path.display(),
                e
            )))
        })?;
        let verified = SignedBundle::parse(&raw)
            .and_then(|b| b.verify(&self.trust, &self.sequence, &self.policy))
            .map_err(LoadError::Bundle)?;
        let out = accept(&verified).map_err(LoadError::Apply)?;
        self.sequence.commit(verified.sequence());
        Ok(out)
    }
}

/// Either the bundle was not acceptable, or it was and the caller could not
/// use it. Kept distinct because they page different people: the first is a
/// security or distribution event, the second is a policy-authoring bug.
#[derive(Debug)]
pub enum LoadError<E> {
    Bundle(BundleError),
    Apply(E),
}

impl<E: fmt::Display> fmt::Display for LoadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Bundle(e) => write!(f, "bundle refused: {}", e),
            LoadError::Apply(e) => write!(f, "bundle accepted but could not be applied: {}", e),
        }
    }
}

/// Generate a signing key from 32 bytes of secret material.
///
/// Key *generation* is intentionally not done here from an OS RNG: this crate
/// is the edge data plane, it should never hold a private key, and giving it
/// a `generate()` makes it far too easy to ship one that does. The control
/// plane owns key generation; this exists so tooling and tests can construct
/// a signer from material they already have.
pub fn signing_key_from_bytes(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// The hex public key for a signing key, in the form [`TrustStore`] accepts.
pub fn public_key_hex(sk: &SigningKey) -> String {
    to_hex(sk.verifying_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        signing_key_from_bytes(&[seed; 32])
    }

    fn store(id: &str, sk: &SigningKey) -> TrustStore {
        let mut t = TrustStore::new();
        t.add_key_hex(id, &public_key_hex(sk)).unwrap();
        t
    }

    fn bundle(sk: &SigningKey, seq: u64, payload: &str) -> SignedBundle {
        let now = now_unix();
        SignedBundle::create(
            sk,
            "k1",
            "b-1",
            "acme",
            seq,
            now - 60,
            now + 3600,
            payload.as_bytes().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn a_genuine_bundle_round_trips_through_the_wire_format() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        let parsed = SignedBundle::parse(&raw).unwrap();
        let v = parsed
            .verify(
                &store("k1", &sk),
                &Sequence::in_memory(),
                &VerifyPolicy::default(),
            )
            .unwrap();
        assert_eq!(v.payload_str().unwrap(), "rules: []\n");
        assert_eq!(v.sequence(), 1);
    }

    #[test]
    fn a_payload_edited_in_transit_is_refused() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        let mut tampered = raw.clone();
        // Flip a byte inside the payload, keeping every header field intact.
        let n = tampered.len();
        tampered[n - 3] ^= 0x20;
        let err = SignedBundle::parse(&tampered)
            .unwrap()
            .verify(
                &store("k1", &sk),
                &Sequence::in_memory(),
                &VerifyPolicy::default(),
            )
            .unwrap_err();
        assert_eq!(err, BundleError::PayloadDigestMismatch);
    }

    #[test]
    fn a_bundle_signed_by_an_untrusted_key_is_refused() {
        let real = key(1);
        let attacker = key(9);
        // The attacker signs a policy that disables everything, and even
        // labels it with the real key's id.
        let raw = bundle(&attacker, 99, "rules: []\n").to_bytes();
        let err = SignedBundle::parse(&raw)
            .unwrap()
            .verify(
                &store("k1", &real),
                &Sequence::in_memory(),
                &VerifyPolicy::default(),
            )
            .unwrap_err();
        assert_eq!(err, BundleError::BadSignature);
    }

    #[test]
    fn an_unknown_key_id_never_reaches_the_verifier() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        let mut t = TrustStore::new();
        t.add_key_hex("some-other-key", &public_key_hex(&sk))
            .unwrap();
        let err = SignedBundle::parse(&raw)
            .unwrap()
            .verify(&t, &Sequence::in_memory(), &VerifyPolicy::default())
            .unwrap_err();
        assert_eq!(err, BundleError::UnknownKey("k1".into()));
    }

    #[test]
    fn a_revoked_key_is_refused_even_though_its_signature_is_valid() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        let mut t = store("k1", &sk);
        t.revoke("k1", "laptop stolen");
        let err = SignedBundle::parse(&raw)
            .unwrap()
            .verify(&t, &Sequence::in_memory(), &VerifyPolicy::default())
            .unwrap_err();
        assert_eq!(err, BundleError::RevokedKey("k1".into()));
    }

    // The attack this whole sequence mechanism exists for: every signature is
    // genuine, nothing is tampered with, and the bundle is still hostile
    // because it is OLD.
    #[test]
    fn a_replayed_older_bundle_is_refused_although_it_is_genuinely_signed() {
        let sk = key(1);
        let t = store("k1", &sk);
        let seq = Sequence::in_memory();
        let p = VerifyPolicy::default();

        let strict = bundle(&sk, 7, "rules: [strict]\n").to_bytes();
        let applied = SignedBundle::parse(&strict)
            .unwrap()
            .verify(&t, &seq, &p)
            .unwrap();
        seq.commit(applied.sequence());

        // An attacker replays the genuinely-signed empty policy from release 3.
        let old = bundle(&sk, 3, "rules: []\n").to_bytes();
        let err = SignedBundle::parse(&old)
            .unwrap()
            .verify(&t, &seq, &p)
            .unwrap_err();
        assert_eq!(
            err,
            BundleError::Rollback {
                offered: 3,
                applied: 7
            }
        );
    }

    #[test]
    fn the_same_sequence_twice_is_also_a_rollback() {
        let sk = key(1);
        let t = store("k1", &sk);
        let seq = Sequence::in_memory();
        seq.commit(7);
        let err = SignedBundle::parse(&bundle(&sk, 7, "x").to_bytes())
            .unwrap()
            .verify(&t, &seq, &VerifyPolicy::default())
            .unwrap_err();
        assert!(matches!(err, BundleError::Rollback { .. }));
    }

    #[test]
    fn the_sequence_high_water_mark_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("eg_seq_{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        {
            let s = Sequence::at_path(&dir);
            s.commit(41);
            s.commit(12); // must not move it backwards
            assert_eq!(s.applied(), 41);
        }
        let reopened = Sequence::at_path(&dir);
        assert_eq!(reopened.applied(), 41);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn a_bundle_for_another_tenant_is_refused() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        let p = VerifyPolicy {
            expect_tenant: Some("globex".into()),
            ..Default::default()
        };
        let err = SignedBundle::parse(&raw)
            .unwrap()
            .verify(&store("k1", &sk), &Sequence::in_memory(), &p)
            .unwrap_err();
        assert!(matches!(err, BundleError::WrongTenant { .. }));
    }

    #[test]
    fn an_expired_bundle_is_refused_and_a_future_one_too() {
        let sk = key(1);
        let now = now_unix();
        let t = store("k1", &sk);
        let p = VerifyPolicy::default();

        let expired = SignedBundle::create(
            &sk,
            "k1",
            "b",
            "acme",
            1,
            now - 7200,
            now - 3600,
            b"x".to_vec(),
        )
        .unwrap()
        .to_bytes();
        assert!(matches!(
            SignedBundle::parse(&expired)
                .unwrap()
                .verify(&t, &Sequence::in_memory(), &p),
            Err(BundleError::Expired { .. })
        ));

        let future = SignedBundle::create(
            &sk,
            "k1",
            "b",
            "acme",
            1,
            now + 7200,
            now + 9000,
            b"x".to_vec(),
        )
        .unwrap()
        .to_bytes();
        assert!(matches!(
            SignedBundle::parse(&future)
                .unwrap()
                .verify(&t, &Sequence::in_memory(), &p),
            Err(BundleError::NotYetValid { .. })
        ));
    }

    #[test]
    fn a_bundle_that_never_expires_is_refused() {
        let sk = key(1);
        let now = now_unix();
        let raw = SignedBundle::create(
            &sk,
            "k1",
            "b",
            "acme",
            1,
            now - 60,
            u64::MAX / 2,
            b"x".to_vec(),
        )
        .unwrap()
        .to_bytes();
        assert!(matches!(
            SignedBundle::parse(&raw).unwrap().verify(
                &store("k1", &sk),
                &Sequence::in_memory(),
                &VerifyPolicy::default()
            ),
            Err(BundleError::ValidityWindowTooLong { .. })
        ));
    }

    // Length-prefixing the signed input is what stops this: without it,
    // moving a character from `tenant` into `bundle_id` produces the same
    // concatenated byte string and the old signature would still verify.
    #[test]
    fn field_boundaries_cannot_be_shifted_while_keeping_the_signature() {
        let a = BundleHeader {
            key_id: "k".into(),
            bundle_id: "ab".into(),
            tenant: "c".into(),
            sequence: 1,
            not_before: 0,
            not_after: 1,
            payload_sha256: [0; 32],
            payload_len: 0,
        };
        let b = BundleHeader {
            bundle_id: "a".into(),
            tenant: "bc".into(),
            ..a.clone()
        };
        assert_ne!(a.signing_input(), b.signing_input());
    }

    #[test]
    fn a_duplicate_header_field_is_a_parse_error_not_last_wins() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "x").to_bytes();
        let txt = String::from_utf8(raw).unwrap();
        let smuggled = txt.replacen("tenant: acme", "tenant: acme\ntenant: globex", 1);
        assert!(matches!(
            SignedBundle::parse(smuggled.as_bytes()),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn a_truncated_payload_is_caught_at_parse_time() {
        let sk = key(1);
        let raw = bundle(&sk, 1, "rules: []\n").to_bytes();
        assert!(matches!(
            SignedBundle::parse(&raw[..raw.len() - 4]),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn garbage_never_panics_the_parser() {
        for case in [
            &b""[..],
            b"\n\n",
            b"edgeguard-bundle/1\n\n",
            b"edgeguard-bundle/9\nkey-id: a\n\npayload",
            b"edgeguard-bundle/1\nkey-id\n\n",
            b"edgeguard-bundle/1\nsignature: zz\n\n",
            &[0xff; 256],
        ] {
            let _ = SignedBundle::parse(case);
        }
        // A header that never terminates must be refused on a bound, not read
        // to the end of a multi-megabyte stream.
        let endless = vec![b'a'; 4 * 1024 * 1024];
        assert!(SignedBundle::parse(&endless).is_err());
    }

    #[test]
    fn a_bundle_that_fails_to_apply_does_not_burn_its_sequence_number() {
        let sk = key(1);
        let t = store("k1", &sk);
        let src = SignedRuleSource::new(t, Sequence::in_memory(), VerifyPolicy::default());
        let dir = std::env::temp_dir().join(format!("eg_bundle_{}.eg", std::process::id()));
        std::fs::write(&dir, bundle(&sk, 5, "rules: [bad").to_bytes()).unwrap();

        let failed: Result<(), LoadError<&str>> =
            src.load_and_apply(&dir, |_| Err("rule group did not compile"));
        assert!(matches!(failed, Err(LoadError::Apply(_))));
        assert_eq!(
            src.applied_sequence(),
            0,
            "a failed apply must not advance the sequence"
        );

        // The very same sequence number must still be acceptable on a retry.
        let ok: Result<(), LoadError<&str>> = src.load_and_apply(&dir, |_| Ok(()));
        assert!(ok.is_ok());
        assert_eq!(src.applied_sequence(), 5);
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn a_trust_store_with_no_keys_is_refused_at_provisioning_time() {
        let dir = std::env::temp_dir().join(format!("eg_empty_trust_{}", std::process::id()));
        std::fs::write(&dir, "# nothing here\n").unwrap();
        let seq = dir.with_extension("seq");
        assert!(SignedRuleSource::from_paths(&dir, &seq, VerifyPolicy::default()).is_err());
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn the_trust_store_text_format_round_trips_including_revocation() {
        let sk = key(3);
        let raw = format!(
            "# provisioned 2026-09-18\nprod-2026 {}\nold-2024 !revoked key-rotated\n",
            public_key_hex(&sk)
        );
        let t = TrustStore::from_str_repr(&raw).unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.is_revoked("old-2024"));
        assert!(t.resolve("prod-2026").is_ok());
    }
}
