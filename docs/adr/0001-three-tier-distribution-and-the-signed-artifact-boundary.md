# ADR-0001: Three-Tier Distribution and the Signed Artifact Boundary

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-20 |
| **Applies to** | `edgeguard-sdk` 0.9 onward |
| **Supersedes** | The implicit "one binary does everything" model of 0.7–0.8 |

---

## 1. Context

### 1.1 The apparent paradox

Two commitments appeared to be in direct conflict:

- **Edge-native DNA.** EdgeGuard is a zero-allocation, offline-first L7 filter. We
  rejected the "smart gateway" shape and deferred the ONNX tier specifically
  because they destroy the constraints that make the engine deployable inside an
  NGINX worker or on firmware.
- **Adoption reality.** Pure C/C++ FFI is high-friction. Without a drop-in
  OpenAI/Ollama-shaped entry point, a large share of the market never evaluates
  the product at all.

The stated conclusion was that these are incompatible in one binary, and that we
must choose between a microsecond firewall and a developer-friendly router.

### 1.2 Why the paradox dissolves

It does not survive our own benchmark. `examples/gate_bench.rs`, release build,
`TieredEngine::inspect_owned` over clean prose:

| Input | Scan cost | Rate |
|---|---|---|
| 64 B | 0.36 µs | 5.66 ns/byte |
| 256 B | 1.32 µs | 5.16 ns/byte |
| 1 KB | 5.11 µs | 4.99 ns/byte |
| 16 KB | 80.8 µs | 4.93 ns/byte |

Cost is linear at ~5 ns/byte. The headline **1.7 µs is a ~300-byte prompt** — it
is not a constant, and it is not a property of the product.

Now price the two deployments separately:

| Deployment | What dominates | Scan cost against it |
|---|---|---|
| Envoy/NGINX filter, 50k RPS/core | core-time | 1.3 µs × 50k = **6.5% of a core**. At 100 µs it would be 5 cores. |
| In-process agent loop, per tool call | sub-ms local work | negligible |
| Sidecar in front of hosted LLM | 200 ms–2 s TTFT | ~0.0005% |
| Sidecar in front of local Ollama | 50–500 ms | ~0.003% |

The decisive detail: a RAG-stuffed proxy prompt is 4–32 KB. At 32 KB the engine
costs **~160 µs**, which already exceeds the ~50–150 µs loopback HTTP hop we were
refusing to add. *In the proxy deployment, our own engine costs more than the
transport we feared.*

Latency is a property of a call path, not of a binary. Putting an HTTP server in
the same process does not slow a pure function. What actually kills the hot path
is shared mutable state, blocking I/O on the scanning thread, and unbounded
per-request allocation — all of which are governable, and all of which we have
already governed twice (§2.2).

### 1.3 What the DNA actually is

> **There must always exist a call path where a scan costs ~1.3 µs, allocates
> nothing on the clean path, makes no syscall, and requires no daemon.**

The DNA is not "every artifact we ship is 1.7 µs." It is that the above path
remains *reachable and uncompromised*. We protect it by keeping it a first-class
shipped artifact, not by refusing to ship anything with a socket in it.

### 1.4 The second problem: nothing loaded from disk can be trusted

Resolving the distribution question exposes a second one. A daemon that fetches
policy and a classifier is only as trustworthy as the weakest artifact it loads,
and today:

- **`policy.yaml` hot-reload is unauthenticated.** `PolicyEngine::new` spawns a
  watcher that polls `mtime` every second and adopts whatever the file now
  contains — no signature, no ownership check — while `src/signing.rs` provides a
  complete Ed25519 bundle path that the loader does not use. Any local write
  primitive disables detection within one second. (Audit finding 6, deliberately
  left open in the 0.9 hardening pass; this ADR closes it.)
- **`ModelConfig` takes bare paths.** `model_path` and `vocab_path` are
  `PathBuf`s handed straight to `Session::commit_from_file`. Swapping the model
  makes the classifier answer "benign" to everything.
- **`ORT_DYLIB_PATH` is an arbitrary-code-execution vector.** `Cargo.toml`
  configures `ort` with `load-dynamic`, so ONNX Runtime is resolved at *runtime*
  from an environment variable. Whoever controls that variable, or the file it
  names, executes native code inside the guardrail process. This is the only
  item on the list that is RCE rather than bypass.

A distribution decision that ignores this ships the friction-free product with
the weakest trust boundary.

---

## 2. Decision

### 2.1 Three distributions, one engine

We ship **one decision engine in three distributions**, with **zero forks of the
decision logic**:

| Tier | Artifact | Transport | Latency class | Semantic tier |
|---|---|---|---|---|
| 1 | `libedgeguard` (staticlib/cdylib) + `edgeguard.h` | in-process FFI | ~1.3 µs, no syscall | never |
| 2 | Language bindings (PyPI wheel, N-API, cgo) | in-process | µs + marshalling | deferred only |
| 3 | `edgeguardd` | HTTP/TLS, OpenAI & Ollama wire-compatible | bounded by upstream LLM | **inline, enforcing** |

### 2.2 The invariant

The boundary is not "core vs wrapper." It is already written in
`src/deferred.rs`:

> **`inspect()` never waits for this module, and never fails because of it.**

That invariant is why `DeferredQueue` can hold raw prompt text, open SQLite,
spawn a thread and do disk I/O *inside the core crate* without corrupting it: a
bounded `try_send` that drops rather than blocks, all SQLite on one owned thread,
a cooldown rather than a spin, and a counter for every drop. We applied the same
discipline to `audit_queue` (structurally separated from `deferred`) and to
`sign_bundle.rs` (kept in `examples/` so the edge SDK never links private-key
handling).

`edgeguardd` is that pattern at a larger radius. The admission test for anything
entering the core is:

- Can it block a scanning thread? → **out**
- Can it allocate unboundedly per request? → **out**
- Does it need a clock, a socket, or tenancy? → **out**
- Does it pull in an async runtime? → **out**, and this is the one that kills us

### 2.3 The dependency rule (the enforceable part)

> **`edgeguardd` is a `Cargo.toml` consumer of the core crate. It is never a
> feature flag on it.**

A workspace whose dependency arrow points one way is architecture. A
`#[cfg(feature = "http")]` is a promise, and promises rot — someone eventually
flips it in the embedded build to get "just one metric." If `tokio`, `hyper`, or
any async runtime appears in `edgeguard-sdk`'s dependency tree, gated or not,
this ADR has been violated.

---

## 3. Tier 1 — `libedgeguard`, the deterministic core

### 3.1 What it is

Normalize → rule graph → deterministic detectors → verdict. A POD
`edgeguard_decision_t` out. Immutable after construction, internally
synchronized, safe from any number of threads. Fails closed on panic, on invalid
UTF-8, and on a NULL handle. This is the artifact the 1.3 µs claim describes, and
the **only** one permitted to make it.

### 3.2 What it may never gain

- No socket, no TLS, no async runtime, no HTTP types.
- No clock in the scan path. Time enters only at bundle verification (§6).
- No filesystem access in the scan path. Rules arrive **already compiled, in
  memory**.
- No ONNX. The semantic tier in the core stays `SemanticMode::Deferred` at most —
  telemetry, never enforcement.

### 3.3 Where verification lives

`src/signing.rs` stays in the core crate, because an NGINX filter pulling rule
bundles genuinely needs to verify them, and duplicating the format in the daemon
would be a second implementation to disagree with the first. It is admissible
because **verification is a construction/reload-time operation that never touches
`inspect()`**.

Two consequences:

- `ed25519-dalek` should move behind a **default-on `signing` feature**, so a
  firmware build with rules baked in at compile time can drop it entirely.
- The core exposes verification as a *capability*, not a policy. It does not
  fetch, does not schedule, does not decide when to reload. Those belong to the
  caller.

### 3.4 The seam

The core's public contract to every tier above it:

```
compiled rules (in memory)  →  Engine  →  Decision (POD)
```

Everything about *where the rules came from* is the caller's problem. That is
precisely what keeps the core purely deterministic: it has no notion of trust,
keys, freshness, or tenancy, so there is no trust decision it can get wrong.

---

## 4. Tier 2 — language bindings

### 4.1 Why this tier absorbs most of the DX problem

Our adoption friction is **packaging, not FFI**. The evidence is in this repo, in
four places:

- `import edgeguard` on a developer machine in this project resolved to a stale
  ctypes wrapper exposing only `EdgeGuard` — no `TieredGuard`, no
  `StreamScanner`. The real extension was shadowed by a same-named package.
- `examples/test_middleware.py`'s entire docstring is about that failure mode.
- `residual_gap_protocol.py` carries a `provenance_gate()` written to defend
  against it.
- `CHANGELOG.md` records "pip-installed user silently lost API-key and secret
  detection."

Nobody in that story was blocked by C. They were blocked by
`maturin develop --release`, an import-name collision, and a `policy.yaml`
resolved by relative path.

### 4.2 Requirements

1. **Prebuilt wheels** for the obvious triples (manylinux x86_64/aarch64, macOS
   universal2, Windows x86_64). `pip install edgeguard` must work with no Rust
   toolchain.
2. **Policy ships inside the package.** The baseline rule graph is compiled in;
   `policy.yaml` is packaged as data and resolved from the package root, not from
   `dirname(__file__)/..`. This closes the class of bug where a relocated script
   silently loses the `sk-`/`ghp_`/`AKIA` detectors. (0.9 already made a
   non-loadable `policy_path` a hard construction error — see ADR §7.)
3. **Import-name provenance.** The extension exposes a build fingerprint
   (version, git SHA, feature set) and the `TieredGuard`/`StreamScanner` symbols
   are the tell. Shadowing must fail loudly, not silently.
4. **No fetching.** Bindings never reach the network. They accept a verified
   bundle from the host application, or they run the baked-in baseline.

### 4.3 Bindings and the trust chain

A binding may *verify* (it links the core, which includes `signing`) but never
*acquire*. The host application supplies bytes; the binding hands them to
`SignedRuleSource::load_and_apply`. This keeps the binding offline-capable and
keeps the acquisition policy — retries, backoff, endpoint pinning — in exactly
one place: `edgeguardd`.

### 4.4 Honest performance caveat

`decision_to_dict` performs ~17 `set_item` calls, a `Vec` collect for obfuscation
names, and several `String` allocations per call. Marshalling plausibly costs
2–3× the scan itself. **We do not quote 1.3 µs for `TieredGuard.inspect()`** —
that number belongs to Tier 1. If a fast Python path is wanted later, a
`scan_fast()` returning `(verdict, code)` is cheap to add.

---

## 5. Tier 3 — `edgeguardd`

### 5.1 What it owns

HTTP/TLS termination, OpenAI and Ollama wire compatibility, SSE stream
reassembly, upstream connection pooling, auth, rate limiting, tenancy, the
control-plane relationship (bundle fetch, audit outbox shipping), and **the
inline semantic tier**.

### 5.2 Why the sidecar is not a compromise

We deferred ONNX because it breaks edge-native constraints. But we already built
`SemanticMode::Deferred`, `DeferredQueue` and `SlowPathWorker` — a complete
fast-path/slow-path architecture whose own documentation says deferral is "the
right trade for a fast-path triage router, and the wrong one for a tool-calling
agent with shell access." `TierConfig::tier2_budget` is 5 ms.

A 5 ms budget is absurd for a firmware filter. It is unremarkable inside a proxy
already waiting on a 300 ms LLM call.

**`edgeguardd` is where the semantic tier becomes enforcing rather than
telemetry.** We designed the tiering thesis for a deployment we had not yet
built. This is that deployment. The DX win is a side effect.

### 5.3 Verdict parity is a test, not a promise

`src/ffi.rs` already contains
`the_c_abi_and_the_rust_api_agree_verdict_for_verdict`. That test is the
template. **One corpus, N transports, identical verdicts, asserted in CI**, from
the first commit of `edgeguardd` — before it has users to disappoint.

Corollary: **`edgeguardd` gets no policy semantics of its own.** No modes the
library lacks, no verdicts the library cannot produce, no proxy-only rules. The
moment the daemon can block something the library allows, we have two products
and customers who trust neither.

---

## 6. The trust chain

### 6.1 Governing principle

> **The filesystem supplies bytes. The trust store decides whether they count.**

Every artifact that can change a verdict, or execute code, is either carried
inside a signed bundle or verified against a digest that is. There are no
exceptions, and "it's on a read-only mount" is not one.

### 6.2 Threat model

| # | Attack | Consequence | Control |
|---|---|---|---|
| T1 | Overwrite `policy.yaml` | detection disabled in ≤1 s | §6.4 — unsigned files are no longer a load path |
| T2 | Replay an older, legitimately-signed bundle with weaker rules | silent coverage regression | `Sequence` monotonic counter |
| T3 | Replay tenant A's bundle onto tenant B's fleet | wrong policy, cross-customer leak | `tenant` is a signed header field + `VerifyPolicy::expect_tenant` |
| T4 | Swap the ONNX model | classifier always benign | §6.5 — digest in the signed manifest |
| T5 | Swap `libonnxruntime.so` via `ORT_DYLIB_PATH` | **native RCE in the guardrail process** | §6.6 — env ignored, digest pinned |
| T6 | Compromise a signing key | mint bundles | `MAX_VALIDITY_WINDOW_SECS` (~13 months) bounds the blast radius; `TrustStore::revoke` |
| T7 | Malformed bundle as a DoS | verifier burns CPU | cheap refusals before Ed25519; `MAX_PAYLOAD_BYTES`, `MAX_HEADER_BYTES` |
| T8 | Hostile ONNX graph from a *valid* signer | parser exploitation in ORT's C++ | §6.7 — honest limits |

### 6.3 The single anchor

The **trust store** (`key_id → Ed25519 public key`, plus revocations) is the only
thing provisioned out of band. Rules:

- Provisioned at image build or device enrolment, never fetched over the same
  channel as bundles. A trust store that can be updated by a bundle is not an
  anchor.
- Mounted read-only; `0400`, owned by a different uid than the daemon runs as,
  where the platform allows.
- **Key rotation is additive-then-subtractive**: the successor key is present in
  every deployed trust store *before* the predecessor is revoked. There is no
  window in which a fleet can receive a bundle it cannot verify.

### 6.4 The bundle signs a manifest, not just rules

`SignedBundle` already gets the hard parts right and we are not redesigning it:
typestate that makes `payload()` unreachable without a `TrustStore`; a
length-prefixed `signing_input()` immune to field-boundary confusion;
authenticate-before-believe ordering in `verify()`; cheap refusals ahead of the
signature check.

The change is to the **payload's shape**. `MAX_PAYLOAD_BYTES` is 8 MiB and a
TinyBERT-class ONNX export is 15–60 MB, so inlining the model is not merely
undesirable, it is impossible. The payload therefore becomes a **manifest**:

| Artifact | Carriage | Rationale |
|---|---|---|
| Rule graph / policy | **inline** | kilobytes; must be atomic with the manifest |
| Tokenizer + `ModelConfig` | **inline** | small, and must move in lockstep with the model |
| ONNX model | **by SHA-256 digest** | too large for the payload cap |
| Vocab file | **by SHA-256 digest** | must match the model exactly |
| ONNX Runtime dylib | **by SHA-256 digest + expected version** | see §6.6 |

This is the standard signed-manifest + content-addressed-blob pattern. The
signature covers the manifest; the manifest covers the blobs; the blobs may
travel over any transport, including an untrusted CDN or a sneakernet USB stick,
because their integrity does not depend on how they arrived.

**`policy.yaml`'s unauthenticated `mtime` watcher is deleted.** Reload is
bundle-mediated: the only way new rules enter a running process is a verified
bundle with a higher sequence. This closes T1 and audit finding 6.

### 6.5 Model and vocab

- Digest verified **before** the bytes reach `Session::commit_from_file`. Never
  load-then-verify.
- Model and vocab digests are verified **together**. A matching model with a
  mismatched vocab is a silently degraded classifier, not an error ORT will
  raise.
- `ModelConfig` gains the digests. The daemon must not be able to construct a
  scorer from bare paths; that constructor becomes unavailable outside tests.
- A digest mismatch is fatal to the *reload*, not to the *process*: keep the
  last known-good model, emit a critical alert.

### 6.6 `ORT_DYLIB_PATH` — the RCE, not a bypass

This gets the strictest treatment on the list because it is the only item that
yields code execution rather than a missed detection.

1. **The daemon does not honour `ORT_DYLIB_PATH` from the environment.** `ort`
   exposes a programmatic dylib path on its environment builder; the daemon sets
   it from its verified manifest. *(Implementation note: confirm the exact
   builder API against `ort` 2.0.0-rc.13 during implementation — the crate is
   pre-release and this surface has moved.)*
2. If the variable is set in the process environment and disagrees with the
   pinned path, the daemon **refuses to start** and says why. Silently
   overriding an operator's environment is as bad as obeying it.
3. The path must be **absolute** and inside the daemon's read-only install root.
   No relative paths, no `$ORIGIN`, no search-path resolution.
4. The digest is verified **before `dlopen`**. After `dlopen` it is too late by
   definition.
5. The `onnx` feature stays **off by default** in the core. Only `edgeguardd`
   turns it on. An NGINX worker must never be in a position to `dlopen` anything.

### 6.7 What digest verification does *not* buy

Stated plainly so nobody over-reads the control: a verified digest proves
**provenance**, not **safety**. An ONNX model is protobuf parsed by a large C++
library, and a hostile graph signed by a *legitimately compromised* control plane
is still parsed by ORT. Mitigations are defence-in-depth, not proof:

- The semantic tier runs **only** in `edgeguardd`, never in an NGINX worker or on
  firmware — blast radius is one sidecar process.
- The sidecar runs non-root with a constrained syscall profile and memory
  ceiling.
- `hard_budget` (default 5 ms) already terminates a runaway inference via ORT's
  terminate flag rather than measuring the overrun afterwards.
- Running inference in a separate, resource-limited subprocess is the next
  increment if the threat model demands it. Recorded as an open question (§9),
  not decided here.

### 6.8 Load order and failure modes

The only permitted order, at startup and at every reload:

```
fetch → parse (syntax only, attacker-controlled)
      → verify signature against TrustStore
      → check time window / sequence / tenant
      → verify artifact digests
      → compile rules + build session pool   [staging, off the request path]
      → atomic swap (Arc)
```

Failure handling:

| Condition | Behaviour |
|---|---|
| Verification fails, **known-good exists** | keep known-good, alert, do not retry in a tight loop |
| Verification fails, **no known-good** | **refuse to start.** Do not serve traffic unguarded. |
| Digest mismatch on model only | keep known-good model, serve rules from the new bundle only if the manifest permits decoupling; otherwise reject the whole bundle |
| Partial compile failure | reject the whole bundle. Never partially apply. |
| `Sequence` commit | **only after** a successful atomic swap, never before |

The "refuse to start" row is the same principle as the 0.9 change to
`PolicyEngine::new`: a guardrail that cannot load its rules must refuse to exist,
not pretend it has none to load.

### 6.9 What the core never knows

Restating §3.4 against the crypto design, because this is the load-bearing
separation:

The core has **no clock in the scan path, no keys on the scan path, no network,
and no filesystem access on the scan path**. `verify()` takes the `TrustStore`,
the `Sequence` and the `VerifyPolicy` as *arguments*, so even the verification
capability holds no ambient state. There is no trust decision the deterministic
engine can get wrong, because there is no trust decision it is able to make.

---

## 7. Consequences

**Positive**

- The 1.3 µs path survives as a shipped artifact with a test that guards it.
- The semantic tier becomes deployable and *enforcing* for the first time.
- `policy.yaml`'s unauthenticated hot-reload is eliminated rather than patched.
- One decision engine means one detection reputation, guarded by a parity corpus.
- Bindings are offline-capable and network-free, which keeps the privacy claim
  true for the largest tier by user count.

**Negative / accepted costs**

- Three release artifacts, three CI matrices, three support surfaces.
- The parity corpus is ongoing work and will occasionally block a release. That
  is the cost of the guarantee, and it is cheaper than the alternative.
- Bundle-mediated reload is slower to iterate on than editing a YAML file.
  Development ergonomics need an explicit, loudly-logged `--insecure-local-policy`
  escape hatch that is **compiled out of release builds**, not merely
  default-off.
- `edgeguardd` reopens surface the 0.9 audit closed: a daemon writing an audit DB
  to a shared volume is a different threat model than a library writing `0600` in
  a process-owned directory. Must be designed in, not bolted on.

**Neutral**

- `ed25519-dalek` behind a default-on feature is a small, mechanical breaking
  change for no-std-adjacent consumers.

---

## 8. Negative constraints

This ADR is violated — and must be revisited, not quietly worked around — if any
of the following becomes true:

1. `tokio`, `hyper`, or any async runtime appears in `edgeguard-sdk`'s dependency
   tree, gated or otherwise.
2. `edgeguardd` can produce a verdict `libedgeguard` cannot, or block input the
   library allows.
3. Any artifact that can change a verdict, or be `dlopen`ed, is loaded without
   digest or signature verification.
4. The trust store becomes updatable through the bundle channel.
5. `inspect()` acquires a call that can block, allocate unboundedly, or fail
   because of a downstream subsystem.
6. The semantic tier runs inline anywhere outside `edgeguardd`.
7. A verification failure results in an *empty* policy rather than the last
   known-good policy or a refusal to start.

---

## 9. Open questions

- **Subprocess isolation for ORT.** Deferred (§6.7). Decide once we have a real
  model and a real threat model from a design-partner deployment.
- **Bundle distribution transport.** Control-plane pull vs. OCI registry vs.
  both. The signed-manifest design is transport-agnostic by construction, so this
  can be decided later without reopening the ADR.
- **Audit DB threat model for `edgeguardd`.** A shared volume in a
  multi-tenant orchestrator is materially different from the library case.
- **Whether Tier 2 bindings should ever verify bundles at all**, or whether
  accepting only baked-in rules is a cleaner contract. Currently permitted (§4.3)
  but not required by any known user.
- **`ort` pre-release churn.** We depend on `2.0.0-rc.13`. The dylib-path and
  session-builder APIs are not yet stable.

---

## 10. Sequencing

| Step | Work | Why this order |
|---|---|---|
| **1** | **Python packaging.** Prebuilt wheels, packaged policy data, import-name provenance. | Removes most real-world friction for ~5% of the effort of a proxy. Building a network daemon to fix a packaging bug is the expensive way to fix the wrong thing. |
| 2 | Workspace split: `edgeguard-core`, `edgeguard-bindings`, `edgeguard-daemon`. Dependency arrow enforced in CI. | Must precede any daemon code, or the boundary is retrofitted rather than designed. |
| 3 | Manifest bundle format; delete the `mtime` watcher; `signing` feature gate. | Closes T1/T4 before there is a daemon that depends on them. |
| 4 | Parity corpus in CI. | Must exist before `edgeguardd` has users. |
| 5 | `edgeguardd` — wire compatibility, then inline semantic tier with the §6.6 dylib pinning. | The payoff, once the ground under it is sound. |

**Step 1 is next and proceeds independently of the rest.**

---

## Appendix A — Evidence index

Claims in this ADR trace to the following, as of commit `d2ce0f2` plus the 0.9
hardening pass:

| Claim | Source |
|---|---|
| ~5 ns/byte, 1.3 µs @ 256 B | `examples/gate_bench.rs`, release build |
| `inspect()` never waits / never fails | `src/deferred.rs` module header |
| Private-key code excluded from the SDK | `examples/sign_bundle.rs:3-5` |
| Typestate verification, length-prefixed signing input | `src/signing.rs:259-330`, `:740-760` |
| 8 MiB payload cap | `src/signing.rs:107` (`MAX_PAYLOAD_BYTES`) |
| ~13-month validity cap | `src/signing.rs:103` (`MAX_VALIDITY_WINDOW_SECS`) |
| Unauthenticated `mtime` policy reload | `src/lib.rs`, `PolicyEngine::new` watcher thread |
| `ort` resolved at runtime via `ORT_DYLIB_PATH` | `Cargo.toml:21`, `src/semantic.rs:45-46` |
| Bare model/vocab paths, no digest | `src/semantic.rs:214-218`, `SessionPool::build` |
| 5 ms Tier 2 budget; terminate-flag watchdog | `src/tier.rs` `TierConfig`, `src/semantic.rs` `hard_budget` |
| Deferral is telemetry, not enforcement | `src/tier.rs`, `SemanticMode::Deferred` docs |
| C/Rust verdict parity precedent | `src/ffi.rs::the_c_abi_and_the_rust_api_agree_verdict_for_verdict` |
| Packaging friction evidence | `examples/test_middleware.py` docstring; `residual_gap_protocol.py::provenance_gate`; `CHANGELOG.md` |
