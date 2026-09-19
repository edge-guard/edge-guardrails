# Changelog

All notable changes to EdgeGuard SDK are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.8.0] — 2026-09-20

The Fast-Path/Slow-Path release. Tier 1 becomes an explicit triage router: it
decides what it can decide deterministically, and says so plainly when it
cannot. It also carries a breaking API change, taken deliberately now rather
than dragged into 1.0.

### ⚠️ BREAKING CHANGES

**Verdict names.** No aliases, no deprecation window.

| Before | After |
|---|---|
| `Verdict::Allow` | `Verdict::Pass` |
| `Verdict::Flag` | `Verdict::NeedsSemanticCheck` |
| `EDGEGUARD_VERDICT_ALLOW` | `EDGEGUARD_VERDICT_PASS` |
| `EDGEGUARD_VERDICT_FLAG` | `EDGEGUARD_VERDICT_NEEDS_SEMANTIC_CHECK` |
| Python `"allow"` | Python `"pass"` |
| Python `"flag"` | Python `"needs_semantic_check"` |

*Why:* "Flag" named what a caller might **do** about a result. The new name
names what the engine actually **concluded** — and after this release it is
literally true: the fast path deliberately did not decide.

*Migration:*

- **C hosts** — numeric values are unchanged (`0`/`1`/`2`). Code comparing
  against literals still behaves correctly; code using the old macro names
  will fail to compile. That is intended: a silently renamed verdict is worse
  than a build error.
- **Python** — update any comparison against `"allow"` or `"flag"`.
- **SIEM rules** — any rule matching the strings `"allow"` or `"flag"` must be
  updated. `decided_by` values are unchanged.

`Action::Allow` and `Action::Flag` are **not** affected. They are a different
type — what a *rule* does, not what the *engine* concluded — and conflating
the two is the confusion this rename removes.

### Added

**`SemanticMode::Deferred` — out-of-band semantic scoring.**
`TierConfig::semantic_mode` selects where Tier 2 runs. `Inline` (default,
unchanged behaviour) scores within the request and can refuse it. `Deferred`
parks the prompt and returns immediately, trading enforcement for latency.

Stated plainly because it matters: a verdict that arrives after the response
was sent cannot stop it. `Deferred` produces **telemetry** for the current
request, which is the right trade for a fast-path triage router and the wrong
one for a tool-calling agent with shell access.

**`Decision::interim`** — what to serve *now*, while the semantic answer is
outstanding. `Some` exactly when something is pending, `None` on every path
that reached a real verdict. Derived solely from the existing
`FallbackPolicy`, so a deferral cannot contradict the deployment's chosen risk
posture. Exposed to Python as `interim`.

**`deferred::DeferredQueue` — local-only slow-path store.** Holds raw prompt
text, because a semantic model cannot score a category. Deliberately **not**
the audit outbox, and the separation is structural rather than documented:

- its own database file and schema;
- both `DeferredQueue::open` and `DeferredWorker::open` refuse any database
  containing an `audit_outbox` table;
- no ship/ack cycle, no serialization to bytes — nothing in the module can put
  a row on a network;
- rows expire (1 h default), enforced on read as well as by a sweeper;
- `complete()` deletes; `purge_all()` is the operator's forget-everything
  control.

`DEFAULT_DB_FILENAME` and `beside_audit_db()` make a collision with the audit
outbox impossible by default rather than merely detectable.

**`slowpath::SlowPathWorker`** — drains the queue, scores with any
`SemanticScorer`, writes the **classification** to the audit outbox, deletes
the row. The only component that needs the `onnx` feature. An absent model is
terminal rather than retried forever; a failing one retries to
`max_attempts` then drops as poison — either way an audit record is written,
because a prompt that silently disappears is worse than one scored wrong.

**Agentic routing rules (baseline 20–25).** All `Action::Flag`: they widen
what the model *sees* and decide nothing. Before them, Tier 2 was consulted on
**0 of 33** in-scope enterprise attacks — clean-prose attacks tripped no rule
and were allowed without the model being asked.

**Decoders.** `\xNN`, `&#105;`, `&#x69;` join the existing `%NN` pass, and
base64 / raw-hex "lanes" decode payloads into separate buffers scanned by the
existing rules.

**Tooling.** `residual_gap_protocol.py`, `corpus_enterprise.py`,
`measure_grey_rate.py`, `examples/slowpath_demo.rs`.

### Changed

- **Unicode tag block (`U+E0020..=U+E007E`) is decoded, not stripped.** It was
  classed as zero-width, which *deleted* a smuggled payload before any rule
  could see it. It is a substitution cipher, not whitespace.
- **`block_on_hostile_obfuscation` now gates on the whole `HOSTILE` set**, not
  `BIDI_OVERRIDE` alone. The code, the field doc and the constant had all
  disagreed; zero-width splitting was documented as blocked and was not.
- **`STRETCHED` removed from `HOSTILE`.** It is a run-length observation, not
  an evasion: it fires on 8 of 8 ordinary emphatic English samples
  (`"Thanks!!!"`, `"Sooooo"`). It still counts toward `layers()`.
- **pyo3 0.22.6 → 0.29.2**, clearing RUSTSEC-2025-0020 and RUSTSEC-2026-0177.
- **`policy.yaml` is packaged into the wheel.** It was not, and
  `EdgeGuard()` with no `policy_path` loads *zero* policy rules — so a
  pip-installed user silently lost API-key and secret detection.
- Dockerfile rewritten multi-stage, non-root (uid 10001), audit DB on a volume
  outside the served tree, with a health check that actually imports the
  extension. New `.dockerignore` keeps `target/`, `.venv/` and every `*.db`
  out of the build context.
- `release.yml`: `cargo audit` as a hard gate, `--no-default-features` tests,
  per-OS artifact names, sdist job, and a smoke test that installs and imports
  the built wheel.
- `requires-python` raised to 3.9 to match what the tooling already targeted.

### Fixed

- **`redteam_adaptive.py`'s regression gate never ran.** A loop rebound
  `legacy`/`tiered` — the names holding the two engines its closures capture —
  to booleans, so the run died before reaching the gate. The `max_bypass` /
  `max_fpr` ceilings had therefore never been evaluated.
- **Tag-run seam.** Decoding alone welded a smuggled payload to the visible
  text (`"Hello" + tag("ignore …")` → `"helloignore …"`), which `whole_word`
  matching correctly declined to match.
- **`DeferredWorker::claim` attempt count** was read before the increment, so
  a worker's "give up after N" check was permanently off by one.
- **`decision_to_dict` was missing `DecidedBy::Tier2Deferred`** — only
  `cargo check --features python` catches that class of gap.
- **`examples/test_middleware.py` ImportError.** It imported `guard_prompt`,
  `wrap_ollama_stream` and `GuardrailViolationException`, which belong to an
  older ctypes wrapper installed under the same import name.
- **`test_tiered_guard.py`** pinned `code: 4001` on a tenant rule, outside the
  `10_000..=19_999` operator band, so the rule was skipped and four checks
  asserted against a rejected rule. Now 71/71 rather than 66/71.

### Security

- Prompt text is confined to `DeferredQueue` and never reaches the audit
  outbox, which is the store that leaves the device. Asserted by a test that
  scores a payload containing a canary and checks the canary does not appear
  in the outbox.
- New CI gates: the deterministic core must build and pass with no features,
  and `ort` must be absent from the default dependency tree.

### Known limitations

- **Semantic efficacy is unmeasured.** Routing is fixed — 16 of 33 residual
  attacks now reach Tier 2, up from 0 — but whether a TinyBERT-class model
  *catches* them has not been established. It needs an ONNX Runtime
  (`ORT_DYLIB_PATH`) and a model file, neither of which ships here.
  `examples/slowpath_demo.rs` is the harness; run it with `--model`/`--vocab`
  and the `onnx` feature. The bundled `HeuristicScorer` is a dependency-free
  stand-in and its numbers say nothing about a real model.
- **The attack corpus is self-authored** and should be reviewed by someone who
  did not write it before its rates drive a roadmap. At n=100 the confidence
  intervals are roughly ±9 pp.
- **`BENIGN_HOLDOUT` has been used for tuning** and is no longer an unbiased
  estimate of grey rate. A fresh holdout from real traffic is needed before
  quoting one externally.
- rot13 and payload reversal remain undecoded: whole-input transforms would
  add a full automaton pass to every request to catch two corpus cases.
- Business-logic abuse and data-scope escalation are explicitly out of scope —
  they need the application's authorization context, not a text filter.

---

## [0.7.0] — earlier

Post-hardening baseline: signed policy distribution, tiered router with an
inline semantic tier, latching stream scanner, offline audit outbox, banded
violation codes, C ABI.
