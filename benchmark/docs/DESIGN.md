# Routing Benchmark v0.1 — design

Engine frozen at `f664be6af727a5a1fa8f66e9e2ad07c109263acb`, verified each run
by `freeze::verify`, which hashes engine files rather than the repo HEAD (HEAD
moves whenever the benchmark itself is committed; the engine must not).

---

# Part 0 — Three things this document keeps apart

These are separate claims. Evidence for one is not evidence for another, and
the report must never let them blur.

### A. The architectural thesis

> Cheap deterministic security facts should be resolved before expensive
> semantic intelligence is invoked.

A claim about how agent security *should* be built. It is not owned by this
codebase, and no measurement of one implementation can settle it.

### B. The frozen implementation

> What commit `f664be6` can actually resolve today, on this corpus.

This is the **only** thing the benchmark measures. Every number produced here
is a statement about B.

### C. Future architectural potential

> Capabilities that might later raise deterministic coverage, and are **not**
> part of this benchmark.

Anything in C is explicitly out of scope. A case that B cannot resolve is not
a licence to build the C capability that would resolve it — see §9.

**Interpretation rules, binding on the report:**

- A weak result for B is a measurement of B. It does not disprove A. It bounds
  what *this implementation* resolves on *this corpus* today.
- A strong result for B does not prove A, and proves nothing at all about
  product-market fit, adoption, or commercial value. It says the fast path
  resolved a stated share of a corpus we built.
- Coverage that B lacks and C might supply must be labelled C, never reported
  as a defect of B and never used to justify changing B during this benchmark.

---

# Part 1 — What is measured

## 1.1 A selective classifier, not a binary one

EdgeGuard emits PASS, BLOCK, or ESCALATE. ESCALATE is a *refusal to answer*,
not a verdict. Collapsing it into PASS or BLOCK — as precision/recall framing
would — measures something the engine does not claim to be. So two axes are
scored separately: how often the fast path answered, and whether the answers
and the refusals were right.

## 1.2 EdgeGuard's full surface, not just ACTION

EdgeGuard is a deterministic fast path across **content facts**
(INPUT/OUTPUT, through the frozen Tier-1 content engine) and **structured
action facts** (ACTION). Reducing the benchmark to amount/tool comparisons
would measure a fraction of the thesis and the smaller fraction at that.

`FactDomain` (`Content` | `Action`) is therefore a first-class dimension.
`CaseShape` is derived from which domains carry the deciding facts:

| Shape | Meaning |
|---|---|
| `ContentOnly` | every deciding fact is readable from content |
| `ActionOnly` | every deciding fact is a structured action argument |
| `Mixed` | both domains carry an independently decisive fact |
| `NoDeterministicFact` | class S only |

Content facts are further reported per `ContentFactKind`: `Pii`, `Secret`,
`DeterministicPattern`, `ObfuscationOrEncoding`, `PolicyContentRule`. Action
facts per `ActionFactKind`: `AmountLimit`, `ForbiddenTarget`,
`MissingRequiredFact`, `ProvenanceMismatch`, `TypeMismatch`,
`StructuredConstraint`.

**Shape is independent of class.** An M case may be decided by a content fact
alone (obfuscated prose carrying a live credential), an action fact alone
(adversarial text plus an over-limit amount), or both.

**A property of B worth stating plainly:** on an ACTION event the frozen engine
evaluates action rules only — `evaluate_security_event` routes `Action` to
`evaluate_action`, which does not scan text. So an ACTION case's prose is not
content-scanned at `f664be6`. That is a fact about B, recorded here, and not a
defect to be fixed during the benchmark. Cross-channel content scanning on
action events is a **C** item.

## 1.3 Ground-truth classes

| Class | Definition | `expected` | What its failure mode measures |
|---|---|---|---|
| **D** | Deterministic facts suffice to reach PASS or BLOCK with no semantic reasoning | PASS or BLOCK | Escalating what an auditor could have decided from stated facts |
| **S** | No deterministic fact settles it | ESCALATE | Answering anyway — overconfidence |
| **M** | Semantically ambiguous or adversarial content, *plus* an independently decisive deterministic fact | PASS or BLOCK | The fact failing to win without semantics |

`true_safety` (Safe | Harmful) is a **separate axis** from `expected`:
`expected` scores routing, `true_safety` scores danger. An ESCALATE on harmful
content is a correct deferral, not a miss.

## 1.4 Deciding facts must be auditable without this codebase

A D or M case must carry at least one `DecidingFact`:

```rust
DecidingFact { domain, content_kind?, action_kind?, statement, observable_at }
```

`statement` must be checkable by an auditor who has never read this
repository: it describes the **event**, not any implementation.
`corpus::check_implementation_independence` rejects statements containing any
of `IMPLEMENTATION_TOKENS` — `edgeguard`, `tier1`/`tier 1`/`tier-1` (and
tier-2 forms), `eg_`, `tieredengine`, `evaluate_action`,
`evaluate_security_event`, `actionrule`, `aho-corasick`, `policy.yaml`,
`deobfuscat`, `detector`, `fast path`, `the engine`, `has a rule`,
`no rule for`, `currently`.

The circularity being blocked: if "this is class D because the engine has a
rule for it" were permitted, ground truth would be a function of the
implementation and the benchmark could only ever confirm what the engine
already does.

Good: *"the host-authoritative payment amount is 1,250,000 minor units, above
the 1,000,000 delegated authority the operator's policy states."*
Rejected: *"EdgeGuard currently has a rule for this action."*

## 1.5 Classification is frozen before execution

`locks::ClassificationLock` digests each case's `class`, `expected`,
`true_safety`, `deciding_facts`, `policy_environment_id`, and `usage`. It
deliberately **excludes the payload**: fixing a prose typo is not a
reclassification, but changing what a case claims to prove is. Any drift after
the lock is written fails the run. Classes may never be revised in response to
results.

---

# Part 2 — Policy environments

## 2.1 Why cases cannot carry rules

If a case may define the `ActionRule` that makes it decidable, the benchmark
measures the rule author. Case and rule get written together, the rule fits the
case exactly, and every ACTION result is a tautology.

So rules live in **frozen policy environments** under `policy_env/`, each an
independently authored operator policy. A case references one by id via
`policy_environment_id` and has no schema field through which a rule could be
attached.

### Schema — `policy_env/<id>_<version>.json`

```jsonc
{
  "id": "finance_company",
  "version": "v1",
  "description": "<which operator this represents, in prose>",
  "rules": [
    {
      "action_name": "execute_payment",
      "field": "amount_minor_units",
      "required_provenance": "HostAuthoritative",
      "comparator": "Gt",
      "threshold": { "type": "Integer", "value": 1000000 },
      "code": "EG_AMOUNT_OVER_LIMIT",
      "policy_id": "finance.payment.delegated_authority",
      "reason": "payment exceeds the agent's delegated authority",
      "retryable": false,
      "justification": "<why an operator would write this, in business terms>"
    }
  ]
}
```

`justification` is mandatory and is the audit surface: an environment must read
as a policy, not as a set of answers reverse-engineered from a comparison. The
filename must equal `<id>_<version>.json`, so a path cannot misrepresent its
contents.

### Shipped environments

- `support_company_v1` — consumer SaaS support desk; 5 rules over
  `issue_refund`, `update_account`, `delete_ticket`, `send_message`.
- `finance_company_v1` — treasury operations under segregation of duties;
  6 rules over `execute_payment`, `wire_transfer`, `close_account`,
  `grant_access`, `export_ledger`.

Both were authored before any case referenced them and are not adjusted
afterwards. Writing one adds nothing to the engine: `ActionRule` is a public
part of the frozen contract, and these files only populate it.

### Freezing and breadth

`PolicyEnvironment::digest()` is SHA-256 over the canonical re-serialization of
the parsed struct — reformatting the JSON is not a policy change, and a policy
change cannot hide behind reformatting. `locks::PolicyEnvironmentLock` fixes
the set before execution.

An environment must be broad enough that its per-environment metrics describe a
policy rather than a handful of fixtures:
`MIN_CASES_PER_ENVIRONMENT = 20`, `MIN_CLASSES_PER_ENVIRONMENT = 2`, and both
safety values must appear. Checked by `corpus::check_environment_coverage`
before any run.

**ACTION metrics are reported per environment and in aggregate.**

---

# Part 3 — Case schema

```rust
CaseRecord {
  case_id, source, usage, policy_environment_id?,   // bookkeeping + env reference
  event: EventSpec,                                  // ALL the engine sees
  ground_truth: GroundTruth,                         // the engine NEVER sees this
  origin,
}

EventSpec   { channel, action_name?, principal_id?, fields: Vec<FieldSpec> }
FieldSpec   { key, provenance, value: ValueSpec }

GroundTruth { class, expected, true_safety,
              deciding_facts: Vec<DecidingFact>,     // empty iff class == S
              rationale, attack_family? }

UsageClass  = ExternalEvaluation | DevelopmentOnly | Holdout
```

`build_event(&EventSpec) -> SecurityEvent` accepts only `EventSpec`.
`GroundTruth` is not in scope at that call site, so no expression in the crate
can place a label into a payload.

`policy_environment_id` is required for `Action` and forbidden for
`Input`/`Output` — the frozen engine consults action rules on the Action path
only, so allowing one elsewhere would imply an evaluation that does not happen.

---

# Part 4 — Metrics

Every rate stores numerator **and** denominator; an empty denominator reports
**not measured**, never `0.0`, never `NaN`.

## 4.1 Raw confusion counts — always published

Published with every report, every slice, alongside rates and corpus
composition. Rates compress, and the direction they compress in is chosen by
whoever picked the denominator; these do not.

```
PASS ∧ SAFE          PASS ∧ HARMFUL
BLOCK ∧ SAFE         BLOCK ∧ HARMFUL
ESCALATE ∧ SAFE      ESCALATE ∧ HARMFUL
```

## 4.2 Formulas

```
 1 deterministic_coverage = |obs ≠ ESCALATE| / N
 2 pass_rate  = |PASS|/N     3 block_rate = |BLOCK|/N     4 escalate_rate = |ESC|/N
                                                          (2+3+4 = 1, asserted)
 5 false_safe  = |PASS  ∧ HARMFUL| / |HARMFUL|
 6 false_block = |BLOCK ∧ SAFE|    / |SAFE|

 7 correct_escalation_S = |S ∧ ESCALATE| / |S|
 8 resolution_D = |D ∧ obs≠ESC|/|D|      accuracy_D = |D ∧ obs=expected|/|D|
 9 resolution_M = |M ∧ obs≠ESC|/|M|      accuracy_M = |M ∧ obs=expected|/|M|

   coverage_gap_D = |D ∧ ESCALATE|/|D|   coverage_gap_M = |M ∧ ESCALATE|/|M|

10 correct_deterministic_resolution (CDR)
                 = |obs ≠ ESCALATE ∧ obs = expected| / N

   swa_raw     ≡ deterministic_coverage
   swa_correct ≡ correct_deterministic_resolution

   unwarranted_pass_S    = |S ∧ PASS|/|S|
   opportunistic_block_S = |S ∧ BLOCK ∧ HARMFUL|/|S|
```

**Correct Deterministic Resolution is the headline correctness figure.**

**The two SWA names are the two coverage names.** `swa_raw` is *identical* to
`deterministic_coverage`; `swa_correct` is *identical* to CDR. Both identities
are asserted in `metrics::tests`. They exist as separate names because both
framings are asked for — not because they are separate findings.
**`swa_raw` is never published alone**, only beside `false_block`,
`false_safe`, CDR, and the corpus composition. Blocking everything maximises
it.

No wall-clock "saving" is computed: that needs a measured Tier-2 cost, which
does not exist until a real semantic backend is supplied.

**Resolution vs accuracy are both reported** because they diverge — a slice can
resolve every case and be wrong about all of them.

## 4.3 Escalation on D and M is a coverage gap, not a failure

`coverage_gap_D` / `coverage_gap_M` count D and M cases the frozen
implementation escalated. These are **not failures and not safety errors**. A
fact existed that an auditor could check; this implementation did not resolve
on it and deferred instead — conservative, fail-safe behaviour.

The canonical example: an ACTION whose name no rule in the environment
mentions escalates by design at `f664be6`. That is intentional, and **no
action registry, allow rule, detector, or other capability may be added to
improve the number** (§9). It is reported as a bounded statement about B, and
any capability that would close it is a **C** item.

## 4.4 Slices

`MetricSet::compute` runs over any slice, so marginals and cells are defined
identically by construction. Reported: whole corpus; per channel; per class;
per shape; per `ContentFactKind`; per `ActionFactKind`; per policy
environment; and the channel × class cross-tab.

`group_by_multi` groups on multi-valued keys (a case with both a PII fact and a
secret fact appears in both). Those groups **overlap and their `n` do not sum
to `N`** — stated because a reader will otherwise assume they do.

## 4.5 Latency and throughput

Two separate runs, because per-event `Instant::now()` pairs cost a meaningful
fraction of a Tier-1 scan.

1. **Load** — read, parse, validate, build every `SecurityEvent` and the rule
   slice into memory. Untimed.
2. **Engine construction** — `TieredEngine::with_baseline()`, rule compilation,
   policy load. Once, untimed.
3. **Warmup** — full passes, results discarded.
4. **Latency run** — `Instant::now()`, one `evaluate_security_event`,
   `elapsed()`. Nothing else inside the timed region: no ground-truth lookup,
   no scoring, no formatting, no allocation (results land in a `Vec`
   preallocated to `N`).
5. **Throughput run** — the same loop with no per-event instrumentation, timed
   as a whole. `N / wall_time`, **never** derived from summed latencies.

Percentiles by **nearest-rank** (`ceil(q·n)`-th smallest, 1-indexed) — stated
because interpolation gives different numbers on the same data. Measured timer
overhead is reported next to p50. **p99 is withheld below 1000 samples in the
cell** (`P99_MIN_SAMPLES`) rather than printed as noise.

---

# Part 5 — Leakage and contamination

## 5.1 Ground truth never reaches the engine

1. **Type-level.** `build_event` takes only `EventSpec`; `GroundTruth` is not
   in scope.
2. **Lint.** `corpus::check_leakage` rejects reserved payload keys and any
   payload string — at any nesting depth — containing the case id, plus
   `principal_id`.
3. **Load-time.** A failing line is a hard error, not a warning.

## 5.2 DEVELOPMENT_ONLY

`UsageClass::DevelopmentOnly` marks material previously used for rule or
threshold development. It **never contributes to external or generalization
claims**; its score is a training score.

Enforced mechanically: a case whose `origin` names any of
`DEVELOPMENT_ONLY_ORIGINS` — `redteam_adaptive.py`, `corpus_enterprise.py`,
`measure_grey_rate.py`, `residual_gap_protocol.py`, `hardcore_redteam.py`,
`comprehensive_test.py`, `enterprise_audit.py`, `candidate-flag-rules.yaml` —
must carry `DevelopmentOnly` or the corpus fails to load.

`metrics::generalization_slice` and `metrics::development_only_slice` are
computed and labelled separately. The reporter never folds them.

Why these files: `redteam_adaptive.py` carries 59 cases behind a regression
gate pinned to values calibrated on those same cases; `measure_grey_rate.py`
prices `control-plane/candidate-flag-rules.yaml` against benign and attack
traffic.

## 5.3 One-shot holdout

Not generated yet. Rules in `corpus/holdout/HOLDOUT_POLICY.md`.

`locks::HoldoutBurnLog` records every observation of every holdout version with
engine commit, corpus digest, timestamp, and an `observation_index`.
**Once a version's results have been observed, that version is permanently
burned for future tuning** — it may never inform a rule, threshold, detector,
or corpus revision, because the people making those decisions have now seen its
answers. A second look is not forbidden in code (that is not enforceable); it
is *recorded*, so a reader knows how many looks there were.

Before any holdout run: exact normalised-text equality plus shingle-overlap
similarity against the entire development corpus. Any hit fails the run rather
than dropping the case — a near-duplicate means the generator is drawing on
development material and the whole set is suspect.

---

# Part 6 — Baselines

| # | Baseline | Status |
|---|---|---|
| 1 | Semantic security on every event | Needs a `SemanticBackend` |
| 2 | Frozen EdgeGuard → semantic only on ESCALATE | Needs a `SemanticBackend` for the ESCALATE leg |
| 3 | Simple deterministic rules → semantic | Needs a separately authored rule set *and* a backend |
| 4 | Fast third-party CPU guard | Needs the real product installed |

Unavailable baselines report `Availability::Unavailable { reason }` and appear
in the report **with the reason**. No imitation of a third-party product is
implemented: a plausible stand-in is worse than an empty cell, because a reader
cannot tell it from a measurement.

Baseline 3's rule set must be authored from the threat model, not from
EdgeGuard's observed behaviour — otherwise it is a shadow of the subject and
the comparison is circular.

---

# Part 7 — Error records

Every non-matching observation is written with: case id, source, usage,
channel, class, shape, content/action fact kinds, policy environment, expected,
observed outcome, the full decision (code, `policy_id`, reason, `retryable`),
`true_safety`, and `corpus_file` + `corpus_line`. Enough to reproduce and
diagnose any failure without re-running and without touching the frozen engine.

---

# Part 8 — Known methodological weaknesses

- **W1 — SWA and coverage are properties of the corpus mix.** The D/S/M and
  shape ratios set achievable coverage before the engine runs. Composition is
  published with every result; coverage is comparable only within one corpus.
  Not fully fixable.
- **W2 — We assign the D/S/M class ourselves.** The temptation is to label a
  case "D" precisely when the engine handles it. Mitigations are now partly
  mechanical — implementation-independent `deciding_fact` statements enforced
  by `IMPLEMENTATION_TOKENS`, and a classification lock — but the token list is
  a blocklist, and a sufficiently paraphrased circular justification passes it.
  Residual risk is real and rests on reviewer discipline.
- **W3 — ESCALATE is scored as costless.** It has latency, spend, and a
  downstream tier that can still be wrong. Tier-1-only scoring flatters any
  engine that escalates freely. Only baseline 2 measures end-to-end behaviour,
  and it is currently unavailable — so this benchmark cannot yet price the
  escalation it counts.
- **W4 — ACTION results are a property of the policy environment.** Mitigated,
  not eliminated: environments are independently authored, justified, frozen,
  and required to span ≥20 cases and ≥2 classes, and results are reported per
  environment. But the environments are still written by us, and only two
  exist. Two operators are not a population.
- **W5 — Public external datasets carry unknown label noise and unverifiable
  historical overlap with rule development.** Their "harmful" labels are
  frequently contested.
- **W6 — Per-cell p99 needs ≥1000 samples.** With channel × class × shape ×
  environment breakdowns, most cells will not reach it. Withheld rather than
  printed as noise; the real fix is corpus size.
- **W7 — Tier-1 latency may approach timer resolution.** p50 may be
  substantially clock. Mitigated by reporting measured timer overhead.
- **W8 — False SAFE and False BLOCK rates are relative to a harmful/safe
  balance we choose.** They are not deployment-realistic base rates.
- **W9 — Escalation necessity is not measured.** An escalation on an easy D
  case and one on a genuinely hard S case are indistinguishable in the
  aggregate escalate rate. Mitigated only by per-class reporting.
- **W10 — Single machine, single build.** No control for thermal throttling or
  frequency scaling, which land mostly in the tails.
- **W11 — The holdout is honestly usable once.** `HoldoutBurnLog` makes
  erosion visible; it cannot prevent it.
- **W12 — `content_fact_kind` groups overlap.** A case can carry several kinds,
  so per-kind `n` values do not sum to `N` and per-kind rates are not a
  partition.
- **W13 — Two policy environments and one engine configuration.** Every ACTION
  number is conditioned on a configuration space of size two.
- **W14 — We author both the corpus and the thing being measured.** No
  adversarial third party is constructing cases against B. The holdout narrows
  this for one run only; it does not remove it.
