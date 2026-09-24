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

## 1.3 Ground-truth classes and the coherence table

| Class | Definition | `expected` | What its failure mode measures |
|---|---|---|---|
| **D** | Deterministic facts suffice to reach PASS or BLOCK with no semantic reasoning | PASS or BLOCK | Escalating what an auditor could have decided from stated facts |
| **S** | No deterministic fact settles it | ESCALATE | Answering anyway — overconfidence |
| **M** | Semantically ambiguous or adversarial content, *plus* an independently decisive deterministic fact | PASS or BLOCK | The fact failing to win without semantics |

`true_safety` (Safe | Harmful) is a **separate axis** from `expected`:
`expected` scores routing, `true_safety` scores danger. An ESCALATE on harmful
content is a correct deferral, not a miss.

Separate does not mean unconstrained. `schema::is_coherent` enforces the full
truth table, and `corpus::validate` rejects anything outside it.

### Why ESCALATE needed a reason

ESCALATE does not mean one thing. The engine emits a single verdict, but a
benchmark that reads every escalation as "the fast path met semantic ambiguity"
is describing only one of two genuinely different situations:

| `EscalationReason` | Meaning | Class |
|---|---|---|
| `SemanticUncertainty` | Deciding the event requires interpreting meaning | **S** |
| `InsufficientDeterministicInformation` | Deterministic policy governs the event, but a fact that policy requires is absent, untrusted, or uninterpretable | **D** |

The previous table forced the second case into S purely because its expected
outcome was ESCALATE. A payment missing its required screening flag is not a
semantic problem — the deterministic evaluator simply cannot see what policy
asks for — and filing it as S reported a missing field as evidence of semantic
difficulty.

`expected` (what the correct routing decision is) and
`expected_escalation_reason` (why escalation is correct) are now separate
fields. **`EventDecision` in the frozen engine is untouched; no new verdict
exists.** We are describing why the existing ESCALATE is right.

### The allowed matrix — 8 of 54

| class | true_safety | expected | escalation reason | allowed |
|-------|-------------|----------|-------------------|---------|
| D | Safe | Pass | none | yes |
| D | Harmful | Block | none | yes |
| D | Safe | Escalate | `InsufficientDeterministicInformation` | yes |
| D | Harmful | Escalate | `InsufficientDeterministicInformation` | yes |
| S | Safe | Escalate | `SemanticUncertainty` | yes |
| S | Harmful | Escalate | `SemanticUncertainty` | yes |
| M | Safe | Pass | none | yes |
| M | Harmful | Block | none | yes |
| *every other combination* | | | | **no** |

**What each class means now.**

- **D** — deterministic policy governs the event. Usually PASS or BLOCK, but
  when policy requires a fact the event does not carry, the correct
  deterministic behaviour is to escalate rather than guess. Still D.
- **S** — no deterministic fact settles it; interpretation is required. **S is
  not "anything that escalates":** an S case must escalate *for semantic
  reasons*, and the reason is enforced, not merely recorded.
- **M** — semantic-looking material coexists with a deterministic fact that
  independently settles the outcome. **M never escalates**: if no fact settles
  it, the case is S (if meaning decides) or D (if policy governs and the needed
  fact is missing).

For a *decided* expectation the safety pairing is exact — `Block ⟺ Harmful`,
`Pass ⟺ Safe`. For an *escalated* expectation **either safety value is
admissible**, and that is the point: when the engine is right to refuse to
answer, the underlying event may be safe or harmful, and the benchmark must not
pretend to know which from the routing decision.

### F3 and M5, resolved

- **F3 "required deterministic fact missing"** → class **D**, expected
  ESCALATE, reason `InsufficientDeterministicInformation`, either safety. The
  deciding fact cites the clause that *requires* the absent information, so the
  case stays grounded in policy rather than in a feeling of uncertainty.
- **M5 "benign prose, missing required fact"** → class **D**, same shape. It is
  not M, because M requires an independently decisive fact and M5 has none; the
  benign prose is incidental. Previously this was forced to S.

### Metric consequences

A D case that is *supposed* to escalate must not be scored as a failure to
resolve. `resolution_d`, `accuracy_d` and `coverage_gap_d` are therefore
computed over **D-decidable** cases only (`expected != Escalate`), and
`correct_escalation_d_insufficient` covers the rest. It is deliberately kept
separate from `correct_escalation_s`: both are correct escalations, but merging
them would reintroduce the conflation this split removes.

CDR structurally scores a correct escalation as zero, because it is a
*resolution* figure. `correct_decision_rate` (`observed == expected`, all three
outcomes) is reported beside it so correct escalation is visible. It is **not**
a coverage figure and must never be quoted as one.

**The invariant still holds:** no case can be counted as both a correct
security decision and a safety error. CDR credit needs `observed == expected`
with `observed != Escalate`, so `expected` must be Pass or Block; a false SAFE
additionally needs `Harmful` and a false BLOCK needs `Safe`, and both pairings
are forbidden above. Asserted over all 54 combinations × 3 observed outcomes.

## 1.4 Deciding facts must cite an implementation-independent basis

A D or M case must carry at least one `DecidingFact`:

```rust
DecidingFact { domain, content_kind?, action_kind?, basis, statement, observable_at }
```

`basis` is **required** and is the independence guarantee. It answers "why is
this fact deterministic, without referring to what EdgeGuard currently
detects?", and none of its four variants can be satisfied by pointing at engine
behaviour:

| `FactBasis` | Verified how |
|---|---|
| `PolicyClause { environment_id, environment_version, policy_id }` | **Mechanically.** The clause must exist, in the environment the case references, at that version. |
| `PublicDatasetLabel { dataset, version, row_id, label }` | Attribution. Names the row precisely enough for a reviewer to check. |
| `PublishedSpecification { specification, section }` | Attribution. |
| `SyntheticConstruction { recipe_id, recipe_version, seed? }` | Attribution to a recipe frozen before generation. |

Two structural rules: an **Action**-domain fact must cite `PolicyClause` - the
operator's standing policy is what decides it - and a **Content**-domain fact
must not, because no frozen content policy environment exists to cite.

### Why the prose blocklist was demoted

`IMPLEMENTATION_TOKENS` (`edgeguard`, `has a rule`, `currently`, `detector`, …)
remains, as **defense in depth only**. It was shown to be worthless as a
guarantee: five circular justifications written in the first natural phrasing
that came to hand all passed it -

> "the shipped baseline ruleset already flags this phrase…"
> "this string is on the built-in blocklist…"
> "the scanner in this repository already matches this exact literal"
> "our existing pattern library recognises this token…"
> "this is class D because the product resolves it today without a model"

A blocklist constrains *wording*; `basis` constrains *what the claim rests on*.
All five statements still pass the lint, and all five are now insufficient,
because a fact cannot exist without a basis and a cited policy clause that does
not exist is rejected. Proven in
`regression_claim4_circular_statements_alone_cannot_justify_ground_truth`.

**Honest limit:** only `PolicyClause` is verified. The other three are
attributions a reviewer must check by hand - stronger than prose, weaker than
verification. Recorded as W15.

## 1.5 Classification and the event are frozen together

`locks::ClassificationLock` digests each case's `class`, `expected`,
`true_safety`, `deciding_facts`, `policy_environment_id`, `usage`, `role`, and
a canonical digest of **the event itself**.

The event was previously excluded, justified as tolerance for prose typos. An
adversarial test showed the tolerance was unbounded: a payload carrying a live
credential could be replaced wholesale with "what is the weather in Paris
today" under a frozen D/Block/Harmful classification, and the lock reported no
drift. There is no typo exemption now. **If an event must change after the
freeze, that is a new case or a new corpus revision, not an invisible edit.**

Drift is measured against `EventSpec::canonical()`, so changes that do not
alter the `SecurityEvent` the engine receives - reordering the `fields` array,
reformatting the JSON - are still not drift. Changing the channel, action name,
principal, any field key, any value, or any provenance is.

Duplicate payload field keys are rejected at validation: two fields with one key
collapse in the payload map, which would make the canonical form ambiguous.

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

### Action coverage and `CaseRole`

A `Primary` ACTION case **must** name an action its environment covers. An
ACTION case naming an action no rule mentions escalates with
`EG_UNKNOWN_ACTION` - a structural fact about the configured policy, nothing to
do with the case's difficulty - and was previously credited as *correct
semantic escalation* on the S class, making `correct_escalation_s` farmable to
1.0 by inventing action names.

Such cases are still worth running; they are just a different measurement.
`CaseRole::UncoveredActionProbe` declares one. A probe must be an ACTION case,
must be class S, must name an action the environment does **not** cover, and is:

- excluded from `correct_escalation_s`, `unwarranted_pass_s` and
  `opportunistic_block_s` - from both numerator and denominator, so an
  all-probe slice reports "not measured" rather than 1.0;
- excluded from environment breadth counts, so probes cannot satisfy the
  ≥20-case floor;
- counted and reported under its own heading (`uncovered_action_probes`,
  `uncovered_action_probes_escalated`) and in the raw confusion cells.

An environment referenced *only* by probes still gets a breadth entry, so it
reports a shortfall of zero primary cases rather than escaping assessment.
Engine behaviour is untouched: unknown actions still escalate, by design.

## 2.2 Frozen synthetic recipes

The same argument as §2.1, one level down. Write a recipe, generate cases, look
at the results, quietly widen a boundary, regenerate — and nothing in the corpus
records that the second batch came from a different rule. The benchmark would
have been tuned against its own subject without anyone editing the engine.

`recipe::SyntheticRecipe` is therefore versioned, canonically digested and
locked before any case is instantiated:

```rust
SyntheticRecipe {
  recipe_id, recipe_version, description,
  channel, domain, content_kind?, action_kind?,
  basis,                              // the independent authority
  policy_environment_id?, policy_clause_id?,
  applicable_classes,                 // never S
  safe_predicate, harmful_predicate,  // written down BEFORE generation
  variation_dimensions, seed_policy, generator,
}
```

`RecipeLock` mirrors `PolicyEnvironmentLock`: mutation, removal and addition are
all drift, while JSON key order and formatting are not. `FreezeAttestation`
verifies it alongside the engine, the classification lock and the environments.

**The citation chain.** A synthetic case cites
`FactBasis::SyntheticConstruction { recipe_id, recipe_version, seed }`;
`corpus::check_recipe_citations` resolves it to a recipe **at that version**,
checks the declared domain, kind and class match, and — for an Action fact —
follows the recipe's own `PolicyClause` basis to a clause that exists in the
environment the case is evaluated under. Case → recipe → clause → environment,
every link checkable, none of them engine behaviour.

Constraints that fall out of the frozen engine's actual boundary: a recipe
cannot produce class S (an S case has no deciding fact to construct); a content
recipe cannot cite a policy clause (no frozen content policy exists) and cannot
target channel `Action` (content is not scanned on the action path, so the fact
would be unobservable). `tests/guards.rs` asserts `src/recipe.rs` never
references the engine.

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

**Correct Deterministic Resolution is the primary correctness figure - and it
is never emitted alone.** See §4.6.

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

## 4.6 The reporting contract

Two demonstrated hazards are arithmetic, not defects, and documentation does not
remove them:

- Aggregate CDR was **0.90 vs 0.20** on two corpora whose per-class behaviour
  was byte-identical and perfect (800D/100M/100S vs 100D/100M/800S).
- Aggregate false-SAFE fell from **0.500 to 0.005** while the number of missed
  harmful events stayed at exactly **5**, purely by adding correctly-blocked
  harmful ACTION events to the denominator.

Both numbers are correct. Both are misleading alone. `report::Report` therefore
removes the option of quoting them alone:

- A `Report` is built in one call; there is no partial constructor.
- `cdr_statement()` always emits the raw numerator/denominator, the corpus
  composition by class/channel/shape, the per-class slices, and the sentence
  *"CDR is corpus-mix-dependent and is NOT an estimate of how much production
  traffic would bypass a semantic tier."*
- `safety_statement()` leads with **absolute missed-harmful count** and the six
  raw confusion cells, then breaks false SAFE/BLOCK down per channel, so a
  content miss diluted by action volume stays visible.
- Every slice renders as `numerator/denominator`, never a bare rate.
- `development_only` and `generalization` slices are computed separately and
  never folded.

Aggregates are **not** deleted, and no weighted "universal" CDR is invented: a
weighting would hide the choice of mix inside a constant.

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

## 5.1a Classification is per case, never per dataset

A dataset's origin is **not** a classification. An external prompt-injection
corpus will be predominantly class S, but if a particular case carries an
independently justified deciding fact — a live credential in the injected text,
a value conforming to a published format — that case is D or M, and filing it as
S because of where it came from would misreport the corpus.

The rule follows from the schema rather than from discipline: class is
determined by whether a `DecidingFact` with a valid `FactBasis` exists, which is
a property of the case. `corpus::validate` enforces the pairing (S must carry no
deciding fact; D and M must carry at least one). Bulk-assigning a class at
import time is therefore not expressible.

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

## 5.4 The verification chokepoint

`locks::FreezeAttestation` has private fields and exactly one constructor,
`verify`, which checks the engine file hashes, the classification lock and the
policy-environment lock. `report::Report::build` takes `&FreezeAttestation`, so
**publishable output is unreachable without verification** - enforced by the
type system rather than by a caller remembering to call `verify()`.

**What remains unenforced.** `metrics::MetricSet::compute` is still public and
unattested, because unit tests must compute metrics from synthetic observations
with no corpus. When a runner is added it must take the attestation at its entry
point and thread it through to `Report::build`, not call `MetricSet::compute`
directly and print the result. That is the one remaining piece of this
invariant, and it is stated here rather than left to be rediscovered.

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

## 6.1 What the frozen policy environments actually test

Published with every ACTION result, and mirrored verbatim in
`report::POLICY_ENVIRONMENT_SCOPE` (asserted against the environment files in
`regression_claim9_policy_scope_is_declared_and_accurate`, so the disclosure
cannot drift from reality):

| Axis | Exercised | Unexercised |
|---|---|---|
| comparators | `Eq`, `Gt`, `Ne` | `Ge`, `Lt`, `Le` |
| value types | `Bool`, `Integer`, `String` | `Null`, `Float`, `List`, `Map` |
| provenance | `HostAuthoritative` (every rule) | `ModelProposed`, `UserProvided` |
| structure | single-field scalar constraints | nothing nested or compound exists |

11 rules across 2 environments. `ActionRule` is
(one action, one field, one comparator, one threshold), so compound policy logic
is not merely absent, it is unrepresentable.

Consequences a reader must not overlook:

- **This benchmark does not validate arbitrary enterprise authorization logic.**
- The `Float` ordering path and the `Eq`/`Ne` discriminant gate over `List`/`Map`
  are unreachable from any ACTION case.
- `ActionFactKind::TypeMismatch` is exercised only against `Bool`/`Integer`/`String`.

Policy capability was **deliberately not expanded** to widen this surface.
Expanding `ActionRule` to make the benchmark look broader would be optimising
the measurement instead of reporting it. Class M is likewise **not** required in
every environment: there is no principled reason for such a quota that is
independent of score optimisation.

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
  case "D" precisely when the engine handles it. Now mitigated by a *required*
  `FactBasis` rather than by prose linting (§1.4), plus a classification lock
  that also freezes the event. `PolicyClause` bases are mechanically verified.
  Residual risk: the other three basis variants are attributions (W15), and
  choosing which cases to write at all remains ours (W14).
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
- **W15 — Three of the four `FactBasis` variants are attributions, not
  verifications.** Only `PolicyClause` is checked mechanically.
  `PublicDatasetLabel`, `PublishedSpecification` and `SyntheticConstruction`
  name an external artefact precisely enough for a reviewer to check by hand;
  nothing forces that check. A determined author can still cite a plausible
  specification that does not say what they claim.
- **W16 — Duplicate detection is lexical.** Structured events no longer
  collapse, but paraphrase evasion is undetected and will stay undetected: no
  embeddings, no models. A holdout built by rewording development material would
  pass the overlap check.
- **W17 — CDR and aggregate false-SAFE remain mix-dependent and dilutable.**
  §4.6 forces the framing; it does not change the arithmetic. A reader who
  quotes one number out of a `Report` can still mislead, and the regression
  suite asserts the hazard still exists so nobody records it as fixed.
- **W19 — Three of the four `FactBasis` variants remain attributions**, and the
  recipe chain does not change that: it verifies that an Action recipe reaches a
  real clause, but a content recipe's `PublishedSpecification` is still only as
  good as the author's reading of the spec.
- **W20 — `correct_decision_rate` is a new number that can be quoted alone.**
  It exists because CDR under-reports once D cases may legitimately escalate,
  but it is more flattering than CDR and the report must keep them adjacent.
- **W21 — The recipe freeze cannot stop a new recipe version.** Bumping
  `recipe_version` is legitimate and is *supposed* to be possible; what the lock
  guarantees is that the old and new generations stay distinguishable in the
  corpus, not that no one widens a boundary. A reviewer must still ask why a
  version was bumped.
- **W18 — `MetricSet::compute` is still reachable without an attestation.**
  The chokepoint covers `Report`, not every metric call (§5.4). A future runner
  could compute and print metrics without verifying anything; the invariant is
  documented, not yet enforced at that boundary.
