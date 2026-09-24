# Phase 1 acquisition log

Frozen EdgeGuard Core: `f664be6af727a5a1fa8f66e9e2ad07c109263acb`
Frozen methodology at start of phase: `58291f1f71ac578d3ff3aafb8c9fd1afdecc6102`

## NO EDGEGUARD RESULTS WERE OBSERVED DURING ACQUISITION

EdgeGuard was not executed at any point in Phase 1. No `TieredEngine` was
constructed, no `evaluate_security_event` call was made, and no acquired record
was passed through the engine. No record was selected, excluded, or ordered on
the basis of expected or observed engine behaviour. Verified mechanically — see
*Verification* below.

## Pre-recorded decision carried into this phase

ACTION evidence for benchmark v0.1 is **synthetic-only**. ACTION results may
demonstrate correctness against the 11 frozen single-field scalar clauses in the
2 frozen policy environments, and must not be presented as real-world ACTION
coverage, enterprise authorization coverage, a production ACTION distribution,
or externally validated agent-action security. Not reopened.

## Acquired

| Source | Commit | Licence | Selected by | Criterion |
|---|---|---|---|---|
| InjecAgent | `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | MIT, verified via GitHub licenses API | Phase-0 acquisition plan | Permissive licence; per-record injected text exists statically; maps to INPUT without inventing host-authoritative facts |
| AgentDojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT, verified via GitHub licenses API | Phase-0 acquisition plan | Permissive licence; named as priority source |

Both acquired by `git clone --depth 1` followed by pinning the resolved commit.
Raw artifacts copied verbatim; nothing rewritten.

## Declined, with reasons

| Source | Reason |
|---|---|
| **R-Judge** | **No licence.** The GitHub licenses API returns 404 and the repository root contains no LICENSE/COPYING file. Acquisition was explicitly gated on verifying terms first; terms could not be verified, so no rights are granted and nothing was downloaded. |
| WASP | CC-BY-NC 4.0 on the majority of the project. |
| SecretBench | Signed data-use agreement not in place. |
| ai4privacy 200k / 300k | 200k: licence not clearly stated on the dataset card. 300k: custom licence, commercial use requires contacting the licensor. |
| gretelai synthetic_pii_finance_multilingual | Licence acceptable (Apache-2.0); **rejected on label quality** — see Part 4. |

## Eligibility criteria, declared before inspecting content

- **InjecAgent**: a record is potentially eligible iff it carries a non-empty
  `Tool Response` string — the text an agent actually ingests, and therefore the
  only field that maps to an INPUT event without invention. **2108 of 2108
  records satisfy it; none excluded.**
- **AgentDojo**: deferred. There are no records to make eligible — see below.

## Structural finding: AgentDojo ships no injected texts

The text an INPUT event would carry does not exist in the repository. It is
synthesised at runtime by an attack class:
`jailbreak.format(goal=injection_task.GOAL, user=..., model=...)` in
`src/agentdojo/attacks/important_instructions_attacks.py`. What the repository
ships is 54 `GOAL` strings across 11 `injection_tasks.py` files, 39 injection
vectors across 4 `injection_vectors.yaml` files (whose defaults are **benign**),
the benign environment YAML, and the attack templates.

Two consequences recorded now rather than discovered later:

1. Deriving INPUT text from AgentDojo is a **Phase-2 derivation**, not an
   acquisition, and must pin the attack class as well as the commit.
2. The default `important_instructions` attack embeds the **target model's
   name** in the injected string, so the text differs per model under
   evaluation. A derivation must use a model-independent variant (upstream
   ships `important_instructions_no_model_name` / `_no_user_name`) and record
   the choice.

## Classification

No record in either source has been assigned a D/S/M class. Dataset origin does
not determine class. The manifest records a *likely dominant* class per source
and says explicitly that this is not a per-record assignment.

## Subsequent exclusions or changes

None. No record has been removed since acquisition.

## Verification performed

- All 41 raw artifacts hashed (SHA-256) and recorded in `manifest.json`.
- InjecAgent counts reconciled against the paper: 510 + 544 = **1,054** base
  cases, matching the published figure; `enhanced` is the same 1,054 with an
  added hacking prompt, for 2,108 records total.
- Licences verified from the GitHub licenses API and copies preserved
  alongside the raw data.
- Acquisition and conversion code searched for engine imports and calls.
