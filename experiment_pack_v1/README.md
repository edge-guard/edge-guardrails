# EdgeGuard Experiment Pack v1.0 — harness

Phase-I deliverable for `EDGEGUARD_EXPERIMENT_PACK_V1.md`. Built **outside**
the production Core; the Core is a path dependency and is never edited for
measurement convenience.

## Layout

| Path | Role |
|---|---|
| `src/schema.rs` | Raw record types for Tracks A / B / C. Pre-exposure `label` is required; `observed` starts `None`. |
| `src/metrics.rs` | Pack §4/§5 metrics. No synthetic winner score. No bare local-resolution ratio. |
| `src/timing.rs` | Three-layer timing, nearest-rank percentiles, warm/cold separation, scale points. |
| `src/adapter.rs` | The only module that touches EdgeGuard. Public API only. |
| `src/results.rs` | Append-only JSONL writer. Never truncates. |
| `src/manifest.rs` | Contamination lock. |
| `src/bin/phase2.rs` | Phase-II gate. Refuses to run unless the lock verifies **and** a corpus exists. |
| `FREEZE_MANIFEST.json` | The frozen manifest produced by `phase2 --freeze`. |

## Commands

```bash
cargo test --release                 # harness self-tests
./target/release/phase2 --check      # verify the lock, report Phase-II readiness
./target/release/phase2 --freeze     # write the live manifest as the frozen one
```

## Invariants the code enforces (not merely documents)

- **A `D` label must carry a deterministic basis.** `TrackARecord::validate`
  rejects `D-PASS`/`D-BLOCK`/`M` with an empty `deterministic_basis`, and
  rejects an `S` label that carries one. Pack §7 forbids labelling a case `D`
  when only invented host state would make it so; this is where that is caught.
- **No-signal is never SAFE.** A terminal PASS on `ContentTruth::Unestablished`
  lands in `pass_on_unestablished` — neither a correct PASS nor a False SAFE.
- **A failure-mode decision is not local resolution.** `Tier2Unavailable`,
  `Tier2Failed`, `Tier2ShedByBreaker`, `Tier2Deferred` and `Tier2Model` all
  return `false` from `is_locally_resolved`, so a terminal verdict produced
  because the scorer was missing can never be counted as deterministic
  coverage. This is the F-04 failure mode, enforced in the harness as well as
  in the Core metric.
- **Slices cannot dilute each other.** `Report::by_slice` is the headline;
  `pooled()` exists but is printed after every slice (Pack §6.8).
- **An empty slice reports no data, not a flattering constant.**
  `correct_local_resolution_ratio()` returns `Option`, `None` at `total == 0`.
- **The adapter does not coerce types.** Integers stay integers, floats stay
  floats; anything unrepresentable becomes `Value::Null`, which the Core fails
  closed on. A silent int→float widening at the boundary would change the
  verdict outside the engine.
- **Raw results are append-only.** Re-opening a results file appends, so a
  second look at the holdout is visible in the record.

## Phase discipline

This harness does **not** execute a corpus. Phase II is one blind run, and it
may begin only when `phase2 --check` reports `PERMITTED`.
