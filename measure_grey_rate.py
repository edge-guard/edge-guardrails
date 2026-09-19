"""Measure the router dial: reachability gained vs grey rate paid.

The protocol found Tier 2 is consulted on 0 of the in-scope enterprise attacks,
because tier.rs:744 routes to the model only on a Flag match or stacked
obfuscation. `control-plane/candidate-flag-rules.yaml` is the proposed fix.
This script prices it.

Two numbers decide whether those rules ship, and they pull against each other:

  REACHABILITY  - share of in-scope attacks that now reach Tier 2 at all.
                  Was 0. Anything the model still never sees, it cannot fix.

  GREY RATE     - share of BENIGN traffic now forwarded to the model.
                  This is the cost dial tier.rs already names: Tier 2 is
                  roughly 10,000x the cost of Tier 1, so mean latency and the
                  compute bill are set by the breadth of the Flag rules, not
                  by the model's speed.

A Flag is not a block, so a benign prompt going grey is not a false positive -
it is latency and spend. It is measured separately from FPR for that reason,
and reported per-prompt so an author can see exactly which rule is expensive.

Run:
    .venv/bin/python measure_grey_rate.py
"""

import sys

from residual_gap_protocol import (
    OUT_OF_SCOPE_FAMILIES,
    load_corpus,
    provenance_gate,
    rate,
)

RULES = "control-plane/candidate-flag-rules.yaml"


def in_scope(case):
    return case["family"].split(".", maxsplit=1)[0].strip() not in OUT_OF_SCOPE_FAMILIES


def classify(guard, text):
    """What the router did with one input.

    `semantic` is non-null only when Tier 2 actually ran, which is the direct
    measurement of reachability - never inferred from the verdict.
    """
    d = guard.inspect(text)
    return {
        "blocked": d["is_blocked"],
        "verdict": d["verdict"],
        "stage": d["decided_by"],
        "reached_tier2": d["semantic"] is not None,
        "code": d["violation_code"],
    }


def main():
    eg = provenance_gate()
    cases, benign = load_corpus(enterprise=True)
    # The holdout is measured separately and was never consulted while drafting
    # the rules. A grey rate quoted only against the fitted corpus is not a
    # measurement, it is a restatement of the rules.
    from corpus_enterprise import BENIGN_HOLDOUT  # noqa: PLC0415
    attacks = [c for c in cases if in_scope(c)]

    # Baseline vs candidate. Both keep the shipped baseline rules; the only
    # difference is the extra Flag group, so any delta is attributable to it.
    #
    # scorer="heuristic" is required, not incidental: with scorer="off" the
    # engine has no Tier 2 to route to and `semantic` is always null, which
    # would silently report reachability as 0 for both arms.
    before = eg.TieredGuard(scorer="heuristic", db_path=None)
    after = eg.TieredGuard(scorer="heuristic", rules_path=RULES, db_path=None)

    if after.rule_errors:
        print("FATAL: candidate rules failed to compile:", file=sys.stderr)
        for e in after.rule_errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print("=" * 78)
    print("ROUTER DIAL - reachability gained vs grey rate paid")
    print("=" * 78)
    print(f"rules: {RULES}  ({after.rule_count() - before.rule_count()} added)")
    print(f"corpus: {len(attacks)} in-scope attacks, {len(benign)} benign\n")

    a_before = [classify(before, c["payload"]) for c in attacks]
    a_after = [classify(after, c["payload"]) for c in attacks]
    b_before = [classify(before, p) for p in benign]
    b_after = [classify(after, p) for p in benign]

    def reach(rs):
        return sum(r["reached_tier2"] for r in rs)

    def blocked(rs):
        return sum(r["blocked"] for r in rs)

    n_a, n_b = len(attacks), len(benign)

    print("ATTACKS (in scope)")
    print("-" * 78)
    print(f"  reach Tier 2   before  {rate(reach(a_before), n_a)}")
    print(f"  reach Tier 2   after   {rate(reach(a_after), n_a)}")
    print(f"  blocked by T1  before  {rate(blocked(a_before), n_a)}")
    print(f"  blocked by T1  after   {rate(blocked(a_after), n_a)}")

    print("\nBENIGN - this is the bill")
    print("-" * 78)
    print(f"  grey (-> Tier 2) before  {rate(reach(b_before), n_b)}")
    print(f"  grey (-> Tier 2) after   {rate(reach(b_after), n_b)}")
    print(f"  BLOCKED (true FP) before {rate(blocked(b_before), n_b)}")
    print(f"  BLOCKED (true FP) after  {rate(blocked(b_after), n_b)}")

    newly_grey = [p for p, x, y in zip(benign, b_before, b_after)
                  if y["reached_tier2"] and not x["reached_tier2"]]
    if newly_grey:
        print(f"\n  benign prompts newly sent to the model ({len(newly_grey)}):")
        for p in newly_grey:
            print(f"    {p[:68]}")

    new_fp = [p for p, x, y in zip(benign, b_before, b_after)
              if y["blocked"] and not x["blocked"]]
    if new_fp:
        print(f"\n  *** NEW HARD FALSE POSITIVES ({len(new_fp)}) - these block real work:")
        for p in new_fp:
            print(f"    {p[:68]}")
    else:
        print("\n  no new hard false positives (every new hit is Flag, not Block)")

    h_before = [classify(before, p) for p in BENIGN_HOLDOUT]
    h_after = [classify(after, p) for p in BENIGN_HOLDOUT]
    n_h = len(BENIGN_HOLDOUT)
    print("\nBENIGN HOLDOUT - never seen while drafting the rules")
    print("-" * 78)
    print(f"  grey (-> Tier 2) before  {rate(reach(h_before), n_h)}")
    print(f"  grey (-> Tier 2) after   {rate(reach(h_after), n_h)}")
    hfp = [p for p, x, y in zip(BENIGN_HOLDOUT, h_before, h_after)
           if y["reached_tier2"] and not x["reached_tier2"]]
    for p in hfp:
        print(f"    newly grey: {p[:64]}")
    if not hfp:
        print("    no holdout prompt newly sent to the model")

    print("\nPER-FAMILY REACHABILITY AFTER")
    print("-" * 78)
    fams = sorted({c["family"] for c in attacks})
    for f in fams:
        idx = [i for i, c in enumerate(attacks) if c["family"] == f]
        got = sum(a_after[i]["reached_tier2"] or a_after[i]["blocked"] for i in idx)
        print(f"  {f:<32} {got}/{len(idx)} now reach T1-block or T2")

    still_dark = [
        attacks[i]["payload"]
        for i in range(n_a)
        if not a_after[i]["reached_tier2"] and not a_after[i]["blocked"]
    ]
    print(f"\nSTILL INVISIBLE TO BOTH TIERS: {len(still_dark)}/{n_a}")
    print("-" * 78)
    for p in still_dark[:12]:
        print(f"  {p[:70]!r}")

    print("\nWHAT THIS COSTS")
    print("-" * 78)
    g = (reach(b_after) + reach(h_after)) / (n_b + n_h)
    print(f"  grey rate on ALL benign (corpus + holdout): {100*g:.1f}%")
    print("  tier.rs quotes Tier 2 at ~10,000x Tier 1 (~1.6 us one-shot), so at")
    print(f"  this grey rate mean added latency is roughly {g*5000:.0f} us/request")
    print("  against a 5 ms Tier 2 budget - dominated entirely by the grey share,")
    print("  not by model speed. Tighten the Flag rules before optimising ONNX.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
