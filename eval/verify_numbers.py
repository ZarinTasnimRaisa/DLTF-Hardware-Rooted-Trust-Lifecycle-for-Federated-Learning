"""
verify_numbers.py -- check the numbers in the paper against the CSVs on disk.

This exists because two of your result sets currently disagree:

    metrics_summary.csv : detection_latency_sleeper = 0.00, whitewash 90/90
    thesis Table 5.3/5.5: sleeper flag latency  = 0.40, whitewash 25/25

Both cannot be the artifact. A reviewer who downloads the code and gets
different numbers than the paper will not assume it is a versioning issue.
Before release, pick the authoritative run, regenerate every table from it,
and make this script pass.

It does not recompute anything. It reads the CSVs, extracts the values the
paper quotes, and prints them side by side with the claim, so a mismatch is
visible in one screen instead of being found by a reviewer.

Run:
    python -m eval.verify_numbers --results results/

Edit CLAIMS below whenever a number in the paper changes.
"""

import os
import csv
import argparse
import statistics as st

# value quoted in the paper -> where it should come from.
# (claim label, expected value, tolerance, csv file, how to extract)
CLAIMS = [
    ("accuracy, no attack (DLTF)",      0.691, 0.002, "accuracy.csv",      "acc:dltf:none"),
    ("accuracy, poisoning (DLTF)",      0.685, 0.002, "accuracy.csv",      "acc:dltf:poison"),
    ("accuracy, poisoning (baseline)",  0.520, 0.002, "accuracy.csv",      "acc:baseline:poison"),
    ("ban latency, all attacks",        1.0,   0.001, "detection.csv",     "ban_latency_mean"),
    ("gas fit intercept",           58281.0,  50.0,   "gas_fit.csv",       "kv:intercept"),
    ("gas fit slope",               38818.0,  50.0,   "gas_fit.csv",       "kv:slope"),
    ("reconcile, 200 rounds (ms)",      2.09, 0.30,   "reconcile.csv",     "rebuild_max"),
]


def _read(path):
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _find(results_dir, fname):
    """Locate a CSV. chain_eval.py writes to results/chain by default while
    run_experiments.py writes to results/, so look in both rather than making
    the user copy files between them. Falls back to a shallow walk."""
    candidates = [os.path.join(results_dir, fname),
                  os.path.join(results_dir, "chain", fname)]
    for c in candidates:
        if os.path.exists(c):
            return c
    for root, _dirs, files in os.walk(results_dir):
        if fname in files:
            return os.path.join(root, fname)
    return None


def _extract(rows, how):
    """Pull the quoted statistic out of a CSV. Returns None if not derivable."""
    if not rows:
        return None
    try:
        if how.startswith("acc:"):
            _, defense, attack = how.split(":")
            last = {}
            for r in rows:
                if r.get("defense") != defense or r.get("attack") != attack:
                    continue
                seed, rnd = r.get("seed"), int(r.get("round", 0))
                if seed not in last or rnd > last[seed][0]:
                    last[seed] = (rnd, float(r["accuracy"]))
            return st.mean(v for _, v in last.values()) if last else None

        if how == "ban_latency_mean":
            vals = [float(r["ban_latency"]) for r in rows
                    if r.get("ban_latency") not in (None, "", "None")]
            return st.mean(vals) if vals else None

        if how.startswith("kv:"):
            want = how.split(":")[1]
            for r in rows:
                k = (r.get("metric") or "").lower()
                if want in k:
                    return float(str(r.get("value")).replace(",", ""))
            return None

        if how == "rebuild_max":
            vals = [(int(r["rounds"]), float(r["rebuild_ms_mean"]))
                    for r in rows if r.get("rebuild_ms_mean")]
            return max(vals)[1] if vals else None
    except (KeyError, ValueError, TypeError):
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    args = ap.parse_args()

    print("%-34s %10s %10s %8s" % ("claim in paper", "paper", "csv", "status"))
    print("-" * 66)
    bad = missing = 0
    for label, expected, tol, fname, how in CLAIMS:
        path = _find(args.results, fname)
        rows = _read(path) if path else None
        got = _extract(rows, how)
        if got is None:
            where = fname if path is None else os.path.relpath(path, args.results)
            why = "file not found" if path is None else "value not derivable"
            print("%-34s %10.3f %10s %8s   (%s: %s)"
                  % (label, expected, "-", "NO DATA", where, why))
            missing += 1
            continue
        ok = abs(got - expected) <= tol
        if not ok:
            bad += 1
        print("%-34s %10.3f %10.3f %8s"
              % (label, expected, got, "ok" if ok else "MISMATCH"))

    print("-" * 66)
    print("%d mismatch(es), %d claim(s) with no data." % (bad, missing))
    if bad:
        print("\nEvery mismatch is a number in the paper that the artifact "
              "does not\nreproduce. Fix the paper or re-run the experiment "
              "before release.")
    if missing:
        print("\nMissing data means the CSV was not found anywhere under %s,\n"
              "or it was found but does not contain the field the claim needs.\n"
              "chain_eval.py writes to results/chain by default:\n"
              "    python -m eval.chain_eval --exp all --out results/chain"
              % args.results)
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
