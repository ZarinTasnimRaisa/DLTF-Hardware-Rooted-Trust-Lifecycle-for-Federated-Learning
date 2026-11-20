"""
summarize_real_mnist.py -- report the real-MNIST run in a way that survives
review. Reads results/real_mnist.csv; re-running the experiment is not needed.

THE PROBLEM WITH FINAL-ROUND ACCURACY HERE

Under label-flip poisoning with no trust layer the global model does not
converge. It oscillates: the poisoned updates drag it toward flipped labels,
the honest majority drags it back, and the cycle repeats every round. In the
measured run the last five rounds of one seed read

    0.454, 0.966, 0.546, 0.972, 0.366

so whether that seed "ends" at 0.37 or 0.97 depends on the parity of the
stopping round. Two of three seeds ended low and one ended high, which is why
final-round accuracy reports a margin of +0.407. Change the round budget by one
and that number moves by a third. It is not a property of the system.

WHAT TO REPORT INSTEAD, and why each is defensible

  MEAN OVER THE LAST k ROUNDS  averages over the oscillation instead of
                               sampling one phase of it. Insensitive to the
                               stopping round, which is the whole point.

  OSCILLATION AMPLITUDE        max minus min over the same window. This is the
                               more interesting number: it says the unprotected
                               federation never converges at all, which is a
                               stronger statement than a lower mean and one the
                               mean alone hides.

  FIRST-BAN ROUND              on real gradients detection is much slower than
                               on the synthetic substrate. Report it; a paper
                               claiming one-round ban latency while its own
                               artifact shows otherwise on real data is a
                               finding waiting to be made by a reviewer.

Run:
    python -m eval.summarize_real_mnist --results results/
    python -m eval.summarize_real_mnist --results results/ --window 5
"""

import os
import csv
import argparse
import statistics as st
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--window", type=int, default=5,
                    help="rounds averaged at the tail")
    ap.add_argument("--file", default="real_mnist.csv",
                    help="which run to summarise, e.g. real_mnist_scale.csv")
    args = ap.parse_args()

    path = os.path.join(args.results, args.file)
    if not os.path.exists(path):
        raise SystemExit("not found: %s -- run eval.exp_real_mnist first" % path)

    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))

    series = defaultdict(dict)      # (attack, defense, seed) -> {round: acc}
    bans = defaultdict(dict)
    for r in rows:
        key = (r["attack"], r["defense"], int(r["seed"]))
        series[key][int(r["round"])] = float(r["accuracy"])
        bans[key][int(r["round"])] = int(r["attackers_banned"])

    k = args.window
    print("Tail window: last %d rounds\n" % k)
    print("%-8s %-8s %10s %10s %10s %10s"
          % ("attack", "defense", "final", "tail mean", "tail min", "amplitude"))
    print("-" * 60)

    summary = {}
    for attack in ("none", "poison"):
        for defense in ("plain", "dltf"):
            finals, means, mins, amps = [], [], [], []
            for (a, d, _s), acc in series.items():
                if (a, d) != (attack, defense):
                    continue
                ordered = [acc[r] for r in sorted(acc)]
                tail = ordered[-k:]
                finals.append(ordered[-1])
                means.append(st.mean(tail))
                mins.append(min(tail))
                amps.append(max(tail) - min(tail))
            if not finals:
                continue
            summary[(attack, defense)] = (st.mean(finals), st.mean(means),
                                          st.mean(mins), st.mean(amps))
            print("%-8s %-8s %10.4f %10.4f %10.4f %10.4f"
                  % (attack, defense, st.mean(finals), st.mean(means),
                     st.mean(mins), st.mean(amps)))

    # A mean over seeds hides a seed the layer LOST. Print the per-seed tail
    # means for the protected arm before any aggregate, so a divergent seed is
    # visible before the margin is read.
    prot = {s_: acc for (a, d, s_), acc in series.items()
            if (a, d) == ("poison", "dltf")}
    if prot:
        per_seed = {s_: st.mean([acc[r] for r in sorted(acc)][-k:])
                    for s_, acc in prot.items()}
        print("PER-SEED tail mean, protected arm:")
        for s_, v in sorted(per_seed.items()):
            print("  seed %d: %.4f" % (s_, v))
        spread = max(per_seed.values()) - min(per_seed.values())
        if spread > 0.2:
            print("  SPREAD %.4f ACROSS SEEDS. The arms did not behave the"
                  % spread)
            print("  same way in every run: at least one seed diverged from the")
            print("  others. Report the per-seed outcomes and the number of")
            print("  seeds in which the attacker was sanctioned. A mean over a")
            print("  bimodal set describes neither mode.")
        print()

    if ("poison", "plain") in summary and ("poison", "dltf") in summary:
        off, on = summary[("poison", "plain")], summary[("poison", "dltf")]
        print("MARGIN UNDER POISONING")
        print("  by final round : %+.4f   <- stopping-round dependent, do not "
              "report alone" % (on[0] - off[0]))
        print("  by tail mean   : %+.4f   <- report this" % (on[1] - off[1]))
        print("  by tail minimum: %+.4f   <- worst case the federation sees"
              % (on[2] - off[2]))
        print("  oscillation    : %.4f without the layer against %.4f with it"
              % (off[3], on[3]))
        if off[3] > 0.1:
            print("\n  The amplitude is the headline. Without the layer the")
            print("  federation does not converge under attack; it alternates")
            print("  between roughly %.2f and %.2f, a stronger claim than a"
                  % (off[2], off[2] + off[3]))
            print("  lower mean and what the per-round figure shows.")
        else:
            print("\n  Amplitude is near zero in the unprotected arm (%.4f):"
                  % off[3])
            print("  the model is not oscillating, it has collapsed and stayed")
            print("  there at %.4f. For a 10-class task that is chance. Report"
                  % off[1])
            print("  it as destruction rather than degradation.")

    if ("none", "plain") in summary and ("none", "dltf") in summary:
        d = (summary[("none", "dltf")][1] - summary[("none", "plain")][1])
        print("\nCLEAN FEDERATION: tail-mean difference %+.4f" % d)
        print("  The layer must cost nothing when there is no adversary. On the")
        print("  synthetic substrate this was exactly zero; on real data it is")
        print("  within noise, which is the honest way to state it.")

    print("\nFIRST-BAN ROUND (real gradients, %s)" % args.file)
    first = []
    for (a, d, s), b in sorted(bans.items()):
        if (a, d) != ("poison", "dltf"):
            continue
        hit = [r for r in sorted(b) if b[r] > 0]
        if hit:
            first.append(hit[0])
            print("  seed %d: first ban at round %d" % (s, hit[0]))
        else:
            print("  seed %d: never banned" % s)
    n_seeds = len({s_ for (a, d, s_) in series if (a, d) == ("poison", "dltf")})
    if first:
        print("  sanctioned in %d of %d seeds; mean %.1f rounds over those that"
              % (len(first), n_seeds, st.mean(first)))
        print("  were sanctioned.")
        if len(first) < n_seeds:
            print("  WARNING: the mean EXCLUDES %d seed(s) in which the"
                  % (n_seeds - len(first)))
            print("  attacker was never sanctioned, so it is biased downward.")
            print("  A latency averaged only over successes is not a latency.")
            print("  Report the success count first and the mean second.")
        print("  Compare against the one-round latency of the synthetic")
        print("  substrate: real gradients are less geometrically distinct, so")
        print("  the detector needs more rounds of evidence. Report both.")


if __name__ == "__main__":
    main()
