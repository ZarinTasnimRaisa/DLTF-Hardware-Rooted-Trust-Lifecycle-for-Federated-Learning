"""
exp_exposure_cost.py -- what does an 11.3-round detection latency actually cost?

WHY

The paper reports that on real gradients the first attacker is banned at round
11.3, against one round on the synthetic substrate, and explains why: a
label-flipped update on a converging CNN is far less geometrically distinct than
a synthetic attack vector. That explanation is correct and it is honest. It is
also incomplete, and a reviewer will say so: eleven rounds is a long time to be
poisoned, and the paper never says how much damage that is.

It can say, because it already defines the unit. Attacker cost is reported in
WEIGHT-ROUNDS -- the sum of the aggregation weight a device holds in each round
it is active. Exposure is the same quantity viewed from the defender's side:
weight-rounds of malicious influence admitted before the sanction lands. Using
one unit for both turns a disclosure into a measurement and lets the latency be
compared directly against the attacker-cost table.

WHAT IT COMPUTES

  exposure = sum over rounds from attack onset to sanction of the attacker's
             aggregation weight in that round

  where weight = D(tier) * T, capped at D_P during probation and zero once
  banned. A HARDWARE attacker holds cap 1.0, so its exposure is bounded above by
  the round count; the trust score decays over those rounds, so the true figure
  is lower and worth reporting rather than assuming the bound.

Three numbers come out, and the third is the one for the paper:

  1. synthetic, 1-round latency          -> the best case
  2. real MNIST, 11.3-round latency      -> the measured case
  3. an unprotected federation           -> the counterfactual: influence never
                                            stops, so exposure grows without
                                            bound in the round budget

Reads results/real_mnist.csv when present, so no re-run is needed.

Run:
    python -m eval.exp_exposure_cost --results results/
    python -m eval.exp_exposure_cost --results results/ --rounds 30
"""

import os
import csv
import argparse
import statistics as st
from collections import defaultdict

from trust.reputation import Params, ReputationEngine
from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle)


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


def measure_exposure(attack, seed, rounds, n_honest=7, attacker_tier=1):
    """Sum the attacker's aggregation weight over every round it is active.
    This is exactly the weight-rounds unit the attacker-cost table uses."""
    kind, n_att, start = ATTACKS[attack]
    world = SyntheticWorld(seed)
    ca_key, ca_cert = generate_test_ca()
    server = FederatedServer(initial_params=[0.0] * world.dim,
                             ca_bundle_pem=ca_bundle_pem(ca_cert),
                             shadow_eval_fn=world.accuracy,
                             reputation_engine=ReputationEngine(Params()))

    handles, attackers = [], []
    for k in range(n_honest):
        handles.append(make_handle("h%d" % k,
                                   behavior(world, "honest", seed * 100 + k)))
    for k in range(n_att):
        label = "a%d" % k
        cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        handles.append(make_handle(
            label, behavior(world, kind, seed * 100 + 50 + k,
                            attack_start=start, group_seed=seed + 1),
            ek_cert_der=cert))
        attackers.append(label)
    for h in handles:
        server.enroll(h)

    exposure = defaultdict(float)
    sanctioned_at = {}
    for r in range(rounds):
        rep = server.run_round(r, handles)
        weights = rep.get("weights", {}) or {}
        for a in attackers:
            if r >= (start or 0):
                exposure[a] += float(weights.get(a, 0.0))
            if a not in sanctioned_at:
                d = server.rep._dev.get(a)
                if "BAN" in str(getattr(d, "status", "")).upper():
                    sanctioned_at[a] = r
    return exposure, sanctioned_at, start


def real_mnist_exposure(results, cap=1.0):
    """From the recorded real-MNIST run: the attackers train from round 0, so
    exposure is the number of rounds before the ban, times the tier cap. This
    is an UPPER bound because trust decays over those rounds; state it as one."""
    path = os.path.join(results, "real_mnist.csv")
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    first = defaultdict(lambda: None)
    for r in rows:
        if r["attack"] != "poison" or r["defense"] != "dltf":
            continue
        seed = int(r["seed"])
        if int(r["attackers_banned"]) > 0 and first[seed] is None:
            first[seed] = int(r["round"])
    hits = [v for v in first.values() if v is not None]
    return (st.mean(hits), len(hits), cap * st.mean(hits)) if hits else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--attacks", nargs="*", default=["poison", "sleeper"])
    args = ap.parse_args()

    unknown = [a for a in args.attacks if a not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack(s) %s" % unknown)

    print("Exposure in weight-rounds: aggregation weight summed over every")
    print("round from attack onset until the sanction lands.\n")
    print("%-10s %8s %12s %14s" % ("attack", "onset", "ban round", "exposure"))
    print("-" * 48)

    rows = []
    for attack in args.attacks:
        exps, bans = [], []
        for seed in range(args.seeds):
            exposure, sanctioned, start = measure_exposure(
                attack, seed, args.rounds)
            for a, e in exposure.items():
                exps.append(e)
                if a in sanctioned:
                    bans.append(sanctioned[a] - (start or 0))
        e_mean = st.mean(exps) if exps else float("nan")
        b_mean = st.mean(bans) if bans else float("nan")
        print("%-10s %8s %12.1f %14.2f"
              % (attack, start, b_mean, e_mean))
        rows.append(["synthetic", attack, start, round(b_mean, 2),
                     round(e_mean, 3)])

    rm = real_mnist_exposure(args.results)
    if rm:
        mean_round, n, bound = rm
        print("\nREAL MNIST (from real_mnist.csv, %d seeds)" % n)
        print("  first ban at round %.1f, attack from round 0" % mean_round)
        print("  exposure <= %.1f weight-rounds at the Hardware cap of 1.0"
              % bound)
        rows.append(["real_mnist", "poison", 0, round(mean_round, 2),
                     round(bound, 3)])
        print("\n  This is an UPPER bound: the cap is 1.0 but trust decays over")
        print("  those rounds, so the true figure is lower. Report it as a")
        print("  bound rather than as a measurement, and say why.")

    _write(os.path.join(args.results, "exposure_cost.csv"),
           ["substrate", "attack", "onset", "rounds_to_ban",
            "exposure_weight_rounds"], rows)

    print("\nFor the paper. Compare these against the attacker-cost table,")
    print("which reports 3.70 weight-rounds of influence bought with 8")
    print("Hardware identities. If a single undetected adversary injects a")
    print("comparable amount before its first sanction, then detection latency")
    print("costs about as much as an attacker's entire identity budget, and")
    print("that is the sentence the latency discussion is currently missing.")


if __name__ == "__main__":
    main()
