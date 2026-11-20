"""
exp_engine_sweep.py -- Class 2 evidence for the Reputation Engine's constants.

The paper sweeps DETECTOR thresholds and reports the defaults sit in a flat
region. It never sweeps the ENGINE's own constants, so every trust trajectory,
sanction path and attacker-cost number rests on Class 1 evidence alone --
"the implementation exhibits this property" -- defended by derivation rather
than by demonstrated stability. Table 4.2 marks seven of those constants
CALIBRATED, and a calibrated constant with no sweep behind it is exactly what
a reviewer probes.

trust.reputation.Params is already an injectable dataclass whose docstring says
"the sensitivity sweep instantiates variants of this", and it already carries
m3_enabled and gate_enabled switches. This is the sweep that was intended.

Two kinds of row are produced.

  SWEEP     -- vary one constant at a time around its default and record final
               accuracy, devices banned, and honest false positives. A constant
               is defensible if results are flat in a neighbourhood of the
               default, in the same sense the detector sweep established.

  ABLATION  -- switch M3 (sustained escalation) and the cold-start gate off.
               These are not sensitivity questions but mechanism questions:
               M3 off should let the SLEEPER survive, since that is the case
               the paper says a score-only design fails. If the sleeper is
               still caught with M3 disabled, M3 is not doing the work the
               paper attributes to it, and you need to know that before a
               reviewer finds it.

Run:
    python -m eval.exp_engine_sweep --seeds 5 --rounds 30 --out results/

Outputs:
    engine_sweep.csv
    engine_ablation.csv
"""

import os
import csv
import argparse
import statistics as st

from trust.reputation import Params, ReputationEngine
from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle,
                            run_rounds)

# constant -> values to try. Defaults per Table 4.2 are included so the
# neighbourhood is visible in the output.
SWEEP = {
    "gamma":                 [0.80, 0.85, 0.90, 0.95],          # default 0.90
    "theta":                 [0.30, 0.40, 0.50],                # default 0.40
    "tau":                   [0.40, 0.60, 0.80],                # default 0.60
    "forgive_after":         [1, 2, 3, 4],                      # default 2
    "major_run_to_escalate": [2, 3, 4],                         # default 2
    "probation_t":           [0.40, 0.45, 0.50, 0.55, 0.60],    # default 0.50
    "ban_t":                 [0.20, 0.25, 0.30, 0.35],          # default 0.30
    "d2":                    [0.3, 0.5, 0.7],                   # default 0.5
    "d3":                    [0.05, 0.10, 0.20],                # default 0.1
}


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


def _run_one(world, attack, seed, params, rounds, n_honest=7, attacker_tier=2):
    """One federation with an injected Params bundle."""
    kind, n_att, start = ATTACKS[attack]
    ca_key, ca_cert = generate_test_ca()
    server = FederatedServer(initial_params=[0.0] * world.dim,
                             ca_bundle_pem=ca_bundle_pem(ca_cert),
                             shadow_eval_fn=world.accuracy,
                             reputation_engine=ReputationEngine(params))

    handles = [make_handle("h%d" % k, behavior(world, "honest", seed * 100 + k))
               for k in range(n_honest)]
    attackers = []
    for k in range(n_att):
        label = "a%d" % k
        cert, fail = None, False
        if attacker_tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif attacker_tier == 3:
            fail = True
        handles.append(make_handle(
            label, behavior(world, kind, seed * 100 + 50 + k,
                            attack_start=start, group_seed=seed + 1),
            ek_cert_der=cert, fail_activation=fail))
        attackers.append(label)

    for h in handles:
        server.enroll(h)
    rec = run_rounds(server, handles, world, rounds)

    banned = rec[-1]["banned"]
    honest = {h.device_label for h in handles
              if h.device_label not in attackers}
    return {"accuracy": rec[-1]["accuracy"],
            "n_banned": len(banned),
            "attackers_banned": len(banned & set(attackers)),
            "honest_banned": len(banned & honest),
            "n_honest": len(honest),
            "n_attackers": len(attackers)}


def sweep(seeds, rounds, attacks, out):
    rows = []
    for field, values in SWEEP.items():
        default = getattr(Params(), field)
        for val in values:
            for attack in attacks:
                accs, hb, ab = [], [], []
                for seed in range(seeds):
                    world = SyntheticWorld(seed)
                    p = Params(**{field: val})
                    r = _run_one(world, attack, seed, p, rounds)
                    accs.append(r["accuracy"])
                    hb.append(r["honest_banned"] / max(1, r["n_honest"]))
                    ab.append(r["attackers_banned"] / max(1, r["n_attackers"]))
                rows.append([field, val, val == default, attack,
                             round(st.mean(accs), 4),
                             round(st.pstdev(accs), 4) if seeds > 1 else 0.0,
                             round(st.mean(hb), 4),
                             round(st.mean(ab), 4)])
                print("  %-22s = %-6s %-10s acc=%.4f honest_fpr=%.3f "
                      "attackers_banned=%.2f%s"
                      % (field, val, attack, st.mean(accs), st.mean(hb),
                         st.mean(ab), "   <- default" if val == default else ""))
    _write(os.path.join(out, "engine_sweep.csv"),
           ["parameter", "value", "is_default", "attack", "accuracy_mean",
            "accuracy_sd", "honest_ban_rate", "attacker_ban_rate"], rows)
    return rows


def ablation(seeds, rounds, attacks, out):
    """Turn one mechanism off at a time. This is the interesting table."""
    variants = [("baseline (all on)", {}),
                ("M3 off (no escalation)", {"m3_enabled": False}),
                ("cold-start gate off", {"gate_enabled": False}),
                ("M3 + gate off", {"m3_enabled": False,
                                   "gate_enabled": False})]
    rows = []
    for name, kw in variants:
        for attack in attacks:
            accs, hb, ab = [], [], []
            for seed in range(seeds):
                world = SyntheticWorld(seed)
                r = _run_one(world, attack, seed, Params(**kw), rounds)
                accs.append(r["accuracy"])
                hb.append(r["honest_banned"] / max(1, r["n_honest"]))
                ab.append(r["attackers_banned"] / max(1, r["n_attackers"]))
            rows.append([name, attack, round(st.mean(accs), 4),
                         round(st.mean(hb), 4), round(st.mean(ab), 4)])
            print("  %-24s %-10s acc=%.4f honest_fpr=%.3f attackers_banned=%.2f"
                  % (name, attack, st.mean(accs), st.mean(hb), st.mean(ab)))
    _write(os.path.join(out, "engine_ablation.csv"),
           ["variant", "attack", "accuracy_mean", "honest_ban_rate",
            "attacker_ban_rate"], rows)
    print("\nRead the sleeper row first: with M3 off the sleeper should "
          "survive.\nIf it is still banned, M3 is not the mechanism catching "
          "it and the\npaper's claim about sustained escalation needs "
          "rewording.")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--out", default="results")
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--skip-sweep", action="store_true")
    args = ap.parse_args()

    attacks = args.attacks or sorted(ATTACKS)
    unknown = [a for a in attacks if a not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack(s) %s; available: %s"
                         % (unknown, sorted(ATTACKS)))

    print("== mechanism ablation ==")
    ablation(args.seeds, args.rounds, attacks, args.out)
    if not args.skip_sweep:
        print("\n== constant sweep ==")
        sweep(args.seeds, args.rounds, attacks, args.out)


if __name__ == "__main__":
    main()
