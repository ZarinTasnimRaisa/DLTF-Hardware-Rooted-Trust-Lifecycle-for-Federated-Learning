"""
exp_scale.py -- does the trust layer still work at federation sizes above six?

WHY

The paper concedes, correctly, that six clients is a feasibility result and not
a scalability one, and that the reviewed literature evaluates 10 to 100
participants. The chain layer is already measured to 20 clients for gas and 50
for latency; the TRUST layer is not. That asymmetry is the gap: cost is shown to
scale, behaviour is not.

Three properties are worth checking as the federation grows, and they can move
in opposite directions:

  ACCURACY MARGIN   more honest clients should help the median-based detector
                    stages, so the margin over an unweighted baseline should
                    hold or improve.

  HONEST FALSE      more honest clients means more opportunities to flag one.
  POSITIVES         If the per-client FPR is constant, the probability that
                    SOME honest client is sanctioned grows with n. This is the
                    number most likely to degrade, and the one a reviewer will
                    ask about, because the paper's headline is zero honest
                    sanctions at n = 7.

  DETECTION         the similarity stage compares against a population median;
  LATENCY           a larger population is a more stable reference, so latency
                    should not worsen.

Adversary fraction is held CONSTANT as n grows, so this measures scale rather
than density. Density is already swept separately at fixed n.

Run:
    python -m eval.exp_scale --sizes 6 10 20 50 --seeds 3 --out results/

Output: scale.csv, plus a printed table shaped for the paper.
"""

import os
import csv
import argparse
import statistics as st

from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle,
                            run_rounds)


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


class PlainServer:
    def __init__(self, initial):
        self.global_params = list(initial)
        self.enrolled = set()
        self.rep = None

    def enroll(self, h):
        self.enrolled.add(h.device_label)
        return {"device_id": h.device_label, "tier": "NONE", "status": "ACTIVE"}

    def run_round(self, rid, handles):
        upd = [h.train(rid, self.global_params)["update"]
               for h in handles if h.device_label in self.enrolled]
        if upd:
            n = len(upd)
            agg = [sum(u[i] for u in upd) / n for i in range(len(upd[0]))]
            self.global_params = [p + a
                                  for p, a in zip(self.global_params, agg)]
        # run_rounds() reads weights, events AND probation_decisions from the
        # round report. A control arm has no trust layer and therefore no
        # probation, but the key must still be present or the harness raises.
        # This mirrors eval.scenarios.BaselineServer exactly.
        return {"round": rid, "events": {}, "weights": {},
                "probation_decisions": [], "aggregated": True}


def build(world, defense, attack, seed, n_total, frac, attacker_tier=2):
    """Adversary count scales with n so the FRACTION is held constant."""
    kind, _default_n_att, start = ATTACKS[attack]
    n_att = max(1, int(round(n_total * frac))) if attack != "none" else 0
    n_honest = n_total - n_att

    ca_key, ca_cert = generate_test_ca()
    if defense == "dltf":
        server = FederatedServer(initial_params=[0.0] * world.dim,
                                 ca_bundle_pem=ca_bundle_pem(ca_cert),
                                 shadow_eval_fn=world.accuracy)
    else:
        server = PlainServer([0.0] * world.dim)

    handles, attackers = [], []
    for k in range(n_honest):
        handles.append(make_handle("h%d" % k,
                                   behavior(world, "honest", seed * 1000 + k)))
    for k in range(n_att):
        label = "a%d" % k
        cert, fail = None, False
        if attacker_tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif attacker_tier == 3:
            fail = True
        handles.append(make_handle(
            label, behavior(world, kind, seed * 1000 + 500 + k,
                            attack_start=start, group_seed=seed + 1),
            ek_cert_der=cert, fail_activation=fail))
        attackers.append(label)

    for h in handles:
        server.enroll(h)
    return server, handles, attackers, n_honest, start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="*", default=[6, 10, 20, 50])
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--frac", type=float, default=0.25,
                    help="adversary fraction, held constant across sizes")
    ap.add_argument("--attacks", nargs="*", default=["none", "poison", "sybil"])
    ap.add_argument("--out", default="results")
    args = ap.parse_args()

    unknown = [a for a in args.attacks if a not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack(s) %s; available: %s"
                         % (unknown, sorted(ATTACKS)))

    rows = []
    print("%-8s %-7s %-6s %9s %9s %11s"
          % ("attack", "clients", "adv", "acc DLTF", "acc plain", "honest FPR"))
    print("-" * 58)

    for attack in args.attacks:
        for n in args.sizes:
            acc = {"dltf": [], "plain": []}
            honest_banned_runs = 0
            honest_banned_clients = 0
            honest_total = 0
            n_att_used = 0
            for defense in ("plain", "dltf"):
                for seed in range(args.seeds):
                    world = SyntheticWorld(seed)
                    server, handles, attackers, n_honest, _ = build(
                        world, defense, attack, seed, n, args.frac)
                    n_att_used = len(attackers)
                    rec = run_rounds(server, handles, world, args.rounds)
                    acc[defense].append(rec[-1]["accuracy"])
                    if defense == "dltf":
                        banned = rec[-1]["banned"]
                        hb = len([b for b in banned if b not in attackers])
                        honest_banned_clients += hb
                        honest_total += n_honest
                        if hb:
                            honest_banned_runs += 1
            fpr = honest_banned_clients / max(1, honest_total)
            rows.append([attack, n, n_att_used,
                         round(st.mean(acc["dltf"]), 4),
                         round(st.mean(acc["plain"]), 4),
                         round(st.mean(acc["dltf"]) - st.mean(acc["plain"]), 4),
                         round(fpr, 4), honest_banned_runs, args.seeds])
            print("%-8s %-7d %-6d %9.4f %9.4f %11.4f"
                  % (attack, n, n_att_used, st.mean(acc["dltf"]),
                     st.mean(acc["plain"]), fpr))

    _write(os.path.join(args.out, "scale.csv"),
           ["attack", "clients", "adversaries", "acc_dltf", "acc_plain",
            "margin", "honest_ban_rate", "runs_with_honest_ban", "runs"], rows)

    print("\nRead the honest-FPR column down each attack block. If it stays at")
    print("zero to 50 clients, the paper can drop 'feasibility, not")
    print("scalability' for the trust layer and keep it only for the physical")
    print("deployment. If it rises with n, that is a real finding and belongs")
    print("in the paper: per-client FPR times n is the quantity that matters.")


if __name__ == "__main__":
    main()
