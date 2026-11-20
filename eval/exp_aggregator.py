"""
exp_aggregator.py -- O4: the trust layer is aggregator-agnostic.

Answers two questions the current evaluation leaves open.

  (1) INTERFACE (the literal O4 claim). The trust layer exports a per-client
      weight dictionary. Is that dictionary consumed *unchanged* by fedavg,
      trimmed_mean and krum alike? We capture a real weight dict from a live
      DLTF round and feed it to all three rules, checking each produces an
      aggregate and none mutates the dictionary it was handed.

  (2) COMPOSITION (the reviewer's question). The paper compares DLTF against
      an equal-weight aggregator only, while spending a page critiquing Krum,
      trimmed mean and FoolsGold. The informative experiment is not "DLTF vs
      Krum" -- they are not alternatives -- but "Krum with and without the
      layer". This runs the full {no layer, DLTF} x {fedavg, trimmed_mean,
      krum} grid so that comparison can be made directly.

  Why (2) matters: Krum and trimmed mean assume a bound on the malicious
  FRACTION. DLTF bounds the identity SUPPLY that fraction is drawn from. If
  the layer lifts Krum under Sybil attack, that demonstrates composition
  rather than competition, which is what the paper actually claims.

No existing file is modified. The no-layer arm is defined here rather than
reusing eval.scenarios.BaselineServer, because that class hardcodes fedavg.

Run:
    python -m eval.exp_aggregator --seeds 5 --rounds 30 --out results/
    python -m eval.exp_aggregator --attacks poison sybil --out results/

Outputs:
    aggregator_grid.csv   one row per (aggregator, attack, defense, seed)
    aggregator_iface.csv  the interface check, one row per rule
"""

import os
import csv
import copy
import argparse

from fl.server import FederatedServer
from fl.aggregator import AGGREGATORS, get_aggregator
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle,
                            run_rounds)

RULES = ("fedavg", "trimmed_mean", "krum")


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


class PlainServer:
    """No identity, no trust: every enrollment accepted, equal weights forever,
    but the aggregation RULE is selectable. This is the 'robust rule without
    the trust layer' arm -- e.g. Krum on its own."""

    def __init__(self, initial_params, aggregator="fedavg"):
        self.global_params = list(initial_params)
        self.enrolled = set()
        self.rep = None                      # run_rounds() checks this
        self._agg = get_aggregator(aggregator)

    def enroll(self, handle):
        self.enrolled.add(handle.device_label)
        return {"device_id": handle.device_label, "tier": "NONE",
                "status": "ACTIVE", "reason": "plain server accepts everything"}

    def run_round(self, round_id, handles):
        updates = {h.device_label: h.train(round_id, self.global_params)["update"]
                   for h in handles if h.device_label in self.enrolled}
        weights = {i: 1.0 for i in updates}
        agg = self._agg(updates, weights)
        self.global_params = [p + u for p, u in zip(self.global_params, agg)]
        return {"round": round_id, "events": {}, "weights": weights,
                "probation_decisions": [], "aggregated": True}


def _federation(world, defense, attack, seed, aggregator,
                n_honest=7, attacker_tier=2):
    """Mirror of eval.scenarios.build(), with the aggregator threaded through
    BOTH arms so the grid is like-for-like."""
    kind, n_att, start = ATTACKS[attack]
    ca_key, ca_cert = generate_test_ca()

    if defense == "dltf":
        server = FederatedServer(initial_params=[0.0] * world.dim,
                                 ca_bundle_pem=ca_bundle_pem(ca_cert),
                                 shadow_eval_fn=world.accuracy,
                                 aggregator=aggregator)
    elif defense == "plain":
        server = PlainServer([0.0] * world.dim, aggregator=aggregator)
    else:
        raise ValueError(defense)

    handles = [make_handle("h%d" % k, behavior(world, "honest", seed * 100 + k))
               for k in range(n_honest)]
    attackers = []
    for k in range(n_att):
        label = "a%d" % k
        trainer = behavior(world, kind, seed * 100 + 50 + k,
                           attack_start=start, group_seed=seed + 1)
        cert, fail = None, False
        if attacker_tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif attacker_tier == 3:
            fail = True
        handles.append(make_handle(label, trainer, ek_cert_der=cert,
                                   fail_activation=fail))
        attackers.append(label)

    for h in handles:
        server.enroll(h)
    return server, handles, attackers, start


# --------------------------------------------------------------------------
# (1) interface check -- the literal O4 claim
# --------------------------------------------------------------------------

def check_interface(seed=0, rounds=6, attack=None):
    """Capture a real weight dict from a DLTF round, then hand the SAME dict to
    every aggregation rule. Records whether each rule accepted it and whether
    the dict came back unmutated."""
    attack = attack or sorted(ATTACKS)[0]
    world = SyntheticWorld(seed)
    server, handles, _, _ = _federation(world, "dltf", attack, seed, "fedavg")

    # advance a few rounds so weights are non-trivial (some devices sanctioned)
    for r in range(rounds):
        rep = server.run_round(r, handles)

    weights = rep["weights"]
    updates = {h.device_label: h.train(rounds, server.global_params)["update"]
               for h in handles if h.device_label in server.enrolled}

    rows = []
    for name in RULES:
        rule = AGGREGATORS[name]
        before = copy.deepcopy(weights)
        try:
            out = rule(updates, weights)
            ok = out is not None and len(out) == world.dim
            err = ""
        except Exception as exc:                       # noqa: BLE001
            ok, err = False, type(exc).__name__ + ": " + str(exc)[:60]
        rows.append([name, len(weights), "yes" if ok else "no",
                     "yes" if weights == before else "NO -- MUTATED", err])
    return rows, weights


# --------------------------------------------------------------------------
# (2) composition grid
# --------------------------------------------------------------------------

def run_grid(seeds, rounds, attacks, out):
    rows = []
    for agg in RULES:
        for attack in attacks:
            for defense in ("plain", "dltf"):
                for seed in range(seeds):
                    world = SyntheticWorld(seed)
                    server, handles, att, start = _federation(
                        world, defense, attack, seed, agg)
                    rec = run_rounds(server, handles, world, rounds)
                    final = rec[-1]
                    rows.append([agg, attack, defense, seed,
                                 round(final["accuracy"], 4),
                                 len(final["banned"])])
                    print("  %-13s %-10s %-6s seed=%d  acc=%.4f banned=%d"
                          % (agg, attack, defense, seed,
                             final["accuracy"], len(final["banned"])))
    _write(os.path.join(out, "aggregator_grid.csv"),
           ["aggregator", "attack", "defense", "seed",
            "final_accuracy", "n_banned"], rows)
    return rows


def summarise(rows):
    """Print the table to paste into the paper: mean final accuracy per
    (rule, attack), layer off vs on, and the delta the layer contributes."""
    import statistics as st
    key = {}
    for agg, attack, defense, seed, acc, nb in rows:
        key.setdefault((agg, attack, defense), []).append(acc)
    print("\n%-13s %-10s %8s %8s %8s" % ("aggregator", "attack",
                                         "no layer", "+DLTF", "delta"))
    print("-" * 52)
    for (agg, attack, _), _v in sorted(key.items()):
        if (agg, attack, "plain") not in key:
            continue
        off = st.mean(key[(agg, attack, "plain")])
        on = st.mean(key[(agg, attack, "dltf")])
        print("%-13s %-10s %8.4f %8.4f %+8.4f" % (agg, attack, off, on, on - off))
        key.pop((agg, attack, "plain"), None)
        key.pop((agg, attack, "dltf"), None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--out", default="results")
    ap.add_argument("--attacks", nargs="*", default=None,
                    help="subset of ATTACKS keys; default = all")
    args = ap.parse_args()

    attacks = args.attacks or sorted(ATTACKS)
    unknown = [a for a in attacks if a not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack(s) %s; available: %s"
                         % (unknown, sorted(ATTACKS)))

    print("== O4 interface check ==")
    iface, weights = check_interface()
    for r in iface:
        print("  %-13s n_weights=%-3d accepted=%-4s unmutated=%s %s"
              % (r[0], r[1], r[2], r[3], r[4]))
    _write(os.path.join(args.out, "aggregator_iface.csv"),
           ["rule", "n_weights", "accepted", "weights_unmutated", "error"],
           iface)

    print("\n== composition grid ==")
    rows = run_grid(args.seeds, args.rounds, attacks, args.out)
    summarise(rows)


if __name__ == "__main__":
    main()
