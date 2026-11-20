"""
exp_m3.py -- when does M3 actually earn its keep?

WHY THIS EXISTS

diagnose_ablation.py established three things about the scenario runs:

  * Params reaches the engine (probation_t=0.99 banned all 7 honest clients),
    so the flat sweep is real behaviour and not a broken harness.
  * The sleeper attackers receive NEUTRAL for eleven rounds and then CRITICAL
    at round 11 -- never MAJOR.
  * Ban round is 11 with M3 on and 11 with M3 off. Identical.

The cause is scenario composition, not a defect. The "sleeper" scenario runs
TWO attackers sharing a group seed, so their post-dormancy updates are mutually
similar and the FoolsGold-style pairwise-similarity stage classifies them as
collusion -> CRITICAL -> immediate ban. A CRITICAL bans ahead of M3, ahead of
the cold-start gate and ahead of every threshold, which is exactly why nine
swept constants all came out flat.

So the paper cannot say, of these runs, that M3 catches the sleeper. What it
CAN say is more interesting, and this experiment is what licenses it.

THE HYPOTHESIS

FoolsGold "degrades to nothing against a single adversary" -- Fung et al. say
so themselves, and the paper already cites that concession. With ONE sleeper
there is no second colluder, no pairwise similarity, and therefore no CRITICAL.
The only remaining signal is self-history reversal, which emits MAJOR. Two
consecutive MAJORs is precisely M3's trigger.

If that holds, M3 covers exactly the blind spot of the detector it sits behind:

    2 attackers -> collusion stage fires  -> CRITICAL -> M3 irrelevant
    1 attacker  -> collusion stage blind  -> MAJOR    -> M3 is the only catch

That is a far stronger claim than "the sleeper is caught", because it says
WHERE the borrowed detector fails and WHY the added mechanism is not
redundant. It also turns the null ablation from an embarrassment into a
result: M3 is a backstop, and here is the case that needs it.

WHAT TO EXPECT

  n_att=1, M3 on   -> attacker banned (or put on probation) a round or two
                      after its attack starts
  n_att=1, M3 off  -> attacker survives noticeably longer, or to the end
  n_att=2, either  -> identical, both banned by CRITICAL

If the n_att=1 rows are ALSO identical, M3 is genuinely redundant against this
detector and the paper should say so plainly rather than claim a mechanism it
cannot demonstrate. Either outcome is publishable; only silence is not.

Run:
    python -m eval.exp_m3 --seeds 5 --rounds 30 --out results/
"""

import os
import csv
import argparse
import statistics as st

from trust.reputation import Params, ReputationEngine
from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle)

SEV_NAME = {0: "POSITIVE", 1: "NEUTRAL", 2: "MINOR", 3: "MAJOR", 4: "CRITICAL"}
NAME_TO_SEV = {v: k for k, v in SEV_NAME.items()}


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


def _sev(s):
    if isinstance(s, int) and not isinstance(s, bool):
        return s
    if isinstance(s, str):
        t = s.strip().upper().split(".")[-1]
        return int(t) if t.isdigit() else NAME_TO_SEV.get(t)
    n = getattr(s, "name", None)
    if isinstance(n, str):
        return NAME_TO_SEV.get(n.upper())
    v = getattr(s, "value", None)
    return v if isinstance(v, int) else None


def _events(rep):
    ev = rep.get("events", {})
    out = {}
    if isinstance(ev, dict):
        for dev, val in ev.items():
            s = _sev(val)
            if s is None and isinstance(val, dict):
                s = _sev(val.get("severity", val.get("sev")))
            if s is not None:
                out[dev] = s
    elif isinstance(ev, (list, tuple)):
        for rec in ev:
            if isinstance(rec, dict):
                d = rec.get("device", rec.get("device_id"))
                s = _sev(rec.get("severity", rec.get("sev")))
                if d is not None and s is not None:
                    out[d] = s
    return out


def _run(world, attack, seed, params, n_att_override, rounds,
         n_honest=7, attacker_tier=1):
    """attacker_tier defaults to HARDWARE so probation is available and the
    full lifecycle -- not just an immediate ban -- can be observed."""
    kind, n_att, start = ATTACKS[attack]
    if n_att_override is not None:
        n_att = n_att_override

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

    sanction_round = {}
    worst_sev = {a: 0 for a in attackers}
    for r in range(rounds):
        rep = server.run_round(r, handles)
        for dev, s in _events(rep).items():
            if dev in worst_sev:
                worst_sev[dev] = max(worst_sev[dev], s)
        for a in attackers:
            if a in sanction_round:
                continue
            d = server.rep._dev.get(a)
            status = str(getattr(d, "status", "")).upper()
            if "BAN" in status or "PROBATION" in status:
                sanction_round[a] = (r, status.split(".")[-1])

    return {"attackers": attackers, "start": start,
            "sanction": sanction_round, "worst_sev": worst_sev}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--out", default="results")
    ap.add_argument("--attacks", nargs="*", default=["sleeper", "poison"])
    args = ap.parse_args()

    unknown = [a for a in args.attacks if a not in ATTACKS]
    if unknown:
        raise SystemExit("unknown attack(s) %s; available: %s"
                         % (unknown, sorted(ATTACKS)))

    rows = []
    print("%-9s %-6s %-7s %9s %9s %s"
          % ("attack", "n_att", "M3", "sanctioned", "mean rnd", "worst severity"))
    print("-" * 68)

    for attack in args.attacks:
        for n_att in (1, 2):
            for m3 in (True, False):
                p = Params(m3_enabled=m3)
                caught, when, sevs = 0, [], []
                total = 0
                for seed in range(args.seeds):
                    world = SyntheticWorld(seed)
                    r = _run(world, attack, seed, p, n_att, args.rounds)
                    total += len(r["attackers"])
                    caught += len(r["sanction"])
                    when.extend(v[0] for v in r["sanction"].values())
                    sevs.extend(r["worst_sev"].values())
                worst = SEV_NAME.get(max(sevs) if sevs else 0, "?")
                mean_rnd = round(st.mean(when), 1) if when else float("nan")
                print("%-9s %-6d %-7s %5d/%-3d %9s %s"
                      % (attack, n_att, "on" if m3 else "off",
                         caught, total, mean_rnd, worst))
                rows.append([attack, n_att, "on" if m3 else "off",
                             caught, total, mean_rnd, worst])

    _write(os.path.join(args.out, "m3_isolation.csv"),
           ["attack", "n_attackers", "m3", "sanctioned", "total",
            "mean_sanction_round", "worst_severity"], rows)

    print("\nHow to read this:")
    print("  Compare the two n_att=1 rows for each attack. If M3 'off'")
    print("  sanctions fewer attackers or sanctions them later, M3 covers the")
    print("  single-adversary blind spot the collusion stage cannot see, and")
    print("  the paper can say so with this table as evidence.")
    print("  If the n_att=1 rows match, M3 is redundant against this detector")
    print("  and the paper should state that instead. Both are results.")
    print("  The n_att=2 rows should match either way -- CRITICAL pre-empts M3.")


if __name__ == "__main__":
    main()
