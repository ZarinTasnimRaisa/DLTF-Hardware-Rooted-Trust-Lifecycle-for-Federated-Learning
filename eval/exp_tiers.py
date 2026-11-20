"""
exp_tiers.py -- O1: identity binding and tier assignment.

The paper currently supports O1 with a single clause ("both physical clients
enrol at Hardware"). O1 is the foundation the other three objectives rest on,
and it has no table. This produces one.

The design claim is that tier is the CONJUNCTION of two independent gates, not
their maximum:

    Gate 1 (certificate)  -- an EK certificate chains to a trusted manufacturer
                             root. Establishes a genuine chip was ISSUED, and
                             nothing about the machine presenting it.
    Gate 2 (activation)   -- a secret sealed to the presented EK public bytes is
                             recovered. Establishes the presenter HOLDS the chip,
                             and nothing about whether it is certified silicon.

Four combinations exist and the matrix must show all four, including the two
that a "maximum" rule would get wrong:

    G1  G2   expected tier    why it matters
    --  --   --------------   ----------------------------------------------
    Y   Y    HARDWARE         both properties proven
    N   Y    TPM_RESIDENT     ordinary firmware TPM with no fetchable cert;
                              also the CEILING a software TPM can reach
    Y   N    SOFTWARE         <-- the load-bearing negative result. A cert
                              without possession is evidence about a chip
                              somewhere in the world, not about this machine.
                              A max() rule would wrongly grant HARDWARE here.
    N   N    SOFTWARE         trust on first use

It also records enrollment wall-clock per case, so O1 has a cost number, and
re-enrolls each identity to show the fingerprint is stable across attempts.

Run:
    python -m eval.exp_tiers --repeats 5 --out results/

Output:
    tier_matrix.csv
"""

import os
import csv
import time
import argparse
import statistics as st

from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import SyntheticWorld, behavior, make_handle

# (case label, present a certificate?, force activation to fail?, expected tier)
CASES = [
    ("discrete TPM, cert fetchable",   True,  False, "HARDWARE"),
    ("firmware TPM, no cert",          False, False, "TPM_RESIDENT"),
    ("software TPM (swtpm) ceiling",   False, False, "TPM_RESIDENT"),
    ("cert present, activation fails", True,  True,  "SOFTWARE"),
    ("no TPM",                         False, True,  "SOFTWARE"),
]


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


def enroll_once(case, want_cert, fail_act, seed):
    """Enroll one fresh identity under a given gate combination."""
    world = SyntheticWorld(seed)
    ca_key, ca_cert = generate_test_ca()
    server = FederatedServer(initial_params=[0.0] * world.dim,
                             ca_bundle_pem=ca_bundle_pem(ca_cert),
                             shadow_eval_fn=world.accuracy)
    label = "d_%d" % seed
    cert = None
    if want_cert:
        cert, _ = issue_ek_cert(ca_key, ca_cert, label)
    handle = make_handle(label, behavior(world, "honest", seed),
                         ek_cert_der=cert, fail_activation=fail_act)

    t0 = time.perf_counter()
    rec = server.enroll(handle)
    ms = (time.perf_counter() - t0) * 1000.0

    tier = str(rec.get("tier", "?"))
    if "." in tier:                      # e.g. "Tier.HARDWARE"
        tier = tier.split(".")[-1]
    return tier, ms, rec.get("status", "?"), server, handle


def run(repeats, out):
    rows = []
    for case, want_cert, fail_act, expected in CASES:
        tiers, times = [], []
        for seed in range(repeats):
            tier, ms, status, _srv, _h = enroll_once(case, want_cert,
                                                     fail_act, seed)
            tiers.append(tier)
            times.append(ms)
        agree = all(t == tiers[0] for t in tiers)
        observed = tiers[0]
        ok = (observed == expected)
        rows.append([case,
                     "pass" if want_cert else "fail",
                     "fail" if fail_act else "pass",
                     expected, observed,
                     "YES" if ok else "NO",
                     "yes" if agree else "no",
                     round(st.mean(times), 2),
                     round(st.pstdev(times), 2) if repeats > 1 else 0.0])
        flag = "" if ok else "   <-- MISMATCH"
        print("  %-32s G1=%-4s G2=%-4s -> %-12s (expected %-12s)%s"
              % (case, "pass" if want_cert else "fail",
                 "fail" if fail_act else "pass", observed, expected, flag))

    _write(os.path.join(out, "tier_matrix.csv"),
           ["case", "gate1_cert", "gate2_activation", "expected_tier",
            "observed_tier", "matches", "stable_across_repeats",
            "enroll_ms_mean", "enroll_ms_sd"], rows)

    bad = [r for r in rows if r[5] == "NO"]
    if bad:
        print("\n%d case(s) did NOT match the design. Investigate before "
              "reporting this table." % len(bad))
    else:
        print("\nAll %d cases match the conjunction rule." % len(rows))
    return rows


def check_fingerprint_stability(repeats=3):
    """A device re-presenting the same EK must produce the same fingerprint,
    which is what makes a sanction survive re-registration (O2)."""
    world = SyntheticWorld(0)
    ca_key, ca_cert = generate_test_ca()
    label = "stable"
    cert, _ = issue_ek_cert(ca_key, ca_cert, label)
    seen = set()
    for _ in range(repeats):
        server = FederatedServer(initial_params=[0.0] * world.dim,
                                 ca_bundle_pem=ca_bundle_pem(ca_cert),
                                 shadow_eval_fn=world.accuracy)
        handle = make_handle(label, behavior(world, "honest", 0),
                             ek_cert_der=cert)
        server.enroll(handle)
        dev = server.rep._dev.get(label)
        if dev is not None and getattr(dev, "ek_hash", None):
            seen.add(dev.ek_hash)
    print("distinct fingerprints across %d enrollments of one EK: %d "
          "(expected 1)" % (repeats, len(seen)))
    return len(seen)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--out", default="results")
    args = ap.parse_args()
    print("== O1 tier assignment matrix ==")
    run(args.repeats, args.out)
    print("\n== fingerprint stability ==")
    check_fingerprint_stability()


if __name__ == "__main__":
    main()
