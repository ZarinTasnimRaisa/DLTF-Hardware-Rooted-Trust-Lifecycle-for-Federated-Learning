"""
exp_commit_gas.py -- what does the commitment layer cost on chain?

WHY THIS EXISTS

`run_local.py --require-commit` runs the commitment layer in a live federation
and prints "commitment: N wallets bound ... clients now commit before sending",
but it reports no gas, and both the on and off runs mirror the same 146 writes.
That is not a bug: run_local drives a MOCK backend, which records events without
charging for them. Nothing in the tree calls `chain_eval.evm_stack(
require_commit=True)`, and there is no CLI flag that reaches it, so the
commitment layer's price has never been measured anywhere.

The paper describes three submission paths in the protocol section and promises
their costs in the evaluation. N24-N28 are proven by the contract suite; what is
missing is the number.

WHAT IT MEASURES

  1. Per-operation gas for bindWallet, commitGradient and the batched path,
     against real bytecode on in-process py-evm under real gas rules.
  2. Deployment gas with requireCommit on versus off, since the flag is
     immutable and set at construction.
  3. Per-round gas for a federation with the layer on versus off, which is the
     figure that belongs beside the existing affine fit: it says what fraction
     of a round's cost non-repudiation actually adds.

Run:
    python -m eval.exp_commit_gas --clients 6 --rounds 6 --out results/chain

Output: commit_gas.csv, and a printed comparison against the paper's
58,281 + 38,818n baseline.
"""

import os
import csv
import hashlib
import argparse

from eval.chain_eval import evm_stack, run_federation, WRITER


def _write(path, header, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("wrote", path, "(%d rows)" % len(rows))


def deploy_cost():
    """requireCommit is immutable and set at construction, so the two
    deployments are different bytecode paths and may differ in cost."""
    off, _, _ = evm_stack(require_commit=False)
    on, _, _ = evm_stack(require_commit=True)
    return off.deploy_gas, on.deploy_gas


def per_operation():
    """Micro-benchmark the commitment entry points, following the same pattern
    as chain_eval.exp_gas so the numbers are directly comparable."""
    from chain.fixedpoint import TierFP

    rows = []
    backend, w3, _ = evm_stack(require_commit=True)
    dev = "c1"
    backend.register(WRITER, dev, TierFP.HARDWARE,
                     hashlib.sha256(b"c1").digest())

    wallet = w3.eth.accounts[1]
    backend.gas_reset()
    try:
        backend.bind_wallet(WRITER, dev, wallet)
        rows.append(["bindWallet", backend.gas_log[-1][1]])
    except AttributeError:
        print("  NOTE: EvmBackend exposes no bind_wallet(); the commitment")
        print("  entry points are reachable from the contract but not from the")
        print("  Python backend. Report deployment and per-round cost only,")
        print("  and say so rather than leaving the row blank.")
        return rows, backend
    return rows, backend


def capability_probe():
    """Can the Python stack reach the commitment layer at all?

    This is the question the per-round comparison was assuming away. An earlier
    version of this script looped over (off, True) and (on, False) and called
    run_federation identically in both branches -- the flag was never used, so
    it measured the same configuration twice and reported the two equal numbers
    as evidence of zero cost. That was a bug in this script.

    Fixing it does not rescue the measurement, because run_federation reaches
    the chain through make_audit(), which calls evm_stack() with the default
    require_commit=False, and more fundamentally because EvmBackend implements
    register/classify/enter_probation/probation_decision/round_summary and
    nothing else. There is no bind_wallet, no commit_gradient and no
    classify_signed on the Python backend, in either the EVM or the mock
    implementation.

    So the commitment layer is real in Solidity and verified by the contract
    suite, and unreachable from the running federation. That is the finding.
    """
    from chain.evm import EvmBackend
    from chain.mock import MockBackend
    wanted = ["bind_wallet", "commit_gradient", "classify_signed",
              "commit_batch", "report_commit_mismatch"]
    rows = []
    for cls in (EvmBackend, MockBackend):
        for name in wanted:
            rows.append([cls.__name__, name, hasattr(cls, name)])
    return rows


def per_round(clients, rounds):
    """Baseline per-round gas, for context against the affine fit. There is no
    commit-enabled counterpart to compare it against; see capability_probe."""
    res = run_federation("node", clients, rounds, n_attackers=0, seed=0)
    gas = [pr["gas"] for pr in res["per_round"]]
    steady = gas[1:] or gas
    return sum(steady) / len(steady)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--out", default="results/chain")
    args = ap.parse_args()

    rows = []

    print("== deployment ==")
    off, on = deploy_cost()
    print("  requireCommit off: %d gas" % off)
    print("  requireCommit on : %d gas  (%+d)" % (on, on - off))
    rows.append(["deploy, requireCommit off", off])
    rows.append(["deploy, requireCommit on", on])

    print("\n== per operation ==")
    ops, _ = per_operation()
    for name, gas in ops:
        print("  %-24s %d gas" % (name, gas))
        rows.append([name, gas])

    print("\n== can the Python stack reach the commitment layer? ==")
    probe = capability_probe()
    for cls, name, present in probe:
        print("  %-14s %-24s %s" % (cls, name, "yes" if present else "NO"))
    reachable = any(p for _c, _n, p in probe)

    print("\n== per round, %d clients (baseline) ==" % args.clients)
    base = per_round(args.clients, args.rounds)
    print("  %.0f gas/round" % base)
    rows.append(["steady round, %d clients" % args.clients, int(base)])

    _write(os.path.join(args.out, "commit_gas.csv"), ["operation", "gas"], rows)

    baseline = 58281 + 38818 * args.clients
    print("\nThe paper's affine fit predicts %d gas for %d clients."
          % (baseline, args.clients))
    print("Express the commitment layer as a fraction of that, not as an")
    print("absolute number: a reviewer wants to know what share of a round")
    print("non-repudiation costs, which is the trade the design is making.")
    if not reachable:
        print("\nCONCLUSION. The commitment layer is implemented in the")
        print("contract and verified by the Foundry suite (N24-N28), but no")
        print("backend method reaches it, so no federation in this tree has")
        print("ever exercised it on chain. The deployment delta above is the")
        print("only cost that can be measured today: setting the immutable")
        print("requireCommit flag costs %d gas, once, at construction."
              % (on - off))
        print("\nThe paper must say the layer is contract-verified but not")
        print("integrated, and must not report its per-round cost as zero.")
        print("Wiring bind_wallet and commit_gradient into EvmBackend is the")
        print("work that would make the cost measurable.")


if __name__ == "__main__":
    main()
