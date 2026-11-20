"""
run_server.py  (place in dltf/ project root, run on the SERVER PC)

Builds RemoteClientHandles from config.CLIENTS, enrolls every client agent,
runs FL rounds, prints a per-round report. Audit chain written to results/.

  PYTHONPATH=. python3 run_server.py --rounds 10            # real MNIST model
  PYTHONPATH=. python3 run_server.py --rounds 5 --stub --dim 6   # net smoke test
  PYTHONPATH=. python3 run_server.py --rounds 10 --chain mock    # + chain layer

CHAIN BEHAVIOUR IN REAL MODE
-----------------------------------------------------------------------------
With --chain on, each client's EK hash is checked against the chain's ban set
BEFORE enrollment. A banned EK is refused and the remaining clients continue:
one whitewashing attacker must not take the federation down with it.

The check FAILS OPEN. If the node is unreachable is_banned_on_chain() returns
False and enrollment proceeds, because failing closed would hand anyone who
can DoS the node a federation-wide enrollment DoS. The staleness window this
opens is a stated limitation, not an oversight.

Likewise, if the node dies mid-run the rounds keep going: ChainRegistry
records the failure, marks the round UNANCHORED, and never propagates. The
chain is never on the critical path.
"""
import argparse
import os

import config
from fl.server import FederatedServer
from net.handles import RemoteClientHandle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--stub", action="store_true",
                    help="send a tiny --dim vector instead of the real model "
                         "(no-torch net test)")
    ap.add_argument("--dim", type=int, default=6, help="param size when --stub")
    ap.add_argument("--chain", choices=["off", "mock", "node"],
                    default=config.CHAIN["mode"],
                    help="optional on-chain trust registry (default: from "
                         "config.CHAIN['mode'], itself defaulting to off)")
    args = ap.parse_args()

    os.makedirs("results", exist_ok=True)

    if args.stub:
        initial = [0.0] * args.dim
        print(f"stub mode: sending {args.dim}-value vector")
    else:
        from fl.model import MNISTModel
        initial = MNISTModel().get_parameters()
        print(f"real MNIST model: {len(initial)} parameters")

    handles = []
    for c in config.CLIENTS:
        label = c["device_label"] if isinstance(c, dict) else c.device_label
        endpoint = c["endpoint"] if isinstance(c, dict) else c.endpoint
        backend = (c.get("tpm_backend", "mock") if isinstance(c, dict)
                   else getattr(c, "tpm_backend", "mock"))
        handles.append(RemoteClientHandle(label, endpoint, tpm_backend=backend))

    # ---- audit / chain stack -------------------------------------------------
    from chain.wiring import build_audit, chain_report_lines
    audit, chain_backend, fed_key = build_audit(
        mode=args.chain,
        audit_path="results/audit.jsonl",
        fed_key_path=(config.CHAIN["federation_key_path"]
                      if args.chain != "off" else None),
        rpc_url=config.CHAIN["rpc_url"],
        contract_address=config.CHAIN["contract_address"])
    if args.chain != "off":
        print(f"chain: {args.chain}")

    ca_pem = open("tpm/ca/amd_ftpm_ca.pem", "rb").read()
    server = FederatedServer(initial, ca_bundle_pem=ca_pem, audit=audit)

    # ---- enrollment, with the pre-enrollment whitewash check ----------------
    enrolled = []
    for h in handles:
        if chain_backend is not None:
            try:
                ek_hash = h.enroll_payload()["ek_hash"]
            except Exception as exc:
                print(f"skipped {h.device_label}: unreachable ({exc})")
                continue
            if audit.is_banned_on_chain(ek_hash):
                print(f"WHITEWASH_REJECTED: {h.device_label} presents an EK "
                      f"banned on chain; refusing enrollment")
                audit.append("WHITEWASH_REJECTED",
                             {"device": h.device_label, "ek_hash": ek_hash})
                continue
        try:
            r = server.enroll(h)
        except Exception as exc:
            print(f"skipped {h.device_label}: enrollment failed ({exc})")
            continue
        enrolled.append(h)
        print(f"enrolled {r['device_id']}: tier {r['tier']}, "
              f"status {r['status']}")

    if not enrolled:
        print("no clients enrolled, nothing to do")
        return

    # ---- rounds --------------------------------------------------------------
    for rnd in range(args.rounds):
        rep = server.run_round(rnd, enrolled)
        flags = {d: e["severity"] for d, e in rep["events"].items()
                 if e["severity"] != "NEUTRAL"}
        print(f"round {rnd}: weights {rep['weights']} flags {flags}")

    for line in chain_report_lines(audit):
        print(line)

    if chain_backend is not None:
        from chain.verifier import verify_backend
        print(verify_backend(chain_backend).summary())

    print("\u2713 done, audit at results/audit.jsonl")


if __name__ == "__main__":
    main()
