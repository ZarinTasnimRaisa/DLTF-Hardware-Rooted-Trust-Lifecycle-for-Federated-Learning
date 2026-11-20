"""
run_local.py  (project root)

Single-PC simulation: one server + N in-process clients (no network, no
agents). The optional on-chain trust registry is wired in here.

  # baseline, unchanged behaviour (no chain, no audit log)
  PYTHONPATH=. python3 run_local.py --clients 6 --rounds 10

  # Tier-1 clients so probation/rehabilitation is reachable
  PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --tier1 4

  # the chain-layer acceptance test: ban, restart, rebuild, whitewash
  PYTHONPATH=. python3 run_local.py \
      --clients 6 --attackers 2 --rounds 20 \
      --chain mock --restart-at 12 --rejoin-as newclient

WHAT --restart-at DEMONSTRATES (N23)
-----------------------------------------------------------------------------
The server process is torn down and rebuilt from the chain alone. Trust
scores, probation state and EK-bound bans all survive, so a banned attacker
cannot wait out a restart. Without the chain the engine is in memory and a
restart wipes every sanction.

Note the honest scope: reconciliation restores TRUST state, not model state.
The global parameter vector is carried forward in-process here; a real
deployment would checkpoint it separately. Model checkpointing is orthogonal
to the trust claim.
"""
import argparse
import os

import numpy as np

from tpm.client import make_signer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from trust.reputation import ReputationEngine, Status

DIM, BULK = 20, [0, 1, 2, 3]


def grad(scale=1.0, noise=0.4, seed=0):
    rng = np.random.default_rng(seed)
    v = np.zeros(DIM)
    for k in BULK:
        v[k] = 1.0
    v = v / np.linalg.norm(v)
    return (scale * v + noise * rng.standard_normal(DIM)).tolist()


def honest(idx):
    return lambda r, p: (grad(1.0, 0.4, seed=100 * r + idx), 64)


def sybil(r, p):
    rng = np.random.default_rng(9000 + r)          # identical across the group
    v = np.zeros(DIM); v[7] = v[8] = 1.0
    v = v / np.linalg.norm(v)
    return (v + 0.05 * rng.standard_normal(DIM)).tolist(), 64


class WhitewashSigner:
    """A signer that presents a BANNED device's EK hash under a NEW label.

    This is the whitewashing attacker: same silicon, fresh name. The EK hash
    is the hardware identity O2 binds bans to, so it is the field that must
    collide. Credential activation is delegated to a normal mock signer for
    the new label, because the mock MakeCredential channel is keyed by label
    and is an artifact of the mock backend, not part of the claim -- on real
    hardware one chip answers with one set of keys regardless of the name the
    operator gives it.
    """

    def __init__(self, new_label, victim_signer):
        self._inner = make_signer("mock", new_label)
        self._victim = victim_signer

    def provision(self):
        prov = self._inner.provision()
        prov.ek_hash = self._victim.provision().ek_hash    # the collision
        return prov

    def activate_credential(self, blob_b64):
        return self._inner.activate_credential(blob_b64)

    def sign_challenge(self, nonce):
        return self._inner.sign_challenge(nonce)


def build_handles(args):
    """Create the client handles. The first --tier1 clients get a test EK
    certificate so they enroll as HARDWARE (REHAB=True, probation reachable);
    the rest enroll as TPM_RESIDENT. Returns (handles, ca_pem, signers)."""
    ca_pem, ca_key, ca_cert = None, None, None
    if args.tier1 > 0:
        ca_key, ca_cert = generate_test_ca()
        ca_pem = ca_bundle_pem(ca_cert)

    handles, signers = [], {}
    n_honest = args.clients - args.attackers
    specs = [(f"client{k}", honest(k)) for k in range(n_honest)]
    specs += [(f"attacker{k}", sybil) for k in range(args.attackers)]

    for idx, (label, trainer) in enumerate(specs):
        cert = None
        if idx < args.tier1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        signer = make_signer("mock", label, ek_cert_der=cert)
        signers[label] = signer
        handles.append(LocalClientHandle(label, signer,
                                         FLClient(label, trainer)))
    return handles, ca_pem, signers


def make_server(args, ca_pem, audit, params, engine=None):
    return FederatedServer(params, ca_bundle_pem=ca_pem, audit=audit,
                           reputation_engine=engine)


def run_rounds(server, handles, start, stop):
    for rnd in range(start, stop):
        rep = server.run_round(rnd, handles)
        flags = {d: e["severity"] for d, e in rep["events"].items()
                 if e["severity"] != "NEUTRAL"}
        w = {d: round(v, 3) for d, v in rep["weights"].items()}
        print(f"round {rnd:2d}: weights {w} flags {flags}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clients", type=int, default=5)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--attackers", type=int, default=0,
                    help="how many of the clients are colluding sybils")
    ap.add_argument("--tier1", type=int, default=0,
                    help="how many clients get a test EK cert (Tier 1, "
                         "rehab-eligible). Without this every SIM client is "
                         "Tier 2 and probation is unreachable.")
    ap.add_argument("--chain", choices=["off", "mock", "node"], default="off",
                    help="optional on-chain trust registry (default: off)")
    ap.add_argument("--restart-at", type=int, default=None, metavar="N",
                    help="tear the server down at round N and rebuild its "
                         "state from the chain (needs --chain)")
    ap.add_argument("--rejoin-as", default=None, metavar="LABEL",
                    help="after the run, a banned attacker returns under this "
                         "label with the same EK (whitewash attempt)")
    ap.add_argument("--audit", default=None, metavar="PATH",
                    help="write the local audit log here (implied by --chain)")
    ap.add_argument("--require-commit", action="store_true",
                    help="enable the gradient-commitment layer: clients commit "
                         "keccak256(gradient) BEFORE sending, and the backend "
                         "refuses to classify an update with no commitment. "
                         "Needs --chain mock|node.")
    args = ap.parse_args()

    if args.restart_at is not None and args.chain == "off":
        ap.error("--restart-at needs --chain mock|node "
                 "(there is nothing to rebuild from with the chain off)")
    if args.rejoin_as and args.attackers < 1:
        ap.error("--rejoin-as needs at least one --attackers to ban first")
    if args.require_commit and args.chain == "off":
        ap.error("--require-commit needs --chain mock|node "
                 "(there is nowhere to record commitments with the chain off)")

    # ---- audit / chain stack -------------------------------------------------
    audit_path = args.audit
    if args.chain != "off" and audit_path is None:
        os.makedirs("results", exist_ok=True)
        audit_path = "results/sim_audit.jsonl"
        if os.path.exists(audit_path):
            os.remove(audit_path)            # SIM runs start clean

    from chain.wiring import (build_audit, reopen_audit, chain_report_lines,
                              DEFAULT_WRITER)
    import config
    audit, backend, fed_key = build_audit(
        mode=args.chain, audit_path=audit_path,
        fed_key_path=(config.CHAIN["federation_key_path"]
                      if args.chain != "off" else None),
        rpc_url=config.CHAIN["rpc_url"],
        contract_address=config.CHAIN["contract_address"],
        require_commit=args.require_commit)

    if args.chain != "off":
        print(f"chain: {args.chain}, audit log {audit_path}"
              + (", commitment layer ON" if args.require_commit else ""))

    # ---- build and enroll ----------------------------------------------------
    handles, ca_pem, signers = build_handles(args)
    server = make_server(args, ca_pem, audit, [0.0] * DIM)

    for h in handles:
        r = server.enroll(h)
        print(f"enrolled {r['device_id']:10s} tier {r['tier']:13s} "
              f"status {r['status']}")

    # ---- commitment layer: bind a wallet per device, then attach agents -----
    if args.require_commit:
        from chain.commit import (CommitAgent, wallet_bind_challenge,
                                  verify_wallet_binding)
        bound = 0
        for i, h in enumerate(handles):
            if h.device_label not in server.enrolled:
                continue                      # refused at enrollment
            wallet = "0x" + f"{i + 1:040x}"   # deterministic stand-in wallet
            # The client proves control of BOTH the TPM and the wallet, so the
            # server cannot bind a wallet it controls to someone else's device.
            challenge = wallet_bind_challenge(h.device_label, wallet)
            sig = h._signer.sign_message(challenge)
            if not verify_wallet_binding(h._signer, h.device_label, wallet, sig):
                print(f"  wallet binding FAILED for {h.device_label}")
                continue
            backend.bind_wallet(DEFAULT_WRITER, h.device_label, wallet)
            h.commit_agent = CommitAgent(backend, h.device_label, wallet)
            bound += 1
        print(f"commitment: {bound} wallets bound to TPM identities, "
              f"clients now commit before sending")

    # ---- rounds, with an optional restart in the middle ----------------------
    stop = args.restart_at if args.restart_at is not None else args.rounds
    run_rounds(server, handles, 0, min(stop, args.rounds))

    if args.restart_at is not None and args.restart_at < args.rounds:
        from chain.reconcile import rebuild_engine, restore_server

        print(f"\n--- server torn down at round {args.restart_at} ---")
        params = list(server.global_params)         # model state is NOT on chain
        del server

        audit = reopen_audit(audit, audit_path=audit_path)
        engine, report = rebuild_engine(backend, audit.inner)
        print(report.summary())
        if not report.ok:
            print("  WARNING: reconciliation reported asymmetries (above)")

        server = make_server(args, ca_pem, audit, params, engine=engine)
        restore_server(server, engine, audit.inner)
        print(f"--- resumed at round {args.restart_at} "
              f"({len(server.enrolled)} devices re-enrolled) ---\n")

        run_rounds(server, handles, args.restart_at, args.rounds)

    # ---- whitewash attempt ---------------------------------------------------
    if args.rejoin_as:
        banned = [l for l in signers
                  if l in server.rep._dev
                  and server.rep.get_status(l) == Status.BANNED]
        if not banned:
            print(f"\n--- rejoin: no banned device to impersonate, skipping ---")
        else:
            victim = banned[0]
            print(f"\n--- rejoin: '{args.rejoin_as}' returns with "
                  f"{victim}'s EK ---")
            ww = LocalClientHandle(args.rejoin_as,
                                   WhitewashSigner(args.rejoin_as,
                                                   signers[victim]),
                                   FLClient(args.rejoin_as, sybil))
            r = server.enroll(ww)
            print(f"enrolled {r['device_id']:10s} tier {r['tier']:13s} "
                  f"status {r['status']}")
            if r["status"] == "BANNED":
                print(f"WHITEWASH_REJECTED: {args.rejoin_as} carries a banned "
                      f"EK ({victim}'s) -- O2 held across the restart")
            else:
                print("WARNING: whitewash was NOT rejected")
            if backend is not None and fed_key is not None:
                on_chain = audit.is_banned_on_chain(
                    server.enrolled[victim]["ek_hash"])
                print(f"chain agrees EK is banned: {on_chain}")

    # ---- chain summary and independent verification --------------------------
    for line in chain_report_lines(audit):
        print(line)

    if backend is not None:
        from chain.verifier import verify_backend
        res = verify_backend(backend)
        print(res.summary())

    print("done")


if __name__ == "__main__":
    main()
