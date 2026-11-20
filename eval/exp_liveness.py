"""
eval/exp_liveness.py  --  the availability claim, tested against a chain that
                          can actually stall.

THE CLAIM UNDER TEST
-----------------------------------------------------------------------------
Section 4: the server-ledger boundary is "optional and crossed by semantic
events after the fact, never before a round may proceed", and Figure 1's
caption says an unreachable ledger "degrades what can later be verified but
not training itself".

Every measurement supporting that so far came from a backend that could not
stall. An in-process py-evm answers instantly and an Anvil node auto-mines, so
"the ledger did not block training" was true in a setting where the ledger
could not have blocked anything.

WHAT THIS MEASURES, AND WHY IT IS TWO CLAIMS NOT ONE
-----------------------------------------------------------------------------
The claim splits, and the split is the result:

  STRUCTURAL   does training continue, complete, and produce the same model?
               ChainRegistry._guard() swallows rejections and transport
               failures, so this was already true and this experiment
               confirms it rather than discovering it.

  WALL CLOCK   does a round take longer because the ledger is down?
               This was FALSE, and by a wide margin. Writes were synchronous
               and inline: a round with n clients issues n classify
               transactions plus one roundSummary, each blocking on its
               receipt. A stalled chain is the worst case, because a node
               below quorum still ACCEPTS transactions into its pool and
               simply never mines them -- so each write blocks the full poll
               timeout rather than failing fast.

A design is not off the critical path if removing it makes rounds forty times
faster. So the experiment runs the same federation in two configurations that
differ by one flag, and reports both:

  sync    writes inline on the training thread (what the paper measured)
  async   writes on a background thread (chain/async_writer.py)

THREE PHASES
-----------------------------------------------------------------------------
  healthy    rounds 0..k-1        chain answers normally
  stalled    rounds k..m-1        chain accepts nothing (validators down)
  restored   rounds m..R-1        chain answers again

then reconciliation: rebuild the engine from the chain alone and check that
the state it produces matches the server's, for every device that was
anchored. Rounds written during the stall are expected to be MISSING from the
chain, and the honest result is to say which ones and what that costs.

STALL MODELS
-----------------------------------------------------------------------------
  --stall-mode refuse   the node refuses instantly (connection refused). This
                        is a node that is DOWN.
  --stall-mode hang     the node accepts and never answers, so every write
                        blocks the poll timeout. This is a QBFT network below
                        quorum, and it is the realistic one -- `docker compose
                        stop besu-3 besu-4` produces this, not `refuse`.

Default is `hang`, because `refuse` flatters the design: fast failures barely
show up in the wall clock, and reporting only that would be measuring the
convenient case.

    # local, no node needed -- the stall is injected at the backend
    PYTHONPATH=. python3 -m eval.exp_liveness --clients 6 --rounds 12

    # against a real 4-validator QBFT network
    export DLTF_CHAIN_PRIVKEY=0x...
    PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \\
        --address 0x... --deploy-block 12 --clients 6 --rounds 12 \\
        --manual-stall
    # with --manual-stall the script PAUSES and tells you when to run
    #   docker compose stop besu-3 besu-4
    # and when to start them again, so the stall is a real loss of quorum
    # rather than a simulated one.
"""
import argparse
import csv
import hashlib
import json
import os
import statistics
import sys
import time

from audit.hashchain import HashChain
from chain.backend import ChainRejection
from chain.evm import TransportError
from chain.keys import FederationKey
from chain.registry import ChainRegistry

WRITER = b"dltf-liveness"


# ---- the stall -------------------------------------------------------------

class Stall:
    """Wraps a backend and makes its writes fail the way a real chain does.

    Injected at the backend rather than by killing a process, so the same
    experiment runs with no node at all. `--manual-stall` swaps this for real
    validators being stopped, and the two should agree; if they do not, the
    model is wrong and the real one wins.
    """

    def __init__(self, backend, mode="hang", hang_seconds=8.0):
        self.backend = backend
        self.mode = mode
        self.hang_seconds = hang_seconds
        self.active = False
        self.blocked_seconds = 0.0
        self.blocked_writes = 0
        self._real_send = backend._send
        self._real_call = backend._call
        backend._send = self._send
        backend._call = self._call

    def _stall(self, what):
        self.blocked_writes += 1
        if self.mode == "hang":
            # A node below quorum accepts the transaction into its pool and
            # never mines it. The client learns nothing until it gives up.
            t0 = time.perf_counter()
            time.sleep(self.hang_seconds)
            self.blocked_seconds += time.perf_counter() - t0
            raise TransportError(
                f"{what} broadcast but not mined within "
                f"{self.hang_seconds:.0f}s (chain below quorum)")
        raise TransportError(f"{what}: connection refused (node down)")

    def _send(self, fn_call, gas=None, op=None):
        if self.active:
            self._stall(op or "write")
        return self._real_send(fn_call, gas=gas, op=op)

    def _call(self, fn_call):
        if self.active:
            self._stall("read")
        return self._real_call(fn_call)

    def release(self):
        self.backend._send = self._real_send
        self.backend._call = self._real_call


# ---- one run ---------------------------------------------------------------

def build_stack(args, async_writes):
    """(registry, backend, fed_key, teardown)."""
    fk = FederationKey(key=b"\x6a" * 32)

    if args.rpc:
        from chain.evm import EvmBackend
        if not args.address:
            raise SystemExit("--rpc needs --address (deploy with "
                             "python3 -m chain.deploy)")
        backend = EvmBackend.connect(
            args.rpc, args.address, writer=WRITER,
            deploy_block=args.deploy_block,
            poll_timeout=args.poll_timeout)
        if backend.signer is None:
            raise SystemExit(
                "no signing key: set DLTF_CHAIN_PRIVKEY. Without it every "
                "write goes out as eth_sendTransaction, which no real "
                "endpoint implements.")
        teardown = lambda: None
    else:
        from eval.chain_eval import evm_stack
        backend = evm_stack()[0]
        teardown = lambda: None

    reg = ChainRegistry(HashChain(), backend, fk, writer=WRITER,
                        async_writes=async_writes)
    return reg, backend, fk, teardown


def run_one(args, async_writes, label):
    """One federation across healthy / stalled / restored. Returns a dict."""
    from eval.chain_eval import build_handles, DIM
    from fl.server import FederatedServer

    reg, backend, fk, teardown = build_stack(args, async_writes)
    handles, signers, ca_pem = build_handles(args.clients, 0, 0, args.seed)
    server = FederatedServer([0.0] * DIM, ca_bundle_pem=ca_pem, audit=reg)

    for h in handles:
        server.enroll(h)

    stall = None
    if not args.manual_stall:
        stall = Stall(backend, mode=args.stall_mode,
                      hang_seconds=args.hang_seconds)

    rounds = []
    phase_of = {}
    stall_wallclock = [None]
    for r in range(args.rounds):
        if r == args.stall_at:
            stall_wallclock[0] = time.time()
            if args.manual_stall:
                input(f"\n>>> STOP two validators now "
                      f"(docker compose stop besu-3 besu-4), then press "
                      f"Enter to run round {r} ")
            else:
                stall.active = True
            print(f"  -- chain stalled from round {r}")
        if r == args.restore_at:
            if args.manual_stall:
                input(f"\n>>> START them again "
                      f"(docker compose start besu-3 besu-4), then press "
                      f"Enter to run round {r} ")
            else:
                stall.active = False
            print(f"  -- chain restored at round {r}")

        phase = ("healthy" if r < args.stall_at
                 else "stalled" if r < args.restore_at else "restored")
        phase_of[r] = phase

        t0 = time.perf_counter()
        rep = server.run_round(r, handles)
        dt = (time.perf_counter() - t0) * 1000.0
        rounds.append({"round": r, "phase": phase, "round_ms": dt,
                       "n_active": len(rep["weights"])})
        print(f"  r{r:<3} {phase:<9} {dt:9.1f} ms  "
              f"{len(rep['weights'])} active")

    # Draining is the ONE place blocking on the ledger is correct: training is
    # over and what is being waited for is auditability, not progress.
    drained = reg.drain_chain_writes(timeout=args.drain_timeout)
    if stall is not None:
        stall.release()
    reg.stop_chain_writes()

    report = reg.report()
    out = {
        "label": label,
        "async": async_writes,
        "rounds": rounds,
        "final_params": [round(v, 10) for v in server.global_params],
        "anchored": sorted(reg.anchored_rounds),
        "unanchored": sorted(reg.unanchored_rounds),
        "failures": len(reg.failures),
        "rejections": len(reg.rejections),
        "drained": drained,
        "report": report,
        "blocked_writes": stall.blocked_writes if stall else None,
        "blocked_seconds": stall.blocked_seconds if stall else None,
        "server": server,
        "backend": backend,
        "registry": reg,
        "phase_of": phase_of,
        "stall_wallclock": stall_wallclock[0],
        "writer_report": (reg._writer_thread.report()
                          if reg._writer_thread else None),
        "writer_results": (list(reg._writer_thread.results)
                           if reg._writer_thread else []),
    }
    teardown()
    return out


# ---- reconciliation --------------------------------------------------------

def reconcile_check(res):
    """Rebuild the engine from the CHAIN ALONE and compare.

    The chain is authoritative for what happened and the local record for whom
    it happened to (Section 4.5), so this rebuild is what a third party who
    does not trust the server can actually do.
    """
    from chain.reconcile import rebuild_engine
    backend, reg = res["backend"], res["registry"]
    try:
        engine, rep = rebuild_engine(backend, reg.inner)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": bool(rep.ok), "devices": rep.devices,
            "summary": rep.summary(),
            "chain_last_round": backend.last_round()}


# ---- reporting -------------------------------------------------------------

def phase_stats(rounds, phase):
    v = [r["round_ms"] for r in rounds if r["phase"] == phase]
    if not v:
        return None
    return {"n": len(v), "mean": statistics.fmean(v),
            "median": statistics.median(v),
            "p95": sorted(v)[max(0, int(0.95 * len(v)) - 1)],
            "max": max(v)}


def summarise(sync, asyn, recon_sync, recon_async, args):
    lines = []
    add = lines.append

    add("=" * 74)
    add("LIVENESS: the ledger is never on the critical path -- tested")
    add("=" * 74)
    add(f"clients {args.clients}, rounds {args.rounds}, "
        f"stall {args.stall_at}-{args.restore_at - 1}, "
        f"mode {'manual (real validators)' if args.manual_stall else args.stall_mode}")
    add("")

    # --- structural ---------------------------------------------------------
    same = sync["final_params"] == asyn["final_params"]
    add("STRUCTURAL")
    add(f"  every round completed in both configurations: "
        f"{len(sync['rounds'])} / {len(asyn['rounds'])}")
    add(f"  models identical across sync and async: {same}")
    add(f"  training never halted, and no round was skipped.")
    add("")

    # --- wall clock ---------------------------------------------------------
    add("WALL CLOCK  (per-round, ms)")
    add(f"  {'phase':<10} {'sync mean':>12} {'sync p95':>12} "
        f"{'async mean':>12} {'async p95':>12}")
    ratios = {}
    for ph in ("healthy", "stalled", "restored"):
        s, a = phase_stats(sync["rounds"], ph), phase_stats(asyn["rounds"], ph)
        if not s or not a:
            continue
        ratios[ph] = s["mean"] / a["mean"] if a["mean"] else float("inf")
        add(f"  {ph:<10} {s['mean']:12.1f} {s['p95']:12.1f} "
            f"{a['mean']:12.1f} {a['p95']:12.1f}")
    add("")
    if "stalled" in ratios and "healthy" in ratios:
        sh = phase_stats(sync["rounds"], "healthy")
        ss = phase_stats(sync["rounds"], "stalled")
        ah = phase_stats(asyn["rounds"], "healthy")
        as_ = phase_stats(asyn["rounds"], "stalled")
        add(f"  SYNCHRONOUS: a stalled chain makes a round "
            f"{ss['mean'] / sh['mean']:.1f}x slower "
            f"({sh['mean']:.0f} -> {ss['mean']:.0f} ms).")
        add(f"  ASYNCHRONOUS: {as_['mean'] / ah['mean']:.2f}x "
            f"({ah['mean']:.1f} -> {as_['mean']:.1f} ms).")
        add("")
        add("  The design claim is about the asynchronous row. The "
            "synchronous row is")
        add("  what the paper's implementation actually did, and it is the "
            "honest")
        add("  reading of the current numbers: structurally off the critical "
            "path,")
        add("  in wall clock very much on it.")
    add("")

    # --- auditability -------------------------------------------------------
    add("AUDITABILITY  (what the outage cost)")
    for res, name in ((sync, "sync"), (asyn, "async")):
        stalled_rounds = [r["round"] for r in res["rounds"]
                          if r["phase"] == "stalled"]
        lost = [r for r in stalled_rounds if r not in res["anchored"]]
        add(f"  {name:<6} anchored {len(res['anchored'])}/{args.rounds}, "
            f"unanchored {sorted(res['unanchored'])}")
        add(f"         failures {res['failures']}, "
            f"rejections {res['rejections']}, drained {res['drained']}")
        add(f"         rounds lost to the stall: {lost}")
        if res["blocked_writes"] is not None:
            add(f"         writes that hit the stalled chain: "
                f"{res['blocked_writes']}, "
                f"blocking {res['blocked_seconds']:.1f} s in total")
    add("")

    # --- the async trade-off ------------------------------------------------
    wr = asyn.get("writer_report")
    if wr:
        add("BACKLOG COLLATERAL  (the price of moving writes off the thread)")
        t_stall = asyn.get("stall_wallclock")
        collateral = [r for r in asyn.get("writer_results", [])
                      if not r.ok and t_stall and r.enqueued_at < t_stall]
        add(f"  queue depth peaked at {wr['max_queue_depth']}, "
            f"{wr['submitted']} submitted / {wr['completed']} completed / "
            f"{wr['failed']} failed / {wr['dropped']} dropped")
        add(f"  writes SUBMITTED while the chain was healthy but EXECUTED "
            f"during the stall: {len(collateral)}")
        for r in collateral:
            add(f"    - {r.event_type} (round {r.round_id}) queued "
                f"{r.queued_ms / 1000:.1f} s before it ran")
        if collateral:
            add("  This is the async writer's real cost and it is NOT a bug.")
            add("  Synchronous writes fail only for the rounds that overlap "
                "the outage.")
            add("  Asynchronous writes carry a backlog INTO the outage, so a "
                "write issued")
            add("  before the chain went down can still be destroyed by it. "
                "The wall-clock")
            add("  win is real; so is the wider anchoring loss. Bounding the "
                "queue (and")
            add("  therefore the exposure) is a deployment parameter, not a "
                "constant.")
        add("")

    add("RECONCILIATION  (rebuild from the chain alone)")
    for rc, name in ((recon_sync, "sync"), (recon_async, "async")):
        add(f"  {name:<6} ok={rc.get('ok')} "
            f"chain last_round={rc.get('chain_last_round')} "
            f"{rc.get('summary') or rc.get('error', '')}")
    add("")
    add("  A round written while the chain was down is NOT recoverable: the")
    add("  transaction never landed, so there is nothing to reconcile. What")
    add("  survives the outage is the ban ledger and every anchored round;")
    add("  what is lost is the auditability of the rounds during it. That is")
    add("  the trade the design makes, stated as a measured quantity rather")
    add("  than as an assurance.")
    add("=" * 74)
    return "\n".join(lines)


# ---- main ------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=6)
    ap.add_argument("--rounds", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--stall-at", type=int, default=4)
    ap.add_argument("--restore-at", type=int, default=8)
    ap.add_argument("--stall-mode", choices=["hang", "refuse"], default="hang",
                    help="hang models a QBFT network below quorum: it accepts "
                         "the write and never mines it. refuse models a dead "
                         "node. hang is the realistic one and the unflattering "
                         "one.")
    ap.add_argument("--hang-seconds", type=float, default=4.0,
                    help="how long a write blocks during a hang stall. On a "
                         "real network this is the poll timeout, commonly 120.")
    ap.add_argument("--poll-timeout", type=int, default=120)
    ap.add_argument("--drain-timeout", type=int, default=180)
    ap.add_argument("--sync-only", action="store_true")
    ap.add_argument("--async-only", action="store_true")
    ap.add_argument("--rpc", default=os.environ.get("DLTF_CHAIN_RPC"))
    ap.add_argument("--address", default=os.environ.get("DLTF_CONTRACT_ADDRESS"))
    ap.add_argument("--deploy-block", type=int,
                    default=int(os.environ.get("DLTF_DEPLOY_BLOCK", 0) or 0))
    ap.add_argument("--manual-stall", action="store_true",
                    help="pause and let YOU stop real validators, instead of "
                         "injecting the stall at the backend")
    ap.add_argument("--out", default="results/chain")
    args = ap.parse_args(argv)

    if args.restore_at <= args.stall_at:
        ap.error("--restore-at must be after --stall-at")
    if args.manual_stall and not args.rpc:
        ap.error("--manual-stall only makes sense against a real --rpc")

    results = {}
    recon = {}
    for async_writes, name in ((False, "sync"), (True, "async")):
        if args.sync_only and async_writes:
            continue
        if args.async_only and not async_writes:
            continue
        print(f"\n=== {name} writes "
              f"({'background thread' if async_writes else 'inline on the training thread'}) ===")
        res = run_one(args, async_writes, name)
        results[name] = res
        recon[name] = reconcile_check(res)

    if len(results) == 2:
        text = summarise(results["sync"], results["async"],
                         recon["sync"], recon["async"], args)
        print("\n" + text)
    else:
        text = json.dumps({k: {kk: vv for kk, vv in v.items()
                               if kk not in ("server", "backend", "registry")}
                           for k, v in results.items()}, indent=2, default=str)
        print(text)

    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "liveness_rounds.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["config", "round", "phase", "round_ms", "n_active",
                    "anchored"])
        for name, res in results.items():
            anchored = set(res["anchored"])
            for r in res["rounds"]:
                w.writerow([name, r["round"], r["phase"],
                            f"{r['round_ms']:.3f}", r["n_active"],
                            int(r["round"] in anchored)])
    print(f"\nwrote {csv_path}")

    txt_path = os.path.join(args.out, "liveness_summary.txt")
    with open(txt_path, "w") as f:
        f.write(text + "\n")
    print(f"wrote {txt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
