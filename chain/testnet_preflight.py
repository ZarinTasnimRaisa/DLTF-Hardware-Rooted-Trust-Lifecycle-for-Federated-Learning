"""
chain/testnet_preflight.py

RUN THIS BEFORE SPENDING FAUCET FUNDS.

Every code path a public testnet or a Besu consortium node exercises, driven
locally against eth-tester with an EXTERNAL funded key -- that is, through
locally signed raw transactions, exactly as a real endpoint requires, and
never through eth_sendTransaction.

That distinction is the whole point. chain/evm.py's original self-test ran on
eth-tester with a node-held account, so it passed while the one thing that
mattered -- local signing -- did not exist. Passing here does not prove the
system works on Amoy. It proves the failures that remain are network
failures rather than ones that could have been found for free.

    PYTHONPATH=. python3 -m chain.testnet_preflight

    # optional live smoke test, ~7 transactions, costs real faucet funds
    PYTHONPATH=. python3 -m chain.testnet_preflight \\
        --rpc https://rpc-amoy.polygon.technology --live

WHAT IT DOES NOT COVER
-----------------------------------------------------------------------------
Block time. eth-tester mines instantly, so nothing here measures confirmation
latency or exercises a transaction that sits pending. Use
`anvil --block-time 12` for that, and `anvil --no-mining` to reproduce a
stalled chain. Those two commands find most of what is left.
"""
import argparse
import hashlib
import sys
import time

from chain.backend import ChainRejection, Reason
from chain.fixedpoint import SeverityFP, StatusFP, TierFP

PASS, FAIL = [], []


def check(name, fn):
    try:
        detail = fn()
        PASS.append(name)
        print(f"\u2713 {name}" + (f": {detail}" if detail else ""))
        return True
    except Exception as exc:
        FAIL.append((name, exc))
        print(f"\u2717 {name}\n    {type(exc).__name__}: {exc}")
        return False


# ---- harness -----------------------------------------------------------------

CLIENT_KEYS = ["0x" + f"{i + 0xC1:02x}" * 32 for i in range(6)]
SERVER_KEY = "0x" + "51" * 32
INTRUDER_KEY = "0x" + "1D" * 32


def ek(label):
    return hashlib.sha256(label.encode()).digest()


def build_local():
    """eth-tester + an external funded key. The signing path, no network."""
    from eth_account import Account
    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    from chain.signer import TxSigner

    w3 = Web3(EthereumTesterProvider(EthereumTester(backend=PyEVMBackend())))
    faucet = w3.eth.accounts[0]
    for k in [SERVER_KEY, INTRUDER_KEY] + CLIENT_KEYS:
        w3.eth.send_transaction({"from": faucet,
                                 "to": Account.from_key(k).address,
                                 "value": w3.to_wei(100, "ether")})
    return w3, TxSigner(w3, SERVER_KEY)


def build_live(rpc, timeout=60):
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware

    from chain.signer import TxSigner
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": timeout}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not w3.is_connected():
        raise SystemExit(f"cannot reach {rpc}")
    import os
    key = os.environ.get("DLTF_CHAIN_PRIVKEY")
    if not key:
        raise SystemExit("set DLTF_CHAIN_PRIVKEY (a funded TEST key)")
    return w3, TxSigner(w3, key)


def deploy(w3, signer, require_commit=False):
    from chain.deploy import deploy_contract
    from chain.evm import EvmBackend, load_abi
    contract, receipt = deploy_contract(
        w3, signer.address, require_commit=require_commit, signer=signer)
    backend = EvmBackend.attach(w3, contract.address, writer=b"pf",
                                server_account=signer.address, abi=load_abi())
    backend.signer = signer
    backend.deploy_block = receipt.blockNumber
    return backend, receipt


# ---- the checks --------------------------------------------------------------

def run(w3, signer, live=False):
    from chain.commit import (SigningCommitAgent, check_commit, grad_hash)
    from chain.evm import EvmBackend, TransportError, load_abi
    from chain.signer import PendingTimeout, TxSigner

    W = b"pf"
    print(f"\nchain id {w3.eth.chain_id}, deployer {signer.address}, "
          f"balance {w3.from_wei(signer.balance(), 'ether')}\n")

    state = {}

    # === 1. Deploy with a LOCAL KEY, no unlocked accounts =================
    def _deploy():
        backend, rc = deploy(w3, signer)
        state["backend"] = backend
        state["deploy_gas"] = rc.gasUsed
        state["deploy_block"] = rc.blockNumber
        assert backend.contract.functions.server().call() == signer.address
        return (f"{backend.contract.address} in block {rc.blockNumber}, "
                f"gas {rc.gasUsed:,}")
    if not check("deploy via locally signed raw transaction", _deploy):
        return                                   # nothing else can run

    b = state["backend"]

    # === 2. Writes go out SIGNED, and land ================================
    def _write():
        st, ev = b.register(W, "d0", TierFP.HARDWARE, ek("d0"))
        assert st == int(StatusFP.ACTIVE)
        assert ev.event_type == "ENROLL"
        assert b.signer is not None, "backend fell back to eth_sendTransaction"
        return f"register landed, {b.signer.sent} signed tx sent so far"
    check("signed writes reach the contract", _write)

    # === 3. Nonces do not collide under rapid sequential writes ===========
    def _nonces():
        n0 = b.signer.sent
        for i in range(1, 5):
            b.register(W, f"d{i}", TierFP.HARDWARE, ek(f"d{i}"))
        assert b.signer.sent == n0 + 4
        for i in range(5):
            assert b.get_device(f"d{i}") is not None
        return f"{b.signer.sent - n0} consecutive writes, all mined"
    check("consecutive writes get distinct nonces", _nonces)

    # === 4. A REVERT is a rejection, not an outage ========================
    def _revert():
        try:
            b.register(W, "dup", TierFP.HARDWARE, ek("d0"))
            raise AssertionError("duplicate EK must revert")
        except ChainRejection as e:
            assert e.reason == Reason.EK_REGISTERED, e.reason
        return "EkAlreadyRegistered decoded through the signed path"
    check("revert -> ChainRejection with the right Reason", _revert)

    # === 5. The revert NAME survives a mined status-0 receipt =============
    # The path a public chain takes when estimation passed and state moved.
    # This used to collapse to "UnknownRevert", which throws away the
    # enforcement result: 'refused' is much weaker than 'refused with
    # BanToActive'.
    def _status0():
        fn = b.contract.functions.register("forced", int(TierFP.HARDWARE),
                                           ek("d0"))
        tx = b.signer.build(fn, gas=300_000)     # skip estimation
        h = b.signer.send_tx(tx)
        rc = b.signer.wait(h, timeout=60 if live else 10, poll=0.05)
        assert rc["status"] == 0, "expected an on-chain failure"
        name, detail = b._revert_name_from_receipt(rc, fn)
        assert name == "EkAlreadyRegistered", (name, detail)
        return f"mined status-0 receipt re-simulated to {name}"
    check("revert name recovered from a status-0 receipt", _status0)

    # === 6. Standard selectors are decodable ==============================
    def _selectors():
        t = b._selectors
        assert t.get("08c379a0") == "Error", "Error(string) missing"
        assert t.get("4e487b71") == "Panic", "Panic(uint256) missing"
        return (f"{len(t)} selectors including Error(string) and "
                f"Panic(uint256) -- neither is an ABI error entry, so both "
                f"used to be misfiled as transport and RETRIED")
    check("standard EVM error selectors are in the table", _selectors)

    # === 7. A provider error containing a tx hash is NOT read as a revert ==
    def _no_false_revert():
        fake = ("Transaction 0x" + "ab" * 32 + " not found; the node may "
                "still be syncing")
        assert b._decode_revert(Exception(fake)) is None, (
            "a 64-hex tx hash in ordinary error text was parsed as revert "
            "data")
        return "hex in non-revert error text ignored"
    check("tx hashes in error text are not mistaken for revert data",
          _no_false_revert)

    # === 8. Unauthorised writer, enforced by the chain ====================
    def _unauth():
        intruder = TxSigner(w3, INTRUDER_KEY)
        b2 = EvmBackend.attach(w3, b.contract.address, writer=W,
                               server_account=intruder.address, abi=load_abi())
        b2.signer = intruder
        try:
            b2.register(W, "intruder", TierFP.HARDWARE, ek("intruder"))
            raise AssertionError("non-writer must be refused")
        except ChainRejection as e:
            assert e.reason == Reason.UNAUTHORIZED_WRITER, e.reason
        return f"{intruder.address[:10]}... refused UnauthorizedWriter"
    check("a second funded key is refused as writer (experiment 2c)", _unauth)

    # === 9. get_logs is BOUNDED and chunked ===============================
    def _logs():
        b.deploy_block = state["deploy_block"]
        b.log_chunk = 2                          # force many chunks
        evs = b.events()
        assert len(evs) >= 6, len(evs)
        assert [e.seq for e in evs] == list(range(len(evs)))
        types = [e.event_type for e in evs]
        assert types.index("ENROLL") < len(types)
        b.log_chunk = 2000
        return (f"{len(evs)} events reassembled in emission order from "
                f"2-block chunks starting at deploy block "
                f"{state['deploy_block']}")
    check("chunked eth_getLogs from the deploy block", _logs)

    # === 10. head_hash RAISES rather than returning a null head ===========
    def _head():
        assert len(b.head_hash()) == 32
        broken = EvmBackend.attach(w3, b.contract.address, writer=W,
                                   server_account=signer.address,
                                   abi=load_abi())

        class Dead:
            def get_block(self, *a, **k):
                raise ConnectionError("down")
        broken.w3 = type("W", (), {"eth": Dead()})()
        try:
            broken.head_hash()
            raise AssertionError("head_hash must raise, not return zeros")
        except TransportError:
            pass
        assert broken.head_hash_or_null() == b"\x00" * 32
        return ("unreachable node raises; the null head is only available "
                "by asking for it explicitly")
    check("head_hash does not fabricate a head", _head)

    # === 11. report() survives an outage ==================================
    def _report():
        from audit.hashchain import HashChain
        from chain.keys import FederationKey
        from chain.registry import ChainRegistry
        reg = ChainRegistry(HashChain(), b, FederationKey(key=b"\x33" * 32),
                            writer=W)
        saved = b.w3

        class Dead:
            def get_block(self, *a, **k):
                raise ConnectionError("down")
        b.w3 = type("W", (), {"eth": Dead()})()
        saved_call = b._call
        b._call = lambda *a, **k: (_ for _ in ()).throw(
            TransportError("down"))
        try:
            rep = reg.report()
        finally:
            b.w3, b._call = saved, saved_call
        assert rep["chain_head"] is None and rep["chain_reachable"] is False
        assert rep["backend_last_round"] is None
        return ("reporting during an outage returns None for the unknown "
                "fields instead of raising -- this used to crash the "
                "liveness experiment AFTER training had survived")
    check("report() never raises when the chain is down", _report)

    # === 12. COMMITMENT LAYER: bind, batch-commit, classify ===============
    # The gap the paper records as "unmeasured rather than zero".
    def _commit():
        cb, rc = deploy(w3, signer, require_commit=True)
        assert cb.require_commit is True
        addr = cb.contract.address
        cid = w3.eth.chain_id

        agents = {}
        for i in range(4):
            lbl = f"c{i}"
            cb.register(W, lbl, TierFP.HARDWARE, ek(lbl))
            a = SigningCommitAgent(lbl, CLIENT_KEYS[i], cid, addr)
            cb.bind_wallet(W, lbl, a.wallet)
            assert cb.get_wallet(lbl).lower() == a.wallet.lower()
            agents[lbl] = a

        grads = {l: [0.01 * i + j for i in range(20)]
                 for j, l in enumerate(agents)}
        batch = [agents[l].sign(0, grads[l]) for l in agents]
        n = cb.commit_batch(W, batch, chain_id=cid, contract_address=addr)
        assert n == 4, n
        for l in agents:
            assert cb.get_commit(l, 0) == grad_hash(grads[l])
            assert check_commit(cb, l, 0, grads[l]).matched

        # classify is now permitted, and refused for a device that did not
        # commit -- the anti-fabrication rule, on chain.
        cb.classify(W, 0, "c0", SeverityFP.NEUTRAL)
        cb.register(W, "nc", TierFP.HARDWARE, ek("nc"))
        try:
            cb.classify(W, 0, "nc", SeverityFP.NEUTRAL)
            raise AssertionError("uncommitted device must not be classifiable")
        except ChainRejection as e:
            assert "MissingCommit" in str(e.reason), e.reason

        state["commit_backend"] = cb
        state["commit_agents"] = agents
        state["commit_addr"] = addr
        state["commit_cid"] = cid
        by_op = cb.gas_by_op()
        return (f"4 wallets bound, commitBatch(4) = "
                f"{by_op['commitBatch'][0]:,} gas, "
                f"anti-fabrication rule enforced on chain")
    check("commitment layer drives end to end from Python", _commit)

    # === 13. classifySigned: the cheap path ===============================
    def _signed():
        cb = state["commit_backend"]
        agents = state["commit_agents"]
        g = [0.5] * 20
        sc = agents["c1"].sign(1, g)
        st, ev = cb.classify_signed(W, 1, "c1", SeverityFP.NEUTRAL,
                                    signed_commit=sc)
        assert ev is not None and ev.event_type == "EVENT"
        by_op = cb.gas_by_op()
        cheap = by_op["classifySigned"][-1]
        batch4 = by_op["commitBatch"][0]
        plain = by_op["classify"][-1]
        return (f"classifySigned {cheap:,} gas vs classify {plain:,} + "
                f"commitBatch/4 {batch4 // 4:,} = "
                f"{plain + batch4 // 4:,} for the two-transaction path")
    check("classifySigned works and is measurably cheaper", _signed)

    # === 14. A FORGED signature is refused =================================
    def _forge():
        cb = state["commit_backend"]
        agents = state["commit_agents"]
        good = agents["c2"].sign(2, [0.1] * 20)
        # c2 signing on c3's behalf. The two entries must name DIFFERENT
        # devices: two entries for the same device hit DuplicateCommit first,
        # which is the contract refusing for the wrong reason and would have
        # made this test pass without testing anything.
        forged = agents["c2"].sign(2, [0.2] * 20)
        forged.device_label = "c3"
        try:
            cb.commit_batch(W, [good, forged], chain_id=state["commit_cid"],
                            contract_address=state["commit_addr"])
            raise AssertionError("a forged signature must reject the batch")
        except ChainRejection as e:
            reason = str(e.reason)
            assert ("Signer" in reason or "Invalid" in reason), reason
        assert cb.get_commit("c2", 2) is None, "batch was not atomic"
        assert cb.get_commit("c3", 2) is None
        return (f"refused {reason}; the VALID half of the batch was not "
                f"written either")
    check("a forged commitment rejects the whole batch atomically", _forge)

    # === 15. Async writes keep the ledger off the critical path ===========
    def _async():
        from audit.hashchain import HashChain
        from chain.keys import FederationKey
        from chain.registry import ChainRegistry

        slow = state["backend"]
        real_send = slow._send

        def laggy(fn_call, gas=None, op=None):
            time.sleep(0.15)                     # stand in for block time
            return real_send(fn_call, gas=gas, op=op)
        slow._send = laggy

        reg = ChainRegistry(HashChain(), slow,
                            FederationKey(key=b"\x44" * 32), writer=W,
                            async_writes=True)
        for lbl in ("a1", "a2", "a3"):
            reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                                  "ek_hash": hashlib.sha256(
                                      lbl.encode()).hexdigest(),
                                  "status": "ACTIVE"})
        t0 = time.perf_counter()
        for rid in range(3):
            reg.append("ROUND", {"round": rid, "participants": ["a1", "a2",
                                                                "a3"],
                                 "aggregated": True})
        blocked_ms = (time.perf_counter() - t0) * 1000
        assert reg.drain_chain_writes(timeout=60)
        total_ms = (time.perf_counter() - t0) * 1000
        reg.stop_chain_writes()
        slow._send = real_send
        assert blocked_ms < total_ms / 2, (blocked_ms, total_ms)
        assert not reg.failures, [f.error for f in reg.failures]
        return (f"3 rounds: training thread blocked {blocked_ms:.0f} ms, "
                f"ledger work took {total_ms:.0f} ms in the background")
    check("async writes remove the ledger from the round's wall clock",
          _async)

    # === 16. Async FAILURES are still visible =============================
    def _async_fail():
        from audit.hashchain import HashChain
        from chain.keys import FederationKey
        from chain.registry import ChainRegistry
        dead = state["backend"]
        real = dead._send
        dead._send = lambda *a, **k: (_ for _ in ()).throw(
            TransportError("node down"))
        reg = ChainRegistry(HashChain(), dead,
                            FederationKey(key=b"\x45" * 32), writer=W,
                            async_writes=True)
        reg.append("ROUND", {"round": 99, "participants": [],
                             "aggregated": True})
        reg.drain_chain_writes(timeout=30)
        reg.stop_chain_writes()
        dead._send = real
        assert reg.failures, "a failed async write vanished"
        assert 99 in reg.unanchored_rounds
        assert 99 not in reg.anchored_rounds
        return (f"{len(reg.failures)} failure(s) recorded, round 99 demoted "
                f"to UNANCHORED -- an async write cannot report success it "
                f"did not have")
    check("a failed background write is still recorded and unanchored",
          _async_fail)

    # === 17. Gas matches the paper's Table 4 ==============================
    def _gas():
        fresh, rc = deploy(w3, signer)
        assert rc.gasUsed == 2_085_425, rc.gasUsed
        # Table 4's 95,344 was measured with a TWO-character device label.
        fresh.register(W, "d0", TierFP.HARDWARE, ek("z0"))
        reg_gas = fresh.gas_by_op()["register"][0]
        assert reg_gas == 95_344, reg_gas
        return (f"deploy {rc.gasUsed:,} and register {reg_gas:,} reproduce "
                f"Table 4 exactly through the signed path")
    check("gas is unchanged by the signing change", _gas)

    # === 17b. Gas depends on device-label LENGTH ==========================
    # Found while writing 17: registering "g" costs 95,332 against 95,344 for
    # "d0". Twelve gas, which is exactly one calldata byte moving from
    # non-zero (16) to zero (4). deviceId is a string argument, so its length
    # is priced. Table 4's per-operation figures and the 58,281 + 38,818n fit
    # are therefore quoted for the label lengths the harness happened to use,
    # not for any label. Small, but it is the difference between "gas is
    # deterministic given identical bytecode and calldata" -- which the table
    # caption correctly says -- and the stronger reading a reviewer might
    # take, that the number depends only on n.
    def _calldata():
        fresh, _ = deploy(w3, signer)
        fresh.register(W, "g", TierFP.HARDWARE, ek("g"))
        short = fresh.gas_by_op()["register"][0]
        fresh.register(W, "gg", TierFP.HARDWARE, ek("gg"))
        longer = fresh.gas_by_op()["register"][1]
        assert longer - short == 12, (short, longer)
        return (f"1-char label {short:,}, 2-char {longer:,}: +12 gas per "
                f"non-zero calldata byte, so Table 4 is per-label-length")
    check("gas varies with device-label length (documented, not a bug)",
          _calldata)

    # === 18. Fees are recorded for the economics phase ====================
    def _fees():
        fresh = state["backend"]
        assert fresh.fee_log, "no fee entries"
        op, gas, price, block = fresh.fee_log[0]
        return (f"{len(fresh.fee_log)} priced writes; first is {op} at "
                f"{gas:,} gas x {price / 1e9:.3f} gwei "
                f"(effectiveGasPrice, which the old gas_log never captured)")
    check("effective gas price is captured per write", _fees)


def e_name(cb):
    return cb.gas_log[-1][0] if cb.gas_log else "?"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rpc", default=None,
                    help="run against a real endpoint instead of eth-tester")
    ap.add_argument("--live", action="store_true",
                    help="required alongside --rpc; confirms you accept that "
                         "this SPENDS funds")
    args = ap.parse_args(argv)

    if args.rpc and not args.live:
        raise SystemExit("--rpc costs real faucet funds; add --live to "
                         "confirm")

    print("chain/testnet_preflight.py")
    print("=" * 72)
    if args.rpc:
        w3, signer = build_live(args.rpc)
        run(w3, signer, live=True)
    else:
        w3, signer = build_local()
        run(w3, signer, live=False)

    print("=" * 72)
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    for name, exc in FAIL:
        print(f"  \u2717 {name}: {type(exc).__name__}: {exc}")
    if FAIL:
        print("\nDo NOT spend faucet funds until these pass.")
        return 1
    print("\nEvery real-chain code path works locally. What is left is the "
          "network itself:\n"
          "  anvil --block-time 12   pending transactions, confirmation "
          "latency\n"
          "  anvil --no-mining       a chain that accepts writes and never "
          "mines them\n"
          "Run against both before touching a faucet.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
