"""
tests/test_chain_integration.py

Integration tests for the chain wiring built in steps 1-4. Runs entirely on
the mock backend, so no node and no hardware are needed.

  PYTHONPATH=. python3 tests/test_chain_integration.py

Covers what the module self-tests cannot, because it needs a real
FederatedServer driving real handles:

  1. chain off is byte-identical to the pre-chain baseline
  2. a full federation mirrors onto the chain and verifies
  3. restart -> rebuild -> the ban survives (N23)
  4. the run_server.py enrollment gate refuses a banned EK and CONTINUES
  5. a dead node degrades instead of halting
  6. reconciliation is faithful over a long run
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np

from tpm.client import make_signer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from trust.reputation import Status

from chain.wiring import build_audit, reopen_audit
from chain.reconcile import rebuild_engine, restore_server
from chain.verifier import verify_backend

DIM, BULK = 12, [0, 1, 2]


def grad(scale=1.0, noise=0.3, seed=0):
    rng = np.random.default_rng(seed)
    v = np.zeros(DIM)
    for k in BULK:
        v[k] = 1.0
    v = v / np.linalg.norm(v)
    return (scale * v + noise * rng.standard_normal(DIM)).tolist()


def honest(idx):
    return lambda r, p: (grad(1.0, 0.3, seed=100 * r + idx), 64)


def sybil(r, p):
    rng = np.random.default_rng(9000 + r)
    v = np.zeros(DIM); v[7] = v[8] = 1.0
    v = v / np.linalg.norm(v)
    return (v + 0.05 * rng.standard_normal(DIM)).tolist(), 64


def make_federation(n_honest=4, n_attackers=2, tier1=0):
    ca_pem, ca_key, ca_cert = None, None, None
    if tier1:
        ca_key, ca_cert = generate_test_ca()
        ca_pem = ca_bundle_pem(ca_cert)
    handles, signers = [], {}
    specs = [(f"h{k}", honest(k)) for k in range(n_honest)]
    specs += [(f"a{k}", sybil) for k in range(n_attackers)]
    for idx, (label, trainer) in enumerate(specs):
        cert = None
        if idx < tier1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        s = make_signer("mock", label, ek_cert_der=cert)
        signers[label] = s
        handles.append(LocalClientHandle(label, s, FLClient(label, trainer)))
    return handles, signers, ca_pem


def test_chain_off_is_the_baseline():
    """Constraint 1: with the chain off nothing under chain/ is constructed
    and the server sees audit=None, exactly as before the layer existed."""
    audit, backend, fk = build_audit("off")
    assert audit is None and backend is None and fk is None

    handles, _, _ = make_federation()
    server = FederatedServer([0.0] * DIM, audit=audit)
    for h in handles:
        server.enroll(h)
    for r in range(4):
        server.run_round(r, handles)

    assert server.audit is None
    assert server.rep.get_status("a0") == Status.BANNED
    assert server.global_params[BULK[0]] > 0.0
    print("  ✓ chain off: audit is None, sybils still banned, model advances")


def test_chain_off_matches_chain_on_trajectory():
    """Constraint 1, the strong form: enabling the chain must not perturb the
    reputation trajectory at all. Same seeds, same weights, every round."""
    def run(mode, d):
        handles, _, _ = make_federation()
        audit, _, _ = build_audit(
            mode, audit_path=os.path.join(d, f"{mode}.jsonl"),
            fed_key_path=(os.path.join(d, "k") if mode != "off" else None))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        return [server.run_round(r, handles)["weights"] for r in range(6)]

    with tempfile.TemporaryDirectory() as d:
        off = run("off", d)
        on = run("mock", d)
    assert off == on, "chain layer perturbed the trust trajectory"
    print("  ✓ identical trajectories with chain off vs mock (6 rounds)")


def test_full_federation_mirrors_and_verifies():
    with tempfile.TemporaryDirectory() as d:
        handles, _, _ = make_federation()
        audit, backend, fk = build_audit(
            "mock", audit_path=os.path.join(d, "a.jsonl"),
            fed_key_path=os.path.join(d, "k"))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(6):
            server.run_round(r, handles)

        assert not audit.rejections, [str(x) for x in audit.rejections]
        assert not audit.failures
        assert audit.anchored_rounds == set(range(6))
        assert backend.get_device("a0").status.name == "BANNED"
        res = verify_backend(backend)
        assert res.ok, res.summary()

        # raw EK hashes must NEVER appear on chain
        raw = server.enrolled["h0"]["ek_hash"]
        for ev in backend.events():
            assert raw not in str(ev.payload), "raw EK hash leaked on chain"
        print(f"  ✓ 6 rounds mirrored, 0 rejections, verifier: {res.summary()}")
        print("  ✓ no raw EK hash appears anywhere in the chain event log")


def test_restart_rebuild_preserves_ban():
    """N23: the whole point. Tear the server down, rebuild from the chain,
    confirm the ban and the trust scores survived."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.jsonl")
        handles, signers, _ = make_federation()
        audit, backend, fk = build_audit(
            "mock", audit_path=path, fed_key_path=os.path.join(d, "k"))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(8):
            server.run_round(r, handles)

        before = {l: server.rep._dev[l].trust for l in server.rep._dev}
        assert server.rep.get_status("a0") == Status.BANNED

        # ---- the process dies; the node does not ----
        params = list(server.global_params)
        del server
        audit = reopen_audit(audit, audit_path=path)
        engine, report = rebuild_engine(backend, audit.inner)
        assert report.ok, report.summary()
        server = FederatedServer(params, audit=audit, reputation_engine=engine)
        restore_server(server, engine, audit.inner)

        assert set(server.enrolled) == set(before)
        for l, t in before.items():
            assert abs(server.rep._dev[l].trust - t) <= 5e-6, l
        assert server.rep.get_status("a0") == Status.BANNED
        assert server.rep.get_weight("a0") == 0.0
        print(f"  ✓ rebuild: {report.devices} devices, trust preserved within "
              f"5e-6, a0 still BANNED")

        # ---- and the rebuilt server keeps training ----
        for r in range(8, 12):
            server.run_round(r, handles)
        assert server.rep.get_status("a0") == Status.BANNED
        assert not audit.rejections, [str(x) for x in audit.rejections]
        print("  ✓ rebuilt server ran 4 more rounds, ban held, 0 rejections")


def test_whitewash_rejected_after_restart():
    """The attacker returns under a fresh label with the same EK, after a
    restart. Both ledgers must refuse it."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.jsonl")
        handles, signers, _ = make_federation()
        audit, backend, fk = build_audit(
            "mock", audit_path=path, fed_key_path=os.path.join(d, "k"))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(4):
            server.run_round(r, handles)
        banned_ek = server.enrolled["a0"]["ek_hash"]
        assert server.rep.get_status("a0") == Status.BANNED

        del server
        audit = reopen_audit(audit, audit_path=path)
        engine, _ = rebuild_engine(backend, audit.inner)
        server = FederatedServer([0.0] * DIM, audit=audit,
                                 reputation_engine=engine)
        restore_server(server, engine, audit.inner)

        # same silicon, new name
        class WW:
            device_label = "fresh_face"
            tpm_backend = "mock"
            def enroll_payload(self):
                p = signers["a0"].provision()
                return {"device_label": "fresh_face", "ek_hash": p.ek_hash,
                        "ak_name": p.ak_name, "ek_cert_b64": None}
            def activate_credential(self, blob):
                return make_signer("mock", "fresh_face").activate_credential(blob)
            def train(self, r, p):
                return {"update": [0.0] * DIM, "num_samples": 1}

        r = server.enroll(WW())
        assert r["status"] == "BANNED", r
        assert audit.is_banned_on_chain(banned_ek) is True
        print("  ✓ whitewash after restart: engine says BANNED, chain agrees")


def test_run_server_enrollment_gate():
    """The run_server.py gate: a banned EK is refused BEFORE enrollment and
    the remaining clients still enroll. One attacker must not DoS the run."""
    with tempfile.TemporaryDirectory() as d:
        handles, signers, _ = make_federation()
        audit, backend, fk = build_audit(
            "mock", audit_path=os.path.join(d, "a.jsonl"),
            fed_key_path=os.path.join(d, "k"))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(4):
            server.run_round(r, handles)
        assert server.rep.get_status("a0") == Status.BANNED

        # a fresh batch arrives: one carries the banned EK
        class Returning:
            device_label = "a0_again"
            tpm_backend = "mock"
            def enroll_payload(self):
                p = signers["a0"].provision()
                return {"device_label": "a0_again", "ek_hash": p.ek_hash,
                        "ak_name": p.ak_name, "ek_cert_b64": None}
            def activate_credential(self, blob):
                return b""
            def train(self, r, p):
                return {"update": [0.0] * DIM, "num_samples": 1}

        newcomer = LocalClientHandle("h_new", make_signer("mock", "h_new"),
                                     FLClient("h_new", honest(9)))

        # this is run_server.py's loop, verbatim in shape
        admitted, refused = [], []
        for h in [Returning(), newcomer]:
            ek = h.enroll_payload()["ek_hash"]
            if audit.is_banned_on_chain(ek):
                refused.append(h.device_label)
                continue
            server.enroll(h)
            admitted.append(h.device_label)

        assert refused == ["a0_again"], refused
        assert admitted == ["h_new"], admitted
        print("  ✓ gate refused the banned EK and still admitted the honest "
              "newcomer (no federation-wide DoS)")


def test_node_down_degrades_not_halts():
    """Constraint 2: the chain is never on the critical path.

    NOTE on how the outage is simulated. MockBackend._force_unavailable()
    only flips the is_available() flag -- writes still succeed (mock.py says
    so in its own self-test: "unavailability is a signal to the registry, not
    an enforced block"). And ChainRegistry._guard() never consults
    is_available(); it degrades when a write RAISES. So a faithful outage is
    a backend whose writes raise, which is exactly what a real EvmBackend
    does on a JSON-RPC timeout. That is what DeadNode injects here.

    Implication for chain/evm.py (step 5): EvmBackend MUST raise on timeout.
    If it only set the flag, rounds would be silently marked anchored while
    nothing reached the node.
    """
    class DeadNode:
        """Wraps a live backend; writes raise, reads pass through."""
        def __init__(self, inner):
            self._inner = inner
            self.down = False

        def _w(self, name, *a, **k):
            if self.down:
                raise TimeoutError("JSON-RPC timeout: node unreachable")
            return getattr(self._inner, name)(*a, **k)

        def register(self, *a, **k):        return self._w("register", *a, **k)
        def classify(self, *a, **k):        return self._w("classify", *a, **k)
        def round_summary(self, *a, **k):   return self._w("round_summary", *a, **k)
        def enter_probation(self, *a, **k): return self._w("enter_probation", *a, **k)
        def exhaust_probation(self, *a, **k): return self._w("exhaust_probation", *a, **k)
        def probation_decision(self, *a, **k): return self._w("probation_decision", *a, **k)

        def is_available(self):             return not self.down
        def get_device(self, d):            return self._inner.get_device(d)
        def is_banned_ek(self, ek):
            if self.down:
                raise TimeoutError("node unreachable")
            return self._inner.is_banned_ek(ek)
        def events(self, *a, **k):          return self._inner.events(*a, **k)
        def head_hash(self):                return self._inner.head_hash()
        def last_round(self):               return self._inner.last_round()

    with tempfile.TemporaryDirectory() as d:
        from audit.hashchain import HashChain
        from chain.mock import MockBackend
        from chain.keys import FederationKey
        from chain.registry import ChainRegistry
        from chain.wiring import DEFAULT_WRITER

        handles, _, _ = make_federation()
        node = DeadNode(MockBackend(DEFAULT_WRITER))
        audit = ChainRegistry(HashChain(path=os.path.join(d, "a.jsonl")),
                              node, FederationKey(key=b"\x33" * 32),
                              writer=DEFAULT_WRITER)
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(3):
            server.run_round(r, handles)
        assert audit.anchored_rounds == {0, 1, 2}

        # ---- the node dies ----
        node.down = True
        for r in range(3, 6):
            rep = server.run_round(r, handles)
            assert rep["weights"], "training stalled while the node was down"
            assert rep["aggregated"], "aggregation stopped while node was down"
        assert audit.failures, "node outage was not recorded"
        assert {3, 4, 5} <= audit.unanchored_rounds
        assert not audit.rejections, "an outage is a Failure, not a Rejection"

        # enrollment fails OPEN while the node is unreachable
        assert audit.is_banned_on_chain("ab" * 32) is False

        # ---- the node comes back ----
        node.down = False
        rep = server.run_round(6, handles)
        assert rep["weights"]
        assert 6 in audit.anchored_rounds
        print(f"  ✓ node down: 3 rounds continued and were marked UNANCHORED "
              f"({len(audit.failures)} failures, 0 rejections), enrollment "
              f"failed OPEN, round 6 re-anchored after recovery")


def test_long_run_reconciliation_is_faithful():
    """Reconciliation must stay exact over a long history, not just a few
    rounds. This is the property Chapter 5 reports against round count."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.jsonl")
        handles, _, _ = make_federation(n_honest=5, n_attackers=2)
        audit, backend, fk = build_audit(
            "mock", audit_path=path, fed_key_path=os.path.join(d, "k"))
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(30):
            server.run_round(r, handles)

        before = {l: (server.rep._dev[l].trust,
                      server.rep._dev[l].status,
                      server.rep._dev[l].clean_run)
                  for l in server.rep._dev}
        audit2 = reopen_audit(audit, audit_path=path)
        engine, report = rebuild_engine(backend, audit2.inner)
        assert report.ok, report.summary()
        for l, (t, st, cr) in before.items():
            assert abs(engine._dev[l].trust - t) <= 5e-6, l
            assert engine._dev[l].status == st, l
            assert engine._dev[l].clean_run == cr, l
        assert verify_backend(backend).ok
        print(f"  ✓ 30 rounds, {report.events_replayed} events: rebuild exact "
              f"for all {report.devices} devices")


def _evm_available():
    """The EVM tests need compiled artifacts and eth-tester. Skip cleanly
    rather than failing when either is absent."""
    try:
        from chain.evm import ABI_PATH, BIN_PATH
        import eth_tester  # noqa: F401
        from web3 import Web3  # noqa: F401
        return ABI_PATH.exists() and BIN_PATH.exists()
    except Exception:
        return False


def test_full_lifecycle_on_deployed_contract():
    """The same federation, driven onto the real Solidity contract instead of
    the mock: enroll, ban, restart, rebuild, whitewash, verify.

    This is the claim Chapter 5 rests on -- the chain layer is not a Python
    simulation of enforcement, the deployed contract does the rejecting.
    """
    if not _evm_available():
        print("  - skipped: no compiled contract artifacts "
              "(run solc with --via-ir) or no eth-tester")
        return

    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider
    from audit.hashchain import HashChain
    from chain.evm import EvmBackend, load_abi
    from chain.deploy import deploy_contract
    from chain.keys import FederationKey
    from chain.registry import ChainRegistry

    w3 = Web3(EthereumTesterProvider(EthereumTester(backend=PyEVMBackend())))
    server_acct = w3.eth.accounts[0]
    contract, receipt = deploy_contract(w3, server_acct)
    W = b"evm-writer"
    backend = EvmBackend.attach(w3, contract.address, writer=W,
                                server_account=server_acct, abi=load_abi())

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.jsonl")
        fk = FederationKey(path=os.path.join(d, "k"))
        audit = ChainRegistry(HashChain(path=path), backend, fk, writer=W)

        handles, signers, _ = make_federation(n_honest=3, n_attackers=2)
        server = FederatedServer([0.0] * DIM, audit=audit)
        for h in handles:
            server.enroll(h)
        for r in range(5):
            server.run_round(r, handles)

        assert not audit.rejections, [str(x) for x in audit.rejections]
        assert not audit.failures, [f.error for f in audit.failures]
        assert server.rep.get_status("a0") == Status.BANNED
        # the CONTRACT, not the mock, holds the ban
        assert backend.get_device("a0").status.name == "BANNED"
        banned_ek = server.enrolled["a0"]["ek_hash"]
        assert backend.is_banned_ek(fk.ek_hmac(banned_ek)) is True
        print(f"  ✓ 5 rounds onto the deployed contract, a0 BANNED on chain, "
              f"gas for deploy {receipt.gasUsed:,}")

        # ---- restart, rebuild from the CONTRACT ----
        before = {l: server.rep._dev[l].trust for l in server.rep._dev}
        del server
        audit2 = ChainRegistry(HashChain(path=path), backend, fk, writer=W)
        engine, report = rebuild_engine(backend, audit2.inner)
        assert report.ok, report.summary()
        server = FederatedServer([0.0] * DIM, audit=audit2,
                                 reputation_engine=engine)
        restore_server(server, engine, audit2.inner)
        for l, t in before.items():
            assert abs(server.rep._dev[l].trust - t) <= 5e-6, l
        assert server.rep.get_status("a0") == Status.BANNED
        print(f"  ✓ rebuilt from the DEPLOYED CONTRACT: {report.devices} "
              f"devices, trust within 5e-6, ban survived")

        # ---- the contract itself refuses the resurrection ----
        # Use a0's ACTUAL enrolled tier: the contract checks TierMutation
        # before the ban rule, so a wrong tier here would test the wrong rule.
        from chain.backend import ChainRejection, Reason
        a0_tier = int(backend.get_device("a0").tier)
        try:
            backend.register(W, "a0", a0_tier, b"\xde" * 32)  # fresh EK
            raise AssertionError("contract should refuse resurrection")
        except ChainRejection as e:
            assert e.reason in (Reason.BAN_TO_ACTIVE, Reason.EK_REGISTERED), \
                e.reason
            reason = e.reason
        assert backend.get_device("a0").status.name == "BANNED"
        print(f"  ✓ ENFORCEMENT: the contract reverted the resurrection "
              f"write ({reason}) -- not a Python check, an EVM revert")

        # ---- whitewash under a fresh label ----
        st, ev = backend.register(W, "a0_fresh_face", a0_tier,
                                  fk.ek_hmac(banned_ek))
        assert ev.event_type == "WHITEWASH_REJECTED"
        assert backend.get_device("a0_fresh_face") is None
        print("  ✓ whitewash on the deployed contract: WhitewashRejected, no "
              "device record created")

        # ---- independent verification of the live contract ----
        res = verify_backend(backend)
        assert res.ok, res.summary()
        print(f"  ✓ third-party verification of the deployed contract: "
              f"{res.summary()}")


TESTS = [test_chain_off_is_the_baseline,
         test_chain_off_matches_chain_on_trajectory,
         test_full_federation_mirrors_and_verifies,
         test_restart_rebuild_preserves_ban,
         test_whitewash_rejected_after_restart,
         test_run_server_enrollment_gate,
         test_node_down_degrades_not_halts,
         test_long_run_reconciliation_is_faithful,
         test_full_lifecycle_on_deployed_contract]


if __name__ == "__main__":
    failed = 0
    for fn in TESTS:
        print(f"[{fn.__name__}]")
        try:
            fn()
            print(f"✓ {fn.__name__}\n")
        except Exception as e:
            failed += 1
            import traceback
            traceback.print_exc()
            print(f"✗ {fn.__name__}: {e}\n")
    print("✓ CHAIN INTEGRATION GREEN" if not failed
          else f"✗ {failed} test group(s) failed")
    sys.exit(1 if failed else 0)
