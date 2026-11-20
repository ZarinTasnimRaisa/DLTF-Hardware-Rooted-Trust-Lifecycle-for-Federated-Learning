"""
tests/test_pipeline.py

One command to know the whole stack is green:

  PYTHONPATH=. python3 tests/test_pipeline.py      (no pytest needed)
  PYTHONPATH=. python3 -m pytest tests/ -q         (if pytest is installed)

Runs every module's self-test in an isolated subprocess, syntax-checks the
torch/machine-side files (their self-tests run on the experiment machine), and
finishes with an end-to-end smoke test: a federation over real HTTP with the
audit chain persisted to disk, exercising enrollment, sybil ban, whitewash
rejection, and chain reload in one pass.
"""
import os
import sys
import py_compile
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SELFTEST_MODULES = [
    "tpm/common.py",
    "tpm/client.py",
    "trust/reputation.py",
    "trust/probation.py",
    "trust/filter.py",
    "fl/dataset.py",
    "fl/aggregator.py",
    "fl/client.py",
    "fl/server.py",
    "net/handles.py",
    "net/agent.py",
    "audit/hashchain.py",
    "eval/scenarios.py",
]

COMPILE_ONLY = [        # need torch or tpm2-tools or a CLI: run machine-side
    "fl/model.py",
    "tpm/check_ek_cert.py",
    "eval/run_experiments.py",
]

# Optional on-chain trust registry. Skipped cleanly when chain/ is absent, so
# the pipeline stays green on a tree without it. Ordered cheapest-first so a
# fixed-point regression fails before the slow EVM suites run.
CHAIN_MODULES = [
    "chain/fixedpoint.py",
    "chain/backend.py",
    "chain/keys.py",
    "chain/mock.py",
    "chain/registry.py",
    "chain/verifier.py",
    "chain/reconcile.py",
    "chain/wiring.py",
    "chain/commit.py",
]

# Need compiled Solidity artifacts (solc --via-ir) plus eth-tester.
CHAIN_EVM_MODULES = [
    "chain/evm.py",
    "chain/evm_parity_test.py",
    "chain/commit_parity_test.py",
    "chain/batch_parity_test.py",
]


def _chain_present():
    return os.path.isdir(os.path.join(ROOT, "chain"))


def _evm_ready():
    """True iff eth-tester, web3 and compiled artifacts are all available."""
    try:
        import eth_tester, web3           # noqa: F401
    except Exception:
        return False
    try:
        sys.path.insert(0, ROOT)
        from chain.evm import find_artifacts
        return find_artifacts()[0] is not None
    except Exception:
        return False


def test_module_selftests():
    env = dict(os.environ, PYTHONPATH=ROOT)
    for mod in SELFTEST_MODULES:
        p = subprocess.run([sys.executable, os.path.join(ROOT, mod)],
                           capture_output=True, env=env, cwd=ROOT, timeout=300)
        assert p.returncode == 0, \
            f"{mod} self-test failed:\n{p.stderr.decode(errors='replace')[-800:]}"
        print(f"  ✓ {mod}")


def test_chain_selftests():
    """Chain-layer module self-tests. Skips, not fails, when chain/ is absent."""
    if not _chain_present():
        print("  - skipped: no chain/ directory (chain layer not installed)")
        return
    env = dict(os.environ, PYTHONPATH=ROOT)
    for mod in CHAIN_MODULES:
        path = os.path.join(ROOT, mod)
        if not os.path.exists(path):
            print(f"  - skipped {mod} (absent)")
            continue
        p = subprocess.run([sys.executable, path], capture_output=True,
                           env=env, cwd=ROOT, timeout=600)
        assert p.returncode == 0, \
            f"{mod} self-test failed:\n{p.stderr.decode(errors='replace')[-800:]}"
        print(f"  ✓ {mod}")


def test_chain_evm_selftests():
    """Deployed-contract suites. Need solc --via-ir artifacts and eth-tester."""
    if not _chain_present():
        print("  - skipped: no chain/ directory")
        return
    if not _evm_ready():
        print("  - skipped: needs eth-tester/web3 and compiled artifacts")
        print("    build: solc --optimize --optimize-runs 200 --via-ir "
              "--bin --abi --overwrite -o contracts/out <DLTFRegistry.sol>")
        return
    env = dict(os.environ, PYTHONPATH=ROOT)
    for mod in CHAIN_EVM_MODULES:
        path = os.path.join(ROOT, mod)
        if not os.path.exists(path):
            print(f"  - skipped {mod} (absent)")
            continue
        p = subprocess.run([sys.executable, path], capture_output=True,
                           env=env, cwd=ROOT, timeout=1800)
        assert p.returncode == 0, \
            f"{mod} failed:\n{p.stderr.decode(errors='replace')[-800:]}"
        print(f"  ✓ {mod}")


def test_chain_integration():
    """The wiring suite: restart, rebuild, whitewash, degradation."""
    if not _chain_present():
        print("  - skipped: no chain/ directory")
        return
    path = os.path.join(ROOT, "tests", "test_chain_integration.py")
    if not os.path.exists(path):
        print("  - skipped: tests/test_chain_integration.py absent")
        return
    env = dict(os.environ, PYTHONPATH=ROOT)
    p = subprocess.run([sys.executable, path], capture_output=True,
                       env=env, cwd=ROOT, timeout=1800)
    assert p.returncode == 0, \
        f"chain integration failed:\n{p.stderr.decode(errors='replace')[-1200:]}"
    print("  ✓ tests/test_chain_integration.py")


def test_chain_off_is_inert():
    """CONSTRAINT 1: with the chain off nothing under chain/ is constructed.

    This is the guarantee that keeps every Chapter 4 sweep reproducible, so it
    is asserted here rather than trusted."""
    if not _chain_present():
        print("  - skipped: no chain/ directory")
        return
    sys.path.insert(0, ROOT)
    from chain.wiring import build_audit
    audit, backend, fk = build_audit("off")
    assert audit is None and backend is None and fk is None
    print("  ✓ chain mode 'off' yields (None, None, None) -- no chain objects")


def test_compile_only_modules():
    for mod in COMPILE_ONLY:
        py_compile.compile(os.path.join(ROOT, mod), doraise=True)
        print(f"  ✓ {mod} compiles")


def test_end_to_end_http_with_audit():
    import numpy as np
    from tpm.client import make_signer
    from fl.client import FLClient
    from fl.server import FederatedServer
    from net.agent import DLTFAgent
    from net.handles import RemoteClientHandle
    from audit.hashchain import HashChain
    from trust.reputation import Status

    DIM, BULK = 6, [0, 1, 2]

    def grad(scale=1.0, noise=0.0, seed=0):
        rng = np.random.default_rng(seed)
        v = np.zeros(DIM)
        for k in BULK:
            v[k] = 1.0
        v = v / np.linalg.norm(v)
        return (scale * v + noise * rng.standard_normal(DIM)).tolist()

    def honest(idx):
        return lambda r, p: (grad(1.0, 0.3, seed=100 * r + idx), 64)

    def sybil(r, p):
        rng = np.random.default_rng(7000 + r)        # identical across members
        v = np.zeros(DIM)
        for k in (3, 4, 5):
            v[k] = 1.0
        v = v / np.linalg.norm(v)
        return (v + 0.05 * rng.standard_normal(DIM)).tolist(), 64

    with tempfile.TemporaryDirectory() as td:
        agents, servers, handles = [], [], []
        specs = [(f"h{k}", honest(k)) for k in range(3)] + \
                [("s1", sybil), ("s2", sybil)]
        for label, trainer in specs:
            a = DLTFAgent(label, make_signer("mock", label), FLClient(label, trainer))
            httpd, port = a.serve_in_thread()
            agents.append(a)
            servers.append(httpd)
            handles.append(RemoteClientHandle(label, f"http://127.0.0.1:{port}",
                                              tpm_backend="mock"))

        chain_path = os.path.join(td, "audit.jsonl")
        fed = FederatedServer([0.0] * DIM, audit=HashChain(path=chain_path))
        res = [fed.enroll(h) for h in handles]
        assert all(r["tier"] == "TPM_RESIDENT" for r in res)

        for r in range(3):
            fed.run_round(r, handles)
        assert fed.rep.get_status("s1") == Status.BANNED
        assert fed.rep.get_status("s2") == Status.BANNED
        print("  ✓ sybil pair banned over HTTP")

        s1_again = RemoteClientHandle("s1", handles[3].endpoint, tpm_backend="mock")
        assert fed.enroll(s1_again)["status"] == "BANNED"
        print("  ✓ whitewash re-enrollment rejected over HTTP")

        w = fed.rep.get_all_weights()
        assert all(0.3 <= w[f"h{k}"] <= 0.5 for k in range(3))
        assert "s1" not in w and fed.global_params[BULK[0]] > 0.0
        print("  ✓ honest weights intact, model advanced")

        types = {e["type"] for e in fed.audit.entries()}
        assert {"ENROLL", "EVENT", "BAN", "WHITEWASH_REJECTED", "ROUND"} <= types
        ok, err = fed.audit.verify()
        assert ok, err
        reloaded = HashChain(path=chain_path)
        assert reloaded.head_hash() == fed.audit.head_hash()
        print("  ✓ audit chain persisted, reloaded, verifies")

        for httpd in servers:
            httpd.shutdown()


def test_eval_whitewash_smoke():
    from eval.run_experiments import exp_whitewash
    with tempfile.TemporaryDirectory() as td:
        rows = exp_whitewash(1, td, attempts=3)
    for defense, seed, banned_at, attempts, blocked in rows:
        assert (blocked == attempts) if defense == "dltf" else (blocked == 0)
    print("  ✓ eval whitewash smoke: DLTF blocks, baseline does not")


TESTS = [test_module_selftests, test_compile_only_modules,
         test_end_to_end_http_with_audit, test_eval_whitewash_smoke,
         test_chain_off_is_inert, test_chain_selftests,
         test_chain_integration, test_chain_evm_selftests]

if __name__ == "__main__":
    failed = 0
    for fn in TESTS:
        print(f"[{fn.__name__}]")
        try:
            fn()
            print(f"✓ {fn.__name__}\n")
        except Exception as e:
            failed += 1
            print(f"✗ {fn.__name__}: {e}\n")
    print("✓ PIPELINE GREEN" if not failed else f"✗ {failed} test group(s) failed")
    sys.exit(1 if failed else 0)