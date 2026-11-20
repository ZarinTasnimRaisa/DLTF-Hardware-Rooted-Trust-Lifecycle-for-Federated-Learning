"""
chain/wiring.py

One place where a run script turns a --chain flag into an audit object.
run_local.py and run_server.py both call build_audit(); keeping it here means
SIM and REAL cannot drift apart, and it keeps the seam in the run scripts to
a couple of lines.

CONTRACT
-----------------------------------------------------------------------------
build_audit(mode=...) returns (audit, backend, fed_key).

  mode "off"    -> (HashChain or None, None, None)
                   Baseline. Nothing under chain/ is constructed. If no
                   audit_path is given the audit object is None too, which is
                   exactly what run_local.py passed before this layer existed.

  mode "mock"   -> (ChainRegistry, MockBackend, FederationKey)
                   Deterministic, in-memory, no node. CI and the SIM
                   acceptance test run here.

  mode "node"   -> (ChainRegistry, EvmBackend, FederationKey)
                   Live Hardhat/Anvil node. chain/evm.py is step 5 of the
                   build order and is not written yet, so this raises a clear
                   NotImplementedError rather than failing obscurely later.

The audit object is duck-typed: FederatedServer only ever calls .append(),
and ChainRegistry forwards to the inner HashChain before mirroring. So the
local audit log is byte-identical whether the chain is on or off.

  python3 -m chain.wiring
"""
import os

MODES = ("off", "mock", "node")

DEFAULT_WRITER = b"dltf-sim-writer-key-32-bytes-xx!"


def _require_mode(mode):
    if mode not in MODES:
        raise ValueError(f"unknown chain mode {mode!r} (have {list(MODES)})")


def build_audit(mode="off", audit_path=None, fed_key_path=None,
                writer=None, rpc_url=None, contract_address=None,
                network="localhost", verbose=False, require_commit=False,
                deploy_block=0, private_key=None, async_writes=False,
                poll_timeout=None):
    """Build the audit object a FederatedServer should be given.

    Returns (audit, backend, fed_key). backend and fed_key are None when the
    chain is off; callers use them for reconciliation and whitewash checks.
    """
    _require_mode(mode)

    if mode == "off":
        if audit_path is None:
            return None, None, None
        from audit.hashchain import HashChain
        return HashChain(path=audit_path), None, None

    # Chain is on: everything below is imported ONLY in this branch, so a
    # baseline run never touches chain/ at all.
    from audit.hashchain import HashChain
    from chain.keys import FederationKey
    from chain.registry import ChainRegistry

    writer = writer or DEFAULT_WRITER

    if mode == "mock":
        from chain.mock import MockBackend
        backend = MockBackend(writer)
        if require_commit:
            # CommitMockBackend adds the commitment surface (bind_wallet,
            # commit_gradient, get_commit) and enforces MissingCommit on
            # classify, mirroring the contract's immutable requireCommit.
            from chain.commit import CommitMockBackend
            backend = CommitMockBackend(backend, require_commit=True)
    else:                                   # "node"
        from chain.evm import EvmBackend, TransportError
        from chain.deploy import resolve_address

        addr = resolve_address(network=network, cli_address=contract_address)
        if not addr:
            raise ValueError(
                "chain mode 'node' needs a contract address. Deploy one with\n"
                "  PYTHONPATH=. python3 -m chain.deploy --network localhost\n"
                "or set config.CHAIN['contract_address'].")
        kw = {}
        if poll_timeout is not None:
            kw["poll_timeout"] = poll_timeout
        try:
            backend = EvmBackend.connect(
                rpc_url, addr, writer=writer,
                private_key=private_key,
                # Bounds every eth_getLogs. Unset, chain/evm.py scans from
                # genesis, which public providers refuse outright.
                deploy_block=deploy_block, **kw)
            if backend.signer is None:
                print(
                    "\u26a0 no signing key: writes will go out as "
                    "eth_sendTransaction, which ONLY Anvil, Hardhat and "
                    "eth-tester implement. On any public or consortium "
                    "endpoint every read will succeed and every write will "
                    "fail. Set DLTF_CHAIN_PRIVKEY.")
            # requireCommit is IMMUTABLE on chain, fixed at deploy. We cannot
            # turn it on here -- only check the deployment matches intent, and
            # say so loudly if it does not, because silently ignoring the flag
            # would let someone believe the rule is active when it is not.
            on_chain = bool(
                backend.contract.functions.requireCommit().call())
            if require_commit != on_chain:
                raise ValueError(
                    f"--require-commit={require_commit} but the deployed "
                    f"contract at {addr} has requireCommit={on_chain}. It is "
                    f"immutable; redeploy with "
                    f"`python3 -m chain.deploy --network {network}"
                    f"{' --require-commit' if require_commit else ''}`.")
        except TransportError as exc:
            raise TransportError(
                f"cannot reach the node at {rpc_url}. Start one with `anvil` "
                f"or `npx hardhat node`, point --rpc at a live endpoint, or "
                f"use --chain mock.") from exc

    if fed_key_path:
        os.makedirs(os.path.dirname(fed_key_path) or ".", exist_ok=True)
        fed_key = FederationKey(path=fed_key_path)
    else:
        # No path: ephemeral in-memory key. Fine for a single SIM process,
        # useless across restarts, so run scripts pass a path.
        fed_key = FederationKey(key=b"\x2a" * 32)

    inner = HashChain(path=audit_path)
    registry = ChainRegistry(inner, backend, fed_key, writer=writer,
                             async_writes=async_writes,
                             verbose=verbose)
    return registry, backend, fed_key


def reopen_audit(registry, audit_path=None, verbose=False):
    """Rebuild a ChainRegistry around the SAME backend after a server restart.

    Models the honest thing: the process died, the node did not. The chain
    backend object survives; the local audit log is reopened from disk (or a
    fresh in-memory chain when there is no path).
    """
    from audit.hashchain import HashChain
    from chain.registry import ChainRegistry
    inner = HashChain(path=audit_path)
    return ChainRegistry(inner, registry.backend, registry.fed_key,
                         writer=registry.writer, verbose=verbose)


def chain_report_lines(registry):
    """Human-readable end-of-run chain summary, or [] when the chain is off."""
    if registry is None or not hasattr(registry, "report"):
        return []
    r = registry.report()
    lines = [f"chain: {r['mirrored_writes']} mirrored writes, "
             f"{r['rejections']} rejections, {r['failures']} failures",
             f"chain: {len(r['anchored_rounds'])} rounds anchored, "
             f"{len(r['unanchored_rounds'])} unanchored"]
    for rej in registry.rejections:
        lines.append(f"  REJECTED {rej}")
    return lines


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import tempfile

    print("chain/wiring.py self-test")

    # === 1. off means OFF =================================================
    audit, backend, fk = build_audit("off")
    assert audit is None and backend is None and fk is None
    print("\u2713 mode off with no path: (None, None, None) -- the exact "
          "baseline run_local.py had before this layer")

    # === 2. off with a path still gives a plain hash chain ================
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "audit.jsonl")
        audit, backend, fk = build_audit("off", audit_path=p)
        from audit.hashchain import HashChain
        assert isinstance(audit, HashChain)
        assert backend is None and fk is None
        audit.append("ENROLL", {"device": "x"})
        assert os.path.exists(p)
    print("\u2713 mode off with a path: plain HashChain, no chain backend")

    # === 3. mock builds the full stack ====================================
    with tempfile.TemporaryDirectory() as d:
        audit, backend, fk = build_audit(
            "mock", audit_path=os.path.join(d, "audit.jsonl"),
            fed_key_path=os.path.join(d, "federation.key"))
        from chain.registry import ChainRegistry
        from chain.mock import MockBackend
        assert isinstance(audit, ChainRegistry)
        assert isinstance(backend, MockBackend)
        assert fk is not None
        # the HashChain surface still works through the facade
        audit.append("ENROLL", {"device": "a", "tier": "HARDWARE",
                                "ek_hash": "aa" * 32, "status": "ACTIVE"})
        ok, err = audit.verify()
        assert ok, err
        assert backend.get_device("a") is not None
        print("\u2713 mode mock: ChainRegistry + MockBackend + FederationKey, "
              "HashChain surface intact, ENROLL mirrored")

        # === 4. federation key persists to its path ====================
        assert os.path.exists(os.path.join(d, "federation.key"))
        _, _, fk2 = build_audit(
            "mock", audit_path=os.path.join(d, "audit2.jsonl"),
            fed_key_path=os.path.join(d, "federation.key"))
        assert fk2.ek_hmac("aa" * 32) == fk.ek_hmac("aa" * 32)
        print("\u2713 federation key persists: same path -> same ek_hmac "
              "(bans survive a restart)")

        # === 5. reopen_audit keeps the backend, reopens the log =========
        reopened = reopen_audit(audit, audit_path=os.path.join(d, "audit.jsonl"))
        assert reopened.backend is backend
        assert reopened.fed_key is fk
        assert reopened.inner is not audit.inner
        # the reopened log still has the ENROLL on disk
        assert len(reopened.entries("ENROLL")) == 1
        print("\u2713 reopen_audit: same backend (node survives), log reopened "
              "from disk, ENROLL still present")

    # === 6. bad mode is rejected loudly ===================================
    try:
        build_audit("banana")
        raise AssertionError("should have raised")
    except ValueError:
        print("\u2713 unknown mode rejected with a clear ValueError")

    # === 7. node mode without a deployment fails with a USEFUL message ====
    try:
        build_audit("node", rpc_url="http://127.0.0.1:8545",
                    contract_address=None, network="__no_such_network__")
        raise AssertionError("should have raised")
    except ValueError as e:
        assert "chain.deploy" in str(e), str(e)
        print("\u2713 node mode with no deployment names the deploy command, "
              "not an obscure error")

    # === 7b. node mode with an address but no node names the fix ==========
    from chain.evm import TransportError
    try:
        build_audit("node", rpc_url="http://127.0.0.1:59999",
                    contract_address="0x" + "11" * 20)
        raise AssertionError("should have raised")
    except TransportError as e:
        assert "anvil" in str(e) or "hardhat" in str(e), str(e)
        print("\u2713 node mode with no reachable node suggests `anvil` / "
              "`npx hardhat node` / --chain mock")

    # === 8. report lines ==================================================
    assert chain_report_lines(None) == []
    with tempfile.TemporaryDirectory() as d:
        audit, backend, fk = build_audit(
            "mock", audit_path=os.path.join(d, "a.jsonl"),
            fed_key_path=os.path.join(d, "k"))
        audit.append("ENROLL", {"device": "z", "tier": "SOFTWARE",
                                "ek_hash": "bb" * 32, "status": "ACTIVE"})
        lines = chain_report_lines(audit)
        assert lines and "mirrored writes" in lines[0]
    print("\u2713 chain_report_lines: [] when off, summary when on")

    print("\u2713 all wiring self-tests passed")


if __name__ == "__main__":
    _self_test()
