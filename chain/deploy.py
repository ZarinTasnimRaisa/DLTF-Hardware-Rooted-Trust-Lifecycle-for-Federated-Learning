"""
chain/deploy.py

Deploy DLTFRegistry.sol to a Hardhat or Anvil node and record the address.

    # compile first (NOTE --via-ir: the contract does not compile without it)
    solc --optimize --optimize-runs 200 --via-ir --bin --abi --overwrite \
         -o contracts/out contracts/src/DLTFRegistry.sol

    # then deploy
    PYTHONPATH=. python3 -m chain.deploy --network localhost

The address is written to chain/deployed.json rather than edited into
config.py: config.py is version-controlled deployment topology, while a
contract address is per-environment run state. Keeping them apart means a
redeploy never produces a spurious config.py diff. config.CHAIN
["contract_address"] still wins if it is set, so a pinned address can be
committed when that is what you want.

Resolution order used by chain/wiring.py and run_server.py:
    1. --address on the command line
    2. config.CHAIN["contract_address"] if not None
    3. chain/deployed.json for the current network
    4. error

REQUIRE_COMMIT IS IMMUTABLE
-----------------------------------------------------------------------------
The constructor's third argument is `requireCommit`, and the contract marks
it `immutable`. It cannot be changed after deployment -- that is deliberate,
so a server operator cannot quietly disable the commitment layer mid-
federation. Choosing it wrongly here means redeploying, which is the point.

  python3 -m chain.deploy --help
  python3 -m chain.deploy --self-test        (eth-tester, no node needed)
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

DEPLOYED_PATH = Path(__file__).resolve().parent / "deployed.json"

NETWORKS = {
    "localhost": "http://127.0.0.1:8545",
    "anvil":     "http://127.0.0.1:8545",
    "hardhat":   "http://127.0.0.1:8545",
}


# ---- deployment record -------------------------------------------------------

def read_deployments(path=DEPLOYED_PATH):
    if not Path(path).exists():
        return {}
    try:
        return json.loads(Path(path).read_text())
    except (ValueError, OSError):
        return {}


def write_deployment(network, record, path=DEPLOYED_PATH):
    data = read_deployments(path)
    data[network] = record
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return path


def resolve_address(network="localhost", cli_address=None, path=DEPLOYED_PATH):
    """The resolution order documented above. Returns None if unresolved."""
    if cli_address:
        return cli_address
    try:
        import config
        if config.CHAIN.get("contract_address"):
            return config.CHAIN["contract_address"]
    except Exception:
        pass
    rec = read_deployments(path).get(network)
    return rec.get("address") if rec else None


# ---- deployment --------------------------------------------------------------

def deploy_contract(w3, account, chain_id_tag=b"\x00" * 32,
                    require_commit=False, abi=None, binary=None, gas=None,
                    signer=None, timeout=600):
    """Deploy and return (contract, receipt).

    Two paths, and the second is the one that was missing:

      signer is None   eth_sendTransaction from an unlocked node account.
                       Anvil, Hardhat, eth-tester.
      signer set       locally signed raw transaction. The ONLY path a public
                       testnet or a Besu consortium node will accept, because
                       neither holds your key and neither implements
                       eth_sendTransaction. Previously `main()` did
                       `w3.eth.accounts[0]`, which on a public RPC returns []
                       and raised IndexError before a single token was spent.

    `account` is the address written into the contract as the IMMUTABLE
    authorised writer. With a signer it must be the signer's own address, or
    every subsequent write reverts UnauthorizedWriter and the deployment is
    scrap.
    """
    from chain.evm import load_abi, load_bin
    abi = abi if abi is not None else load_abi()
    binary = binary if binary is not None else load_bin()

    factory = w3.eth.contract(abi=abi, bytecode=binary)

    if signer is not None:
        if signer.address.lower() != str(account).lower():
            raise ValueError(
                f"the deployer signs the transaction, so it becomes the "
                f"immutable writer: account={account} but signer="
                f"{signer.address}. Deploying this way would produce a "
                f"contract no key you hold can write to.")
        ctor = factory.constructor(account, chain_id_tag,
                                   bool(require_commit))
        tx_hash, _ = signer.send(ctor, gas=gas)
        receipt = signer.wait(tx_hash, timeout=timeout)
    else:
        tx_params = {"from": account}
        if gas:
            tx_params["gas"] = gas
        tx = factory.constructor(account, chain_id_tag,
                                 bool(require_commit)).transact(tx_params)
        receipt = w3.eth.wait_for_transaction_receipt(tx, timeout=timeout)

    if receipt.get("status", 1) == 0:
        raise RuntimeError("deployment transaction reverted")
    contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)
    return contract, receipt


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Deploy DLTFRegistry.sol and record its address.")
    ap.add_argument("--network", default="localhost",
                    help=f"one of {sorted(NETWORKS)} or a raw RPC URL")
    ap.add_argument("--rpc-url", default=None,
                    help="override the RPC URL for --network")
    ap.add_argument("--account", default=None,
                    help="deployer/server address (default: accounts[0]). "
                         "This address becomes the IMMUTABLE authorised "
                         "writer.")
    ap.add_argument("--require-commit", action="store_true",
                    help="enable the gradient-commitment layer. IMMUTABLE "
                         "after deploy: it cannot be turned off later.")
    ap.add_argument("--chain-tag", default="00" * 32,
                    help="32-byte hex federation tag in the Genesis event")
    ap.add_argument("--key", default=None,
                    help="deployer private key (or DLTF_CHAIN_PRIVKEY). "
                         "REQUIRED for any public or consortium endpoint: "
                         "they do not hold keys and do not implement "
                         "eth_sendTransaction. Never a key with real funds.")
    ap.add_argument("--gas", type=int, default=None)
    ap.add_argument("--out", default=str(DEPLOYED_PATH),
                    help="where to record the deployment")
    ap.add_argument("--self-test", action="store_true",
                    help="deploy against eth-tester and verify (no node)")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    rpc = args.rpc_url or NETWORKS.get(args.network, args.network)

    from web3 import Web3
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        print(f"\u2717 cannot reach a node at {rpc}\n"
              f"  start one with:  anvil\n"
              f"               or: npx hardhat node", file=sys.stderr)
        return 2

    # Local signing if a key is available. Without one, fall back to an
    # unlocked node account -- and say so clearly when there are none, rather
    # than raising IndexError on accounts[0].
    signer = None
    key = args.key or os.environ.get("DLTF_CHAIN_PRIVKEY")
    if key:
        from chain.signer import TxSigner
        signer = TxSigner(w3, key)
        account = signer.address
        if args.account and Web3.to_checksum_address(args.account) != account:
            print(f"\u2717 --account {args.account} does not match the key's "
                  f"address {account}. The signer becomes the immutable "
                  f"writer, so these must agree.", file=sys.stderr)
            return 2
    else:
        accounts = w3.eth.accounts
        if not accounts and not args.account:
            print(f"\u2717 {rpc} exposes no unlocked accounts and no key was "
                  f"given.\n"
                  f"  Public endpoints never hold your key. Set one:\n"
                  f"    export DLTF_CHAIN_PRIVKEY=0x<funded test key>\n"
                  f"  (or pass --key). Never a key with real funds.",
                  file=sys.stderr)
            return 2
        account = args.account or accounts[0]
    account = Web3.to_checksum_address(account)

    print(f"network      : {args.network} ({rpc})")
    print(f"chain id     : {w3.eth.chain_id}")
    print(f"deployer     : {account}  ({'local key' if signer else 'node account'})")
    print(f"requireCommit: {args.require_commit}  (IMMUTABLE after deploy)")

    if signer is not None:
        bal = signer.balance()
        print(f"balance      : {w3.from_wei(bal, 'ether')} (native token)")
        if bal == 0:
            print("\u2717 the deployer has a zero balance. Fund it from the "
                  "faucet before deploying.", file=sys.stderr)
            return 2

    t0 = time.time()
    contract, receipt = deploy_contract(
        w3, account, chain_id_tag=bytes.fromhex(args.chain_tag),
        require_commit=args.require_commit, gas=args.gas, signer=signer)
    elapsed = time.time() - t0

    # Read the deployed state back rather than trusting the local intent.
    on_chain_server = contract.functions.server().call()
    on_chain_commit = contract.functions.requireCommit().call()
    assert on_chain_server == account, "deployed server address mismatch"
    assert on_chain_commit == bool(args.require_commit)

    record = {
        "address": contract.address,
        "server": on_chain_server,
        "require_commit": on_chain_commit,
        "chain_id": w3.eth.chain_id,
        "block": receipt.blockNumber,
        "tx": receipt.transactionHash.hex(),
        "gas_used": receipt.gasUsed,
        "effective_gas_price": int(receipt.get("effectiveGasPrice", 0) or 0),
        # THE FIELD THAT MATTERS AFTERWARDS: every eth_getLogs is bounded from
        # here. Without it chain/evm.py scans from genesis, which public
        # providers refuse.
        "deploy_block": receipt.blockNumber,
        "signed_locally": signer is not None,
        "rpc_url": rpc,
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path = write_deployment(args.network, record, args.out)

    print(f"\u2713 deployed at {contract.address}")
    print(f"  gas used   : {receipt.gasUsed:,}")
    print(f"  block      : {receipt.blockNumber}")
    print(f"  elapsed    : {elapsed:.2f}s")
    print(f"  recorded in: {path}")
    price = int(receipt.get("effectiveGasPrice", 0) or 0)
    if price:
        cost = receipt.gasUsed * price
        print(f"  paid       : {w3.from_wei(cost, 'ether')} native token "
              f"at {price / 1e9:.2f} gwei")
    print()
    print("Use it:")
    print(f"  export DLTF_CHAIN=node")
    print(f"  export DLTF_CHAIN_RPC={rpc}")
    print(f"  export DLTF_DEPLOY_BLOCK={receipt.blockNumber}")
    print(f"  PYTHONPATH=. python3 -m eval.run_local --chain node "
          f"--network {args.network} --rounds 10")
    return 0


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import tempfile
    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    from chain.evm import EvmBackend, load_abi
    from chain.fixedpoint import StatusFP, TierFP

    print("chain/deploy.py self-test (eth-tester, no node needed)")

    w3 = Web3(EthereumTesterProvider(EthereumTester(backend=PyEVMBackend())))
    server = w3.eth.accounts[0]
    other = w3.eth.accounts[1]

    # === 1. Deploy and read the state back ================================
    contract, receipt = deploy_contract(w3, server)
    assert contract.functions.server().call() == server
    assert contract.functions.requireCommit().call() is False
    assert contract.functions.lastRoundSet().call() is False
    print(f"\u2713 deploy: server immutable = deployer, requireCommit False, "
          f"gas {receipt.gasUsed:,}")

    # === 2. The deployed contract drives EvmBackend =======================
    b = EvmBackend.attach(w3, contract.address, writer=b"w",
                          server_account=server, abi=load_abi())
    st, _ = b.register(b"w", "d1", TierFP.HARDWARE, b"\x01" * 32)
    assert st == int(StatusFP.ACTIVE)
    assert b.get_device("d1") is not None
    print("\u2713 a freshly deployed contract is immediately usable through "
          "EvmBackend")

    # === 3. requireCommit=True is honoured AND immutable ==================
    c2, _ = deploy_contract(w3, server, require_commit=True)
    assert c2.functions.requireCommit().call() is True
    # there is no setter on the ABI at all -- that is the guarantee
    setters = [e["name"] for e in c2.abi
               if e["type"] == "function"
               and "requirecommit" in e["name"].lower()
               and e["stateMutability"] != "view"]
    assert not setters, f"requireCommit is mutable via {setters}"
    print("\u2713 requireCommit=True deploys and has NO non-view setter in the "
          "ABI (immutable by construction, not by convention)")

    # === 4. The deployer becomes the only authorised writer ===============
    from chain.backend import ChainRejection, Reason
    b_other = EvmBackend.attach(w3, contract.address, writer=b"w",
                                server_account=other, abi=load_abi())
    try:
        b_other.register(b"w", "d2", TierFP.HARDWARE, b"\x02" * 32)
        raise AssertionError("non-deployer write should revert")
    except ChainRejection as e:
        assert e.reason == Reason.UNAUTHORIZED_WRITER, e.reason
    print("\u2713 --account fixes the authorised writer: any other address "
          "gets UnauthorizedWriter")

    # === 5. Two deploys are independent ledgers ===========================
    c3, _ = deploy_contract(w3, server)
    assert c3.address != contract.address
    b3 = EvmBackend.attach(w3, c3.address, writer=b"w",
                           server_account=server, abi=load_abi())
    assert b3.get_device("d1") is None       # d1 exists only on the first one
    print("\u2713 a second deploy is a separate ledger (no state bleed)")

    # === 6. deployed.json round-trip ======================================
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "deployed.json")
        rec = {"address": contract.address, "server": server,
               "require_commit": False, "chain_id": 131277322940537}
        write_deployment("localhost", rec, p)
        back = read_deployments(p)
        assert back["localhost"]["address"] == contract.address
        # a second network does not clobber the first
        write_deployment("anvil", {"address": c3.address}, p)
        back = read_deployments(p)
        assert set(back) == {"localhost", "anvil"}
        assert back["localhost"]["address"] == contract.address
        print("\u2713 deployed.json: per-network records, second deploy does "
              "not clobber the first")

        # === 7. resolve_address precedence ================================
        assert resolve_address("localhost", cli_address="0xABC", path=p) == "0xABC"
        assert resolve_address("localhost", path=p) == contract.address
        assert resolve_address("nonexistent", path=p) is None
        print("\u2713 resolve_address precedence: --address > config > "
              "deployed.json > None")

    # === 8. Missing artifacts fail with a BUILD COMMAND, not a traceback ==
    # This test used to override evm.ABI_PATH, which load_abi() ignored -- it
    # called find_artifacts() unconditionally, so the assertion below could
    # never pass and this suite had been failing. Make the artifacts actually
    # unfindable, which is the condition the error message is for.
    import chain.evm as evm_mod
    saved_path, saved_find = evm_mod.ABI_PATH, evm_mod.find_artifacts
    try:
        evm_mod.ABI_PATH = Path("/nonexistent/DLTFRegistry.abi")
        evm_mod.find_artifacts = lambda: (None, None)
        try:
            evm_mod.load_abi()
            raise AssertionError("should have exited")
        except SystemExit as e:
            assert "--via-ir" in str(e), str(e)
    finally:
        evm_mod.ABI_PATH = saved_path
        evm_mod.find_artifacts = saved_find
    print("\u2713 missing artifacts print the exact solc command (including "
          "--via-ir, which the contract requires)")

    print("\u2713 all deploy self-tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
