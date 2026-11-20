"""
trust/legacy/deploy_chain.py  --  SUPERSEDED. DO NOT USE FOR DEPLOYMENT.

This script compiles and deploys trust/ReputationRegistry.sol: an earlier,
different contract. It is NOT DLTFRegistry.sol.

  ReputationRegistry.sol        DLTFRegistry.sol (what the paper evaluates)
  ------------------------      -----------------------------------------
  solc 0.8.20                   solc 0.8.24, Cancun
  no --via-ir                   --via-ir MANDATORY (classify exceeds the
                                16-slot stack limit without it)
  constructor()                 constructor(server, chainTag, requireCommit)
  no custom errors              21 custom errors, which are the L3 result
  no commitment layer           bindWallet/commitGradient/commitBatch/
                                classifySigned

DEPLOYMENT.md's Phase 1 pointed at this file's --mode testnet path. Following
it would have put the wrong bytecode on a public testnet, spent real faucet
funds doing it, and produced an address that chain/evm.py cannot drive -- the
ABIs do not overlap, so the failure would have surfaced as an unrelated
decoding error rather than as "you deployed the wrong contract".

Deploy with this instead:

    export DLTF_CHAIN_PRIVKEY=0x<funded test key>
    PYTHONPATH=. python3 -m chain.deploy \
        --network amoy --rpc-url https://rpc-amoy.polygon.technology

Kept in the tree because the legacy results were produced with it; it refuses
to run rather than being deleted, so an old command fails loudly instead of
succeeding wrongly.
"""
import sys

_ORIGINAL_DOC = """
trust/legacy/deploy_chain.py

Compiles trust/ReputationRegistry.sol and deploys it. Two modes:

  dev      in-process EthereumTesterProvider. No network, no gas cost,
           instant. Use this for every attack-scenario run and for the
           thesis demo itself, so the defense is not hostage to a public
           testnet's uptime.
  testnet  a real RPC endpoint (Polygon Amoy, or any EVM chain you point
           it at), signed with a private key from DLTF_CHAIN_PRIVKEY. Run
           this ONCE to get a real, public, independently-verifiable
           deployment + tx hash for the thesis writeup.

Usage:
  PYTHONPATH=. python3 -m trust.legacy.deploy_chain --mode dev
  PYTHONPATH=. python3 -m trust.legacy.deploy_chain --mode testnet \\
      --rpc https://rpc-amoy.polygon.technology --out build/registry_amoy.json

Never commit DLTF_CHAIN_PRIVKEY or build/registry_testnet.json's private
material; only the deployed address/abi need to be shared.
"""
import argparse
import json
import os

# Imported lazily inside compile_contract() so the refusal in main()
# is reachable even where solcx is not installed.

CONTRACT_PATH = os.path.join(os.path.dirname(__file__), "ReputationRegistry.sol")
SOLC_VERSION = "0.8.20"


def compile_contract():
    import solcx
    installed = solcx.get_installed_solc_versions()
    if not any(str(v) == SOLC_VERSION for v in installed):
        solcx.install_solc(SOLC_VERSION, show_progress=False)
    with open(CONTRACT_PATH) as f:
        source = f.read()
    compiled = solcx.compile_source(
        source, output_values=["abi", "bin"], solc_version=SOLC_VERSION)
    _, contract_interface = compiled.popitem()
    return contract_interface["abi"], contract_interface["bin"]


def deploy_dev(w3, abi, bytecode):
    sender = w3.eth.accounts[0]
    Registry = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Registry.constructor().transact({"from": sender})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.contractAddress, sender


def deploy_testnet(w3, privkey, abi, bytecode):
    acct = w3.eth.account.from_key(privkey)
    sender = acct.address
    Registry = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = Registry.constructor().build_transaction({
        "from": sender,
        "nonce": w3.eth.get_transaction_count(sender),
        "gas": 3_000_000,
        "gasPrice": w3.eth.gas_price,
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt.contractAddress, sender, tx_hash.hex()


def main():
    if "--i-know-this-is-the-legacy-contract" not in sys.argv:
        raise SystemExit(
            "trust/legacy/deploy_chain.py deploys ReputationRegistry.sol, NOT "
            "DLTFRegistry.sol.\n"
            "Deploying it to a testnet spends faucet funds on the wrong "
            "bytecode.\n\n"
            "Use:\n"
            "  export DLTF_CHAIN_PRIVKEY=0x<funded test key>\n"
            "  PYTHONPATH=. python3 -m chain.deploy --network amoy \\\n"
            "      --rpc-url https://rpc-amoy.polygon.technology\n\n"
            "If you really want the legacy contract, pass "
            "--i-know-this-is-the-legacy-contract.")
    sys.argv = [a for a in sys.argv
                if a != "--i-know-this-is-the-legacy-contract"]
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["dev", "testnet"], default="dev")
    ap.add_argument("--rpc", default=os.environ.get("DLTF_CHAIN_RPC"))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    abi, bytecode = compile_contract()
    print(f"\u2713 compiled ReputationRegistry.sol with solc {SOLC_VERSION}")

    if args.mode == "dev":
        from web3 import Web3, EthereumTesterProvider
        w3 = Web3(EthereumTesterProvider())
        address, sender = deploy_dev(w3, abi, bytecode)
        out = args.out or "build/registry_dev.json"
        tx_hash = None
    else:
        if not args.rpc:
            raise SystemExit("--rpc or DLTF_CHAIN_RPC is required for testnet mode")
        privkey = os.environ.get("DLTF_CHAIN_PRIVKEY")
        if not privkey:
            raise SystemExit("set DLTF_CHAIN_PRIVKEY in the environment (never commit it)")
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(args.rpc))
        if not w3.is_connected():
            raise SystemExit(f"could not reach RPC endpoint {args.rpc}")
        address, sender, tx_hash = deploy_testnet(w3, privkey, abi, bytecode)
        out = args.out or "build/registry_testnet.json"

    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        json.dump({"address": address, "abi": abi, "sender": sender,
                   "deploy_tx": tx_hash}, f)

    print(f"\u2713 deployed ReputationRegistry at {address}")
    if tx_hash:
        print(f"\u2713 deployment tx: {tx_hash}")
    print(f"\u2713 address + abi written to {out}")


if __name__ == "__main__":
    main()
