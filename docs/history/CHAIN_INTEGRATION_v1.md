> **RETIRED (2026-11-17) - DO NOT FOLLOW THESE INSTRUCTIONS.** This is the v1 push-model addon guide (ReputationRegistry.sol + chain_bridge). It instructs running trust/deploy_chain.py, which deploys the WRONG contract and now refuses to run. The v1 code was moved to trust/legacy/ (imports patched). The current system is the DLTFRegistry enforcement layer: chain/README.md, root RUNBOOK.md. Historical value: the restart-persistence whitewash demo narrative and the honest off-chain scope list.

# Blockchain integration: what this adds and how to run it

## Files in this addon
```
trust/chain_bridge.py    ChainReputationEngine - drop-in for ReputationEngine
trust/deploy_chain.py    compiles + deploys trust/ReputationRegistry.sol
trust/demo_whitewash.py  real attack scenario, chain-backed, + whitewash proof
audit/hashchain.py       gap-fill: referenced by fl/server.py and run_server.py
                         but was not in the reviewed zip; drop your real one
                         in instead if you have it elsewhere
requirements-chain.txt   web3, py-solc-x
```
Unzip into your project root (same level as `trust/`, `fl/`, `audit/`).
`trust/ReputationRegistry.sol` already exists in your repo and is used as-is,
unchanged.

## Why nothing else needed to change
`fl/server.py` already takes `reputation_engine=` as a constructor arg (you
use this for the additive/beta ablation). `ChainReputationEngine` implements
the exact same public surface your code calls elsewhere (`register`,
`record_event`, `reinstate`, `get_status`, `get_weight`, `get_all_weights`,
`get_opinion`, `rank`, `banned_ek_hashes`) so `trust/probation.py` and
`fl/server.py`'s round loop work with zero edits. Detection (`trust/filter.py`)
is untouched — it feeds severities into `record_event` exactly as before.

## Install
```
pip install -r requirements-chain.txt --break-system-packages
```

## 1. Dev mode (use this for the demo and all attack runs)
```
PYTHONPATH=. python3 -m trust.deploy_chain --mode dev
PYTHONPATH=. python3 -m trust.chain_bridge        # bridge self-test
PYTHONPATH=. python3 -m trust.demo_whitewash      # full attack + whitewash proof
```
`demo_whitewash.py` runs a real "poison" attacker through your actual
`fl/server.py` round loop with `eval/scenarios.py`'s `SyntheticWorld`, gets it
banned via the chain-backed engine, then attempts to re-enroll the SAME
hardware EK under a new `device_label` and proves the contract rejects it —
then simulates a full server restart and proves the ban still holds against
the same deployed contract.

## 2. One real public deployment (for the thesis writeup / defense)
```
export DLTF_CHAIN_RPC=https://rpc-amoy.polygon.technology
export DLTF_CHAIN_PRIVKEY=0x...        # a funded Amoy testnet key, NEVER commit this
PYTHONPATH=. python3 -m trust.deploy_chain --mode testnet --out build/registry_amoy.json
```
Gives you a real contract address + deployment tx hash on a public testnet,
independently checkable on a block explorer. Reconnect a live run to it with
`trust.chain_bridge.load_registry(w3, "build/registry_amoy.json")` instead of
redeploying.

## Wiring into your real server (`run_server.py`)
```python
from web3 import Web3
from trust.chain_bridge import ChainReputationEngine, load_registry

w3 = Web3(Web3.HTTPProvider(rpc_url))          # or EthereumTesterProvider() for dev
contract, sender = load_registry(w3, "build/registry_dev.json")
engine = ChainReputationEngine(w3, contract, sender)
server = FederatedServer(initial, ca_bundle_pem=ca_pem,
                         reputation_engine=engine, audit=HashChain(...))
```

## What "prevents whitewash on the blockchain" concretely means here
- `ReputationRegistry.sol`'s `bannedEk` mapping is keyed by EK hash, not
  `device_id`, and lives on-chain, not in this process.
- `register()` in the contract re-checks `bannedEk` on every new device_id;
  a banned EK comes back `Status.Banned` immediately, before that identity
  ever gets a nonzero aggregation weight or trains a single round.
- Because the ledger is on-chain, a server restart does not forget a ban —
  this directly closes the "in-memory engine state (restart = re-enroll)"
  item in your own Known Limitations section.
- `isEkBanned(ekHash)` is a public view function: anyone with the contract
  address can verify a ban independently of trusting your server's word,
  which is the actual "transparency" property worth putting in the thesis
  (as opposed to just "we wrote it to a chain").

## What's still off-chain, stated plainly for your limitations section
- The contract does not compute reputation (by design, per your own v3
  docstring in the .sol file) — it stores what the Python engine already
  proved correct via `trust/test_parity.py`. If you extend parity testing to
  the live attack scenarios (not just the golden ones), that closes the loop:
  add a small assertion loop in `demo_whitewash.py` that recomputes
  `trust = (1e6 + s) / (2e6 + s + f)` from `s, f` fetched off the
  `ReputationPushed` event log and compares it to the chain's stored value.
- Opinion `(b, d, u, a)` and `rank()` are not on-chain state (the contract
  only emits `s, f` in events, doesn't store them queryably) — currently
  served from the local engine copy. State this as a scope boundary, not a
  bug: recomputing them from the event log is possible and is exactly what
  `test_parity.py` already demonstrates works.
- Gas: `pushReputations` (plural, batch) exists in the contract already for
  one-tx-per-round instead of one-tx-per-event if you deploy to a real
  testnet and want to report per-round gas cost in the thesis.
