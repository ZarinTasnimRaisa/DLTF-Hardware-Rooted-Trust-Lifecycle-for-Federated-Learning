"""
DLTF topology. Tailscale tailnet (account tpm97510@).
  100.95.144.127 (ubuntu)      -> SERVER  (runs run_server.py; not in CLIENTS)
  100.70.28.2    (s4zz4d HP)   -> client1 (runs net/agent.py)
  100.64.57.82   (tafsir HP)   -> client2 (runs net/agent.py)
"""
import os
MODE = os.environ.get("DLTF_MODE", "real")

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

NUM_CLIENTS = 2

CLIENTS = [
    {
        "device_label": "client1",
        "tpm_backend":  "real",
        "tcti":         "device:/dev/tpmrm0",
        "endpoint":     "http://100.70.28.2:8470",
    },
    {
        "device_label": "client2",
        "tpm_backend":  "real",
        "tcti":         "device:/dev/tpmrm0",
        "endpoint":     "http://100.64.57.82:8470",
    },

 ]

# ---- optional on-chain trust registry ---------------------------------------
# OFF BY DEFAULT. With mode "off" nothing in chain/ is imported and the system
# behaves exactly as it did before the layer existed. This is a hard constraint:
# the sweeps in eval/ and tests/test_pipeline.py must stay reproducible.
#
#   off    no chain. Baseline.
#   mock   chain/mock.py, deterministic in-memory backend. No node needed;
#          this is what CI and the SIM acceptance test use.
#   node   chain/evm.py against a Hardhat or Anvil node at rpc_url.
#
# DLTF_CHAIN overrides mode from the environment so a run can opt in without
# editing this file.
#   rpc_url was hard-coded to localhost with no override, so there was no way
#   to point a run at a testnet or a consortium node short of editing this
#   file. DLTF_CHAIN_RPC now does it, matching DLTF_CHAIN.
#
#   network selects which record chain/deployed.json is read from. It defaulted
#   to "localhost" everywhere, so a contract deployed as "amoy" was invisible
#   to run_local even after a successful deployment.
#
#   deploy_block bounds every eth_getLogs. Left at 0, chain/evm.py scans from
#   genesis, which public providers refuse and which is millions of useless
#   blocks on any real chain. chain/deploy.py prints the value to export.
CHAIN = {
    "mode":                 os.environ.get("DLTF_CHAIN", "off"),
    "rpc_url":              os.environ.get("DLTF_CHAIN_RPC",
                                           "http://127.0.0.1:8545"),
    "network":              os.environ.get("DLTF_CHAIN_NETWORK", "localhost"),
    "contract_address":     os.environ.get("DLTF_CONTRACT_ADDRESS") or None,
    "deploy_block":         int(os.environ.get("DLTF_DEPLOY_BLOCK", 0) or 0),
    "federation_key_path":  "results/federation.key",
    "require_commit":       False,            # commitment layer off by default
    # Writes go through a background thread so a stalled or slow chain cannot
    # block the training round. See chain/async_writer.py. OFF preserves the
    # original synchronous behaviour exactly, which is what the existing
    # parity and latency results were measured under.
    "async_writes":         os.environ.get("DLTF_CHAIN_ASYNC", "0") == "1",
}

# Never read from a file, never logged, never written into deployed.json.
CHAIN_PRIVKEY_ENV = "DLTF_CHAIN_PRIVKEY"

CHAIN_MODES = ("off", "mock", "node")