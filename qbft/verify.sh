#!/usr/bin/env bash
#
# Prove the network is what you think it is BEFORE running any experiment.
#
# This exists because the two commonest QBFT failures both look like success:
#
#   1. Four containers are up, but only one is in the validator set, so you
#      have a single-validator chain wearing four containers. Every result you
#      then produce is the result you already had, and the caveat you deleted
#      was true after all.
#
#   2. The nodes never peered, so blocks stop at 0 while every RPC answers
#      normally. That looks like a stall and is a misconfiguration.
#
# Neither shows up as an error. Both must be checked positively.
set -euo pipefail
RPC="${1:-http://127.0.0.1:8545}"

rpc() { curl -s -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":${2:-[]},\"id\":1}" \
        "$RPC" | jq -r "${3:-.result}"; }

echo "endpoint : $RPC"
echo "chain id : $(rpc eth_chainId)"

echo
echo "== validator set =="
VALS=$(rpc qbft_getValidatorsByBlockNumber '["latest"]')
N=$(echo "$VALS" | jq 'length' 2>/dev/null || echo 0)
echo "$VALS" | jq -r '.[]' 2>/dev/null | sed 's/^/  /'
if [ "$N" -ne 4 ]; then
  echo "  !! $N validators, expected 4."
  echo "     A chain with one validator is the chain you already had. Do not"
  echo "     run experiments against it and do not delete the multi-validator"
  echo "     caveat on the strength of it."
  exit 1
fi
echo "  OK: 4 validators, f = 1"

echo
echo "== peering =="
PEERS=$(rpc net_peerCount)
echo "  node1 peers: $PEERS (expect 0x3)"
[ "$PEERS" = "0x3" ] || echo "  !! not fully peered -- blocks will not advance"

echo
echo "== liveness =="
B1=$(rpc eth_blockNumber); sleep 6; B2=$(rpc eth_blockNumber)
echo "  block $B1 -> $B2"
if [ "$B1" = "$B2" ]; then
  echo "  !! height frozen. The chain is not producing blocks."
  exit 1
fi
echo "  OK: producing blocks"

echo
echo "== fee market =="
BASE=$(rpc eth_getBlockByNumber '["latest",false]' '.result.baseFeePerGas')
echo "  baseFeePerGas: $BASE"
if [ "$BASE" = "null" ] || [ "$BASE" = "0x0" ]; then
  echo "  !! zero/absent base fee. chain/signer.py will take the legacy"
  echo "     gasPrice path, and effectiveGasPrice will be meaningless, so"
  echo "     exp_economics.py has nothing real to read. This also stops"
  echo "     matching the code path Amoy and Sepolia exercise."
fi

echo
echo "== BYZANTINE TOLERANCE (the property being claimed) =="
echo "  Stop ONE validator: 3 of 4 remain, quorum (2f+1 = 3) holds, blocks"
echo "  continue. This is f = 1 tolerance, demonstrated."
echo "    docker compose stop node4 && sleep 10 && $0 $RPC"
echo
echo "  Stop TWO: 2 of 4 remain, quorum is lost, the chain accepts"
echo "  transactions and mines none. This is the liveness experiment's"
echo "  condition."
echo "    docker compose stop node3 node4"
echo
echo "  Run BOTH. The first is what makes the second meaningful: a network"
echo "  that stalls at f = 1 is broken, not fault-tolerant, and reporting the"
echo "  outage without the tolerance would describe a misconfiguration as a"
echo "  result."
