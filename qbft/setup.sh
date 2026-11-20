#!/usr/bin/env bash
#
# Generate a 4-validator QBFT network and lay it out for docker-compose.
#
# UNTESTED IN THIS FORM. It is standard Besu boilerplate, but nobody has run
# it end to end, so verify each step rather than trusting the exit code.
#
#   ./setup.sh 0xYOUR_DEPLOYER_ADDR 0xYOUR_NONWRITER_ADDR
#
# Requires: besu on PATH (or use the docker image, see README), jq, docker.
set -euo pipefail

DEPLOYER="${1:?pass the deployer address -- becomes the contracts IMMUTABLE writer}"
NONWRITER="${2:?pass a second address -- experiment 2c needs a funded NON-writer}"

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/networkFiles"
BAL='0x200000000000000000000000000000000000000000000000000000000000000'

if [ -d "$OUT" ]; then
  echo "!! $OUT already exists. Deleting it destroys the chains identity:"
  echo "   the validator keys are IN there, and regenerating them produces a"
  echo "   different validator set, so the existing chain data becomes"
  echo "   unreadable. Move it aside rather than overwriting."
  exit 1
fi

# ---- 1. genesis with both accounts funded -----------------------------------
# The deployer needs gas; the non-writer needs gas to have its write REFUSED,
# which is the point of 2c. An unfunded non-writer fails for the wrong reason
# (insufficient funds, not UnauthorizedWriter) and proves nothing.
jq --arg d "${DEPLOYER#0x}" --arg n "${NONWRITER#0x}" --arg b "$BAL" '
  .genesis.alloc = {($d): {balance: $b}, ($n): {balance: $b}}
' "$HERE/qbft-config.json" > "$HERE/.qbft-config.resolved.json"

echo "==> generating 4 validator keys and genesis"
besu operator generate-blockchain-config \
    --config-file="$HERE/.qbft-config.resolved.json" \
    --to="$OUT" \
    --private-key-file-name=key

# ---- 2. lay the keys out as node1..node4 ------------------------------------
i=1
for d in "$OUT"/keys/*/; do
  mkdir -p "$HERE/node$i/data"
  cp "$d/key"     "$HERE/node$i/data/key"
  cp "$d/key.pub" "$HERE/node$i/data/key.pub"
  echo "    node$i  validator $(basename "$d")"
  i=$((i+1))
done
cp "$OUT/genesis.json" "$HERE/genesis.json"

# ---- 3. bootnode enode -------------------------------------------------------
# Every other node dials node1. Without this the four nodes never find each
# other, produce no blocks, and the symptom is a chain that answers every RPC
# and has a block height frozen at 0 -- which looks like a stall and is not.
PUB=$(sed 's/^0x//' "$HERE/node1/data/key.pub")
echo "enode://${PUB}@node1:30303" > "$HERE/bootnode.txt"

cat <<EOF

==> done

  genesis      : $HERE/genesis.json
  bootnode     : $(cat "$HERE/bootnode.txt")
  validators   : node1..node4
  funded       : $DEPLOYER (deployer / writer)
                 $NONWRITER (non-writer, for experiment 2c)

Next:
  docker compose up -d
  ./verify.sh

KEEP networkFiles/ . The validator keys are the chains identity; regenerating
them gives you a different validator set and orphans all existing chain data.
EOF
