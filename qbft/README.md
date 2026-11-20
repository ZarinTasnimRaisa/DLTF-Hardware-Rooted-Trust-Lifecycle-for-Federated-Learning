# Four-validator QBFT: what it proves and how to run it

> **STATUS UPDATE (2026-11-17, from the 2026-09-11 run logs).** The network
> ran. Experiment 2b (`--manual-stall`, real quorum loss by stopping besu-3 +
> besu-4) completed twice: sync healthy ~14.4 s/round, first stalled round
> 188.9 s, async healthy ~115–136 ms/round; after restore, 6 devices rebuilt
> from 78 chain events, 0 discrepancies. Experiment 2c preflight (writer and
> non-writer keys): **18 passed, 1 failed** — `UnauthorizedWriter` was refused
> by consensus, deploy gas 2,085,425 reproduced exactly, `commitBatch(4)` =
> 168,069, `classifySigned` = 46,613. **The 1 failure is an open bug:**
> `head_hash()` raises `ExtraDataLengthError` on Besu's 327-byte POA
> `extraData` — inject web3's `geth_poa_middleware` in `chain/evm.py` before
> re-running. 2a (confirmation latency) and 2d (reorg null result) have no
> archived logs — treat as not yet run. Original banner below is historical.

**These files are untested.** They are standard Besu boilerplate and I am
reasonably confident in them, but I had no Docker or Besu available, so nothing
here has been executed end to end. `verify.sh` exists because the two commonest
failure modes both look like success — treat its output, not the exit code of
`docker compose up`, as evidence the network is real.

---

## Why this stage and not another sweep

The paper's L3 level claims a contract revert is "sound against the operator,
for enumerated transitions." Today the revert is executed by a process you
started, running bytecode you compiled, on a machine you own. A reviewer asking
"could the operator have written a `BanToActive` transition?" gets "no, the
bytecode reverts" — but the operator executes the bytecode. Nothing in the
evidence distinguishes *a contract that refuses* from *an operator who reports
that it refused*.

What is actually demonstrated today is enforcement against an implementation
bug: your own server code cannot accidentally emit an illegal transition. Worth
having. Not what L3 claims.

Under QBFT with four validators, the transaction goes to four nodes, each
executes it independently against its own copy of state, and a block needs
2f+1 = 3 signatures to commit. To land an illegal transition the operator must
now corrupt three of four independently-run nodes. The refusal stops being an
assertion by the operator and becomes a property of a protocol the operator
does not control.

That substitution is the whole point of this directory.

---

## Setup

```bash
cd qbft
./setup.sh 0xDEPLOYER 0xNONWRITER          # both get funded in genesis
export DLTF_BOOTNODE=$(cat bootnode.txt)
docker compose up -d
./verify.sh                                 # do not skip this
```

`0xNONWRITER` is not optional. Experiment 2c submits a legal-looking write from
an unauthorised account and shows four nodes refuse it. An unfunded non-writer
fails with "insufficient funds" instead of `UnauthorizedWriter`, which proves
nothing.

Then deploy and record the block:

```bash
export DLTF_CHAIN_PRIVKEY=0x<deployer key>
PYTHONPATH=. python3 -m chain.deploy --network qbft \
    --rpc-url http://127.0.0.1:8545
# note the printed DLTF_DEPLOY_BLOCK
```

---

## The four experiments

### 2a — Confirmation latency under consensus

The paper reports 0.206–0.984 ms of ledger overhead from an in-process
interpreter and honestly says those timings do not transfer. Replace them.

Measure submission-to-inclusion and inclusion-to-finality separately, and
report **median and p95, not the mean** — block times are not normally
distributed and a mean will be dragged by the tail you actually care about.
Set `blockperiodseconds` to 5 before measuring: a 2-second chain is convenient
and nobody deploys one, so the distribution would describe the test rig.

### 2b — The availability claim, against a chain that can genuinely stall

```bash
PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \
    --address 0x... --deploy-block N --manual-stall --clients 6 --rounds 12
```

`--manual-stall` pauses and tells you when to run `docker compose stop node3
node4` and when to start them again, so the outage is a real loss of quorum
rather than a stall injected at the Python boundary.

Run `docker compose stop node4` first and confirm blocks continue. A network
that stalls at f = 1 is misconfigured, not fault-tolerant, and reporting the
two-node outage without the one-node tolerance would present a broken setup as
a result.

Expect the injected-stall numbers from the local run to be **wrong**, probably
optimistic: an injected failure raises immediately at the Python boundary,
while a real pending transaction burns the full poll timeout inside web3. The
real numbers win.

### 2c — Enforcement by consensus rather than by your node

Two submissions, both expected to revert:

1. An illegal transition (un-ban a device) from the **authorised** writer.
2. A legal-looking write from the **non-writer** account.

`chain/testnet_preflight.py` already exercises both paths, so the code works;
what changes here is who refuses. Record the revert **name** for each —
`BanToActive`, `UnauthorizedWriter` — not just that it failed. The
status-0 re-simulation added to `chain/evm.py` is what makes the name
recoverable when a public chain mines a failed transaction.

### 2d — Reorg behaviour

QBFT has immediate finality, so this is a null result, and null results are
worth one sentence when they bound something. State that finality is immediate
under QBFT and that a probabilistic-finality chain would require the
reconciliation logic to handle orphaned round summaries, which it currently
does not. Do **not** claim this from Sepolia, where it is false.

Note: Besu's QBFT may not answer the `finalized` block tag. Use `latest` and
say finality is immediate; `head_hash(block="finalized")` exists for
probabilistic chains.

---

## Known interactions with the new code

**Priority-fee floor.** `chain/signer.py` floors the priority fee at 2 gwei by
default and 30 gwei on Polygon chain ids. On a private chain with
`--min-gas-price=1000000000` that is fine, and the genesis allocation is large
enough that it does not matter. If you switch to a free-gas chain, pass
`priority_floor=0` — but prefer keeping the fee market live, because it is the
same code path Amoy and Sepolia exercise and it is what
`exp_economics.py` reads.

**Deploy block.** `eth_getLogs` is bounded by it. On a private chain starting
from genesis this matters less than on a public one, but set it anyway so the
two configurations behave identically.

**Gas should match Table 4 exactly.** Same bytecode, same calldata, same EVM
version. If it does not, `cancunTime` is wrong in the genesis, and that is a
configuration bug wearing the costume of a measurement finding.

---

## What this still does not establish

Say all of it plainly. A paper that names its boundary precisely reads stronger
than one that implies it has none.

- **Four validators in Docker on one host are not four organisations.** The
  consensus mechanism is real; the mutual distrust is simulated. You have
  demonstrated that the enforcement path runs under Byzantine agreement, not
  that it was agreed to by parties with conflicting interests. One clause in
  Limitations, and it costs you nothing to say.
- **Six to fifty clients is not deployment scale.**
- **Two physical TPMs is not a hardware study.**
- **A stealthy directed-deviation attack from a legitimately enrolled device
  still defeats the design**, and no amount of deployment touches that. It is
  architectural.
