# DLTF deployment: what changed, what to run, what to write

All code here was executed, not asserted. Every self-test in `chain/` passes,
including the three parity suites, against eth-tester with an **external funded
key** — that is, through locally signed raw transactions, the path a real
endpoint requires. The original self-tests used a node-held account, which is
why they passed for months while local signing did not exist.

---

## 1. Files

**New**

| File | What it is |
|---|---|
| `chain/signer.py` | Local transaction signing, nonce management, EIP-1559 fees, safe receipt polling |
| `chain/async_writer.py` | Single-threaded FIFO write queue, so a stalled chain cannot extend a round |
| `chain/testnet_preflight.py` | 19 checks covering every real-chain path. **Run before spending faucet funds** |
| `eval/exp_liveness.py` | Experiment 2b: stall the chain mid-run, measure what training pays |
| `eval/exp_economics.py` | Phase 4: the gas model in currency at a stated price and date |

**Changed**: `chain/evm.py`, `chain/deploy.py`, `chain/registry.py`,
`chain/wiring.py`, `config.py`, `eval/run_local.py`, `trust/deploy_chain.py`
(moved to `trust/legacy/` in the 2026-11-17 cleanup).

---

## 2. Blockers, now closed

**Local signing.** `_send` called `fn.transact({"from": addr})`, i.e.
`eth_sendTransaction`. Anvil, Hardhat and eth-tester implement it; no public
RPC does. Every write would have failed, and failed misleadingly: the error
text contained no revert data, so it was classified as transport, retried three
times, and reported as `node unreachable` about a node answering every read.
`chain/signer.py` signs locally; `EvmBackend.connect(private_key=...)` or
`DLTF_CHAIN_PRIVKEY` switches it on. Without a key, `wiring.py` now prints an
explicit warning rather than letting you discover it on chain.

**The wrong contract.** `trust/legacy/deploy_chain.py --mode testnet` compiles
`ReputationRegistry.sol` — solc 0.8.20, no `--via-ir`, no-arg constructor, no
custom errors, no commitment layer. It is not `DLTFRegistry.sol`. Following
`DEPLOYMENT.md`'s Phase 1 would have put the wrong bytecode on Amoy and spent
faucet funds doing it. That script now refuses to run and names the correct
command. `chain/deploy.py` deploys the right contract and now works without
unlocked accounts (it previously did `w3.eth.accounts[0]`, which is `IndexError`
on a public RPC).

**Nothing could be pointed at a remote endpoint.** `config.CHAIN["rpc_url"]`
was a hard-coded localhost string; `run_local.py` had no `--rpc`; and
`build_audit` defaulted `network="localhost"`, so a contract deployed as `amoy`
was invisible even after a successful deployment. All three are now
configurable by flag and by environment.

---

## 3. Correctness fixes

**The resend bug — the one that would have corrupted your parity result.**
`_send` retried the whole operation on any non-revert exception. The commonest
such exception on a public chain is a poll timeout on a transaction that *was*
broadcast and simply is not mined. The retry rebuilt it at a fresh nonce, so
both copies could land, and `classify` would apply the reputation rule twice —
silently, because nothing raises. The on-chain packed word would diverge from
the local engine and "every deviation is exactly zero" would be false. Now: the
hash is computed from the signed bytes *before* broadcast, so a lost RPC
response is recoverable by lookup; a stuck transaction is replaced at the *same*
nonce, which the chain can include at most once.

**Revert names were lost where you need them most.** A mined `status == 0`
receipt raised `ChainRejection("UnknownRevert")` with the name discarded. That
is the path a public chain takes when estimation passed and state moved before
inclusion — and experiment 2c is supposed to show *which* rule refused. Now the
call is re-simulated with `eth_call` at its own block to recover the custom
error. Verified: a forced status-0 receipt re-simulates to
`EkAlreadyRegistered`.

**Two standard selectors were missing.** Solidity does not emit `Error(string)`
or `Panic(uint256)` as ABI error entries, so a `require`-with-string or an
arithmetic panic decoded to `None`, was misfiled as transport, and was retried
three times before being reported as an outage. Both added by hand.

**A loose regex read tx hashes as revert data.** `_extract_revert_data` matched
any 8+ character hex run in an exception message. Public provider errors embed
transaction hashes constantly. Now gated on the message actually describing a
revert.

**`eth_getLogs` would have been refused.** `get_logs(from_block=0)`, once per
entry in `EVENT_NAME_MAP` — fourteen full-chain scans. Providers cap the span
and several reject genesis-to-latest outright. Now chunked from the recorded
deploy block, halving the span when a provider complains. `snapshot()` does one
log pass instead of three.

**`head_hash()` fabricated a head.** It swallowed every exception and returned
32 zero bytes — the one place the module violated its own stated rule that a
path must never report success when nothing reached the node. It now raises;
`head_hash_or_null()` exists for reporting paths that must not.

---

## 4. Two bugs the liveness experiment found

Both pre-existing, both in `ChainRegistry`, both invisible until the chain
could actually stall.

**`report()` crashed during exactly the outage it was meant to report on.**
`head_hash()` and `last_round()` were unguarded, so a run in which training
correctly survived a dead chain ended in a traceback at the reporting step —
reading as a failure of the very claim it had just demonstrated. Now returns
`None` and `chain_reachable: False`.

**A round lost to an outage was counted in neither `anchored_rounds` nor
`unanchored_rounds`.** `_flush_round` performed unguarded `backend.get_device()`
reads before each inferred classify. During a stall the first read raised, the
flush aborted before the bookkeeping line, and `append()`'s broad handler
recorded the failure with `round_id=None`. Training survived, but `report()`
undercounted the outage — the rounds simply vanished. Reads are now guarded like
writes, a round always lands in exactly one set, and a `_reads_down` latch stops
the flush probing a chain that has already proved unreachable, so a round pays
one timeout instead of *n*.

---

## 5. The commitment layer is wired (Phase 3 closed)

`bind_wallet`, `commit_gradient`, `commit_batch`, `classify_signed`,
`get_commit`, `get_wallet`, `mark_absent`, `report_commit_mismatch` — mirroring
`CommitMockBackend` method-for-method. Measured against deployed bytecode:

| Path | Gas |
|---|---|
| `commitBatch(4)` | 168,081 (42,020 per client) |
| `classifySigned` | 46,647 |
| `classify` + amortised batch | 80,268 |

So the signed path is **42% cheaper** than commit-then-classify. The
anti-fabrication rule is enforced on chain: a device that did not commit cannot
be classified (`MissingCommit`), and a forged signature rejects the whole batch
atomically with `SignerNotDeviceWallet`, leaving the valid half unwritten.

One asymmetry against the mock that cannot be closed: `GradientCommitted` is
indexed on `keccak(deviceId)`, so the event carries `device_key`, not the label.
The payload exposes `device_key` and omits `device` rather than inventing a
value.

---

## 6. Experiment 2b, and its honest result

`python3 -m eval.exp_liveness --clients 4 --rounds 10 --stall-at 4 --restore-at 7`

The claim splits in two, and the split *is* the result.

**Structural — holds.** Every round completed, no round was skipped, and the
sync and async runs produced identical models. `_guard` swallows rejections and
transport failures, so this was already true; the experiment confirms it rather
than discovering it.

**Wall clock — did not hold.** Per-round, ms:

| phase | sync mean | async mean |
|---|---|---|
| healthy | 409 | 61 |
| stalled | 2002 | 1003 |

Synchronously, a stalled chain makes a round ~5× slower. That is with a 1 s
stall model; on a real network the poll timeout is 120 s, so a 6-client round
takes tens of minutes. **A ledger whose removal makes rounds an order of
magnitude faster is not off the critical path.** The design claim is about the
async row; the sync row is what the paper's implementation actually did.

**The async writer is not free, and this is the finding I'd protect.** Moving
writes off the training thread carries a *backlog* into the outage: writes
submitted while the chain was healthy are executed after it has failed. Measured
at queue depth 17, three writes — including one `ENROLL` — were destroyed
despite having been issued before the stall, and chain-only reconciliation then
failed with `enrolled locally but absent on chain: ['h3']`. Losing a device's
enrolment is worse than losing three rounds of classifications. Synchronous
writes fail only for rounds that overlap the outage; asynchronous writes fail
for a window as wide as the backlog. That is a deployment parameter, not a
constant, and the paper should say so.

Use `--stall-mode hang` (the default). `refuse` flatters the design: fast
failures barely register in the wall clock, and a QBFT network below quorum
*accepts* transactions into its pool and never mines them, which is `hang`.
`--manual-stall` pauses so you can stop real validators instead.

---

## 7. Phase 4, economics

`python3 -m eval.exp_economics --gas-price 30 --token-price 0.42 --token POL --price-date 2026-08-31`

At 30 gwei with POL at USD 0.42:

| clients | gas/round | USD/round | USD / 30-round federation |
|---|---|---|---|
| 10 | 446,461 | 0.0056 | 0.169 |
| 20 | 834,641 | 0.0105 | 0.316 |
| 50 | 1,999,181 | 0.0252 | 0.756 |

Deployment is a one-off USD 0.026. The comparison the paper cannot currently
make: a 30-round federation at n=20 costs USD 0.32, while the HARDWARE
attacker's 8 certified modules (Table 3) cost about USD 120 — **the attack costs
~380× what it costs to run the ledger that sanctions it.** That ratio is the
economic argument stated in one currency on both sides, and it moves with two
markets, so quote the date.

Prices are supplied, never fetched: a number scraped at run time makes the
result irreproducible six months later. `--price-date` is mandatory.

---

## 8. Three findings for the paper

**Gas depends on device-label length.** Registering `"g"` costs 95,332;
`"d0"` costs 95,344. Twelve gas — exactly one calldata byte moving from non-zero
(16) to zero (4), because `deviceId` is a `string` argument. Table 4's caption
is correct as written ("deterministic given identical bytecode and calldata"),
but the affine fit is quoted for the label lengths your harness used, not for
any label. One clause, not a caveat.

**The 50-client projection is off by six gas.** The paper says 1,999,175;
58,281 + 38,818×50 = 1,999,181. You quoted the projection from unrounded fit
coefficients while printing rounded ones. Either recompute from the printed
constants or say the projection uses the unrounded fit.

**`chain/deploy.py --self-test` had been failing.** `load_abi()` re-ran
`find_artifacts()` and ignored the module-level `ABI_PATH` the test overrode, so
the "missing artifacts, here is the solc command" guard was unreachable and the
assertion could never pass. Fixed both sides. Worth checking whether that suite
was in whatever you counted as 55 passing tests.

---

## 9. Order of work

```bash
# 0. free, finds nearly everything
PYTHONPATH=. python3 -m chain.testnet_preflight

# 1. still free: pending transactions and a chain that never mines
anvil --block-time 12   &   # confirmation latency, mempool path
anvil --no-mining       &   # a chain that accepts writes and stalls
PYTHONPATH=. python3 -m chain.deploy --network localhost
PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \
    --address 0x... --clients 6 --rounds 12

# 2. public testnet
# NOTE: CLAUDE.md §6 Step 2 recommends Sepolia over Amoy (Amoy rate-limits
# aggressively; 25 gwei minimum priority fee). Commands below show Amoy as
# originally run; substitute sepolia + its RPC if following the recommendation.
export DLTF_CHAIN_PRIVKEY=0x<funded TEST key>     # never a real key
PYTHONPATH=. python3 -m chain.deploy --network amoy \
    --rpc-url https://rpc-amoy.polygon.technology
# note the printed DLTF_DEPLOY_BLOCK — every eth_getLogs is bounded by it
forge verify-contract <address> contracts/src/DLTFRegistry.sol:DLTFRegistry \
    --chain amoy --watch

export DLTF_CHAIN=node DLTF_CHAIN_RPC=https://rpc-amoy.polygon.technology
export DLTF_CHAIN_NETWORK=amoy DLTF_DEPLOY_BLOCK=<block>
PYTHONPATH=. python3 -m eval.run_local --clients 6 --rounds 10 --chain node

# 3. QBFT, four validators, then the experiment that matters
PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \
    --address 0x... --manual-stall --clients 6 --rounds 12

# 4. economics, with the prices and date you can defend
PYTHONPATH=. python3 -m eval.exp_economics --gas-price <g> \
    --token-price <p> --price-date <YYYY-MM-DD>
```

`eth-tester` mines instantly, so nothing verified here exercises a transaction
that sits pending. Step 1 costs nothing and covers most of what remains.

---

## 10. What is still not true

The commitment layer is now measured, the multi-validator caveat is closable,
and the liveness claim has a real result. None of that touches the rest:

- Six to fifty clients is not deployment scale.
- Two physical TPMs is not a hardware study.
- A stealthy directed-deviation attack from a legitimately enrolled device
  still defeats the design.
- And now: the wall-clock cost of a synchronous ledger write is a property of
  the implementation you evaluated. If you report the async numbers, say the
  async writer is new, and report the backlog collateral beside them.

---

## 11. Addendum — the QBFT runs of 2026-09-11 (added 2026-11-17)

After this runbook was written, the 4-validator Besu network ran. From the
archived logs (full detail in `MASTER_CONTEXT.md` §15.6):

- **2b liveness, `--manual-stall`, real quorum loss** (stop besu-3+besu-4),
  completed twice. Sync: healthy ~14.4 s/round; first stalled round 188.9 s
  (full poll timeout — the injected-stall numbers above were indeed
  optimistic); later stalled rounds ~14–16 s (the `_reads_down` latch);
  restored ~14.4 s. Async: healthy ~115–136 ms/round. After restore: 6
  devices rebuilt from 78 events, 0 discrepancies.
- **2c preflight, writer + non-writer keys: 18 passed, 1 failed.**
  `UnauthorizedWriter` refused by consensus; deploy gas 2,085,425 reproduced
  exactly through the signed path; `commitBatch(4)` = 168,069;
  `classifySigned` = 46,613; forged commitment rejected atomically.
- **Open bug (the 1 failure):** `head_hash()` raises `ExtraDataLengthError`
  on Besu — POA `extraData` is 327 bytes; web3 needs `geth_poa_middleware`
  injected in `chain/evm.py`. Fix before re-running preflight or spending
  faucet funds.
- 2a (confirmation latency) and 2d (reorg null result): no archived logs —
  treat as not yet run.
