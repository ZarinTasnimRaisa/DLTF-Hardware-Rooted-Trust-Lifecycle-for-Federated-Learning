# CLAUDE.md — DLTF deployment, session handoff

Paste this as the first message of a new chat, with the attachments listed in
§0. Everything below is the state at the end of the previous session.

> **STATUS UPDATE (2026-11-17).** (1) The repo is now on GitHub
> (TafsirFaiyaz/DLTF) and was consolidated: v1 chain code moved to
> `trust/legacy/`, the canonical contract is `contracts/src/DLTFRegistry.sol`
> (flat copies in `chain/` removed), docs merged (see `docs/INDEX.md`).
> (2) The QBFT stage was PARTIALLY EXECUTED on 2026-09-11: 2b manual-stall
> liveness completed twice; 2c preflight 18/19 — the one failure is
> `head_hash()` on Besu POA `extraData` (needs `geth_poa_middleware` in
> `chain/evm.py`). Fix that first. Details: `RUNBOOK.md` §11,
> `MASTER_CONTEXT.md` §15.6, `qbft/README.md` status banner.

---

## 0. Files to attach

**Minimum viable set — attach these five and nothing else if you are short on
context budget:**

| File | Why |
|---|---|
| the whole repo (git clone or a fresh zip) | Everything. If you can attach one thing, attach this. |
| `dltf_nsyss.tex` | The paper. Every change has to be justified against it. |
| `RUNBOOK.md` | What changed last session and why (§11: the QBFT runs) |
| `qbft/README.md` | The next phase, and what it proves (status banner: what already ran) |
| `liveness_summary.txt` | The one new experimental result (in `results/chain/`) |

**If you cannot attach the zip**, attach these individually. The repo layout is
in §2; run everything from the repo root.

Changed or new last session (attach all of these — the versions in the zip may
be stale if you have not re-zipped):

```
chain/signer.py              NEW  local signing, nonces, EIP-1559, safe polling
chain/async_writer.py        NEW  background write queue
chain/testnet_preflight.py   NEW  19 checks, run before spending faucet funds
chain/evm.py                 MOD  send path, selectors, chunked logs, commit layer
chain/registry.py            MOD  guarded reads, guarded report(), async wiring
chain/deploy.py              MOD  key-signed deploy, no unlocked accounts needed
chain/wiring.py              MOD  threads the new options through
config.py                    MOD  env overrides for rpc/network/deploy block
eval/run_local.py            MOD  --rpc, --network, --async-chain
eval/exp_liveness.py         NEW  experiment 2b
eval/exp_economics.py        NEW  phase 4
trust/legacy/deploy_chain.py MOD  now refuses to run (deploys the WRONG contract)
qbft/*                       NEW  4-validator Besu setup (ran 2026-09-11, see banner)
```

Needed for context but unchanged:

```
contracts/src/DLTFRegistry.sol the contract — attach it, several claims depend on it
chain/backend.py             Backend interface, Reason enum
chain/commit.py              CommitMockBackend, SigningCommitAgent, grad_hash
chain/mock.py                MockBackend (the parity reference)
chain/reconcile.py           rebuild_engine
eval/chain_eval.py           evm_stack, run_federation, build_handles
```

Results produced last session:

```
liveness_summary.txt   liveness_rounds.csv   economics.csv
```

**Do not bother attaching:** `fl/`, `trust/reputation.py`, `trust/probation.py`,
`tpm/`, the figure PDFs, or the older CSVs, unless the task touches them. None
of the remaining work does.

---

## 1. The prompt to paste

> I am deploying a federated-learning trust framework (DLTF) to a real
> blockchain and writing the results into a conference paper. Read the attached
> files, especially `CLAUDE.md` and `RUNBOOK.md`, before answering.
>
> Last session closed the implementation blockers and produced two new results.
> What remains is the deployment itself, in this order: Anvil, public testnet,
> four-validator Besu QBFT. §6 below has the exact next step.
>
> How I want you to work:
> - **Verify, do not assume.** Read the actual file before writing code
>   against it. Several bugs in this project came from guessing an interface.
> - **Compile or execute before claiming something works.** Last session every
>   claim was backed by a passing run; hold that standard.
> - **Be skeptical of good results.** If a number looks clean, ask what else
>   would produce it. A previous run reported a large margin that turned out to
>   be an artifact of the stopping round; an ablation returned a null result
>   because a stronger code path pre-empted the mechanism being ablated.
> - **Tell me when a result is bad.** Negative findings go in the paper.
> - **Own errors plainly** and say what the consequence was.

---

## 2. What the system is

DLTF is a trust layer between clients and the aggregator of a federated
learning system. Client identities bind to TPM 2.0 Endorsement Keys, sanctions
key on a hash of that key so they survive re-registration, and a Solidity
registry refuses illegal trust-state transitions so the ban ledger is
verifiable by a party that does not trust the server operator.

The central claim is not better detection. It is that the **consequence** of
detection is made durable, so exclusion costs the excluded party a certified
TPM.

```
chain/     evm.py, mock.py, registry.py, reconcile.py, commit.py, signer.py,
           async_writer.py, wiring.py, deploy.py, testnet_preflight.py
contracts/ src/DLTFRegistry.sol + Foundry test suites (canonical contract home)
fl/        server.py client.py aggregator.py model.py dataset.py
trust/     reputation.py probation.py filter.py  (+ legacy/ — v1, do not use)
tpm/       common.py client.py
audit/     hashchain.py
eval/      chain_eval.py run_local.py exp_*.py
qbft/      4-validator Besu setup (partially executed 2026-09-11)
```

Run from the repo root as `PYTHONPATH=. python3 -m <module>`.
A venv exists at `./venv` (matplotlib 3.11.1, numpy 2.5.1); an older venv path
may still be exported in the shell.

**Paper:** ACM `sigconf`, NSysS, hard 6–8 page limit including references.
Currently exactly 8 pages, zero warnings, 19 references, 4 tables, 2 figures.
Anything added must displace something. Build with `latexmk -pdf`, and
**delete `dltf.bib` first** — it is embedded via `filecontents`, which will not
overwrite an existing file, so a stale bib silently survives. `acmart.cls` must
be v2.19.

---

## 3. Established before last session

- 55/55 contract tests passing. Objectives O1–O4 each have a measured result.
- Trust layer to 50 clients, zero honest sanctions at every size.
- Poisoning comparison reproduced on a real 409k-parameter CNN over non-IID
  MNIST. The layer composes in front of FedAvg, trimmed mean and Krum from one
  unmodified weight dictionary, restoring Krum from 0.053 to 0.637.
- Gas affine in federation size: 58,281 + 38,818n per round, R² = 1.000000.
- Known and disclosed: detection takes 11.3 rounds on real gradients against 1
  on synthetic; under a ×10 scaling attack the layer recovers in 2 seeds of 3
  and loses the model in the third.

---

## 4. What last session did

All of it was executed, not asserted. Every self-test in `chain/` passes,
including the three parity suites, against eth-tester with an **external funded
key** — locally signed raw transactions, the path a real endpoint requires. The
original self-tests used a node-held account, which is why they passed for
months while local signing did not exist.

### 4.1 Blockers closed

- **No local signing existed.** `_send` used `eth_sendTransaction`, which only
  Anvil, Hardhat and eth-tester implement. Every write on a public RPC would
  have failed, and failed misleadingly as `node unreachable`.
- **`trust/legacy/deploy_chain.py --mode testnet` deploys the WRONG CONTRACT** —
  `ReputationRegistry.sol`, not `DLTFRegistry.sol`. Different solc, no
  `--via-ir`, no custom errors, no commitment layer. The old `DEPLOYMENT.md`
  pointed at it. It now refuses to run.
- **Nothing could be pointed at a remote endpoint.** Hard-coded localhost RPC,
  no `--rpc` flag, and `network="localhost"` everywhere.

### 4.2 Correctness fixes

- **The resend bug.** `_send` retried on any non-revert exception, and the
  commonest on a public chain is a poll timeout on a transaction that *was*
  broadcast. The retry rebuilt it at a fresh nonce, so both could land and
  `classify` would apply the reputation rule twice — silently. That would have
  falsified the parity result ("every deviation is exactly zero"). Now the hash
  is computed before broadcast and a stuck transaction is replaced at the
  **same** nonce.
- Revert names recovered from mined status-0 receipts via `eth_call` replay
  (was collapsing to `UnknownRevert`, which destroys the 2c result).
- `Error(string)` and `Panic(uint256)` added to the selector table — Solidity
  does not emit them as ABI entries, so both were misfiled as transport and
  retried.
- `eth_getLogs` chunked from the deploy block (was `from_block=0` × 14).
- `head_hash()` raises instead of returning 32 zero bytes.

### 4.3 Two pre-existing `ChainRegistry` bugs, found by the liveness experiment

- `report()` raised during exactly the outage it existed to report on.
- A round lost to an outage was counted in **neither** `anchored_rounds` nor
  `unanchored_rounds`, because unguarded `get_device()` reads aborted the flush
  before the bookkeeping line. Your own instrumentation under-reported every
  outage.

### 4.4 Commitment layer wired (Phase 3 closed)

`bind_wallet`, `commit_gradient`, `commit_batch`, `classify_signed`,
`get_commit`, `get_wallet`, `mark_absent`, `report_commit_mismatch`.

| Path | Gas |
|---|---|
| `commitBatch(4)` | 168,081 (42,020/client) |
| `classifySigned` | 46,647 |
| `classify` + amortised batch | 80,268 |

Signed path is 42% cheaper. Anti-fabrication enforced on chain
(`MissingCommit`); a forged signature rejects the whole batch atomically
(`SignerNotDeviceWallet`), leaving the valid half unwritten.

### 4.5 Experiment 2b — split verdict, and the split IS the result

**Stall injected at the backend, not by killing validators.** So this is a
valid test of the server's behaviour under ledger failure, **not** a test of a
multi-validator chain.

- **Structural: holds.** Every round completed, models identical sync vs async.
- **Wall clock: did not hold.** Per-round mean, healthy → stalled:
  sync 409 → 2002 ms (~5×); async 61 → 1003 ms. Under a realistic 120 s poll
  timeout the sync case becomes tens of minutes per round. A ledger whose
  removal makes rounds an order of magnitude faster is on the critical path.
- **Backlog collateral — the novel finding.** The async writer carries a
  backlog *into* the outage, so writes issued while the chain was healthy are
  destroyed by it. Measured at queue depth 17, three writes including an
  `ENROLL` were lost, and chain-only reconciliation then failed
  (`enrolled locally but absent on chain: ['h3']`). Sync loses only the rounds
  overlapping the outage; async loses a window as wide as the queue.

### 4.6 Phase 4 — economics

At 30 gwei, POL = USD 0.42: 30-round federation costs USD 0.169 / 0.316 / 0.756
at 10 / 20 / 50 clients. Deployment USD 0.026 one-off. A HARDWARE attacker's 8
modules (Table 3) at USD 15 each = USD 120, so **the attack costs ~380× the
ledger that sanctions it**. Prices are supplied, never fetched;
`--price-date` is mandatory.

### 4.7 Three corrections for the paper

- **Gas depends on device-label length.** `"g"` = 95,332; `"d0"` = 95,344.
  Twelve gas = one calldata byte moving from non-zero (16) to zero (4), because
  `deviceId` is a `string`. The affine fit is quoted for your label lengths.
- **The 50-client projection is off by six gas.** Paper says 1,999,175;
  58,281 + 38,818×50 = 1,999,181. Projection used unrounded coefficients.
- **`chain/deploy.py --self-test` had been failing.** `load_abi()` ignored the
  module-level `ABI_PATH` the test overrode, so the "missing artifacts" guard
  was unreachable. Check whether that suite was in the 55 counted as passing.

---

## 5. What is NOT true yet

**The Limitations sentence stays exactly as written:**
> "evaluated on a local development node, so this demonstrates enforcement
> behaviour, not the trust properties of a multi-validator deployment."

Nothing has run against a chain with more than one validator. Everything in
§4.1–4.4 is capability, not deployment result. `eth-tester` mines instantly, so
**no code here has ever seen a pending transaction.**

Also still true, and should stay in the paper: six to fifty clients is not
deployment scale; two physical TPMs is not a hardware study; and a stealthy
directed-deviation attack from a legitimately enrolled device still defeats the
design, regardless of where the ledger runs.

**Caution on the async numbers:** `chain/async_writer.py` is new code from last
session. If you report the async row, say the mechanism is new and report the
backlog collateral beside it. A 16× improvement from a component introduced in
the same session is exactly the shape of thing that turns out to be measuring
itself.

---

## 6. Next steps, in order

### Step 1 — Anvil (free, half a day). START HERE.

```bash
anvil --block-time 12     # real mempool; nothing has seen a pending tx
anvil --no-mining         # accepts writes, never mines — the QBFT-below-quorum condition
PYTHONPATH=. python3 -m chain.testnet_preflight        # 19 checks, must pass first
PYTHONPATH=. python3 -m chain.deploy --network localhost
PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \
    --address 0x... --clients 6 --rounds 12
```

Expect the §4.5 wall-clock numbers to be **wrong, probably optimistic**: an
injected failure raises immediately at the Python boundary, a real pending
transaction burns the full poll timeout inside web3. The real numbers win.
Nothing from this step goes in the paper.

### Step 2 — Public testnet (half a day)

Sepolia over Amoy: Amoy's public RPC is aggressively rate-limited and its
25 gwei minimum priority fee is a failure class you do not need. Deploy, verify
source, run one short federation, record address + tx hash + verified-source
link + gas actually charged.

Buys: one sentence in Availability. Does **not** delete the caveat. Do not
claim the reorg null result from Sepolia — it has probabilistic finality and
`reconcile.py` does not handle orphaned round summaries.

### Step 3 — Four-validator QBFT (2–3 days). THE ONE THAT MATTERS.

See `qbft/README.md`. **The files ran on 2026-09-11** (2b liveness twice,
2c preflight 18/19) — but `head_hash()` fails on Besu POA `extraData`; inject
`geth_poa_middleware` in `chain/evm.py` and re-run preflight before anything
else. 2a and 2d are still unrun.

Run `qbft/verify.sh` before any experiment. Two failure modes both look like
success: four containers with only one validator in the set (a single-validator
chain wearing four containers), and nodes that never peered (height frozen at 0
while every RPC answers). Also run `docker compose stop node4` first and
confirm blocks continue — a network that stalls at f = 1 is broken, and
reporting the two-node outage without the one-node tolerance presents a
misconfiguration as a result.

Then: 2a confirmation latency (median and p95, `blockperiodseconds` 5), 2b
liveness with `--manual-stall`, 2c enforcement by consensus (needs a **second
funded key** for the non-writer), 2d reorg null result.

Most likely time-waster: gas not matching Table 4, which means `cancunTime` is
wrong in the genesis — a configuration bug wearing the costume of a measurement
finding.

### Step 4 — Paper (1 day)

Delete: the multi-validator caveat; "the in-process backend's gas figures are
those the contract produces anywhere; its timings are not"; the commitment-layer
paragraph; two of three future-work items.

Add, in order of value: (1) the availability claim split into structural and
wall-clock, three sentences — this is the strongest new material and it
validates an architectural claim rather than a parameter; (2) contract address
in Availability; (3) commitment-layer cost, two sentences plus a Table 4 row;
(4) confirmation latency median and p95; (5) cost in currency, one sentence.

Budget: the paper is at exactly 8 pages. The deletions above free roughly what
the additions need. If forced to choose, keep the liveness result and the
contract address; latency can go in a table caption.

---

## 7. Realistic value

The previous estimate was 9 → 9.5 for the full week.

- **In the paper now: ~+0.15.** Commitment layer closes a stated gap; economics
  answers a question no reference answers. Both honest, neither a headline.
- **After steps 1–3: +0.4 to +0.5.** That is where the caveat dies and
  enforcement moves from "one node running bytecode you deployed" to "a
  protocol you do not control refused it."

Protect step 3 over everything else.

Ceiling, and say it in one clause: four validators in Docker on one host is
consensus in mechanism, not in threat model. You will have shown the
enforcement path runs under Byzantine agreement, not that it was agreed to by
parties with conflicting interests.

---

## 8. First thing to ask the new chat

> Read `RUNBOOK.md` and `qbft/README.md`, then check `qbft/setup.sh`,
> `qbft/docker-compose.yml` and `qbft/qbft-config.json` against current Besu
> documentation — they were written without Besu available and have never been
> run. Tell me what is wrong before I spend a day on it.
