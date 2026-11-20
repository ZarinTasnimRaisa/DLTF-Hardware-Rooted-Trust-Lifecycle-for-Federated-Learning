# DLTF Chain Layer

An optional on-chain trust registry that enforces the DLTF trust-lifecycle
rules independently of the FL server. It is **off by default**; enabling it
never removes a guarantee, only adds one.

> Updated 2026-11-17: all modules below are built and tested; the commitment
> layer is wired end to end; local signing, the async writer and the testnet
> preflight were added in the September 2026 phase (root `RUNBOOK.md`,
> `MASTER_CONTEXT.md` §15). The canonical contract lives in
> `contracts/src/DLTFRegistry.sol` — the old flat copies in `chain/` were
> removed.

## What this layer guarantees

Six things the server cannot do while this layer is enabled:

| Rule | Enforced by |
|---|---|
| A **BANNED** device cannot become **ACTIVE** by any path | `BanToActive` custom error |
| A device's **tier** cannot change after enrollment | `TierMutation` |
| A reputation delta outside the published rule | Structural — no delta API surface |
| A duplicate or out-of-order **round id** | `DuplicateRound`, `StaleRound` |
| Re-enrolling a **registered EK** under a different device | `EkAlreadyRegistered` |
| Any write from **non-server** address | `UnauthorizedWriter` |

Every rule has a corresponding revert test in `chain/evm_parity_test.py` and
`contracts/test/DLTFRegistryRules.t.sol`. The commitment layer adds
`MissingCommit` (no commit → no classification) and `SignerNotDeviceWallet`
(forged signature rejects the whole batch atomically), tested in
`chain/commit_parity_test.py`, `chain/batch_parity_test.py` and
`contracts/test/DLTFRegistryCommit.t.sol`.

## What this layer does NOT guarantee

Documented up front so nobody has to ask at defense:

* **Truthfulness of classifications.** A compromised server key can still
  emit `MAJOR` against an honest client (T26). The contract constrains the
  transition rule given a classification, not the classification itself.
  Mitigating this requires multi-party classification consensus or ZK proofs
  of update validity; out of scope.
* **Decentralisation.** A local Hardhat/Anvil node has no consensus
  properties. The 4-validator Besu QBFT stage (`qbft/`) exercises enforcement
  under Byzantine agreement, but four Docker validators on one host are not
  four organisations — consensus in mechanism, not in threat model.
* **Long-term storage.** Immutable ledgers conflict with GDPR-style
  erasure. The `ek_hmac` layer (HMAC-SHA256 of the EK hash under a
  federation-scoped key) mitigates the fingerprinting risk but does not
  provide erasure. If the federation key is destroyed, existing `ek_hmac`s
  become unlinkable to any physical machine — the closest approximation to
  erasure the design supports. The federation key MUST be independent of
  `audit.jsonl.key`.

## Mode-selection table

The three axes (TPM identity × transport × chain) are independent. All
combinations work; these are the ones that matter:

| TPM | Transport | Chain | Command | Purpose |
|---|---|---|---|---|
| mock | in-process | off | `python3 run_local.py --clients 6 --rounds 20` | Sweeps, CI, iteration |
| mock | in-process | mock | `python3 run_local.py --chain mock --clients 6 --rounds 20` | Rejection tests, restart demo, reconciliation |
| mock | in-process | node | `python3 run_local.py --chain node --clients 6 --rounds 20` | Gas / latency measurement, scale tests |
| real | HTTP | off | `python3 run_server.py --rounds 15` | Hardware validation without chain overhead |
| real | HTTP | node | `python3 run_server.py --chain node --rounds 15` | The thesis demo |

`--require-commit` adds the commitment layer (needs `--chain mock|node`;
fails loudly otherwise). `DLTF_CHAIN_ASYNC=1` moves writes to a background
queue — report its numbers WITH the backlog collateral (RUNBOOK §6).

## Copy-pasteable commands

### CI / self-tests

```bash
PYTHONPATH=. python3 -m trust.reputation      # 16 checks
PYTHONPATH=. python3 -m chain.fixedpoint      # 14 checks
PYTHONPATH=. python3 -m chain.keys            # 11 checks
PYTHONPATH=. python3 -m chain.backend         #  5 checks
PYTHONPATH=. python3 -m chain.mock            # 20 checks
PYTHONPATH=. python3 -m chain.registry        # 14 checks
PYTHONPATH=. python3 -m chain.verifier        # 11 checks
PYTHONPATH=. python3 -m chain.reconcile       # 16 checks
PYTHONPATH=. python3 -m chain.wiring          # 10 checks
```

### Deployed-contract parity (needs solc 0.8.24, --via-ir)

```bash
# Compile once (or: cd contracts && forge build)
solc --optimize --optimize-runs 200 --via-ir --bin --abi --overwrite \
     -o contracts/out contracts/src/DLTFRegistry.sol

PYTHONPATH=. python3 -m chain.evm_parity_test     # 15 checks
PYTHONPATH=. python3 -m chain.commit_parity_test  # 17 checks
PYTHONPATH=. python3 -m chain.batch_parity_test   # 21 checks
```

### With a live node (Hardhat or Anvil)

```bash
# Terminal 1 (server machine)
anvil                                          # or: npx hardhat node
# Terminal 2
PYTHONPATH=. python3 -m chain.deploy --network localhost
```

Note: the on-chain node **must** be bound to `localhost` on the server
machine only. The server is the only writer; exposing the node to the
tailnet would let a client attempt to write directly (the contract's
`onlyServer` modifier would refuse it, but the exposure is unnecessary).

For a REAL endpoint: `DLTF_CHAIN_PRIVKEY` enables local signing (public RPCs
do not implement `eth_sendTransaction`); run
`PYTHONPATH=. python3 -m chain.testnet_preflight` (19 checks) before spending
faucet funds. Known open bug: `head_hash()` fails on Besu POA `extraData`
(327 bytes) — needs `geth_poa_middleware`; see MASTER_CONTEXT §15.6.

### With Foundry (independent verification)

```bash
cd contracts && forge test -vvv
```

The Foundry suites (`DLTFRegistryRules.t.sol`, `DLTFRegistryCommit.t.sol`)
are an independent verification path. The Python harness is authoritative
for spec compliance because it runs the same contract from the same code
path Python uses in production.

## Fixed-point arithmetic (why it agrees bit-for-bit)

The reputation rule in `trust/reputation.py` uses floats. Solidity has no
floats. `chain/fixedpoint.py` mirrors the float engine using integer
arithmetic at `SCALE = 10⁶`, chosen so that every constant is exactly
representable (`THETA = 400_000`, `TAU = 600_000`, thresholds all with
small denominators).

Only one operation truncates: `decay(x) = (9 * x) // 10`. Solidity's `/`
on `uint256` is floor; Python's `//` on non-negative `int` is floor.
They agree by construction, not approximately.

Threshold checks are done by cross-multiplication (`(1 + s) * SCALE
<= t * (2 + s + f)`), which is exact. The reinstatement floor
`need_s = 3f + 2` is exact because θ_r = 0.75 gives the integer ratio 3.

**Provable bound**: `|T_float − T_fixed| ≤ 5×10⁻⁶` (derived in
`docs/history/LATEX_CHANGES.md` Part F.2: recurrence e′ ≤ 0.9e + 1, fixed
point 10 units, |∂T/∂s| ≤ ¼). Measured over 80,000 random events across all
three tiers: **zero status decisions differ**.

## Storage cost

One packed 256-bit slot per device: `s` (64) + `f` (64) + `cleanRun`
(16) + `majorRun` (16) + `status` (8) + `tier` (8) + `lastRound` (32) =
**208 bits declared**, with 48 bits reserved. One **warm** `SSTORE` per
device per round. (Measured `bit_length()` varies with the last round
written — quote the declared layout, not the incidental measurement.)

Measured gas (solc 0.8.24, optimizer 200, via-IR, deployed bytecode):

| Operation | Gas |
|---|---:|
| Deploy contract | 2,085,425 |
| `register` (fresh device) | 95,344 |
| `register` (banned EK → whitewash) | 27,358 |
| `classify NEUTRAL` (warm) | 36,186 |
| `classify MINOR / MAJOR` (warm) | 35,961 / 36,046 |
| `classify CRITICAL → BAN` | 62,075 |
| `roundSummary` | 91,367 |
| `bindWallet` | 71,630 |
| `commitGradient` (CLIENT pays) | 51,653 |
| `commitBatch(4)` | 168,081 (42,020/client) |
| `classifySigned` | 46,647 |
| `classify` + amortised batch | 80,268 |

Cold-vs-warm matters: a cold classify slot costs ~261 gas more than warm
(36,332 vs 36,593 in the pre-commitment measurement). Gas depends on
device-label length (+12 gas per non-zero calldata byte: `"g"` 95,332 vs
`"d0"` 95,344). **Cost model:** `round_gas ≈ 58,281 + 38,818 × clients`,
R² = 1.000000 (slope exact; intercept ±5 gas from calldata variation).
The signed path is 42% cheaper than commit-then-classify. In currency at
30 gwei / POL $0.42 (2026-08-31): a 30-round federation costs USD 0.169 /
0.316 / 0.756 at 10 / 20 / 50 clients (`eval/exp_economics.py`).

## Availability & degradation

Chain failures never halt training: a rejection, RPC timeout or any
exception is recorded with reason and detail, the round is marked
`UNANCHORED`, and training continues. At enrollment the layer fails
**open** against a cached snapshot of the ban list — failing closed would
hand any attacker who can DoS the node a federation-wide enrollment DoS.
The staleness window is a documented limitation.

**The wall-clock nuance (measured, RUNBOOK §6):** *structural* survival
holds, but synchronous writes ARE on the wall-clock critical path — a
stalled chain made rounds ~5× slower in the injected-stall experiment, and
the first stalled round on real QBFT burned ~189 s. The async writer
(`chain/async_writer.py`) removes ledger work from the round (~115–136 ms
healthy rounds on QBFT) but carries a backlog INTO an outage: writes issued
while healthy can be destroyed by it (measured: an ENROLL lost at queue
depth 17). Report async numbers with that collateral.

## File map (all built and tested)

```
chain/
  fixedpoint.py        — integer arithmetic (mirror of trust/reputation.py)
  backend.py           — abstract Backend API + Event + ChainRejection
  mock.py              — deterministic in-memory Backend (CI, rule testing)
  keys.py              — FederationKey: HMAC-SHA256 EK privacy layer
  registry.py          — HashChain-compatible adapter (drops into audit=)
  verifier.py          — third-party recomputation from events alone
  commit.py            — gradient commitment + EIP-712 batch signing
  reconcile.py         — rebuild ReputationEngine state at startup (N23)
  wiring.py            — --chain flag -> audit object (both run scripts)
  evm.py               — web3.py live-node backend, locally signed txs
  deploy.py            — deployment script + chain/deployed.json
  signer.py            — local signing, nonces, EIP-1559 fees, safe polling
  async_writer.py      — background FIFO write queue
  testnet_preflight.py — 19 checks before spending faucet funds
  evm_parity_test.py   — deployed-contract parity (base)
  commit_parity_test.py— deployed-contract parity (commitment)
  batch_parity_test.py — deployed-contract parity (batch signing)

contracts/
  src/DLTFRegistry.sol           — the contract (canonical)
  test/DLTFRegistryRules.t.sol   — trust-state rejection rules (N18–N22)
  test/DLTFRegistryCommit.t.sol  — commitment layer (N24–N28)
  foundry.toml                   — solc 0.8.24 pinned, via_ir, lint exclusion
  lib/forge-std/                 — vendored
  out/                           — build artifacts (generated, gitignored)
```
