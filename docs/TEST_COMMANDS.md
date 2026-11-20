# TEST_COMMANDS.md — Every Command, What It Tests, What The Output Means

Answering your question first: **no, not everything is tested yet.** What you
have run covers SIM completely. What remains is REAL mode, the live node, and
the commitment layer — and one of those was a genuine gap I just closed.

Tiers below are ordered by how much they prove per minute spent.

| Tier | Covers | Your status |
|---|---|---|
| 0 | environment sanity | ⚠ verify the chain PNGs |
| 1 | behaviour, with negative controls | ✅ 41/41 |
| 2 | does it run | ✅ 8/8 + 9/9 |
| 3 | contract vs spec, two languages | ✅ 34 + 53 |
| 4 | SIM demos | ✅ baseline + restart demo |
| 5 | Chapter 4 / 5 evidence | ✅ but confirm figures exist |
| 6 | **commitment layer end to end** | ❌ **new, see §6** |
| 7 | **REAL mode, 3 machines** | ❌ never run |
| 8 | **live Anvil node** | ❌ never run |

---

# TIER 0 — Environment sanity

## 0.1 Are numpy and matplotlib from the same place?

```bash
python3 -c "
import matplotlib; print('matplotlib', matplotlib.__file__)
import numpy;      print('numpy     ', numpy.__file__)"
```

**Tests:** whether your venv is leaking system packages.

**Both paths must contain `venv/`.** If either shows
`/usr/lib/python3/dist-packages` or `.local`, you have two NumPy ABIs in one
interpreter — the exact cause of `figures skipped (numpy.core.multiarray failed
to import)`.

**Why this matters:** that failure is **silent**. `chain_eval.py` catches the
ImportError, prints one line, and still reports `CHAIN EVAL GREEN`. Your CSVs
were fine; the PNGs simply never existed.

## 0.2 Did the figures actually render?

```bash
ls -la results/figures/*.png results/chain/*.png
```

**Expect 8 in `results/figures/` and 5 in `results/chain/`.**

Your `make_figures` run printed ✓ for all 8, so those exist. But **you have not
re-run `chain_eval` since the numpy error**, so `results/chain/` is probably
still empty of PNGs. Re-run Tier 5.2.

## 0.3 Toolchain present

```bash
python3 --version && solc --version | tail -1 && forge --version | head -1
```

Expect Python 3.10+, `0.8.24+commit.e11b9ed9`, `forge Version: 1.x`.

---

# TIER 1 — Does it behave as intended?

## 1.1 The falsification harness

```bash
PYTHONPATH=. python3 tools/prove_it_works.py
```

**Tests:** 10 behavioural properties, each paired with a negative control that
must fail. ~60 s.

**Expect:** `41 checks passed, 0 failed` → `✓ SYSTEM BEHAVES AS INTENDED`

**What it means:** this is the only suite that can distinguish "works" from
"passes vacuously". "Attackers were banned" also passes if *everything* is
banned — check 1's control catches that. "0 discrepancies" also passes if the
verifier always returns OK — check 7 corrupts the chain and confirms it notices.

**The line to quote:**
```
TAMPER 2: a0.status: recomputed=2 on_chain=0
```
`recomputed=2` is BANNED from replaying events; `on_chain=0` is ACTIVE, the
corrupted value. A third party who does not trust the server detects a silent
un-ban.

**If a control passes when it should fail:** that check is meaningless and the
harness says so explicitly. Read which one.

---

# TIER 2 — Does everything run?

## 2.1 Whole stack

```bash
PYTHONPATH=. python3 tests/test_pipeline.py
```

**Tests:** 13 module self-tests, 4 compile-only, HTTP end-to-end, whitewash
smoke, and 4 chain groups.

**Expect:** `✓ PIPELINE GREEN` (8 groups).

**Group meanings:**

| Group | Proves |
|---|---|
| `module_selftests` | every module's own assertions hold |
| `compile_only` | torch/CLI files parse (they run machine-side) |
| `end_to_end_http_with_audit` | real sockets: enroll, ban, whitewash, chain reload |
| `eval_whitewash_smoke` | DLTF blocks re-registration, baseline does not |
| `chain_off_is_inert` | chain off builds nothing → Ch.4 stays reproducible |
| `chain_selftests` | 9 chain modules |
| `chain_integration` | delegates to 2.2 |
| `chain_evm_selftests` | 4 suites against real EVM bytecode |

## 2.2 Chain wiring

```bash
PYTHONPATH=. python3 tests/test_chain_integration.py
```

**Expect:** `✓ CHAIN INTEGRATION GREEN` (9 groups).

**The five lines that are your thesis:**

```
✓ identical trajectories with chain off vs mock (6 rounds)
      -> the chain does not alter training; Ch.4 results carry over unchanged
✓ no raw EK hash appears anywhere in the chain event log
      -> N22 privacy
✓ rebuild: 6 devices, trust preserved within 5e-6, a0 still BANNED
      -> N23, bans survive restart
✓ node down: 3 rounds continued, UNANCHORED (15 failures, 0 rejections)
      -> N24, never on the critical path
✓ ENFORCEMENT: the contract reverted the resurrection write (BanToActive)
               -- not a Python check, an EVM revert
      -> N21, the single most important line in your test output
```

**On `15 failures, 0 rejections`:** failures are transport (node unreachable);
rejections are the contract refusing an illegal write. Conflating them would be
a silent integrity bug. 15 = 3 rounds × 5 clients.

---

# TIER 3 — Does the contract match the spec?

Two independent implementations. If both agree, a bug in one harness cannot hide.

## 3.1 Python, against deployed bytecode

```bash
PYTHONPATH=. python3 -m chain.evm_parity_test        # 15 checks
PYTHONPATH=. python3 -m chain.commit_parity_test     # 17
PYTHONPATH=. python3 -m chain.batch_parity_test      # 21
```

**Tests:** the Solidity contract's behaviour against `chain/mock.py`'s
specification, bit-for-bit on the packed 256-bit device word after every write.

**Expect:** `✓ all EVM parity tests passed -- contract matches mock spec`

**What it means:** the fixed-point integer mirror in Solidity produces the same
state as the Python reference. `|T_float − T_fixed| ≤ 5e-6`, zero status
divergence.

## 3.2 Solidity-native

```bash
cd contracts && forge test -vv && cd ..
```

**Expect:** `Compiling 20 files` (contract + forge-std) then
`34 passed; 0 failed`.

Your run now shows exactly that. **If it says `Compiling 1 files` and `No tests
found`**, the `.t.sol` is not in `contracts/test/`.

**Two logs in that output are deliberate findings, not warnings:**

```
[PASS] test_ClassifySigned_NoDuplicateProtectionAcrossProofs
  NOTE: signed path accepts two conflicting proofs for one round
```
The EIP-712 path lacks `commitGradient`'s `DuplicateCommit` guard. The server
cannot *forge* a proof (both carry the client's signature) but an observer sees
conflicting commitments with no on-chain tiebreak. Chapter 5 limitation.

```
[PASS] test_DomainSeparator_BindsChainId
  domain before: 0xc1e87a11...
  domain after chainId change: 0xc1e87a11...
```
Identical, so the separator is **cached at construction**, not recomputed. That
is standard practice (OpenZeppelin does the same) and safe on a chain that does
not fork. Worth a footnote if you discuss cross-chain replay.

---

# TIER 4 — SIM demos

## 4.1 Baseline — the "off by default" guarantee

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --rounds 10
```

**Expect:** weights climbing 0.292 → 0.391, `flags {}` throughout, **no chain
output and no `results/` directory**.

**What it means:** with the chain off the system is byte-identical to the
pre-chain version. This is what keeps your Chapter 4 sweeps reproducible.

## 4.2 Detection and structural exclusion

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 10
```

**Expect:**
```
round  1: flags {'attacker0': 'CRITICAL', 'attacker1': 'CRITICAL'}
round  2: weights {'client0': ..., 'client1': ..., 'client2': ..., 'client3': ...}
```

**What it means:** from round 2 the attackers are **absent from the weights dict
entirely** — structurally excluded, not down-weighted. No aggregator needs
special-casing, which is O4.

## 4.3 Tier 1 — probation reachable

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --tier1 6 --rounds 15
```

**Expect:** `tier HARDWARE` and round-0 weights 0.583 not 0.292 — cap 1.0 rather
than 0.5 on the same trust value.

**Without `--tier1`** every SIM client is Tier 2, `REHAB=False`, and **probation
is unreachable.** Note sybils still ban outright even at Tier 1: CRITICAL is
ungated and bypasses rehab by design. Probation needs a *poisoner*
(sustained MAJOR) — which is what Tier 5.1's rehab experiment measures.

## 4.4 The full demo

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient
```

**The line that proves reconciliation:**
```
round 11: weights {'client0': 0.397, ...}
--- server torn down at round 12 ---
rebuilt from chain: 6 devices (4 active, 0 probation, 2 banned), 58 events replayed
round 12: weights {'client0': 0.4, ...}
```

**0.397 → 0.400.** A wiped engine restarts at **0.292**. Continuity is the proof.

```
WHITEWASH_REJECTED: newclient carries a banned EK (attacker0's)
chain agrees EK is banned: True
VERIFIED: 6 devices, 90 events replayed, 0 discrepancies
```

Both ledgers refuse the return: the rebuilt engine (raw `ek_hash` from the local
log) and the chain (one-way `ek_hmac`).

**On `8 rounds anchored` not 20:** the registry object was recreated at the
restart and counts only rounds 12–19. Correct — have the answer ready.

---

# TIER 5 — Chapter 4 and 5 evidence

## 5.1 Chapter 4 — trust model

```bash
grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/      # landmine check, expect nothing
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
PYTHONPATH=. python3 -m eval.make_figures
```

> Run from the **project root**, not `contracts/`. `PYTHONPATH=.` is relative, so
> from `contracts/` you get `ModuleNotFoundError: No module named 'eval'` —
> exactly what happened in your log before you `cd ../`.

**Expect:** 6 CSVs, `✓ all evaluation checks passed`, 8 figures, and:

```
note: honest FLAG rate 0.0059 (1 flag(s) over 170 honest client-runs).
      No sanction follows from a lone MINOR -- see fig3 caption.
✓ all figure-level assertions passed
```

**What each block proves:**

| Output | Proves |
|---|---|
| `none: baseline 0.691, dltf 0.691` | the defence is **free** when unneeded |
| `poison: 0.520 → 0.685` | 96.5% of attack loss recovered |
| `flag 0.0–1.0, ban 1.0` | attacker window is 1–2 rounds |
| `whitewash 25/25 vs 0/25` | O2, clean separation |
| `per identity 0.462 / 0.201 / 0.040` | O3: influence priced in identities |
| `recovering 5/5, persistent 0/5` | rehabilitation discriminates, perfectly |
| sweep knee at −0.45 | **your answer to "why 0.45?"** |

**On the FPR note:** 1 flag in 170 honest client-runs = 0.6% at the **flag**
level, 0% at the **sanction** level. A lone MINOR takes trust to 0.5525 at worst
— above `PROBATION_T = 0.5`, with `major_run = 0` so M3 does not fire. For a new
client the cold-start gate blocks it outright.

## 5.2 Chapter 5 — chain layer ⚠ re-run this

```bash
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check
ls -la results/chain/*.png                # MUST show 5
```

**Expect:**
```
✓ CHECK parity: 6 configurations, all deviations exactly 0
✓ CHECK storage: per-round gas drift 0.15% (<5%), state is O(devices)
✓ CHECK gas: round_gas = 58,282 + 38,818 x clients, R^2 = 1.000000
✓ CHAIN EVAL GREEN
```

**Which lines must match mine, and which must not:**

| Line | Expect |
|---|---|
| gas fit | **identical to the digit** — gas is deterministic |
| storage drift | ~0.15% |
| reconcile ms | **different** — your CPU |
| latency ms | **different** — your CPU |

Your earlier run already matched the gas fit exactly, which confirms your
contract and solc settings are right.

---

# TIER 6 — Commitment layer end to end ❌ NEW

## The gap I found and closed

`config.CHAIN["require_commit"]` existed but was **never read** by
`wiring.py`, `run_local.py`, or `run_server.py`. A config knob that silently does
nothing. So the commitment layer was verified at contract level (17 + 21 parity
checks, 34 Foundry tests) but had never run inside a live federation.

Now wired:
- `chain/wiring.py` wraps the mock backend in `CommitMockBackend` when asked, and
  for node mode **checks the deployed `requireCommit` matches** — it is immutable
  on chain, so a mismatch raises rather than being ignored.
- `net/handles.py` `LocalClientHandle` accepts `commit_agent` and commits
  **before** `train()` returns, mirroring what `net/agent.py` does over HTTP.
- `run_local.py` gains `--require-commit`: binds a wallet per device via a TPM
  AK signature, then attaches a `CommitAgent`.
- `chain/verifier.py` now knows `WALLET_BOUND` / `GRADIENT_COMMITTED` /
  `COMMIT_PROOF` / `COMMIT_MISMATCH` are non-state events, so replaying them is
  a documented no-op rather than an "unknown event type" failure.

## 6.1 Run it

```bash
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 8 \
    --chain mock --require-commit
```

**Expect:**
```
chain: mock, audit log results/sim_audit.jsonl, commitment layer ON
enrolled client0 ... attacker1
commitment: 5 wallets bound to TPM identities, clients now commit before sending
round  0: ...
round  1: flags {'attacker0': 'CRITICAL', 'attacker1': 'CRITICAL'}
...
chain: 41 mirrored writes, 0 rejections, 0 failures
chain: 8 rounds anchored, 0 unanchored
VERIFIED: 5 devices, 33 events replayed, 0 discrepancies
```

**What it means:**
- `5 wallets bound to TPM identities` — each client proved control of **both**
  the TPM (AK signature over a domain-separated challenge) and the wallet. A
  server cannot bind a wallet it controls to someone else's device.
- Every round now carries `GRADIENT_COMMITTED` events: the client hashed its
  update and recorded the hash **before** transmitting.
- `0 rejections` — no client failed the `MissingCommit` gate.
- `VERIFIED ... 0 discrepancies` — the commitment events do not perturb trust
  replay.

**If you see `unknown event types: ['GRADIENT_COMMITTED', 'WALLET_BOUND']`**, you
have the old `chain/verifier.py`. Copy the supplied one.

## 6.2 The guard rail

```bash
PYTHONPATH=. python3 run_local.py --clients 4 --require-commit
```

**Expect:** `error: --require-commit needs --chain mock|node (there is nowhere
to record commitments with the chain off)`. Failing loudly beats accepting a flag
that cannot work.

---

# TIER 7 — REAL mode ❌ never run

Nothing below has been exercised. This is the largest remaining gap.

## 7.1 Mesh reachability

```bash
tailscale status                          # all three machines
ping -c2 100.70.28.2
curl http://100.70.28.2:8470/health       # {"ok": true, "device": "client1"}
```

> ⚠ Resolve the client2 IP conflict first: MASTER_CONTEXT says `100.73.178.45`,
> `config.py` says `100.64.57.82`. `config.py` is what runs.

## 7.2 Smoke test — no torch, no MNIST

```bash
# each client
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --stub
# server
PYTHONPATH=. python3 run_server.py --rounds 3 --stub --dim 6
```

**Expect:** `tier HARDWARE` for client1/client2. **If `TPM_RESIDENT`**, the cert
chain failed — check the CA bundle has both AMD intermediates (`CN=PRG-RN` *and*
`CN=PRG-SSP`).

**What it proves:** O1. Two physical chips, two distinct EK hashes, both
verified to a manufacturer root.

## 7.3 Real MNIST

```bash
PYTHONPATH=. python3 run_server.py --rounds 10
```

**Expect:** `real MNIST model: 409034 parameters`, then per-round weights.

## 7.4 With the ledger

```bash
PYTHONPATH=. python3 run_server.py --rounds 10 --chain mock
```

**Expect:** weights identical to 7.3, plus `VERIFIED ... 0 discrepancies`.
Identical weights is the point.

## 7.5 Live attack ⚠ needs a third agent

```bash
# THIRD agent on the server box -- add client3 (mock TPM) to config.CLIENTS
PYTHONPATH=. python3 -m net.agent --label client3 --port 8471

# client2 attacks
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470 --attack flip
# server
PYTHONPATH=. python3 run_server.py --rounds 12 --chain mock
```

**Expect:** `client2` flagged MAJOR; two consecutive MAJORs trip M3; being Tier 1
it goes to **PROBATION**, not banned.

> ### With only 2 clients, nothing is detected
>
> Measured: `scale`, `flip`, `sleeper` all return NEUTRAL at n=2. Stage 1
> compares against 2.5× the median of **all** norms including the attacker's,
> and with n=2 the median lands between them: `[1,10] → median 5.5 → ratio 1.82
> < 2.5`. A median needs ≥3 samples. Stage 2's robust reference degenerates to
> one noisy client.
>
> The third agent restores every stage **and** makes the federation mixed-tier,
> so one run shows Tier-1 probation *and* Tier-2 immediate ban on real hardware.
> State the n ≥ 3 requirement in Chapter 6 regardless.

Sybil variant (same seed on both, or stage 3 will not fire):
```bash
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --attack sybil --attack-seed 1337
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470 --attack sybil --attack-seed 1337
```
A **lone** sybil is NEUTRAL by design — collusion is what stage 3 detects.

## 7.6 REAL latency — the only quotable absolute

```bash
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain off  --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain mock --real-rounds 10
```

**Every other latency figure in your thesis is in-process py-evm**, which
over-states EVM execution (pure-Python interpreter) while under-stating transport
(no socket, no block time). Only these cross a real network.

---

# TIER 8 — Live Anvil node ❌ never run

## 8.1 Deploy

```bash
anvil &                                   # keep on localhost
PYTHONPATH=. python3 -m chain.deploy --network localhost
```

**Expect:**
```
✓ deployed at 0x5FbDB2315678afecb367f032d93F642f64180aa3
  gas used   : 2,085,425
  recorded in: chain/deployed.json
```

**Gas must read 2,085,425** — same as every in-process run. That is your
determinism check on a real node.

## 8.2 Run against it

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain node --restart-at 12 --rejoin-as newclient
```

**Expect:** identical output to 4.4, but every write is now a real transaction
and every rejection a real EVM revert. Slower.

## 8.3 With the commitment layer

```bash
PYTHONPATH=. python3 -m chain.deploy --network localhost --require-commit
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 8 \
    --chain node --require-commit
```

`requireCommit` is **immutable** — set at deploy, never changeable. If you pass
`--require-commit` against a contract deployed without it, `wiring.py` raises and
names the redeploy command rather than silently ignoring you.

## 8.4 Degradation — kill the node mid-run

```bash
PYTHONPATH=. python3 run_local.py --clients 4 --rounds 10 --chain node
# in another terminal, ~round 5:  pkill anvil
```

**Expect:** rounds keep running. Final report shows non-zero `failures` and
`unanchored rounds`, but training never stops.

**What it means:** N24. A node outage degrades auditability, not availability.

---

# One-shot regression script

```bash
#!/usr/bin/env bash
set -u
cd "$(dirname "$0")" && source venv/bin/activate
fail=0
run(){ printf "%-46s " "$1"; shift; if "$@" >/tmp/t.log 2>&1; then echo "PASS"; else echo "FAIL"; fail=1; tail -5 /tmp/t.log|sed 's/^/    /'; fi; }

export PYTHONPATH=.
run "behaviour (41 checks)"      python3 tools/prove_it_works.py
run "pipeline (8 groups)"        python3 tests/test_pipeline.py
run "chain integration (9)"      python3 tests/test_chain_integration.py
run "evm parity (15)"            python3 -m chain.evm_parity_test
run "commit parity (17)"         python3 -m chain.commit_parity_test
run "batch parity (21)"          python3 -m chain.batch_parity_test
run "SIM baseline"               python3 run_local.py --clients 6 --rounds 5
run "SIM restart demo"           python3 run_local.py --clients 6 --attackers 2 \
                                   --rounds 20 --chain mock --restart-at 12 \
                                   --rejoin-as newclient
run "SIM commitment layer"       python3 run_local.py --clients 5 --attackers 2 \
                                   --rounds 8 --chain mock --require-commit
( cd contracts && forge test >/tmp/f.log 2>&1 && echo "forge (34)                                     PASS" \
  || { echo "forge (34)                                     FAIL"; fail=1; } )

echo
[ $fail -eq 0 ] && echo "ALL GREEN" || echo "SOMETHING FAILED"
exit $fail
```

Save as `run_all_tests.sh`, `chmod +x`, run before every thesis milestone.

---

# Where you stand

| Tier | Status |
|---|---|
| 0 environment | ⚠ confirm `results/chain/*.png` exist |
| 1 behaviour | ✅ 41/41 |
| 2 runs | ✅ 8/8 + 9/9 |
| 3 contract | ✅ 34 Solidity + 53 Python |
| 4 SIM demos | ✅ |
| 5 Ch.4 / Ch.5 | ✅ Ch.4 done; re-run Ch.5 for the PNGs |
| 6 commitment | ❌ **run 6.1 — newly wired** |
| 7 REAL mode | ❌ needs your 3 machines |
| 8 live node | ❌ needs anvil |

## Do next, in order

```bash
# 1. new: commitment layer end to end (2 min)
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 8 \
    --chain mock --require-commit

# 2. get the 5 missing chain PNGs
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check
ls -la results/chain/*.png

# 3. anvil (10 min)
anvil &
PYTHONPATH=. python3 -m chain.deploy --network localhost
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain node --restart-at 12 --rejoin-as newclient

# 4. REAL mode -- the big one, needs all three machines + a third agent
```

## Housekeeping — ✔ EXECUTED 2026-11-17 (record only, do not re-run)

All items below were completed in the consolidation: `eval/plot_results.py`
deleted and dropped from `COMPILE_ONLY`; v1 moved to `trust/legacy/` (imports
patched); `build/registry_dev.json` moved to `trust/legacy/`; `dsadas/`,
`all files/`, `smartcontract file all/` removed; `chain/reputation.py`
confirmed identical to `trust/reputation.py` and deleted.

```bash
git rm eval/plot_results.py           # byte-identical copy of scenarios.py
# then drop it from COMPILE_ONLY in tests/test_pipeline.py
```

Your own log proves it: `python3 -m eval.plot_results` printed
`eval/scenarios.py self-test`. Same file, wrong name, generates no plots.

```bash
mkdir -p trust/legacy
git mv trust/chain_bridge.py trust/ReputationRegistry.sol trust/deploy_chain.py \
       trust/test_parity.py trust/demo_whitewash.py trust/legacy/
git mv build/registry_dev.json trust/legacy/
rm -rf dsadas/
diff chain/reputation.py trust/reputation.py    # delete the loser
```

## Genuinely untestable here

1. **Public-chain deployment.** Anvil has no consensus, finality, or gas market.
2. **Model checkpointing across restart.** Reconciliation restores trust state,
   not the parameter vector. Orthogonal to the trust claim — state it in Ch. 6.
3. **Revocation.** X.509 path validation is simplified: name chaining plus
   signatures, no CRL/OCSP.

---

## Addendum (2026-11-17): the September suites

Status columns above are historical (Tiers 7/8 and the QBFT stage have since
run at least partially; `chain/deploy.py --self-test` had a silently failing
ABI_PATH bug, now fixed — re-check any count that included it). New commands
to add to the catalogue:

```bash
# Real-chain preflight — 19 checks, run BEFORE spending faucet funds.
# On Besu/QBFT currently 18/19: head_hash() fails on POA extraData
# (geth_poa_middleware needed in chain/evm.py). Fix first.
PYTHONPATH=. python3 -m chain.testnet_preflight

# Experiment 2b — liveness under chain stall (structural vs wall-clock split)
PYTHONPATH=. python3 -m eval.exp_liveness --clients 4 --rounds 10 \
    --stall-at 4 --restore-at 7                     # injected stall (eth-tester)
PYTHONPATH=. python3 -m eval.exp_liveness --rpc http://127.0.0.1:8545 \
    --address 0x... --deploy-block N --manual-stall --clients 6 --rounds 12
# --manual-stall pauses so you can stop REAL validators (QBFT quorum loss).
# --stall-mode hang (default) is honest; refuse flatters the design.

# Phase 4 — economics in currency; prices supplied, never fetched
PYTHONPATH=. python3 -m eval.exp_economics --gas-price 30 \
    --token-price 0.42 --token POL --price-date 2026-08-31

# Commitment gas comparison (A/B/C/D designs)
PYTHONPATH=. python3 -m eval.exp_commit_gas

# Paper-evidence harnesses (see eval/RUNBOOK.md for the plan)
PYTHONPATH=. python3 -m eval.exp_aggregator
PYTHONPATH=. python3 -m eval.exp_tiers
PYTHONPATH=. python3 -m eval.exp_window
PYTHONPATH=. python3 -m eval.exp_engine_sweep
PYTHONPATH=. python3 -m eval.exp_scale
PYTHONPATH=. python3 -m eval.exp_m3
PYTHONPATH=. python3 -m eval.exp_real_mnist
PYTHONPATH=. python3 -m eval.verify_numbers        # CLAIMS reconciliation
```

Expected-output interpretation for the new suites: root `RUNBOOK.md` §§6–8
and `MASTER_CONTEXT.md` §15 (liveness split verdict, backlog collateral,
economics table, label-length gas, projection off-by-six).
