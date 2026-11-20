# Results Explained — What Each Number Proves

> **CONSOLIDATION NOTICE (2026-11-17).** This is the canonical results
> interpretation. It merges the original `RESULTS_EXPLAINED.md` with the
> evergreen content of two retired docs: `GRAPHS_AND_VERIFICATION.md`
> (figure guidance, negative-control methodology) and
> `TIER_0_6_VERIFICATION.md` (the three non-discrepancies, commitment cost
> table). Both originals are in `docs/history/`. Resolved one-time fix-it
> instructions (venv rebuild, Foundry assembly, housekeeping) were removed —
> they are done; setup lives in `SETUP_GUIDE.md`. September 2026 results are
> summarised in §9 and detailed in root `RUNBOOK.md` / `MASTER_CONTEXT.md` §15.

Four output sets, all green under v3. Chapter 4's data was regenerated under
v3 (the last July blocker, cleared).

---

## 1. `test_pipeline.py` + integration + demo

**8/8 pipeline groups, 9/9 integration groups.** The numbers reproduce to the
digit on different hardware:

| | Reference run | Reproduced |
|---|---|---|
| deploy gas | 2,085,425 | **2,085,425** |
| verifier | 6 devices, 34 events | **identical** |
| long-run reconcile | 30 rounds, 161 events, 7 devices | **identical** |
| restart rebuild | 6 devices (4/0/2), 58 events | **identical** |

That reproducibility is what makes the figures quotable. (The old "No tests
found in project!" Foundry gap is resolved: `contracts/test/` holds both
suites; see SETUP_GUIDE §4.)

## 2. `prove_it_works.py` — 41/41, and why passing tests are not proof

Every positive check is paired with a negative control that must fail. This
matters because every check can pass **vacuously**:

| The check | How it passes while broken |
|---|---|
| "chain recorded the round" | chain recorded *nothing*, round silently unanchored |
| "verifier: 0 discrepancies" | verifier is broken and always returns OK |
| "attackers were banned" | *everything* is banned, honest clients included |
| "trust survived the restart" | trust was reset to a value that looks plausible |
| "banned EK was rejected" | enrollment rejects *everyone* |
| "no raw EK on chain" | nothing at all is on chain |

### The ten questions the harness answers

| # | Question | Positive | Negative control |
|---|---|---|---|
| 1 | Does detection work? | attackers banned | honest-only federation → **zero** bans |
| 2 | Is the chain really recording? | 38 events, log grows 38→53 | chain off builds no backend |
| 3 | Are bans *enforced*? | banned absent from weights | an ACTIVE device **is** present |
| 4 | Did restart rebuild real state? | trust matches within 5e-6 | recovered weight ≠ a fresh engine's |
| 5 | Is whitewash blocked? | banned EK → BANNED | unseen EK → **ACTIVE** |
| 6 | Does the chain alter training? | deviation `0.000e+00` | — |
| 7 | Does the verifier work? | clean chain verifies | **corrupt it → caught** |
| 8 | Does tier matter? | same trust all tiers | weights differ 1.0/0.5/0.1 |
| 9 | Are new devices protected? | T < 0.3 at round 3 | no sanction until round 4 |
| 10 | Does EK privacy hold? | 0 raw hashes leaked | ban lookup still returns True |

### Check 7 is the one that changes everything

"VERIFIED: 0 discrepancies" is unfalsifiable unless you can show the verifier
*notices* corruption. The harness deliberately corrupts the chain:

```
✓ POSITIVE: untampered chain verifies cleanly
    VERIFIED: 6 devices, 34 events replayed, 0 discrepancies
✓ TAMPER 1: inflating a device's stored trust IS detected
    h0.s: recomputed=1874236 on_chain=2651236
✓ TAMPER 2: silently un-banning an attacker IS detected
    a0.status: recomputed=2 on_chain=0
✓ chain verifies again once the tampering is reverted
✓ local audit log detects an edited entry  → (False, entry 2 broken)
```

**TAMPER 2 is the thesis claim made concrete:** a server that silently un-bans
an attacker is caught by a third party who does not trust the server.
`recomputed=2` (BANNED, from replaying events) vs `on_chain=0` (ACTIVE, what
the state was mutated to). Demonstrated by falsification, not assertion.

### Check 4 distinguishes recovery from a plausible reset

```
✓ NOT A RESET: recovered 0.3914 vs fresh-start 0.2917 (pre-restart was 0.3914)
```

A reset would land at 0.2917 — a brand-new Tier-2 device after one clean
round. The recovered value equals the pre-restart value exactly. Without
that comparison, "trust survived" would be a number you had no way to judge.

### Check 5 tests both directions

A gate that rejects everyone would "block whitewashing" perfectly while
destroying the federation — so an unseen EK must be ADMITTED as ACTIVE.

### Check 9 shows the gate, not luck

```
after 1 MINOR: s+f=0.60 evidence_dominated=False T=0.385 ACTIVE
after 2 MINOR: s+f=1.20 evidence_dominated=False T=0.312 ACTIVE
after 3 MINOR: s+f=1.80 evidence_dominated=False T=0.263 ACTIVE   <- T < 0.3
after 4 MINOR: s+f=2.40 evidence_dominated=True  T=0.227 BANNED   <- gate opens
```

Trust crosses `BAN_T = 0.3` at round 3 but no sanction fires until round 4.
One full round of protection a score-only rule would not give. This table
belongs in the methodology chapter verbatim.

## 3. `chain_eval.py` — the deterministic/non-deterministic split

| Line | Reference | Reproduced | Should match? |
|---|---|---|---|
| gas fit | `58,282 + 38,818 × clients`, R²=1.000000 | **identical** | ✅ yes — gas is deterministic |
| storage drift | 0.15% | **0.15%** | ✅ yes |
| reconcile @ 200 rounds | 3.3 ms | 2.0 ms | ❌ no — different CPU |
| worst chain overhead | 4903.90 ms | 4575.98 ms | ❌ no |

Gas matching to the digit confirms the contract and solc settings are right;
timing differing is correct — it is your hardware. A quick run fitting only 3
client counts gave `58,315 + 38,811`; the full run's fit is the number to
quote (and see §7a on intercept jitter).

The July figure-skipping incident (NumPy 1.x/2.x ABI clash from a
`--system-site-packages` venv; matplotlib failing silently while the run
still reported GREEN) is resolved — the fix and its verification are
SETUP_GUIDE §2. **Always confirm figure files exist** (`ls results/figures/*.png
results/chain/*.png`, expect 8 and 5); an ImportError prints one line and the
run still reports GREEN.

## 4. `run_experiments.py` — Chapter 4 under v3

```
✓ all evaluation checks passed
```

The stale v2.1 CSVs were replaced with v3 numbers. What each block proves:

### Accuracy — the headline result

| Attack | Baseline | DLTF | Δ | Loss recovered |
|---|---:|---:|---:|---:|
| none | 0.691 | 0.691 | **+0.000** | n/a |
| poison | 0.520 | 0.685 | +0.165 | **96.5%** |
| sleeper | 0.559 | 0.684 | +0.125 | **94.7%** |
| sybil | 0.583 | 0.687 | +0.104 | **96.3%** |

Two claims, both strong: **zero cost when there is no attack** (identical to
three decimals with identical standard deviation — kills the "your defence
hurts honest performance" objection), and **94.7–96.5% of the attack-induced
loss recovered**. The ±0.014 over 5 seeds shows the effect size is roughly
10× the noise. Say that explicitly.

### Detection latency

```
poison   flag 0.0  full ban 1.0
sleeper  flag 0.4  full ban 1.0
sybil    flag 1.0  full ban 1.0
```

Rounds from attack onset to first flag. Poison is flagged the same round.
Sybil takes 1 round because stage 3 requires similarity *sustained* over 2
rounds — deliberate, and it is what keeps the FPR near zero. Everything is
fully banned within 1 round of the first flag: the attacker's window is 1–2
rounds regardless of strategy.

### Whitewash — O2

```
dltf      blocked 25/25
baseline  blocked 0/25
```

25 attempts, 100% vs 0%. Clean separation. This single line is the O2 evidence.

### Attacker cost — O3

```
tier 1: identities 8.0,  influence 3.70 weight-rounds, per identity 0.462
tier 2: identities 15.4, influence 3.09 weight-rounds, per identity 0.201
tier 3: identities 15.4, influence 0.62 weight-rounds, per identity 0.040
```

The ranking looks backwards at first: **Tier 1 buys the most influence per
identity (0.462)** — but each identity costs a physical TPM. **Tier 3 buys
almost nothing (0.040)** even though identities are free. 11.5× more
influence per identity at Tier 1, at unboundedly higher cost (a TPM is a
purchase; a software identity is a function call). Framing: *the system
prices influence in identities, and identity price is set by hardware.*
Tier 2/3 burn 15.4 identities vs Tier 1's 8.0 because rehabilitation lets a
Tier-1 identity survive longer before permanent ban.

### Rehabilitation

```
recovering  -> ['REINSTATED']    (5/5 reinstated)
persistent  -> ['PERMANENT_BAN'] (0/5 reinstated)
```

Perfect separation across 5 seeds. The shadow-model slope test discriminates
a genuinely reforming device from one that keeps attacking during probation.
No false reinstatements, no failed reinstatements. This is what makes
"rehabilitation" a mechanism rather than a loophole.

### Sensitivity sweep — the calibration defence

```
COSINE_MEDIAN_THRESHOLD -0.65: fpr 0.000  lat poison  0.6
COSINE_MEDIAN_THRESHOLD -0.45: fpr 0.000  lat poison  0.0    <- default
COSINE_MEDIAN_THRESHOLD -0.25: fpr 0.057  lat poison -1.0
COSINE_MEDIAN_THRESHOLD -0.15: fpr 0.229  lat poison -1.8
```

The default −0.45 sits exactly at the knee: zero FPR with zero detection
latency. Negative latency means clients flagged *before* the attack starts —
false positives on honest noise. `FOOLSGOLD_SIM` and `NORM_CLIP_FACTOR` are
flat across their ranges — report as a robustness result, not an omission.
**This table is the answer to "why 0.45?"** Not taste — the measured knee.

### Flag-level FPR 0.6%, sanction-level FPR 0%

`make_figures.py` once asserted `fpr == 0.0` and crashed on
`0.0058823... = 1/170`: over 5 seeds × 34 honest clients, exactly one honest
client was flagged once. That is a result, not a bug. A lone MINOR cannot
sanction anyone: worst case takes trust to 0.5525, still above
`PROBATION_T = 0.5`, with `major_run = 0` so M3 does not fire; for a new
client the cold-start gate blocks it outright (`s + f = 0.60 < W_PRIOR = 2`).
Verified identical across all three tiers (trust is tier-neutral). The
honest claim is stronger than the assertion:

> **Flag-level FPR: 0.6% (1 of 170 honest client-runs). Sanction-level FPR: 0%.**

The patched `make_figures.py` asserts a 2% flag tolerance and gates on what
matters, with the reasoning in a comment.

## 5. Figures — which transfer, and what each argues

**Gas is deterministic. Timing is not.** Measured: deploy/register identical
to the digit across trials; per-round timings vary ~20%.

| Figure | Measures | Transfers? |
|---|---|---|
| `fig_gas_clients.png` | gas vs client count + affine fit | ✅ exactly |
| `fig_storage.png` | per-round gas flat over 30 rounds | ✅ exactly |
| `fig_latency.png` | round latency, 3 modes, log scale | ❌ regenerate on your hardware |
| `fig_latency_mock.png` | off vs mock overhead | ❌ regenerate |
| `fig_reconcile.png` | rebuild/verify time vs history | ❌ regenerate |

Regenerate all five for provenance; the two gas figures coming back with the
same numbers is itself a result: *gas is a property of the contract, not the
machine.*

What each figure argues:
- **fig_gas_clients** — the cost model is affine, not proportional: fixed
  `roundSummary` cost + constant marginal `classify` cost. "Gas per client"
  alone misleads (falls from 67,968 at 2 clients to 41,733 at 20 purely
  through amortisation).
- **fig_storage** — state grows with devices, not rounds. Under EIP-2929/3529
  a cold SSTORE costs 22,100 vs 2,900–5,000 warm; flat per-round gas ⇒ no new
  per-device slots ⇒ the packed word is overwritten in place. **Gas is the
  instrument; storage growth is the finding.**
- **fig_latency** — quote the *shape*, not absolutes: in-process py-evm
  over-states EVM execution (pure-Python interpreter) and under-states
  transport (no socket, no block time). A different regime, not a bound.
- **fig_latency_mock** — what CI actually pays: sub-2 ms near-constant
  overhead while training grows 60× from 2 to 50 clients.
- **fig_reconcile** — the restart guarantee is nearly free: ~1.6 µs/event,
  200 rounds rebuild in ~2.3 ms.

Regeneration order matters (figures read the CSVs):

```bash
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check          # Chapter 4, chain OFF
PYTHONPATH=. python3 -m eval.make_figures
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check   # Chapter 5
ls -la results/figures/*.png results/chain/*.png               # expect 8 + 5
```

REAL-mode latency (`--exp real`, off/mock/node) provides the only quotable
absolute latencies from the physical machines — until the QBFT runs (§9),
which are quotable when labeled as a 4-validator Docker network.

## 6. The full verification sequence

```bash
PYTHONPATH=. python3 tools/prove_it_works.py           # 1. behaviour (41 checks)
PYTHONPATH=. python3 tests/test_pipeline.py            # 2. runs (8 groups)
PYTHONPATH=. python3 tests/test_chain_integration.py   #    + 9 groups
PYTHONPATH=. python3 -m chain.evm_parity_test          # 3. contract = spec (15)
PYTHONPATH=. python3 -m chain.commit_parity_test       #    (17)
PYTHONPATH=. python3 -m chain.batch_parity_test        #    (21)
cd contracts && forge test -vv && cd ..                #    Solidity-native
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient # 4. watch it happen
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check  # 5. reproducible
```

The single most important line in the whole run:

```
✓ ENFORCEMENT: the contract reverted the resurrection write (BanToActive)
               -- not a Python check, an EVM revert
```

A Python check is enforced by code the server operator controls. An EVM
revert is not. That distinction is the entire argument for the chain layer.

### Three sentences you can defend

1. **"The system detects attackers without false-positiving honest clients."**
   Both directions measured: 2/2 attackers banned, 0/5 honest flagged in an
   all-honest control (and at scale: flag-FPR 0.6%, sanction-FPR 0%).
2. **"A server cannot silently rewrite the ban ledger."** Demonstrated by
   corrupting the chain: the independent verifier reports `recomputed=2
   on_chain=0` — it catches a silent un-ban.
3. **"Adding the chain layer does not change training."** `0.000e+00`
   deviation in weight trajectories and final model parameters across 3
   seeds and 2 chain modes. Exact zeros, not tolerances — which is what lets
   every Chapter 4 accuracy result be reused unchanged.

## 7. Three non-discrepancies (do not lose an evening to these)

### 7a. Gas intercept moves by a few units

Fits across runs: intercept 58,282 / 58,283 / 58,279; slope **38,818 exact
every time**, R² = 1.000000. Cause: `classify()` takes a `reason` string;
calldata costs 4 gas per zero byte, 16 per non-zero, and the reason text
differs between rounds. The quick-run `58,315` fitted only 3 client counts.
**Quote `round_gas ≈ 58,280 + 38,818 × clients`, slope exact, intercept ±5.**
(September runs print 58,281 — same phenomenon.)

### 7b. Packed word: 179 bits here, 181 there

```
after  1 round  (lastRound= 0) -> 169 bits
after  6 rounds (lastRound= 5) -> 179 bits
after 20 rounds (lastRound=19) -> 181 bits
```

`lastRound` occupies the top 32 bits, so `bit_length()` tracks wherever the
test stopped. **Quote the declared layout, 208 bits** — the structural claim,
always true. What matters is that it fits one 256-bit SSTORE slot, which is
why per-round gas is flat in round count.

### 7c. `--tier1` weights reach 0.807 — M1 saturation, not a bug

`TRUST_CEILING = (1+S_MAX)/(W_PRIOR+S_MAX) = 0.8333` with `S_MAX = θ/(1−γ) = 4`.
At Tier 1, cap D = 1.0, so weight equals trust approaching the ceiling from
below. Increments `+0.055, +0.038, +0.028, +0.021, ...` monotonically
decrease — the geometric series `s ← γs + θ` converging. **This run is a
usable methodology figure**: no amount of good behaviour buys unbounded
influence — the mechanism that defeats reputation banking.

## 8. The commitment cost table (from `batch_parity_test`)

```
A  per-client txs + classify :  539,406 gas  (clients pay 89,901 each)
B  commitBatch  + classify   :  469,532 gas  (clients pay 0)
C  classifySigned            :  279,662 gas  (clients pay 0)
D  baseline, no commitment   :  216,036 gas  (no guarantee)

C vs A: 48.2% cheaper
cost of the guarantee (C - D): 63,626 gas = 29.5% over baseline
marginal cost per additional client: ~35,951 gas
```

This answers the obvious objection directly: *what does the anti-fabrication
guarantee cost?* **29.5% over baseline, and the clients pay nothing.** The
naive implementation would have been 48% more expensive and required every
client to fund a wallet. The ~35,951 marginal cost is consistent with the
38,818 slope from `chain_eval` (different path — batched signatures vs
individual classify calls): a nice independent cross-check.

⚠ These are 6-client, pre-September measurements. The September signed-path
measurements (4 clients: `commitBatch(4)` 168,081; `classifySigned` 46,647;
`classify` + amortised batch 80,268) are a different context — label client
count and path; do not mix the tables.

The commitment layer running live inside a federation:

```
commitment: 5 wallets bound to TPM identities, clients now commit before sending
chain: 41 mirrored writes, 0 rejections, 0 failures
VERIFIED: 5 devices, 33 events replayed, 0 discrepancies
```

Each client proved control of both its TPM and its wallet, committed
`keccak256(gradient)` before transmitting, and the verifier confirms the
commitment events do not perturb trust replay. Guard rail:
`--require-commit` without `--chain mock|node` fails loudly — nowhere to
record commitments with the chain off.

## 9. September 2026 results (summary — full detail in RUNBOOK / MASTER_CONTEXT §15)

- **Liveness (2b), injected stall:** structural survival holds; wall clock
  does not (sync 409→2002 ms/round, ~5×; async 61→1003 ms). Async backlog
  collateral: at queue depth 17, three writes including an ENROLL were
  destroyed; chain-only reconciliation failed (`['h3']`). The split verdict
  IS the result; report async numbers with the collateral.
- **Economics (Phase 4):** at 30 gwei / POL $0.42 (2026-08-31), a 30-round
  federation costs USD 0.169 / 0.316 / 0.756 at 10 / 20 / 50 clients; deploy
  USD 0.026. The attack (~USD 120 in certified modules) costs ~380× the
  ledger that sanctions it. Prices supplied, never fetched.
- **QBFT (2026-09-11, real 4-validator Besu):** 2b manual-stall completed
  twice (sync healthy ~14.4 s/round, first stalled round 188.9 s; async
  ~115–136 ms); 2c preflight 18/19 — `UnauthorizedWriter` refused by
  consensus, deploy gas reproduced exactly. **Open bug:** `head_hash()` on
  Besu POA `extraData` (needs `geth_poa_middleware`). 2a/2d not yet run.
- **Paper corrections:** label-length gas (+12/byte); 50-client projection
  1,999,181 from printed coefficients (paper's 1,999,175 used unrounded);
  `deploy.py --self-test` ABI_PATH bug fixed.

## 10. Where you stand

| Area | Status |
|---|---|
| Methodology | ✅ every constant verified, sanction paths measured |
| Trust model (Ch.4) | ✅ data regenerated under v3, all checks passed |
| Systems (Ch.5) | ✅ CSVs + figures; commitment measured; liveness/economics added |
| Real chain | ⚠ QBFT partially executed; POA bug open; testnet pending |
| Limitations | ✅ every gap measured, not guessed |

Still genuinely untested:
1. **Detection on real hardware** — n ≥ 3 required, measured. Run the third agent.
2. **Pending-transaction path** — eth-tester mines instantly; Anvil with
   `--block-time` / `--no-mining` is the cheap next step.
3. **Public-chain deployment** — Sepolia recommended (CLAUDE.md §6 Step 2).
4. **QBFT 2a/2d** and a clean preflight after the POA fix.

Naming these is stronger than claiming they are covered.
