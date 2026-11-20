> **RETIRED (2026-11-17) - POINT-IN-TIME STATUS REPORT.** Tiers 0-6 verification (~180 checks green). Its evergreen content (three non-discrepancies section 2, commitment cost table section 3) was merged into docs/RESULTS_EXPLAINED.md sections 7-8. Tiers 7/8 and QBFT have since run at least partially; the housekeeping list is done.

# Verification — Tiers 0 through 6

**Verdict: everything you ran is working correctly.** 6 tiers, ~180 individual
checks, zero genuine failures.

One environment landmine that has not bitten you yet but will, and three numbers
that look like discrepancies but aren't — explained so you don't lose an evening
to them later.

---

## Tier by tier

| Tier | Result |
|---|---|
| 0 environment | ✅ venv fixed, figures render — ⚠ but see §1 |
| 1 behaviour (41 checks + controls) | ✅ 41/41 |
| 2 pipeline + integration | ✅ 8/8 and 9/9 |
| 3 contract, two languages | ✅ 15 + 17 + 21 Python, 34 Solidity |
| 4 SIM demos | ✅ all four |
| 5 Chapter 4 + Chapter 5 | ✅ 6 CSVs, 8 figures, 9 CSVs, 5 figures |
| 6 commitment layer | ✅ end to end, plus the guard rail |

The venv fix worked cleanly:

```
matplotlib .../venv/lib/python3.12/site-packages/matplotlib/__init__.py
numpy      .../venv/lib/python3.12/site-packages/numpy/__init__.py
```

Both inside `venv/`, and all 5 chain PNGs now exist (69–86 KB each). That
confirms the NumPy ABI clash is gone.

---

## §1 — The one thing to fix: `solc` on your PATH is 0.5.16

```
Version: 0.5.16+commit.9c3226ce.Linux.g++
```

That is a 2019 compiler. The contract declares `pragma solidity ^0.8.20`, so
0.5.16 rejects it outright:

```
Error: Source file requires different compiler version
```

**Why nothing has broken.** Foundry manages its own solc through `svm` — your
`forge test` log says `Compiling 20 files with Solc 0.8.24`, which is Foundry's
copy, not the one on your PATH. And the Python suites read the prebuilt
`.abi`/`.bin`, so they never invoke solc at all.

**When it will bite.** The moment you run the documented manual build:

```bash
solc --optimize --optimize-runs 200 --via-ir --bin --abi --overwrite \
     -o contracts/out chain/DLTFRegistry.sol
```

That fails with 0.5.16, and the error mentions compiler versions rather than
anything recognisable, so it reads like a contract problem.

### Two fixes, either is fine

**Simplest — just use Foundry, since it already works:**

```bash
cd contracts && forge build && cd ..
```

**Or install the right solc alongside** (`~/bin` before `/usr/bin` on PATH):

```bash
mkdir -p ~/bin && cd /tmp
curl -sL -o solc \
  https://github.com/ethereum/solidity/releases/download/v0.8.24/solc-static-linux
chmod +x solc && mv solc ~/bin/
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc && source ~/.bashrc
solc --version        # must now read 0.8.24+commit.e11b9ed9
```

Do **not** `apt remove solc` — something else may want it. Shadowing via PATH
order is enough.

---

## §2 — Three non-discrepancies

### 2a. Gas intercept moves by a few units

You have seen `58,315` (quick run), `58,282`, and `58,281`. I ran the fit three
more times:

```
run 0: intercept=58,282  slope=38,818  R2=1.000000
run 1: intercept=58,283  slope=38,818  R2=1.000000
run 2: intercept=58,279  slope=38,818  R2=1.000000
```

**The slope is exact and identical every time. The intercept jitters ±4 gas.**

Cause: `classify()` takes a `reason` string, and calldata costs 4 gas per zero
byte and 16 per non-zero byte. The reason text differs between rounds
(`"inferred"` vs an actual detector message), so the fixed per-round cost moves
by a handful of gas. Nothing to do with your setup.

The `58,315` from the quick run is different for a different reason: it fitted
only 3 client counts instead of 5.

**For the thesis:** quote `round_gas ≈ 58,280 + 38,818 × clients`, R² = 1.000000.
State the slope as exact and the intercept as ±5 gas from calldata variation —
that is more credible than a spuriously precise figure.

### 2b. Packed word: 179 bits here, 181 bits there

`evm_parity_test` says 179 bits; `storage_summary.csv` said 181. Both are right:

```
after  1 round  (lastRound= 0) -> 169 bits
after  6 rounds (lastRound= 5) -> 179 bits
after 20 rounds (lastRound=19) -> 181 bits
after 30 rounds (lastRound=29) -> 181 bits
```

`lastRound` occupies the **top 32 bits** of the packed word, so `bit_length()`
tracks whatever round the test happened to stop at. The two suites use different
round counts.

**For the thesis:** quote the **declared layout, 208 bits**:

```
s(64) + f(64) + cleanRun(16) + majorRun(16) + status(8) + tier(8) + lastRound(32) = 208
```

That is the structural claim and it is always true. Measured `bit_length` is
incidental to test data. What matters — and what both numbers confirm — is that
it fits **one 256-bit SSTORE slot**, which is why per-round gas is flat in round
count.

### 2c. `--tier1` weights reach 0.807

```
round 14: weights {'client0': 0.807, ...}
```

Not a bug — **that is M1 saturation becoming visible.** `TRUST_CEILING =
(1+S_MAX)/(W_PRIOR+S_MAX) = 0.8333`, where `S_MAX = θ/(1−γ) = 4`. At Tier 1 the
cap `D = 1.0`, so weight equals trust, and trust is asymptotically approaching
0.8333 from below.

Watch the increments: `+0.055, +0.038, +0.028, +0.021, +0.017, +0.013, +0.011,
+0.009, +0.008, +0.006, +0.006, +0.004, +0.004, +0.004`. Monotonically
decreasing — that is the geometric series `s ← γs + θ` converging.

**This run is a usable Chapter 3 figure.** It shows empirically that no amount of
good behaviour buys unbounded influence, which is the mechanism that defeats
reputation banking. Worth keeping the log.

---

## §3 — Results in your output worth putting in the thesis

### The commitment cost table (from `batch_parity_test`)

```
A  per-client txs + classify :  539,406 gas  (clients pay 89,901 each)
B  commitBatch  + classify   :  469,532 gas  (clients pay 0)
C  classifySigned            :  279,662 gas  (clients pay 0)
D  baseline, no commitment   :  216,036 gas  (no guarantee)

C vs A: 48.2% cheaper
cost of the guarantee (C - D): 63,626 gas = 29.5% over baseline
```

This is a strong Chapter 5 result and it answers the obvious objection directly:
*what does the anti-fabrication guarantee cost?* **29.5% over baseline, and the
clients pay nothing.** The naive implementation would have been 48% more
expensive and would have required every client to fund a wallet.

Also from the same suite:

```
marginal cost per additional client: ~35,951 gas
```

Consistent with the 38,818 slope from `chain_eval` (different path — batched
signatures vs individual classify calls), which is a nice independent
cross-check.

### The commitment layer running live

```
commitment: 5 wallets bound to TPM identities, clients now commit before sending
chain: 41 mirrored writes, 0 rejections, 0 failures
VERIFIED: 5 devices, 33 events replayed, 0 discrepancies
```

Before this, the commitment layer was verified only at contract level. Now it
runs inside a federation: each client proved control of **both** its TPM and its
wallet, committed `keccak256(gradient)` before transmitting, and the verifier
confirms the commitment events do not perturb trust replay.

### The guard rail

```
error: --require-commit needs --chain mock|node
       (there is nowhere to record commitments with the chain off)
```

Failing loudly beats accepting a flag that cannot work. Worth mentioning if
anyone asks how the modes interact.

---

## §4 — What remains

| Tier | Needs |
|---|---|
| 7 REAL mode | your 3 machines + Tailscale + **a third agent** |
| 8 live Anvil | 10 minutes, one terminal |

**Do Tier 8 first — it is cheap and it is the strongest single claim you can
make.**

```bash
anvil &
PYTHONPATH=. python3 -m chain.deploy --network localhost
```

Expect `gas used : 2,085,425`. That figure has now appeared in your in-process
runs and mine; seeing it again from a real JSON-RPC deployment closes the loop on
determinism.

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain node --restart-at 12 --rejoin-as newclient
```

Identical output to the mock run, except every write is a real transaction and
every rejection a real EVM revert. Slower.

Then the degradation test, which is the one an examiner will ask about:

```bash
PYTHONPATH=. python3 run_local.py --clients 4 --rounds 10 --chain node
# in another terminal, around round 5:
pkill anvil
```

Rounds must keep running. The final report should show non-zero `failures` and
`unanchored rounds` while training never stops. That is N24 demonstrated against
a genuinely dead node rather than a simulated one.

### Tier 7 — the thing that will silently not work

Your two physical machines **cannot demonstrate detection**. Measured: `scale`,
`flip` and `sleeper` all return NEUTRAL at n=2, because stage 1 compares against
2.5× the median of all norms *including the attacker's* — with two samples the
median lands between them (`[1,10] → median 5.5 → ratio 1.82 < 2.5`) — and stage
2's robust reference degenerates to a single noisy client.

Add a third agent on the server box with `tpm_backend: "mock"`. It costs nothing,
restores every stage, and makes the federation mixed-tier so one run shows
Tier-1 probation *and* Tier-2 immediate ban on real hardware.

State the n ≥ 3 requirement in Chapter 6 either way.

---

## §5 — Housekeeping still open

```bash
# plot_results.py is a byte-identical copy of scenarios.py -- your own log proved
# it: `python3 -m eval.plot_results` printed "eval/scenarios.py self-test"
git rm eval/plot_results.py
# then remove it from COMPILE_ONLY in tests/test_pipeline.py

mkdir -p trust/legacy
git mv trust/chain_bridge.py trust/ReputationRegistry.sol trust/deploy_chain.py \
       trust/test_parity.py trust/demo_whitewash.py trust/legacy/
git mv build/registry_dev.json trust/legacy/
rm -rf dsadas/
diff chain/reputation.py trust/reputation.py     # delete the loser
ls -la run_server.py                             # confirm it exists
```

---

## Bottom line

Nothing is broken. Your evidence base right now:

| Artifact | Count |
|---|---|
| module self-tests | 274 ✓ across 22 modules |
| pipeline groups | 8/8 |
| chain integration groups | 9/9 |
| falsification checks with controls | 41/41 |
| Python contract parity checks | 53 |
| Solidity tests | 34 |
| Chapter 4 CSVs + figures | 6 + 8 |
| Chapter 5 CSVs + figures | 9 + 5 |

That is enough to write Chapters 1, 2, 3, 4, 5 and 6 with evidence behind every
claim. Tier 8 adds one paragraph to Chapter 5. Tier 7 adds the live-hardware
section — and needs the third agent to say anything about detection.

Fix the solc PATH before you next touch a build command, and quote 208 bits and
`38,818 × clients` rather than the incidental measurements.
