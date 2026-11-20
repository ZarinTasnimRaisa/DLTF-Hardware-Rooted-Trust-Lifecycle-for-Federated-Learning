> **RETIRED (2026-11-17) - MERGED.** Figure guidance (Parts 1-2) and the negative-control verification methodology (Part 3) were merged into docs/RESULTS_EXPLAINED.md sections 2, 5-6. Its internal status is stale (Chapter 4 was re-run; it recommends the bogus plot_results.py, since deleted).

# Graphs, Test Output, and How to Know It Actually Works

Three answers. The third is the one that matters most.

---

# PART 1 — Which graphs are valid, and which you must regenerate

I tested whether each measurement is deterministic. The answer splits cleanly.

```
=== gas ===                                    === timing ===
trial 0: deploy=2,085,425 register=95,332      trial 0: [0.913, 0.727, 0.746, 0.855] ms
trial 1: deploy=2,085,425 register=95,332      trial 1: [0.750, 0.676, 0.711, 0.735] ms
                       ^ identical                                    ^ ~20% variance
```

**Gas is deterministic. Timing is not.** And you already proved gas transfers:
your run reported `gas for deploy 2,085,425` — the same figure to the digit.

## The five figures

| Figure | Measures | Valid for your thesis? |
|---|---|---|
| `fig_gas_clients.png` | gas vs client count + affine fit | ✅ **transfers exactly** |
| `fig_storage.png` | per-round gas flat over 30 rounds | ✅ **transfers exactly** |
| `fig_latency.png` | round latency, 3 modes, log scale | ❌ **regenerate** — my CPU, not yours |
| `fig_latency_mock.png` | off vs mock overhead | ❌ **regenerate** |
| `fig_reconcile.png` | rebuild/verify time vs history | ❌ **regenerate** |

Regenerate all five anyway, for provenance. The two gas figures will come back
with the same numbers, which is itself a result worth stating: *gas is a property
of the contract, not the machine.*

## What each figure actually argues

**`fig_gas_clients.png` — "the cost model is affine, and here it is"**

Measured points, the fitted line `58,282 + 38,818 × clients` at R² = 1.000000, and
a dotted line marking the fixed cost. The argument: per-round cost is **not**
proportional to federation size. There is a fixed cost (`roundSummary`, paid once
per round regardless of size) plus a constant marginal cost per client
(`classify`). This is why quoting "gas per client" alone would mislead — it falls
from 67,968 at 2 clients to 41,733 at 20, purely because the fixed cost amortises.

**`fig_storage.png` — "state grows with devices, not with rounds"**

Per-round gas plotted against round index, flat at ~292,185 with 0.15% drift over
30 rounds. The argument is indirect and worth spelling out in the caption: under
EIP-2929/3529 a cold SSTORE to a fresh slot costs 22,100 while a warm update
costs 2,900–5,000. So per-round gas is dominated by how many *new* slots that
round touched. Flat gas ⇒ no new per-device slots ⇒ the packed 256-bit word is
being overwritten in place. **Gas is the instrument; storage growth is the
finding.**

**`fig_latency.png` — "the shape of the scaling curve"**

Three modes on a log axis, because in-process py-evm sits ~4 orders of magnitude
above the others and a linear axis would flatten `off` and `mock` into the
baseline. Quote the *shape*, not the absolute values: py-evm is a pure-Python
interpreter, so it over-states EVM execution relative to Anvil while
under-stating transport (no socket, no block time). It is a different regime, not
a bound in either direction.

**`fig_latency_mock.png` — "what CI actually pays"**

`off` vs `mock` on a linear axis with overhead bars. Overhead stays near-constant
and sub-2 ms while training time grows 60× from 2 to 50 clients. This is the
figure that supports "never on the critical path".

**`fig_reconcile.png` — "the restart guarantee is nearly free"**

Rebuild and verify time against history length, linear at ~1.6 µs/event. 200
rounds of history rebuilds in ~2.3 ms. Supports N23 being practical rather than
theoretical.

## What is MISSING — and it is the more important half

Those five are all *systems* figures. They belong in Chapter 5. You have **no
Chapter 3 or 4 figures yet**, and those carry the actual contribution:

| Missing figure | What it would show |
|---|---|
| trust trajectory per tier | honest clients climbing to the 0.8333 ceiling |
| sanction path per tier | Tier 1 → probation, Tier 2/3 → ban on the same offence |
| M1 saturation | `s` plateauing at `θ/(1−γ) = 4`, defeating reputation banking |
| M2 stickiness | `f` refusing to decay until 2 clean rounds pass |
| M3 escalation | a high-trust sleeper caught while T is still above threshold |
| cold-start gate | the round where score crosses BAN_T vs where the gate opens |
| whitewash blocking rate | DLTF blocks N/N attempts, baseline blocks 0/N |
| attacker cost per tier | rounds-to-ban × identity replacement cost |
| accuracy under attack | DLTF vs undefended FedAvg on identical seeds |

You already have `eval/make_figures.py` and `eval/plot_results.py` for these. They
read `results/*.csv` — which are **stale v2.1 output**. So the sequence is
mandatory and ordered:

```bash
# 1. regenerate Chapter 4 data (chain OFF)
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check

# 2. THEN the figures
PYTHONPATH=. python3 -m eval.make_figures
PYTHONPATH=. python3 -m eval.plot_results
```

Running `make_figures` before step 1 produces beautiful plots of numbers that no
longer describe your system. That is worse than having no figures.

---

# PART 2 — Generate everything from your own system

## Chapter 5, chain figures (~4 minutes)

```bash
cd DLTF-main && source venv/bin/activate

PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check
```

Writes to `results/chain/`: 9 CSVs, 5 PNGs, and `TABLES.md` (paste-ready LaTeX,
BRACU-safe — `tabular` with `\hline` only).

Expected tail:

```
✓ CHECK parity: 6 configurations, all deviations exactly 0
✓ CHECK storage: per-round gas drift 0.15% (<5%), state is O(devices)
✓ CHECK gas: round_gas = 58,282 + 38,818 x clients, R^2 = 1.000000
✓ CHECK reconcile: 3.3 ms at 200 rounds
✓ CHAIN EVAL GREEN
```

**Your gas lines should match mine to the digit.** If they don't, something
differs in your contract or solc settings and you want to know immediately. Your
latency and reconcile lines *will* differ — that is correct, they are your
hardware.

### One figure at a time, if you are iterating

```bash
PYTHONPATH=. python3 -m eval.chain_eval --exp gas       --out results/chain
PYTHONPATH=. python3 -m eval.chain_eval --exp storage   --out results/chain
PYTHONPATH=. python3 -m eval.chain_eval --exp latency   --out results/chain
PYTHONPATH=. python3 -m eval.chain_eval --exp reconcile --out results/chain
PYTHONPATH=. python3 -m eval.chain_eval --exp parity    --out results/chain
```

### Quick sanity pass (~30 s, do this first)

```bash
PYTHONPATH=. python3 -m eval.chain_eval --exp all --quick --check
```

## Chapter 4, trust figures — the blocker

```bash
# check for a landmine first: CRITICAL is not a BAD_EVIDENCE key
grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/

PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check      # chain OFF, takes a while
PYTHONPATH=. python3 -m eval.make_figures
```

## REAL-mode latency — the only quotable absolute

```bash
# agents running on the client machines, then on the server:
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain off  --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain mock --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain node --real-rounds 10
```

Every other latency number in your thesis is in-process py-evm. **These are the
only ones you may quote as absolute figures.**

---

# PART 3 — What your test output means, and how to know it truly works

## Your output, group by group

```
[test_module_selftests]         each module's own assertions
  ✓ tpm/common.py               tiering policy, EK cert verification
  ✓ tpm/client.py               credential activation, wallet-binding signature
  ✓ trust/reputation.py         the trust formula and all hardening mechanisms
  ✓ trust/probation.py          shadow model, OLS slope, randomised window
  ✓ trust/filter.py             the 4 detector stages
  ✓ fl/*.py                     model, data partitioning, aggregators, server
  ✗ net/handles.py              <- stale v2.1 assertion, fix supplied

[test_compile_only_modules]     torch/CLI files parse (they run machine-side)

[test_end_to_end_http_with_audit]   the real thing, over real HTTP sockets
  ✓ sybil pair banned over HTTP
  ✓ whitewash re-enrollment rejected over HTTP
  ✓ honest weights intact, model advanced
  ✓ audit chain persisted, reloaded, verifies

[test_eval_whitewash_smoke]     DLTF blocks re-registration, baseline does not

[test_chain_off_is_inert]       chain off constructs NOTHING
                                -> your Chapter 4 sweeps stay reproducible

[test_chain_selftests]          9 chain modules' own assertions

[test_chain_integration]        restart, rebuild, whitewash, node-down

[test_chain_evm_selftests]      against the DEPLOYED contract, real EVM bytecode
```

The single most important line in your whole run:

```
✓ ENFORCEMENT: the contract reverted the resurrection write (BanToActive)
               -- not a Python check, an EVM revert
```

A Python check is enforced by code the server operator controls. An EVM revert is
not. That distinction is the entire argument for the chain layer.

## But passing tests are not proof

Here is the uncomfortable part. Every one of those checks can pass **vacuously**:

| The check | How it passes while broken |
|---|---|
| "chain recorded the round" | chain recorded *nothing*, round silently unanchored |
| "verifier: 0 discrepancies" | verifier is broken and always returns OK |
| "attackers were banned" | *everything* is banned, honest clients included |
| "trust survived the restart" | trust was reset to a value that looks plausible |
| "banned EK was rejected" | enrollment rejects *everyone* |
| "no raw EK on chain" | nothing at all is on chain |

So I built a harness where **every positive check is paired with a negative
control that must fail.**

```bash
PYTHONPATH=. python3 tools/prove_it_works.py
```

Result: **41 checks passed, 0 failed.**

### The ten questions it answers

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
*notices* corruption. So the harness deliberately corrupts the chain:

```
✓ POSITIVE: untampered chain verifies cleanly
    VERIFIED: 6 devices, 34 events replayed, 0 discrepancies

✓ TAMPER 1: inflating a device's stored trust IS detected
    FAILED: 1 discrepancies over 6 devices
    h0.s: recomputed=1874236 on_chain=2651236

✓ TAMPER 2: silently un-banning an attacker IS detected
    FAILED: 1 discrepancies over 6 devices
    a0.status: recomputed=2 on_chain=0

✓ chain verifies again once the tampering is reverted
✓ local audit log detects an edited entry
    verify() -> (False, entry 2 broken)
```

TAMPER 2 is the thesis claim made concrete: **a server that silently un-bans an
attacker is caught by a third party who does not trust the server.** `recomputed=2`
(BANNED, from replaying the events) versus `on_chain=0` (ACTIVE, what the state
was mutated to). That is the property, demonstrated by falsification rather than
assertion.

### Check 4 distinguishes recovery from a plausible reset

```
✓ NOT A RESET: recovered weight differs from a fresh engine's
    recovered 0.4033 vs fresh-start 0.2917 (pre-restart was 0.4033)
```

A reset would land at 0.2917 — a brand-new Tier-2 device after one clean round.
The recovered value equals the pre-restart value. Without this comparison,
"trust survived" would just be a number you had no way to judge.

### Check 5 tests both directions

```
✓ POSITIVE: banned EK under a NEW label is rejected
✓ NEGATIVE CONTROL: an unseen EK is ADMITTED as ACTIVE
    status = ACTIVE (BANNED here = the gate rejects everyone)
```

A gate that rejects everyone would "block whitewashing" perfectly while
destroying the federation.

### Check 9 shows the gate, not luck

```
after 1 MINOR: s+f=0.60 evidence_dominated=False T=0.385 ACTIVE
after 2 MINOR: s+f=1.20 evidence_dominated=False T=0.312 ACTIVE
after 3 MINOR: s+f=1.80 evidence_dominated=False T=0.263 ACTIVE   <- T < 0.3
after 4 MINOR: s+f=2.40 evidence_dominated=True  T=0.227 BANNED   <- gate opens
```

Trust crosses `BAN_T = 0.3` at round 3 but no sanction fires until round 4, when
`s + f > W_PRIOR = 2`. **One full round of protection a score-only rule would not
give.** This table belongs in Chapter 3 verbatim.

---

## The full verification sequence

```bash
cd DLTF-main && source venv/bin/activate

# 1. does it behave as intended?  (the one that matters)
PYTHONPATH=. python3 tools/prove_it_works.py        # 41 checks

# 2. does it all still run?
PYTHONPATH=. python3 tests/test_pipeline.py         # 8 groups
PYTHONPATH=. python3 tests/test_chain_integration.py  # 9 groups

# 3. does the contract match the spec?  (two independent implementations)
PYTHONPATH=. python3 -m chain.evm_parity_test       # 15  Python vs deployed
PYTHONPATH=. python3 -m chain.commit_parity_test    # 17
PYTHONPATH=. python3 -m chain.batch_parity_test     # 21
cd contracts && forge test -vv && cd ..             # 34  Solidity-native

# 4. can you watch it happen?
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient

# 5. are the numbers reproducible?
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check
```

| Step | Expect | If it fails |
|---|---|---|
| 1 | 41 checks, 0 failed | a behaviour is wrong — read which control fired |
| 2 | 8/8 and 9/9 green | something is broken or a file is missing |
| 3 | 15/17/21 and 34 | contract ≠ spec, or `forge` not installed |
| 4 | `round 12: 0.4` after restart | reconciliation reset instead of rebuilding |
| 5 | gas matches mine exactly | your contract or solc settings differ |

## Three sentences you can defend

**"The system detects attackers without false-positiving honest clients."**
Both directions measured: 2/2 attackers banned, 0/5 honest clients flagged in an
all-honest control.

**"A server cannot silently rewrite the ban ledger."**
Demonstrated by corrupting the chain and showing the independent verifier reports
`recomputed=2 on_chain=0` — it catches a silent un-ban.

**"Adding the chain layer does not change training."**
`0.000e+00` deviation in both weight trajectories and final model parameters
across 3 seeds and 2 chain modes. Exact zeros, not tolerances — which is what
lets you reuse every Chapter 4 accuracy result unchanged.

## Honest gaps

Even at 41/41, four things remain untested here:

1. **Real hardware detection.** With exactly 2 physical clients, median-based
   stages cannot fire — measured. Run a third agent.
2. **Real network latency.** Everything above is in-process. `--exp real` only.
3. **Public chain.** Anvil has no consensus, no finality, no gas market.
4. **Chapter 4 numbers.** Stale v2.1 CSVs. Nothing in Chapter 5 finalises until
   those are re-run.

Naming these is stronger than claiming they are covered.
