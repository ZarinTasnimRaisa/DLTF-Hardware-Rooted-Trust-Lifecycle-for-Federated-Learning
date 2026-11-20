# SIM Walkthrough — Prove FL + Reputation + Probation + Blockchain Are Connected

Nine steps, in order. Each one proves a specific layer works and tells you the
exact line of output that is the proof. Run them all and you have demonstrated
the whole system on one PC with no hardware.

---

## Step 0 — Setup (once)

```bash
cd DLTF-main
source venv/bin/activate
pip install web3 eth-tester py-evm eth-utils eth-account
```

Verify the layers import:

```bash
PYTHONPATH=. python3 -c "
import trust.reputation, trust.probation, trust.filter
import fl.server, fl.aggregator, audit.hashchain
import chain.registry, chain.reconcile, chain.wiring, chain.mock
print('✓ all four layers import')"
```

**Contract artifacts are pre-built** in `contracts/out/`, so you can skip solc.
If you do want to rebuild (note `--via-ir`, it is mandatory):

```bash
solc --optimize --optimize-runs 200 --via-ir --bin --abi --overwrite \
     -o contracts/out contracts/src/DLTFRegistry.sol
```

---

## Step 1 — Trust engine alone

```bash
PYTHONPATH=. python3 -m trust.reputation
```

**Proof:** ends with `✓ all reputation self-tests passed` (16 ✓ lines).

This is the layer everything else hangs off. If it fails, stop here.

---

## Step 2 — Probation engine alone

```bash
PYTHONPATH=. python3 -m trust.probation
```

**Proof:** `✓ all probation self-tests passed` (9 ✓ lines).

Shadow-model isolation, OLS slope decision, HMAC-randomised trial window.

---

## Step 3 — FL server: the whole lifecycle in one process

```bash
PYTHONPATH=. python3 -m fl.server
```

**Proof — these seven lines are the entire thesis in miniature:**

```
✓ enrollment: EK cert + activation -> Tier 1, activation only -> Tier 2
✓ sybil pair banned after sustained identical updates (CRITICAL)
✓ O2: banned EK re-enrolling is rejected (whitewashing blocked)
✓ Tier-1 poisoner: two MAJOR strikes -> probation (not instant ban)
✓ recovery slope on shadow model -> REINSTATED, weight restored
✓ O4: trust exports plain weights, honest Tier-2 at cap 0.5, model advanced
✓ audit chain captured the full lifecycle and verifies
```

Line 4 and 5 are **probation working end to end** — strike, probation, shadow
trial, reinstatement. Line 3 is **O2**. Line 6 is **O4**.

---

## Step 4 — SIM baseline: FL running, no chain

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --rounds 10
```

**Expected:**

```
enrolled client0    tier TPM_RESIDENT  status ACTIVE
...
round  0: weights {'client0': 0.292, ...} flags {}
round  9: weights {'client0': 0.391, ...} flags {}
done
```

**Proof:** trust climbs 0.292 → 0.391 as clean rounds accumulate. All Tier 2, so
weights are capped at 0.5 × T.

**No chain output, no `results/` directory.** That is the "off by default"
guarantee — this is byte-identical to the pre-chain system.

---

## Step 5 — Attackers get detected and banned

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 10
```

**Proof:**

```
round  1: weights {...} flags {'attacker0': 'CRITICAL', 'attacker1': 'CRITICAL'}
round  2: weights {'client0': 0.338, 'client1': 0.338, ...}   <- only 4 clients
```

Round 1 flags both attackers CRITICAL (FoolsGold-style stage 3 caught identical
updates). From round 2 they are **absent from the weights dict entirely** —
structurally excluded from aggregation, not down-weighted. That is O4: banned
devices never appear, so no aggregator needs special-casing.

---

## Step 6 — Tier 1, so probation becomes reachable

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --tier1 6 --rounds 15
```

**Proof:**

```
enrolled client0    tier HARDWARE      status ACTIVE
round  0: weights {'client0': 0.583, ...}
```

`HARDWARE` not `TPM_RESIDENT`, and weight 0.583 not 0.292 — the discount cap is
now 1.0 instead of 0.5, on the same trust value.

**Why this flag matters:** without `--tier1` every SIM client is Tier 2, and
`REHAB[TPM_RESIDENT] = False`, so **probation is unreachable in simulation**.
This was a long-standing gap in the SIM harness. Confirm the mechanism directly:

```bash
PYTHONPATH=. python3 -c "
from trust.reputation import ReputationEngine, Status, Tier
e = ReputationEngine()
e.register('t1', Tier.HARDWARE, 'aa'); e.register('t2', Tier.TPM_RESIDENT, 'bb')
for _ in range(2):
    e.record_event('t1','MAJOR'); e.record_event('t2','MAJOR')
print('Tier 1 after 2 MAJOR:', e.get_status('t1').value)   # PROBATION
print('Tier 2 after 2 MAJOR:', e.get_status('t2').value)   # BANNED
"
```

Note the sybil profile still bans outright even at Tier 1: **CRITICAL is ungated
and bypasses REHAB by design.** To see probation fire in a full run you need a
*poisoner* (sustained MAJOR), not a sybil — which is what `fl/server.py`'s
self-test in Step 3 demonstrates.

---

## Step 7 — Chain layer on, mock backend

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 10 --chain mock
```

**Proof — the last three lines:**

```
chain: 60 mirrored writes, 0 rejections, 0 failures
chain: 10 rounds anchored, 0 unanchored
VERIFIED: 6 devices, 50 events replayed, 0 discrepancies
```

`VERIFIED ... 0 discrepancies` means `chain/verifier.py` independently replayed
every chain event from scratch and arrived at the same device states — without
trusting the server. That is the point of the layer.

`0 rejections` means the server never attempted anything the contract's rules
forbid.

Compare the weights against Step 5: **identical.** The chain observes, it never
feeds back.

---

## Step 8 — THE FULL DEMO: ban → restart → rebuild → whitewash

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient
```

This is the one to show a supervisor. Read the output in four parts:

**Part 1 — attackers banned (rounds 0–11)**
```
round  1: flags {'attacker0': 'CRITICAL', 'attacker1': 'CRITICAL'}
round 11: weights {'client0': 0.397, 'client1': 0.397, ...}
```

**Part 2 — the server dies and is rebuilt from the chain**
```
--- server torn down at round 12 ---
rebuilt from chain: 6 devices (4 active, 0 probation, 2 banned),
                    58 events replayed, 2 banned EKs
--- resumed at round 12 (6 devices re-enrolled) ---
```

**Part 3 — training resumes with the recovered state**
```
round 12: weights {'client0': 0.4, ...}
```

> ### This line is the proof. Point at it.
> Round 11 ended at **0.397**. Round 12 continues at **0.400**.
> A wiped engine restarts at **0.292** — a fresh Tier-2 device's first round.
> The continuity is what proves trust state came off the chain rather than
> being silently re-initialised. Without the chain layer, a restart erases
> every sanction and every attacker walks free.

**Part 4 — the whitewash attempt fails**
```
--- rejoin: 'newclient' returns with attacker0's EK ---
enrolled newclient  tier TPM_RESIDENT  status BANNED
WHITEWASH_REJECTED: newclient carries a banned EK (attacker0's) -- O2 held across the restart
chain agrees EK is banned: True
VERIFIED: 6 devices, 90 events replayed, 0 discrepancies
```

A brand-new label, the same silicon. Both ledgers refuse it: the rebuilt
reputation engine (raw `ek_hash` recovered from the local audit log) *and* the
chain (via the one-way `ek_hmac`). **This is O2 surviving a process restart** —
which was previously listed as a limitation.

---

## Step 8b — The commitment layer (anti-fabrication)

```bash
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 8 \
    --chain mock --require-commit
```

**Proof:**

```
chain: mock, audit log results/sim_audit.jsonl, commitment layer ON
commitment: 5 wallets bound to TPM identities, clients now commit before sending
round  1: flags {'attacker0': 'CRITICAL', 'attacker1': 'CRITICAL'}
chain: 41 mirrored writes, 0 rejections, 0 failures
VERIFIED: 5 devices, 33 events replayed, 0 discrepancies
```

Each client proved control of **both** its TPM (AK signature over a
domain-separated challenge) and its wallet, then committed
`keccak256(gradient)` **before** transmitting. `0 rejections` means no client
failed the `MissingCommit` gate. This is the mechanism that stops a malicious
*server* inventing an update and attributing it to a client.

The guard rail:

```bash
PYTHONPATH=. python3 run_local.py --clients 4 --require-commit
# error: --require-commit needs --chain mock|node
```

## Step 9 — Against a real Ethereum node

Everything above used the in-memory mock. Now use actual EVM bytecode.

```bash
# terminal 1
anvil                                    # or: npx hardhat node

# terminal 2
PYTHONPATH=. python3 -m chain.deploy --network localhost
```

**Proof:**
```
✓ deployed at 0x5FbDB2315678afecb367f032d93F642f64180aa3
  gas used   : 2,085,425
  recorded in: chain/deployed.json
```

Then run the same demo against it:

```bash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain node --restart-at 12 --rejoin-as newclient
```

Identical output to Step 8, except every write is now a real transaction and
every rejection is a real EVM revert. Slower — py-evm and Anvil both cost
milliseconds per call versus microseconds for the mock.

---

## Verification suite

```bash
# everything: all module self-tests + chain suites + HTTP end-to-end
PYTHONPATH=. python3 tests/test_pipeline.py

# chain wiring: restart, rebuild, whitewash, node-down degradation
PYTHONPATH=. python3 tests/test_chain_integration.py
```

`test_chain_integration.py` should print 9 groups ending `✓ CHAIN INTEGRATION
GREEN`. The two most interesting:

```
[test_chain_off_matches_chain_on_trajectory]
  ✓ identical trajectories with chain off vs mock (6 rounds)

[test_full_lifecycle_on_deployed_contract]
  ✓ ENFORCEMENT: the contract reverted the resurrection write (BanToActive)
                 -- not a Python check, an EVM revert
```

The second is worth quoting in the defense: the ban is enforced by the EVM, not
by Python code the server operator controls.

### Contract tests (two independent implementations)

```bash
# Python, against the deployed bytecode
PYTHONPATH=. python3 -m chain.evm_parity_test        # 15 checks
PYTHONPATH=. python3 -m chain.commit_parity_test     # 17
PYTHONPATH=. python3 -m chain.batch_parity_test      # 21

# Solidity-native, same contract
cd contracts && forge test -vv                       # 34 tests
```

---

## Evaluation

```bash
# Chapter 5 chain numbers (~4 min)
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check
```

Ends with:

```
✓ CHECK parity: 6 configurations, all deviations exactly 0
✓ CHECK storage: per-round gas drift 0.15% (<5%), state is O(devices)
✓ CHECK gas: round_gas = 58,282 + 38,818 x clients, R^2 = 1.000000
✓ CHECK reconcile: 3.3 ms at 200 rounds
✓ CHAIN EVAL GREEN
```

Writes CSVs, `TABLES.md` (BRACU-safe LaTeX), and 5 PNGs to `results/chain/`.

```bash
# Chapter 4 -- MUST BE RE-RUN, chain OFF (see the blocker below)
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```

---

## Which layer each step proves

| Step | FL | Reputation | Probation | Blockchain |
|---|---|---|---|---|
| 1 | | ✓ | | |
| 2 | | | ✓ | |
| 3 | ✓ | ✓ | ✓ | audit only |
| 4 | ✓ | ✓ | | |
| 5 | ✓ | ✓ (bans) | | |
| 6 | ✓ | ✓ (tiers) | ✓ reachable | |
| 7 | ✓ | ✓ | | ✓ mock |
| 8 | ✓ | ✓ (survives restart) | ✓ | ✓ **the demo** |
| 9 | ✓ | ✓ | ✓ | ✓ real EVM |

If you only have time for two: **Step 3** (whole lifecycle) and **Step 8**
(chain layer earning its place).

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ModuleNotFoundError: chain` | missing `PYTHONPATH=.` |
| `--restart-at needs --chain mock\|node` | working as intended; restart needs something to rebuild from |
| `Stack too deep` from solc | missing `--via-ir` |
| `artifacts not found` | run the solc command in Step 0, or use the shipped `contracts/out/` |
| `TypeError: cannot unpack non-iterable bool` | the placeholder `audit/hashchain.py`; see below |
| `--chain node` cannot connect | `anvil` not running, or no `chain/deployed.json` |
| probation never fires | missing `--tier1`; also CRITICAL bypasses rehab, use a poisoner |
| `net/handles.py` self-test fails | stale v2.1 band; see below |

### Two known issues in your tree

**`audit/hashchain.py` may be the placeholder.** Check:

```bash
grep -n "def verify\|self.entries\|def head_hash" audit/hashchain.py
```

If `verify` returns a bare `bool` and there is no `head_hash`, replace it with
the one supplied. Your own `test_pipeline.py` needs the fuller surface.

**`net/handles.py:99` has a stale v2.1 assertion.** Under v3 a fresh Tier-2
device after one NEUTRAL round is `s=0.4, f=0 → T=0.5833 → w=0.2917`, but the
line asserts `0.3 <= w <= 0.5`. Fix:

```python
assert all(0.25 <= w <= 0.35 for w in report["weights"].values())
```

---

## The one real blocker

**Chapter 4 CSVs must be re-run.** Every file in `results/` was generated under
v2.1 (per-tier priors, FORGET = 0.95, `w(MAJOR)=3`). v3 uses a uniform Beta(1,1)
prior, FORGET = 0.90, and MINOR == MAJOR in evidence weight — so **every trust
trajectory in Chapter 4 has shifted.**

```bash
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```

Chain off. The `net/handles.py` failure above is the same staleness showing up in
a self-test, which is good reason to believe the CSVs really are stale rather
than close enough. Nothing in Chapter 5 can be finalized until Chapter 4's
numbers are stable.

---

> **STATUS NOTE (2026-11-17).** The resolved-blocker warnings above are
> historical: Chapter 4 was regenerated under v3 (all checks passed),
> `net/handles.py` now asserts the correct `0.25..0.35` band, the Foundry
> project is assembled in `contracts/` (both suites), and the hashchain is
> the full interface, not the placeholder. The nine-step demo narrative and
> its proof lines remain valid as written.
