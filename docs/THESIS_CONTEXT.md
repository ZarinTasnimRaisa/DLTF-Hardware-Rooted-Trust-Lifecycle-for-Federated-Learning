# DLTF — Thesis Writing Context

Everything you need to write the report from scratch. Every number here was read
back from live code or measured, not recalled from documentation. Where the
existing docs disagree with the code, the code wins and I flag it.

**Read §0 first.** It lists the claims you cannot make, which is the most
expensive thing to discover late.

---

## 0. Claims you must NOT make, and what to say instead

| Do not write | Write instead |
|---|---|
| "DLTF prevents whitewashing" | "DLTF makes whitewashing hardware-cost-bound: a new identity requires new silicon with a verifiable EK certificate" |
| "Detection is a contribution" | "Detection uses established techniques (FoolsGold-style similarity, norm clipping, cosine deviation); the contribution is what happens *after* detection" |
| "The system is decentralized" | "Training is centralized; the *ban ledger* is decentralized and independently verifiable" |
| "Tier 1 clients are more trustworthy" | "Trust is tier-neutral. Tier determines *consequences* (weight cap, rehabilitation eligibility), not the score" |
| "Two physical clients demonstrate detection" | "Median-based detection stages require n ≥ 3; the 2-client deployment demonstrates identity, enrollment, and sybil collusion only" (§9) |
| Absolute chain latency from SIM | Only quote `--exp real` figures; SIM uses in-process py-evm (§8) |
| "Kang 2019 provides the tier priors" | Kang provides θ=0.4 and τ=0.6 (Table I). The tier discounts are [CALIBRATED] by our own sweep |
| "The reputation constants are cited" | Only some are. Use the [CITED]/[DERIVED]/[CALIBRATED] taxonomy in §5 rigorously |

The last one matters most. Attaching a citation to a number no paper contains is
a fabricated citation, and it is the single easiest thing for an examiner to
catch. The [CITED]/[DERIVED]/[CALIBRATED] discipline is your defence.

---

## 1. The problem, in one paragraph each

**Federated learning has an identity problem, not just a detection problem.**
Existing poisoning defences (Krum, trimmed mean, FoolsGold) identify bad updates
statistically and down-weight or exclude them. All of them share an assumption:
that excluding a client *costs the client something*. In an open federation it
costs nothing. A client detected and excluded simply re-registers under a new
pseudonym with a clean reputation and resumes. Friedman & Resnick (2001) named
this the cheap-pseudonym problem two decades before federated learning existed.

**The consequence is that reputation in FL is unfalsifiable.** Any reputation
system built on re-registrable identities measures how long an attacker has been
using its *current* name, not how it has behaved. Sui et al. (2024) document
exactly this flaw in Kang's otherwise well-regarded FL reputation scheme: new
clients and reformed attackers are indistinguishable.

**DLTF's answer is to make identity expensive by binding it to hardware.** A
TPM's Endorsement Key is burned into the chip at manufacture and cannot be
extracted. If a sanction binds to `SHA256(EK_pub)` rather than to a chosen
username, then escaping the sanction requires new silicon. Whitewashing does not
become impossible — it becomes an expense, and one you can quantify.

**But that alone would be a blunt instrument.** Permanently banning a device for
one anomalous round in a non-IID federation punishes honest clients with unusual
data. So the sanction policy is graduated (Ostrom 1990), and — the key design
move — **graduated as a function of identity cost**. A device whose identity is
expensive to replace has more to lose, so it earns due process: probation, an
isolated trial, and reinstatement if it demonstrably reforms. A device whose
identity is free gets no such consideration, because extending it would be free
to abuse.

**One gap remained, and it is what the chain layer addresses.** The ban ledger
lived in the server's memory and in a local audit log. A restart erased it. And
a reader had to trust the server that wrote the log. Putting the ban ledger on a
smart contract makes it survive restarts and makes it verifiable by a party who
does not trust the server — while keeping the raw EK hashes off-chain for
privacy.

---

## 2. Objectives

| ID | Objective | Where realised | How evidenced |
|---|---|---|---|
| **O1** | Sybil resistance: one TPM chip = one identity | TPM credential activation (`tpm/`) | Two physical AMD fTPMs enroll with distinct EK hashes (client1 `ac6971…`, client2 `e7c273…`) |
| **O2** | Anti-whitewashing: bans bind to the EK hash and survive re-registration | `reputation.py::_banned_ek`, `chain/` | Re-enrollment with a banned EK rejected in SIM, over HTTP, and on the deployed contract |
| **O3** | Quantified trust: deterministic formula, measured attacker cost | `trust/reputation.py` | Closed-form thresholds, sensitivity sweep, per-tier sanction paths |
| **O4** | Aggregator-agnostic: trust exports plain weights | `fl/aggregator.py` | Same weight dict drives fedavg, trimmed-mean, and Krum (as an eligibility mask) |

**Novelty, stated precisely.** Not detection. Four things:
1. A hardware-rooted sanction-**and-rehabilitation** lifecycle (most work stops at exclusion).
2. The sanction policy is a *function of* hardware trust tier — identity replacement cost drives due process.
3. Attacker cost per tier is quantified rather than asserted.
4. The ban ledger is independently verifiable without trusting the server.

---

## 3. Threat model

**Trusted:** the aggregation server, for *training*. Manufacturer roots and
intermediates in the CA bundle.

**Untrusted:** all clients. Their data, their updates, their claimed identities.

**Partially untrusted — new in v3:** the server, *for the ban ledger*. The chain
layer's contract rejects writes that break the lifecycle (BANNED→ACTIVE, tier
mutation, duplicate rounds), so a server cannot rewrite sanction history even
though it is the only authorised writer. The commitment layer additionally stops
the server fabricating an update and attributing it to a client.

**Attacker capabilities:** submit arbitrary updates; collude with other clients;
observe the global model each round; re-register under new labels; behave
honestly for arbitrarily long before attacking.

**Attacker limits:** cannot extract a TPM's EK private key; cannot forge a
manufacturer-signed EK certificate; cannot break SHA-256 or HMAC; cannot
compromise the server (that is out of scope and should be stated).

**Attack classes and the stage that addresses each:**

| Attack | Mechanism | Detector stage | Severity |
|---|---|---|---|
| Scale / boosting | inflate update norm | 1: norm > 2.5× median | MINOR |
| Targeted poisoning | update opposes consensus | 2: cosine to robust ref < −0.45 | MAJOR |
| Sybil collusion | multiple identities, identical updates | 3: pairwise sim ≥ 0.95, sustained 2 rounds | CRITICAL |
| Sleeper / on-off | bank trust, then attack | 4: self-history flip sustained | MAJOR |
| Whitewashing | re-register after ban | O2: EK-bound ban set | rejected at enrollment |
| Server fabrication | invent a client's update | commitment layer (N25) | `MissingCommit` revert |

---

## 4. Architecture

```
┌──────────────────────────── CLIENT (net/agent.py) ────────────────────────────┐
│  tpm/client.py     provision: EK cert + AK, credential activation             │
│  fl/client.py      TorchTrainer -> flat list[float] update                    │
│  chain/commit.py   OPTIONAL: commit keccak256(gradient) BEFORE sending        │
└──────────────────────────────── HTTP / Tailscale ─────────────────────────────┘
┌──────────────────────────── SERVER (fl/server.py) ────────────────────────────┐
│  ENROLL   tpm/common.py: verify EK cert -> assess_tier -> Tier 1/2/3          │
│           reputation.register(id, tier, ek_hash)  <- O2 check here            │
│  ROUND    handle.train() -> trust/filter.py -> severity per client            │
│           reputation.record_event(id, severity) -> status + weight            │
│           trust/probation.py: shadow model for probated Tier-1 devices        │
│           fl/aggregator.py: weights -> aggregated update                      │
│  AUDIT    audit/hashchain.py   OR   chain/registry.py (drop-in replacement)   │
└───────────────────────────────────────────────────────────────────────────────┘
                                      │ optional
┌─────────────────── CHAIN (chain/, contracts/DLTFRegistry.sol) ────────────────┐
│  mock backend (in-memory, CI)  |  EVM backend (Anvil/Hardhat via web3)        │
│  contract recomputes trust from severity; rejects illegal transitions         │
│  chain/reconcile.py: rebuild ReputationEngine after restart                   │
│  chain/verifier.py: third-party recomputation, no server trust needed         │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Three independent axes — a useful framing for Chapter 3

| Axis | Options | Selector |
|---|---|---|
| TPM | mock / swtpm / real | `make_signer`, `config.CLIENTS[].tpm_backend` |
| Transport | in-process / HTTP | `LocalClientHandle` / `RemoteClientHandle` |
| Chain | off / mock / node | `--chain`, `config.CHAIN["mode"]` |

All nine combinations run. This is worth a paragraph: it is *why* the same code
path is exercised in CI and on real hardware, which is the basis for claiming the
SIM results transfer.

### The integration seam

`ChainRegistry` implements the exact `HashChain` surface (`append`, `entries`,
`verify`, `head_hash`, `__len__`), so it drops into `FederatedServer(audit=...)`
with **zero changes to `fl/server.py`**. Worth a sentence — it is the reason the
chain layer can be claimed as non-invasive.

One subtlety worth a footnote: `fl/server.py` never logs NEUTRAL
classifications, so the adapter **infers** them from the complement of logged
EVENTs against the ROUND participant list. Exact, not heuristic — NEUTRAL still
decays `s` and `f`, so omitting it would corrupt the replay.

---

## 5. The reputation engine — the analytical core of Chapter 3

### Trust score

Josang's probability expectation, `E = b + a·u`:

```
T = (α₀ + s) / (α₀ + β₀ + s + f)
```

with opinion `(b, d, u, a)` where `b = s/n`, `d = f/n`, `u = (α₀+β₀)/n`,
`a = α₀/(α₀+β₀)`, `n = α₀+β₀+s+f`. Aggregation weight `w = D(tier) · T`, zero if
banned.

### THE HEADLINE DESIGN DECISION: trust is tier-neutral

Lead Chapter 3 with this. Every tier uses the **same uniform Beta(1,1) prior and
the same dynamics** — verified from live code:

| | HARDWARE | TPM_RESIDENT | SOFTWARE |
|---|---|---|---|
| prior (α₀, β₀) | (1, 1) | (1, 1) | (1, 1) |
| start trust | 0.500 | 0.500 | 0.500 |
| trust ceiling | 0.8333 | 0.8333 | 0.8333 |
| γ | 0.90 | 0.90 | 0.90 |
| **weight cap D** | **1.0** | **0.5** | **0.1** |
| **rehab eligible** | **yes** | **no** | **no** |

Tier enters at exactly three places, none of them the score: the weight cap,
rehabilitation eligibility, and EK ban binding.

> **Behaviour determines trust. Hardware determines consequences.**

This kills the obvious objection to the earlier design — that a Tier-1 attacker
received a head start it had not earned. It also lets you cite Kang 2019 Table I
*directly* for θ and τ, which the earlier per-tier-prior design could not, since
their values would have overwritten the tier priors.

> ⚠ **The MASTER_CONTEXT in your repo describes the OLD design** (priors
> (8,2)/(4,2)/(2,2), start trust 0.80/0.667/0.50, per-tier γ, `w(MINOR)=1
> w(MAJOR)=3`, θ_r=0.55, FORGIVE_AFTER=5, FORGET=0.95 Tier-1-only). None of those
> values are in the code. Use the rewritten MASTER_CONTEXT.md.

### Constants, with provenance — copy this taxonomy into the thesis

```
W_PRIOR       = 2.0    [CITED]       Josang non-informative prior weight
BASE_RATE     = 0.5    [CITED]       principle of insufficient reason
PRIOR         = (1,1)  [CITED]       = (W·a, W·(1−a)), uniform across tiers
THETA         = 0.4    [CITED]       Kang 2019 Table I, positive interaction
TAU           = 0.6    [CITED]       Kang 2019 Table I, negative > positive
GAMMA         = 0.9    [CONVENTIONAL] standard exponential decay
FORGET        = 0.90   [DERIVED]     = GAMMA; ONE decay primitive, not two
FORGIVE_AFTER = 2      [CALIBRATED]  swept
MAJOR_RUN_TO_ESCALATE = 2  [CALIBRATED]  repetition begins at 2
PROBATION_T   = 0.5    [CALIBRATED]  indifference point
REINSTATE_T   = 0.75   [DERIVED]     closed form: PROBATION_T·(1 + 1/W_PRIOR)
BAN_T         = 0.3    [CALIBRATED]  backstop; probation fires first on rehab tiers
D(HARDWARE)   = 1.0    [CANONICAL]   no discount for proven identity
D(TPM_RESIDENT) = 0.5  [CALIBRATED]  swept
D(SOFTWARE)   = 0.1    [CALIBRATED]  swept
S_MAX         = θ/(1−γ) = 4          goodwill ceiling (M1)
TRUST_CEILING = (1+S_MAX)/(W+S_MAX) = 0.8333
PROBATION_WEIGHT_CAP = D(SOFTWARE) = 0.1   suspect ≤ unproven identity
```

**Two of these deserve explicit defence in the text:**

`FORGET = GAMMA = 0.90` is **[DERIVED], not calibrated.** The earlier design had
two independent decay constants and justified the asymmetry by citing Slovic on
trust asymmetry. v3 collapses them into one primitive: the asymmetry now comes
from *when* forgetting is permitted (only after `FORGIVE_AFTER` clean rounds —
mechanism M2), not from a different rate. **One fewer free parameter, same
behaviour.** That is a strictly better position to defend.

`REINSTATE_T = 0.75` is a **closed form**, not a chosen number:
`0.5 × (1 + 1/2) = 0.75`. It is the probation threshold plus exactly one unit of
prior mass — the smallest margin that survives one noise event without
immediately re-triggering probation.

### MINOR and MAJOR carry the same weight

Both are τ = 0.6. They differ only in that MAJOR increments `major_run`, which
drives M3 escalation. Expect the question "then why two severities?" The answer:
**severity selects the rule, not the magnitude.** A MAJOR is not worse evidence;
it is evidence that repetition should be tracked.

### Hardening mechanisms — each defeats a specific attack

**M1, bounded recency.** `s ← γ·s + θ` per good round, saturating at
`θ/(1−γ) = 4`. Defeats *reputation banking*: no amount of prior good behaviour
buys unbounded cushion. The ceiling is a consequence of the recurrence, not a
clamp.

**M2, earned forgetting.** `f` is sticky and never decays round-by-round; it
fades (×0.90) only after `FORGIVE_AFTER = 2` consecutive clean rounds. Defeats
*on-off attacks*: one good round launders nothing.

**M3, sustained escalation.** Two consecutive MAJORs route to probation/ban
**bypassing the score**. Defeats the *veteran sleeper*, whose banked `s` keeps
T above the threshold while it attacks. This is why M3 must be a rule rather than
a weight — any finite weight could be offset by enough banked history.

**Cold-start gate.** The score path is gated on the opinion being
evidence-dominated: `u < 0.5 ⟺ s + f > W_PRIOR = 2`. A device cannot be
sanctioned on its first noisy round. **M3 is deliberately ungated** — it is a
rule about repetition, not a claim about the score. Measured, Tier 3, repeated
MINOR:

```
after 1 MINOR: s+f=0.60  evidence_dominated=False  T=0.385  ACTIVE
after 2 MINOR: s+f=1.20  evidence_dominated=False  T=0.312  ACTIVE
after 3 MINOR: s+f=1.80  evidence_dominated=False  T=0.263  ACTIVE
after 4 MINOR: s+f=2.40  evidence_dominated=True   T=0.227  BANNED
```

T crosses `BAN_T` at round 2 but no sanction fires until the gate opens at round
4. **This table is worth including** — it makes the gate concrete.

**D5, due process.** An ACTIVE rehab-tier device hitting even `BAN_T` receives
PROBATION first; the backstop bans only from PROBATION onward.

**CRITICAL as a rule, not a weight.** Confirmed sybil collusion is identity
abuse. Any finite weight would let banked history offset it, so CRITICAL bans
non-compensably and ungated, regardless of tier.

### Verified sanction paths — put this table in Chapter 3

| Tier | 2× MAJOR | 1× CRITICAL | 4× MINOR |
|---|---|---|---|
| HARDWARE | ACTIVE → **PROBATION** | **BANNED** | ACTIVE×3 → **PROBATION** |
| TPM_RESIDENT | ACTIVE → **BANNED** | **BANNED** | ACTIVE×3 → **BANNED** |
| SOFTWARE | ACTIVE → **BANNED** | **BANNED** | ACTIVE×3 → **BANNED** |

One table, and the entire tier-coupling thesis is legible.

---

## 6. Probation and rehabilitation

Tier-1 only. A probated client's updates train an **isolated shadow model**: a
frozen global snapshot plus only that client's gradients. The global model is
never exposed to a suspect update during the trial.

```
REINSTATE_SLOPE  = 0.005   → REINSTATED
EXTEND_SLOPE     = 0.001   → EXTENDED once (+3 rounds), else PERMANENT_BAN
WINDOW = HMAC(device_id, entry_round) ∈ [4, 9], salt = os.urandom per process
SLOPE_ESTIMATOR  = "ols"   (theil_sen available for noisy MNIST)
```

`WINDOW_MIN = 4` is the shortest series where a single outlier cannot flip the
OLS sign. `WINDOW_MAX = 9` keeps a trial resolvable within trust memory. The
per-process HMAC salt is a security property, not an implementation detail: a
**fixed** window would let an attacker behave well for exactly that many rounds
and then resume. Randomising it per device and per entry round makes that
strategy unavailable. Worth calling out explicitly.

**Slope → reputation coupling.** The slope decides the *branch*; the trial rounds
are then credited as **earned evidence** (`s += trial_rounds · θ`) before the
0.75 floor. A longer demonstrated recovery returns with proportionally higher
trust. No new constants.

**One-shot.** A reinstated device that re-offends hits `REHAB_EXHAUSTED` →
permanent ban. Rehabilitation is a chance, not a renewable resource.

---

## 7. The chain layer

### Why it exists

The local audit log is tamper-**evident** but centralized: a reader must trust
the server that wrote it. Two concrete gaps followed:

1. **Restart erased sanctions.** Engine state was in memory. An attacker could
   wait out a restart. This was previously listed as a limitation.
2. **The ban ledger was unfalsifiable to a third party.** No way to check the
   server had applied its own rules.

### Guarantees

| ID | Guarantee |
|---|---|
| N20 | Semantic API: callers submit *severity*; the contract recomputes trust. There is no `submitState()`, so a server cannot assert an arbitrary score |
| N21 | Six rejection rules enforced **by EVM revert**, not by Python |
| N22 | EK privacy: only `ek_hmac = HMAC(fed_key, "DLTF-EKv1\|" + ek_hash)` goes on chain |
| N23 | **Bans survive restart** — `chain/reconcile.py` |
| N24 | Never on the critical path: node down → round UNANCHORED, training continues |
| N25 | Commitment layer: clients commit `keccak256(gradient)` before sending, so the server cannot fabricate an update |

### Rejection rules

| Rule | Custom error |
|---|---|
| BANNED → ACTIVE resurrection | `BanToActive` |
| tier change after enrollment | `TierMutation` |
| duplicate / stale round | `DuplicateRound` / `StaleRound` |
| one EK, two device ids | `EkAlreadyRegistered` |
| write from a non-server address | `UnauthorizedWriter` |
| classify unknown / banned device | `DeviceUnknown` / `DeviceBanned` |

N20 is worth a paragraph. A state-driven API (`submitState(deviceId, trust)`)
would make the contract a notary for whatever the server claims. A semantic API
makes it an *enforcer*: it recomputes from the submitted severity and reverts if
the result would violate the lifecycle.

### Reconciliation reads two ledgers, and must

| What | Source | Why |
|---|---|---|
| `s, f, clean_run, major_run, status, tier` | **chain** | authoritative: the contract rejected any illegal write |
| raw `ek_hash` | **local audit log** | the chain holds only the one-way HMAC |

This is load-bearing, not an implementation detail worth skipping. `register()`
decides O2 via `ek_hash in self._banned_ek`, where `ek_hash` is the **raw** hex
the handle presents. Seeding that set with HMAC digests would leave it non-empty,
make every lookup miss, and **silently re-admit every banned device** — O2 would
fail with no error anywhere. A permanent regression test guards it.

There is a nice observation for the thesis here: the privacy requirement (N22)
and the O2 requirement pull in opposite directions, and the resolution is to
split authority between the two ledgers rather than compromise either.

### Fixed-point parity

The contract cannot use floats, so `chain/fixedpoint.py` mirrors the engine in
integers at `SCALE = 1e6`. Proven bound `|T_float − T_fixed| ≤ 5e-6`, zero
measured status divergence. Bit-parity with the deployed contract verified after
**every** write across 6 rounds × 2 devices.

### Storage layout

One packed 256-bit word per device:

```
s(64) + f(64) + cleanRun(16) + majorRun(16) + status(8) + tier(8) + lastRound(32)
= 208 bits declared, 181 bits measured in use, of 256
```

One SSTORE slot per device is why per-round gas is flat in round count (§8).

### Commitment layer, and an asymmetry worth documenting

Clients commit `keccak256(canonical(gradient))` before transmitting;
canonical = little-endian IEEE-754 float64 (`struct.pack("<Nd", *G)`). A wallet
is bound to the TPM identity at enrollment via an AK signature over a
domain-separated challenge — one wallet, one device, immutable. `requireCommit`
is `immutable`, so a server cannot disable the rule mid-federation.

**Status: wired end to end.** The layer was previously verified only at contract
level; `config.CHAIN["require_commit"]` existed but nothing read it. It now runs
inside a live federation (`run_local.py --require-commit`), with each client
proving control of both its TPM and its wallet before committing.

Two submission paths:

| Path | Cost | Evidence lives in |
|---|---|---|
| `commitGradient` | client pays ~51,653 gas | contract storage |
| `classifySigned` (EIP-712) | client pays **zero**; server batches | `CommitProof` **event** |

**The Foundry suite surfaced a real asymmetry.** `classifySigned` deliberately
does *not* write `commitments[]` — a cold SSTORE is ~22,100 gas per client, which
is exactly the cost the signed path exists to avoid. Consequences:

- `getCommit()` returns **zero** for a valid signed commitment, so it is not a
  reliable "did this client commit?" oracle once that path is in use.
- The signed path lacks `commitGradient`'s `DuplicateCommit` protection, so a
  server can emit two `CommitProof` events for one round with different gradient
  hashes. It cannot *forge* either — both carry the client's signature — but an
  observer sees conflicting commitments with no on-chain tiebreak.

Neither is a vulnerability; both are honest limitations of the cheap path. State
them. Also state what the signed path gives up: **independent timestamping.** The
server controls submission and could withhold a signature, making a present
client look absent. The client retains its signature and can publish it, so this
is detectable, not prevented.

---

## 8. Results — what is measured, and what each number licenses

### Gas (solc 0.8.24, optimizer 200 runs, via-IR, Cancun)

| Operation | Gas |
|---|---:|
| deploy | 2,085,425 |
| register (fresh) | 95,344 |
| classify NEUTRAL (warm) | 36,186 |
| classify MINOR / MAJOR (warm) | 35,961 / 36,046 |
| classify CRITICAL → BAN | 62,075 |
| roundSummary | 91,367 |
| register (banned EK, whitewash) | 27,358 |
| bindWallet | 71,630 |
| commitGradient (client pays) | 51,653 |

**Cost model:** `round_gas = 58,282 + 38,818 × clients`, **R² = 1.000000**, max
residual 37 gas.

Affine, not proportional. Report the intercept/slope split rather than "gas per
client", because per-client cost *falls* from 67,968 (2 clients) to 41,733 (20)
purely as the fixed `roundSummary` amortises — quoting it alone would understate
the marginal cost of scaling.

> ⚠ Your docs say deploy = 1,397,314 and bytecode 6.5 KB or 8.9 KB. Measured:
> **2,085,425 gas and 9,941 bytes (9.7 KB)**. `--via-ir` is mandatory (the
> contract exceeds the 16-slot stack limit without it) and produces larger
> bytecode. Runtime per-operation gas is essentially unchanged, so most of your
> table survives; only deploy moves. EIP-170 limit is 24,576 bytes.
> Per-round at 6 clients: **291,180**, not ~309,000.

### Parity — the central claim

| Configurations | Max weight deviation | Max parameter deviation | Verdict |
|---|---|---|---|
| 6 (3 seeds × {mock, node}) | **0.000e+00** | **0.000e+00** | PASS |

Exact zeros, not "within tolerance". Enabling the chain — mock or deployed
contract — perturbs no trust value, no model parameter, and no ban decision.
**This is what licenses reusing your Chapter 4 accuracy results unchanged.**
Without it, every Chapter 4 number would need re-running per chain mode.

### Storage growth

| Metric | Value |
|---|---|
| round 0 gas (cold slots) | 290,869 |
| steady-state round gas | 292,185 (s.d. 2,928) |
| first-half vs second-half drift over 30 rounds | **0.15%** |
| device state | 6 devices × 1 packed word |
| max packed width | 181 of 256 bits |
| `roundClosed` slots | 30 (one per round — genuinely O(rounds)) |

**Why gas is a sound proxy** — include this reasoning, it is the interesting
part. Under EIP-2929/3529 a cold SSTORE to a zero slot costs 22,100 while a warm
non-zero update costs 5,000 or 2,900. Per-round gas is therefore dominated by how
many *new* slots that round touched. Flat gas across 30 rounds ⇒ no new
per-device slots ⇒ the packed word is being overwritten in place. That is the
O(devices) claim, measured rather than asserted. Report the O(rounds)
`roundClosed` term rather than hiding it.

### Reconciliation

| Rounds | Events | Rebuild (ms) | µs/event | Verify (ms) |
|---:|---:|---:|---:|---:|
| 10 | 77 | 0.18 | 2.29 | 0.14 |
| 50 | 357 | 0.59 | 1.65 | 0.58 |
| 100 | 707 | 1.18 | 1.67 | 1.04 |
| 200 | 1,407 | 2.26 | 1.61 | 2.19 |

Linear at ~1.6 µs/event, constant *falling* slightly as setup amortises. 200
rounds of history rebuilds in **2.3 ms** and independently re-verifies in 2.2 ms.
The N23 guarantee is effectively free.

### Latency, and the caveat that must accompany it

| Mode | 2 | 5 | 10 | 20 | 50 clients |
|---|---:|---:|---:|---:|---:|
| off (ms/round) | 0.284 | 0.641 | 1.579 | 4.269 | 17.680 |
| mock (ms/round) | 0.469 | 0.900 | 1.905 | 4.555 | 19.454 |
| **mock overhead** | 0.185 | 0.258 | 0.325 | 0.287 | 1.774 |
| node, in-process py-evm | 266 | 585 | 1,111 | 2,231 | 5,593 |

Mock overhead is near-constant and sub-2 ms while training time grows 60×.

> ⚠ **Absolute node latency does not transfer, in either direction.** py-evm is a
> pure-Python interpreter: it *over*-states bytecode execution relative to Anvil
> (Rust) or Geth, and *under*-states transport (no socket, no block time). It is
> a different regime, not a bound. Use the SIM curve for the *shape* of the
> scaling relationship and quote absolutes only from `--exp real` on the physical
> machines.
>
> Also drop percentages. SIM training is a 20-dimensional numpy step costing
> under a millisecond, so overhead-as-percentage inflates absurdly (86,000%+).
> Absolute milliseconds transfer; percentages do not.

### Test counts

| Suite | Checks |
|---|---|
| Python module self-tests | 274 ✓ across 22 modules |
| Chain integration groups | 9 |
| Foundry contract tests | 34 |

Two independent contract test implementations (Python parity + Solidity-native)
that agree is a defensible verification story. Say so.

---

## 9. Limitations — write ALL of these

**Detection requires n ≥ 3.** Measured: with exactly 2 clients, `scale`, `flip`
and `sleeper` all go **undetected** (NEUTRAL). Stage 1 compares against the
median of all norms including the attacker's, and with n=2 the median lands
between the two values (norms [1,10] → median 5.5 → ratio 1.82 < 2.5). Stage 2's
"robust reference" degenerates to a single noisy client. Your 2-machine
deployment demonstrates identity, enrollment, tiering and sybil collusion — not
the median-based stages. **Fix: run a third agent** (see the runbook).

**X.509 path validation is simplified.** Name chaining plus signature checks; no
revocation, no full RFC 5280, no EK-profile OID enforcement.

**Plain HTTP at the request level.** Mitigated by Tailscale/WireGuard in
deployment. Request-level authentication is future work.

**Tier 1 only where a verifiable EK certificate exists.** The claim is
"whitewashing becomes hardware-cost-bound", never "impossible".

**Reconciliation restores trust state, not model state.** The global parameter
vector is not on chain; `run_local.py` carries it in-process across a restart. A
real deployment checkpoints separately. Orthogonal to the trust claim but state
it before someone asks.

**The on-chain ban check fails OPEN.** If the node is unreachable,
`is_banned_on_chain()` returns False and enrollment proceeds. Failing closed
would hand anyone who can DoS the node a federation-wide enrollment DoS. The
staleness window is a deliberate trade, not an oversight.

**Server is the only authorised writer.** The contract prevents *illegal*
writes, not *withheld* ones. A server can decline to report a classification.
Detectable by a third party comparing rounds anchored versus rounds run, but not
prevented.

**Signed commitments give up independent timestamping** (§7).

**Small federation.** 2 real (3 with the local agent), ≤50 simulated.

**Synthetic substrate for trust metrics.** Chapter 4's reputation trajectories
use a synthetic gradient generator; MNIST accuracy is measured separately. This
is deliberate — it isolates the trust dynamics from model-convergence noise —
but say so.

**Several constants remain [CALIBRATED]** within derived bounds (`d2`, `d3`,
`FORGIVE_AFTER`, `BAN_T`, `MAJOR_RUN_TO_ESCALATE`), defended by sweep rather than
citation.

**Uncertainty `u` never reaches zero** (bounded memory). Deliberate — it is what
defeats sleepers.

**Anvil/Hardhat is a development chain.** No consensus, no finality, no gas
market. Deploying to a public chain changes cost and latency, not correctness.

---

## 10. Related work — positioning per source

| Work | What it gives DLTF | What DLTF adds |
|---|---|---|
| **Josang 2001** | subjective logic; `T = E = b + a·u`; W=2, a=0.5; Def.10 ordering = `rank()` | tier-coupled consequences, bounded memory |
| **Kang 2019/2020** | θ=0.4, τ=0.6 (Table I); negative > positive; recent > past | hardware-bound identity, so reputation is not re-registrable |
| **Sui 2024** | documents Kang's new-vs-old-client flaw | the flaw DLTF's EK binding fixes — the same one your supervisor flagged |
| **Fung 2018 (FoolsGold)** | the similarity stage (stage 3) | identity for detection to bind to; consequences beyond exclusion |
| **Friedman & Resnick 2001** | the cheap-pseudonym problem | a hardware answer to it |
| **Ostrom 1990** | graduated sanctions | graduation *as a function of identity cost* |
| **Wang 2022** | TPM + blockchain in FL | TPM for persistent *identity*, not just update integrity ⚠ **missing from REFERENCES.md** |
| **Slovic 1993** | trust asymmetry | v3 gets asymmetry from *when* forgetting is allowed, not from a different rate — cite carefully |

⚠ Reference [24] Domingo-Ferrer marked VERIFY.

**Framing sentence for Chapter 2:** every FL reputation system assumes exclusion
costs the excluded party something. In an open federation it does not. DLTF makes
that assumption true rather than assuming it.

---

## 11. Chapter plan

**Ch. 1 Introduction.** The problem from §1. Objectives table from §2. State the
non-claims from §0 early — it buys credibility cheaply.

**Ch. 2 Literature review.** §10. Build to the gap: detection is mature,
identity is not, and reputation over re-registrable identities is unfalsifiable.

**Ch. 3 Methodology.** The largest chapter.
- Threat model (§3), including T21–T30 from `LATEX_CHANGES.md`
- Architecture and the three axes (§4)
- TPM identity and tiering (§4 enrollment path)
- Reputation engine (§5) — lead with tier-neutrality; include the constants
  table with provenance, the sanction-path table, and the cold-start gate trace
- Probation (§6), emphasising HMAC window randomisation
- Chain layer (§7) — N20–N25, the two-ledger split, fixed-point parity
- Requirements N18–N27 with traceability (`LATEX_CHANGES.md`)

**Ch. 4 Trust-model evaluation.** ⚠ **Must be re-run** (§12). Sanction paths per
tier, attacker cost, sensitivity sweep, whitewash blocking rate.

**Ch. 5 System evaluation.** §8. Gas, the affine cost model, storage growth with
the EIP-2929 reasoning, reconciliation, latency *with* the py-evm caveat,
REAL-mode table once measured, live attack demo transcript.

**Ch. 6 Limitations and future work.** §9, all of it. Future: revocation, public
chain deployment, request-level auth, larger federation, cross-manufacturer CA
support.

**Ch. 7 Conclusion.** The four novelty points from §2.

### Figures available now

| File | Shows |
|---|---|
| `fig_gas_clients.png` | measured gas + fitted affine model + fixed-cost line |
| `fig_storage.png` | per-round gas flat across 30 rounds |
| `fig_latency.png` | latency vs clients, 3 modes, log y-axis |
| `fig_latency_mock.png` | off vs mock + overhead bars |
| `fig_reconcile.png` | rebuild and verify time vs history |

`results/chain/TABLES.md` has paste-ready LaTeX under BRACU constraints:
`tabular` with `\hline` only, no `booktabs`, `longtable`, `amssymb`, `tikz`,
`listings`, `float`, or `subcaption`. Figures are external PNGs. biblatex/biber,
IEEE style.

---

## 12. Before you write: the one real blocker

**Chapter 4's CSVs must be re-run.** Every file in `results/` was generated under
v2.1 — per-tier priors, FORGET = 0.95, `w(MAJOR) = 3`. v3 uses a uniform
Beta(1,1) prior, FORGET = 0.90, and MINOR == MAJOR in evidence weight.
**Every trust trajectory has shifted.**

```bash
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```

Chain off. Before running: `grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/` —
CRITICAL is not a `BAD_EVIDENCE` key and any code reading it will KeyError.

Corroborating evidence that the CSVs really are stale: `net/handles.py:99`
asserts `0.3 <= w <= 0.5`, but v3 gives a fresh Tier-2 device `s=0.4, f=0 →
T=0.5833 → w=0.2917` after one clean round. Same staleness, surfacing in a
self-test. Fix that band to `0.25 <= w <= 0.35`.

**Write Chapters 1, 2, 3, 6 now** — they do not depend on Chapter 4's numbers.
Chapter 5's chain results are already measured and stable. Only Chapter 4, and
whatever Chapter 5 says about trust trajectories, needs the re-run.

### Housekeeping before submission

- Resolve the client2 IP conflict (`100.73.178.45` vs `100.64.57.82`)
- Move v1 chain work (`trust/chain_bridge.py`, `trust/ReputationRegistry.sol`,
  `trust/deploy_chain.py`, `trust/test_parity.py`, `build/registry_dev.json`) to
  `legacy/` — two implementations in the import path invites "which one is the
  contribution?"
- `diff chain/reputation.py trust/reputation.py` and delete the loser
- `check_tiers.py` is referenced in docs but absent — write it or drop it
- Add Wang 2022 to REFERENCES.md; verify reference [24]
- Remove stray `dsadas/`; check `chain/files/`
- Confirm `audit/hashchain.py` is not the placeholder:
  `grep -n "def verify\|def head_hash" audit/hashchain.py`

---

## Addendum (2026-11-17): status shifts since this document

The content above (claims-not-to-make, constant provenance, threat model,
engine design, limitations) remains the writing authority. Status changes:

1. **Writing target shifted** from the BRACU thesis chapter plan (§11) to an
   **ACM NSysS 6–8-page paper** (acmart sigconf v2.19; CLAUDE.md §2,
   `eval/RUNBOOK.md`). The content maps directly; the chapter plan is now a
   structure guide, not a deliverable list. Keep the two tracks' LaTeX
   constraints separate (MASTER_CONTEXT §16.11).
2. **The Chapter-4 blocker (§12) is cleared** — data regenerated under v3,
   all checks passed (`RESULTS_EXPLAINED.md` §4).
3. **§9 limitations partially addressed:** the "Anvil is a development chain /
   server is sole writer" limitation now has a measured counterpoint — the
   4-validator QBFT stage ran (2b liveness, 2c enforcement by consensus;
   18/19 preflight, one open POA bug). The Docker-on-one-host ceiling and the
   stealthy-directed-deviation limitation are unchanged.
4. **New material for the paper:** commitment-layer cost (signed path 42%
   cheaper), the liveness split verdict + async backlog collateral, economics
   in currency (~380× attack-vs-ledger ratio). See `MASTER_CONTEXT.md` §15.
5. **Housekeeping done:** v1 in `trust/legacy/`, `dsadas/` removed,
   `chain/reputation.py` duplicate deleted, `audit/hashchain.py` is the full
   interface (not the placeholder), docs consolidated (`docs/INDEX.md`).
