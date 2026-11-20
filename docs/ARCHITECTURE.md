# DLTF — Full Architecture Breakdown

> Written 2026-11-18, grounded in the live code (fl/server.py, net/handles.py,
> net/agent.py, trust/filter.py, audit/hashchain.py, chain/registry.py,
> chain/commit.py, run_server.py) and the consolidated docs. Companion to
> `MASTER_CONTEXT.md` (authoritative constants/state) and `docs/INDEX.md`.

## 0. The essence in one paragraph

DLTF is a **trust layer wrapped around a federated learning (FL) system**.
Clients train a shared model locally and send gradient updates to a server.
DLTF decides *how much each client's update counts*, based on a reputation
score that is driven by behavior but whose **consequences** are indexed to
hardware identity (a TPM 2.0 chip). Misbehaving devices get banned, and the
ban binds to the chip's Endorsement Key hash — so re-registering under a new
name doesn't shed it ("whitewashing"). Optionally, a **Solidity contract on an
EVM chain enforces the trust lifecycle**, so even a dishonest *server
operator* cannot silently un-ban someone or fabricate updates — and a third
party can verify the whole history without trusting the server.

**The central claim is not better detection.** Detection uses existing
techniques. The contribution is what happens *after* detection: a durable,
hardware-cost-bound, independently-verifiable sanction-and-rehabilitation
lifecycle.

---

## 1. Bird's-eye view

```
                        ┌─────────────────────────────────────────────┐
                        │              ORCHESTRATION                  │
                        │  run_local.py (SIM, 1 PC)                   │
                        │  run_server.py (REAL, 3 PCs, Tailscale)     │
                        │  config.py = topology + CHAIN block         │
                        └──────────────────┬──────────────────────────┘
                                           │
        ┌──────────────────────────────────▼──────────────────────────────────┐
        │                  FederatedServer  (fl/server.py)                    │
        │        enroll()  +  run_round()  — where all layers meet            │
        └──┬──────────┬───────────┬───────────┬───────────┬──────────────┬────┘
           │          │           │           │           │              │
     ┌─────▼────┐ ┌───▼────┐ ┌────▼─────┐ ┌───▼─────┐ ┌───▼────┐   ┌─────▼─────┐
     │ tpm/     │ │ trust/ │ │ trust/   │ │ trust/  │ │ fl/    │   │ audit=    │
     │ identity │ │ filter │ │ reputation│ │probation│ │ model/ │   │ HashChain │
     │ EK/AK,   │ │ detect │ │ v3 score │ │ rehab   │ │ data/  │   │    or     │
     │ tiers    │ │ 4 stages│ │ + policy │ │ shadow  │ │ aggr.  │   │ ChainRegistry
     └──────────┘ └────────┘ └──────────┘ └─────────┘ └────────┘   └─────┬─────┘
                                                                          │ mirrors
                                              ┌───────────────────────────▼──────────┐
                                              │        chain/  (optional layer)      │
                                              │ registry → backend (mock | evm)      │
                                              │ commit / signer / async_writer /     │
                                              │ deploy / reconcile / verifier        │
                                              └───────────────────┬──────────────────┘
                                                                  │ JSON-RPC / in-proc EVM
                                              ┌───────────────────▼──────────────────┐
                                              │ contracts/src/DLTFRegistry.sol       │
                                              │ Anvil / Hardhat / eth-tester /       │
                                              │ 4-validator Besu QBFT (qbft/)        │
                                              └──────────────────────────────────────┘

   Transport seam (net/):  LocalClientHandle (in-process)  ↔  RemoteClientHandle (HTTP)
                                                              ↕
                                              net/agent.py on each client PC (:8470)
```

**Three independent axes** — never coupled, all combinations run:

| Axis | Options | Switch |
|---|---|---|
| TPM identity | mock / swtpm / real hardware | `make_signer()`, `config.CLIENTS[].tpm_backend` |
| Transport + data | in-process synthetic / HTTP + real MNIST | `LocalClientHandle` vs `RemoteClientHandle` |
| Chain | off / mock / node | `--chain`, `DLTF_CHAIN` env |

The chain layer sees only `(event_type, payload)` — it cannot tell SIM from
REAL. That's why every result transfers between modes.

---

## 2. Layer 1 — Hardware identity (`tpm/`)

**Goal: O1 (one chip = one identity) and the foundation for O2 (bans bind to
hardware).**

Each client has a TPM 2.0 chip with:
- **EK (Endorsement Key)** — a device-bound RSA key burned into the chip at
  manufacture. `ek_hash = SHA256(EK_pub)` is the identity fingerprint.
- **AK (Attestation Key)** — a restricted signing key created inside the TPM,
  used for quotes and (in v3) wallet-binding signatures.
- **EK certificate** — manufacturer-signed (AMD) proof that the EK lives in
  genuine silicon.

**Enrollment protocol** (JSON over HTTP, binary fields base64):

```
client → server   POST /enroll    ⟨device_label, ek_hash, ak_name, ek_cert, ek_pub⟩
server → client   POST /activate  ⟨blob⟩  where blob = MakeCredential(ek_pub, secret)
client → server                 ⟨secret'⟩ where secret' = ActivateCredential(blob)
```

`MakeCredential` encrypts a secret so that **only a TPM physically holding
that EK can decrypt it** (credential activation). The server compares the
answer with `hmac.compare_digest`. This is what makes identity unforgeable in
software — a Sybil can't mint a new TPM.

**Tier gate** (`fl/server.py:enroll` → `tpm.common.assess_tier`):

```
cert_ok = (cert present) AND (CA bundle loaded) AND verify_ek_certificate(cert, bundle)
tier    = assess_tier(cert_ok, activation_ok)
```

| Tier | Condition | Meaning |
|---|---|---|
| 1 HARDWARE | cert verified **AND** activation passed | certified silicon |
| 2 TPM_RESIDENT | activation passed, no verifiable cert | real TPM, unproven provenance |
| 3 SOFTWARE | no hardware proof | TOFU / mock |

**The AMD quirks that cost real debugging time** (see `FETCH_EK_CERT.md`):
- AMD EK certs are *technically malformed* (non-spec DEFAULT encoding on a
  critical extension field). Python's strict X.509 parser rejects them →
  `verify_ek_certificate` falls back to `openssl verify -partial_chain`. Both
  paths are needed.
- AMD chips chain through **different intermediates** (CN=PRG-RN vs
  CN=PRG-SSP). The CA bundle (`tpm/ca/amd_ftpm_ca.pem`) must contain **both**
  + the AMDTPM root, or valid certs silently downgrade everyone to Tier 2.
- Certs are read **from disk first** (`cert/ek.crt`, per-machine, never
  shared); live fetch from AMD's PKI is flaky and has returned a different,
  failing cert.
- Not all AMD fTPMs expose a cert at all (board/BIOS provisioning) — the tier
  model degrades correctly.

**v3 addition — wallet binding:** `tpm/client.py` gained `sign_message(bytes)`
(signs arbitrary bytes with the AK via `tpm2_sign`, RSASSA/SHA-256) and
server-side `verify_ak_signature`. Deliberately separate from `sign_challenge`
(which produces a PCR *quote*, not a signature over caller bytes — overloading
it would have produced unverifiable wallet bindings).

---

## 3. Layer 2 — Detection (`trust/filter.py`)

**Explicitly NOT the contribution.** Four established techniques, one per
attack class, combined by max-severity. Its only contract with the rest of the
system: emit severity strings (`NEUTRAL/MINOR/MAJOR/CRITICAL`).

| Stage | Test | Threshold | Emits | Catches |
|---|---|---|---|---|
| 1 | `‖g‖ > 2.5 × median(‖all‖)` | `NORM_CLIP_FACTOR=2.5` | MINOR | scaling attacks |
| 2 | `cos(g, robust_ref) < −0.45` | `COSINE_MEDIAN_THRESHOLD` | MAJOR | targeted poisoning |
| 3 | pairwise `cos ≥ 0.95`, **sustained 2 rounds** | FoolsGold-style | CRITICAL | Sybil collusion |
| 4 | `cos(g, own_history_mean) < −0.45`, sustained 2 rounds | temporal flip | MAJOR | sleeper agents |

Robustness details that matter (all in the code):
- The **reference direction** is the coordinate-wise median over devices that
  held *positive weight last round* — zero-weight Sybils can't drag it.
- It's **leave-one-out**: the evaluated client is excluded from its own
  reference, so an attacker can't dilute the yardstick it's measured against.
- Stage 3 compares **current-round** updates (not cumulative history): honest
  clients share a descent direction but inject fresh noise each round;
  colluding Sybils submit near-identical updates every round.
- Stage 4 needs history ≥ 3 rounds (window 10) and **2 consecutive** flip
  rounds — noise doesn't anti-correlate twice in a row; persistent attackers do.
- **History is written after classification, never before.**
- The −0.45 threshold is the **measured knee** of the FPR/latency sweep (zero
  FPR, zero latency; loosening to −0.15 explodes FPR to 22.9%). This is the
  defense for "why 0.45?" — calibration, not taste.

**Known measured limit:** with exactly **2 clients**, median-based stages
mathematically cannot fire (`[1,10] → median 5.5 → ratio 1.82 < 2.5`).
Detection demos need **n ≥ 3** — hence the third-agent requirement in REAL
mode.

---

## 4. Layer 3 — The reputation engine (`trust/reputation.py`, v3)

A **strict black box** — the chain layer mirrors it but never edits it.
Bayesian reputation in Jøsang subjective-logic form.

### The score

```
T = (α₀ + s) / (α₀ + β₀ + s + f)   with α₀ = β₀ = 1  (uniform Beta(1,1))
w = D(tier) · T      (0 if BANNED)
```

`s` = accumulated good evidence, `f` = accumulated bad evidence. Opinion
`(b,d,u,a)` exposed; `rank()` = Jøsang Def.10 ordering.

### The v3 design decision: identity-blind score, tier-coupled policy

Every tier starts at **T₀ = 0.5** with the same prior and dynamics. Tier
enters at exactly **three places, none of them the score**:

1. **Weight cap** `D = {HARDWARE: 1.0, TPM_RESIDENT: 0.5, SOFTWARE: 0.1}`
2. **Rehabilitation eligibility** `REHAB = {HW: True, T2: False, T3: False}`
3. **EK-bound ban list** — only a real EK can be banned durably

> *Behaviour determines trust; hardware determines consequences.* A verified
> TPM says the machine is **accountable**, not that it is **honest** — giving
> Tier 1 a score head-start conflated the two (that was v2.1, retired).

### Update rule (from live code)

```
POSITIVE|NEUTRAL:  s ← γ·s + θ ; clean_run += 1 ; major_run ← 0
                   if clean_run ≥ FORGIVE_AFTER:  f ← f · FORGET
MINOR|MAJOR:       s ← γ·s ; f ← f + τ ; clean_run ← 0
                   major_run += 1 if MAJOR else 0
CRITICAL:          a RULE, not a weight — immediate, non-compensable ban
```

### Constants (all read back from code, with provenance grades)

| Constant | Value | Provenance |
|---|---|---|
| θ (THETA) | 0.4 | **[CITED]** Kang 2019 Tab. I |
| τ (TAU) | 0.6 | **[CITED]** Kang 2019 (negative > positive) |
| γ (GAMMA) | 0.90 | [CONVENTIONAL] |
| FORGET | **0.90 = γ** | **[DERIVED]** — one decay primitive, not two |
| FORGIVE_AFTER | 2 | [CALIBRATED] — one clean round launders nothing |
| PROBATION_T | 0.5 | [CALIBRATED] indifference point |
| BAN_T | 0.3 | [CALIBRATED] backstop |
| REINSTATE_T | **0.75** | **[DERIVED]** closed form `0.5·(1+1/W)` |
| MAJOR_RUN_TO_ESCALATE | 2 | [CALIBRATED] |
| PROBATION_WEIGHT_CAP (d3) | 0.1 | suspect ≤ unproven identity |

Derived: `S_MAX = θ/(1−γ) = 4` → **trust ceiling 0.8333**; u-gate opens when
`s+f > W_PRIOR = 2`.

**MINOR and MAJOR carry the same evidence weight (0.6).** They differ only in
that MAJOR feeds `major_run` (the M3 rule). Severity selects the *rule*, not
the *magnitude*.

### Hardening mechanisms

- **M1 bounded recency** — `s ← γs + θ` saturates at 4. A sleeper cannot bank
  unbounded cushion (this is why `--tier1` weights plateau at ~0.807→0.833).
- **M2 earned forgetting** — `f` is sticky; it fades ×0.90 **only after 2
  consecutive clean rounds**. Defeats on-off attacks. The trust/distrust
  asymmetry comes from *when* forgetting is allowed, not a different rate (the
  old Slovic "5:1 ratio" story is retired).
- **M3 sustained escalation** — 2 consecutive MAJORs → probation/ban
  **bypassing the score**, catching a high-`s` veteran sleeper while T > 0.5.
  Ungated.
- **D4 cold-start gate** — score-path sanctions require the opinion to be
  evidence-dominated (`s+f > 2`). A fresh device's first noisy round
  (T=0.385 < BAN_T) does **not** sanction; the gate opens at round 4. Measured,
  one full round of protection.
- **D5 due process** — an ACTIVE rehab-tier device crossing even BAN_T gets
  PROBATION first; the backstop bans only from PROBATION onward (except
  CRITICAL).

### State machine (check order pinned: backstop → M3 → probation)

```
∅ → ACTIVE        register(), ek_hash ∉ banned
∅ → BANNED        register(), ek_hash ∈ banned   ← this is O2
ACTIVE|PROB → BANNED    CRITICAL (ungated)
ACTIVE → PROBATION      T ≤ 0.3 or T ≤ 0.5 or M3, gate open, REHAB
ACTIVE|PROB → BANNED    same triggers, not REHAB / already PROBATION
PROBATION → ACTIVE      reinstate() only
```

**BANNED is absorbing — no code path back to ACTIVE.** There is one
*deliberate* latent hole: `register(id, tier)` with `ek_hash=None` resurrects
a banned device. It's unreachable from `fl/server.py` (always passes the EK
hash), and it's **left in place on purpose**: the chain layer catches the
resurrection (`EkAlreadyRegistered` / `BanToActive`), making it a live demo of
the contract's value. Do not "fix" it.

---

## 5. Layer 4 — Rehabilitation (`trust/probation.py`)

Tier-1-only, one-shot. A probated client's updates train an **isolated shadow
model** (frozen global snapshot + only that client's gradients) — it cannot
poison the real model while on trial.

```
WINDOW = HMAC(device_id, entry_round) ∈ [4, 9]   (per-process random salt)
slope  = OLS(shadow accuracy over trial window)
slope ≥ 0.005  → REINSTATED
slope ≥ 0.001  → EXTENDED once (+3 rounds), else PERMANENT_BAN
```

- The **HMAC-randomized window** blocks "behave just long enough" timing
  attacks (the device can't predict when it will be judged). Window bounds are
  derived: 4 = OLS sign-stability floor, 9 = trust-memory horizon `1/(1−γ)−1`.
- **Slope→reputation coupling:** the slope decides the *branch*; the trial
  rounds are forwarded as **earned evidence** (`s += θ·rounds`) before the
  **REINSTATE_T = 0.75 floor**. A longer proven recovery returns with
  proportionally higher trust. (0.75/(1−0.75)=3 exactly → the on-chain floor
  `need_s = 3f+2` is exact integer arithmetic.)
- **One-shot:** a reinstated device that re-offends → `REHAB_EXHAUSTED` →
  permanent ban, no second trial.
- Measured: **5/5 genuinely recovering devices reinstated, 0/5 persistent
  attackers reinstated**, across 5 seeds. Perfect separation — this is what
  makes rehabilitation a mechanism, not a loophole.
- Subtlety: the shadow evaluator must use **linear-response, not cosine**
  (cosine saturates in 1–2 rounds → near-zero slope → honest clients fail).

---

## 6. Layer 5 — The FL substrate (`fl/`)

Deliberately textbook, so the trust layer's effect is isolated:
- **`model.py`** — a 409,034-parameter CNN on MNIST (real mode); SIM uses
  synthetic gradient vectors.
- **`dataset.py`** — conventional non-IID partitioning; all agents partition
  identically (same seed + client count), each taking its shard.
- **`aggregator.py`** — FedAvg, Krum, trimmed-mean, selected by name.
- **O4 (aggregator-agnostic):** the trust layer outputs a plain
  `dict[str, float]` of weights. Banned devices are **absent** from the dict →
  structurally excluded. Krum uses the weights as an *eligibility mask*. One
  unmodified weight dictionary composes in front of all three aggregators —
  measured: restores Krum accuracy from 0.053 → 0.637 under attack.

---

## 7. The seam — `FederatedServer` (`fl/server.py`)

This is where everything meets. Two methods:

### `enroll(handle)`
1. `handle.enroll_payload()` → EK hash, AK name, optional cert.
2. Verify cert against the manufacturer CA bundle (if loaded).
3. Issue MakeCredential challenge → `handle.activate_credential(blob)` →
   constant-time compare.
4. `assess_tier(cert_ok, activation_ok)` → `rep.register(label, tier, ek_hash)`.
5. If register returns BANNED → audit `WHITEWASH_REJECTED`. **The device never
   gets a nonzero weight or trains a single round.**

### `run_round(round_id, handles)` — the exact sequence
```
1. active = enrolled AND status ≠ BANNED          ← exclusion is structural
2. updates[label] = handle.train(round, global_params)
3. classifications = filter.classify(round, updates, prev_weights)
4. for each device:
     rep.record_event(label, severity)            ← score + state machine
     audit EVENT (only if severity ≠ NEUTRAL)     ← the sparsity that matters later
     audit BAN on transition to BANNED
     on ACTIVE→PROBATION: probation.enter_probation(...)
        audit PROBATION_ENTER or REHAB_EXHAUSTED
5. probation.step(round, probationers' updates, shadow_eval_fn)
6. weights = rep.get_all_weights()
7. agg = aggregator(updates, weights);  global_params += agg
8. audit PROBATION_DECISION(s), then ROUND {round, participants, aggregated}
9. return report {events, weights, probation_decisions, aggregated}
```

The server is **transport-agnostic**: it talks only to objects exposing
`.device_label .tpm_backend .enroll_payload() .activate_credential(blob)
.train(r, params)`. That five-method surface is the entire integration seam.

---

## 8. Transport (`net/`) — SIM vs REAL

- **`LocalClientHandle`** — in-process signer + FLClient (SIM).
- **`RemoteClientHandle`** — HTTP proxy to a client PC (REAL): `POST /enroll`,
  `/activate`, `/train` (train timeout 600 s for real MNIST).
- **`net/agent.py`** — the per-client HTTP server (`ThreadingHTTPServer`, port
  8470) exposing that machine's TPM signer and trainer. Endpoints:
  `GET /health`, `POST /enroll`, `/activate`, `/train`, **`/bind-wallet`**.
  Also carries the `--attack` profiles (flip / sybil / sleeper / scale, with
  `--attack-seed`, `--attack-after`) used for the live attack demos.

**REAL deployment** (3 Ryzen boxes, AMD fTPMs, Tailscale WireGuard mesh —
required because Bangladeshi CGNAT blocks inbound):
```
100.95.144.127 (ubuntu)   → SERVER   run_server.py
100.70.28.2   (s4zz4d HP) → client1  net/agent.py
100.64.57.82  (tafsir HP) → client2  net/agent.py
```
The **server dials out** to clients; clients never dial the server. Both
clients enroll as real Tier 1 with distinct EK hashes. Plain HTTP at request
level, mitigated by WireGuard encryption (request-level auth is a stated
limitation).

**Commit ordering is a security property:** both handles commit the gradient
hash **before** `train()` returns / before the update leaves the machine. A
commitment made *after* handing over the update proves nothing — the recipient
already had the chance to substitute it.

---

## 9. Local audit (`audit/hashchain.py`)

An append-only, **HMAC-signed hash chain** (JSONL on disk,
`results/audit.jsonl`):

```
entry = {seq, ts, type, payload, prev, hash, sig}
hash  = HMAC-SHA256(key, prev_hash_hex + canonical_json(body))
GENESIS = 64 zeros, auto-appended
verify() → (ok, err)  recomputes every link
```

Event types: `ENROLL, EVENT, BAN, WHITEWASH_REJECTED, PROBATION_ENTER,
PROBATION_DECISION, REHAB_EXHAUSTED, ROUND`.

**What it proves:** nobody *edited* the log. **What it cannot prove:** that
the log's contents are *true* — a dishonest server can write a plausible
fiction. That gap is exactly what the chain layer closes.

**Critical quirk — NEUTRAL sparsity:** `fl/server.py` skips NEUTRAL
classifications when logging. But NEUTRAL is precisely what decays `s`,
increments `clean_run`, and forgives `f`. **The audit log alone cannot
reconstruct reputation state.** The chain adapter solves this by inference
(next section), without touching the server.

---

## 10. The chain layer (`chain/` + `contracts/`) — the heart of the contribution

### Why it exists (threat-model amendment)

The hash chain is verifiable but **centralized** — you must trust the server
that wrote it. The chain layer extends the threat model to a
**partially-adversarial server operator** (threats T21–T26, requirements
N18–N23). Core principle:

> **On-chain policy ENFORCEMENT, not on-chain logging.** The hash chain
> records whatever the server writes. The contract **REJECTS** writes that
> violate the trust lifecycle. That rejection capability is the entire
> justification.

### The contract (`contracts/src/DLTFRegistry.sol`)

**Semantic API (N20):** there is **no `submitState()`**. Callers submit a
*severity*; the contract **recomputes** reputation in fixed-point arithmetic.
A server cannot assert an arbitrary score — structurally.

**Six rejection rules, enforced by EVM revert:**

| Rule | Custom error |
|---|---|
| BANNED → ACTIVE by any path | `BanToActive` |
| tier change after enrollment | `TierMutation` |
| reputation delta outside the rule | structural — no delta API exists |
| duplicate / out-of-order round | `DuplicateRound` / `StaleRound` |
| one EK, two device ids | `EkAlreadyRegistered` |
| write from non-server address | `UnauthorizedWriter` |

**Fixed-point mirror (`chain/fixedpoint.py`):** Solidity has no floats.
Integer arithmetic at `SCALE = 10⁶`, chosen so every constant is exactly
representable (θ→400000, τ→600000, thresholds 300000/500000/750000). Only
**one** operation truncates: `decay(x) = 9x//10` — Solidity `/` and Python `//`
are both floor → bit-identical by construction. Threshold tests use
**cross-multiplication** (`(1+s)·SCALE ≤ t·(2+s+f)`) — exact, no division on
the decision path. Proven bound `|T_float − T_fixed| ≤ 5×10⁻⁶`; measured over
80,000 random events: **zero status decisions differ**.

**Storage:** one packed 256-bit slot per device —
`s(64)+f(64)+cleanRun(16)+majorRun(16)+status(8)+tier(8)+lastRound(32)` =
**208 bits declared**, one *warm* SSTORE per device per round. (Measured
`bit_length()` varies 169/179/181 with the last round — quote 208.) This is
why per-round gas is flat in round count: state is **O(devices), not
O(rounds)** (0.15% drift over 30 rounds).

**EK privacy (N22):** raw EK hashes **never** go on chain (a permanent
physical-machine fingerprint on an immutable ledger). Instead:
```
ek_hmac = HMAC-SHA256(federation_key, "DLTF-EKv1|" + ek_hash)
```
The federation key (`results/federation.key`, mode 0600) **must be independent
of the audit key** — sharing it would let anyone who can verify the audit log
de-anonymise every EK. Key rotation ≈ GDPR-style erasure (destroying the key
makes existing ek_hmacs unlinkable).

**Toolchain discipline:** solc **pinned to 0.8.24** (measured: 0.8.31 moves
deploy gas by −49,167, invalidating the thesis figure for no benefit);
`--via-ir` **mandatory** (stack-too-deep in `_classifyCore` otherwise);
Foundry project in `contracts/` with two test suites (Rules N18–N22,
Commitment N24–N28). Truffle/Ganache are dead (archived 2023).

### The adapter (`chain/registry.py`) — how it drops in with zero server changes

`ChainRegistry` implements the **exact HashChain surface**
(`append/entries/verify/head_hash/__len__`), so
`FederatedServer(audit=registry)` works unchanged. Mechanics:

1. **Forward to the inner HashChain FIRST** — the local log is byte-identical
   to chain-off.
2. **Mirror semantics** onto a Backend:
   - `ENROLL` → `backend.register(writer, label, tier, ek_hmac)` immediately.
   - `EVENT`, `PROBATION_*` → **buffered** per round.
   - `BAN`, `WHITEWASH_REJECTED` → **ignored** (they're *consequences* the
     backend already cascades; dispatching them would double-count).
3. On `ROUND` → **flush**:
   - **Infer NEUTRALs**: participants minus devices-with-an-EVENT = the
     NEUTRAL set. **Exact, not heuristic** — with a safety proof: a device
     that transitions status always has a logged non-NEUTRAL event (NEUTRAL
     can't cross any threshold in the sanctioning direction), so no device
     gets both an inferred NEUTRAL and a transition event.
   - Dispatch buffered events in arrival order (per-device order preserved;
     cross-device order irrelevant — the engine is per-device independent).
   - `round_summary(participants_hash, aggregated, local_audit_head)` —
     anchors the round and ties it to the local log head.
4. **Never halt training:** every mirror call is wrapped. A `ChainRejection`
   (server tried something illegal) is recorded loudly in `.rejections`; a
   transport failure goes to `.failures`; the round is marked **UNANCHORED**.
   The distinction matters: *rejection = enforcement signal; failure = chain
   unavailable*. A `_reads_down` latch makes an outage cost one timeout per
   round, not n. Every round lands in **exactly one** of
   `anchored_rounds`/`unanchored_rounds` (a bug where rounds vanished from
   both was found by the liveness experiment and fixed).

### Backends and modes (`chain/wiring.py`, `config.py`)

`build_audit(mode, ...)` returns `(audit, backend, fed_key)`:
- **off** → plain HashChain. Nothing in `chain/` is imported. Hard constraint:
  sweeps stay reproducible.
- **mock** → `MockBackend` (deterministic in-memory; **no timestamps in hashed
  bodies**, unlike the audit chain — same sequence → same head). CI never
  needs a node. Optionally wrapped in `CommitMockBackend`.
- **node** → `EvmBackend` (web3.py) against Anvil/Hardhat/eth-tester/QBFT/
  public testnet. Address resolution: `--address` >
  `config.CHAIN["contract_address"]` > `chain/deployed.json`. Env overrides:
  `DLTF_CHAIN`, `DLTF_CHAIN_RPC`, `DLTF_CHAIN_NETWORK`, `DLTF_DEPLOY_BLOCK`,
  `DLTF_CHAIN_PRIVKEY`, `DLTF_CHAIN_ASYNC`.

**Fail-open enrollment:** if the node is unreachable, `is_banned_on_chain()`
returns False and enrollment proceeds. Failing closed would hand anyone who
can DoS the node a **federation-wide enrollment DoS**. The staleness window is
a stated limitation, not an oversight.

---

## 11. The commitment layer (`chain/commit.py`) — anti-fabrication

**The problem it closes:** baseline DLTF's trail begins at "the server *says*
it received X." A server could claim it received a gradient the client never
sent; a client could deny what it sent. Neither is disprovable.

**The 7-step flow:**
```
1. client computes gradient G
2. H = keccak256(canonical(G))
3. client writes H to chain FROM ITS OWN WALLET, before sending
4. client sends G to server over HTTP
5. server computes H' and reads H from chain
6. H' ≠ H → reportCommitMismatch, update dropped
7. server calls classify() → contract REFUSES unless a commit exists (MissingCommit)
```
Step 7 is the part worth having: **not logging — a rule the server cannot
break.** A classification fabricated against a client that never participated
reverts.

**Canonical serialization** (both sides must hash identical bytes):
`struct.pack("<Nd", *G)` — little-endian IEEE-754 float64, no prefix/padding.
Never repr/JSON/pickle (they vary across platforms).

**Wallet binding is load-bearing:** a commitment from an arbitrary wallet
proves nothing (a banned machine would just generate a fresh keypair). So at
enrollment:
```
challenge = "DLTF-WALLETv1|" + device_label + "|" + wallet_bytes   (domain-separated)
client signs challenge with its TPM AK  →  server verifies against the enrolled identity
server calls bindWallet(deviceId, wallet)   — one wallet, one device, immutable
```
`commitGradient` checks the calling wallet maps to a non-BANNED device → **a
banned physical machine cannot commit at all**, and its wallet can't be
rebound to a new label. The server performs the binding (it's the party that
verified the TPM proof); a malicious server could bind a wallet it controls,
but the binding is **public** — the client reads `deviceWallet[myKey]` and
sees it. *Detectable, not preventable* — same class as T26.

**EIP-712 batch signing:** clients sign typed commitments off-chain; the
server batches them (`commitBatch`) or uses `classifySigned` (commit+classify
in one tx). Signature malleability guards: low-s, v ∈ {27,28}. `requireCommit`
is `immutable` — cannot be disabled mid-federation.

**Measured cost (the answer to "what does the guarantee cost?"):**
```
A  per-client txs + classify : 539,406 gas (clients pay 89,901 each)
B  commitBatch + classify    : 469,532 gas (clients pay 0)
C  classifySigned            : 279,662 gas (clients pay 0)   ← 48.2% cheaper than A
D  baseline, no commitment   : 216,036 gas
guarantee premium (C−D)      :  63,626 gas = 29.5% over baseline, clients pay nothing
```
September signed-path (4 clients): `commitBatch(4)` 168,081; `classifySigned`
46,647; classify+amortised batch 80,268 → signed path **42% cheaper**. A
forged signature rejects the **whole batch atomically**
(`SignerNotDeviceWallet`), leaving the valid half unwritten.

---

## 12. Real-chain plumbing (the September 2026 phase)

### `chain/signer.py` — local signing
Public RPCs don't implement `eth_sendTransaction` (only Anvil/Hardhat/
eth-tester do). The old code would have failed every write on a real endpoint
— *misleadingly*, as "node unreachable." Now: raw transactions signed locally
(`DLTF_CHAIN_PRIVKEY`), nonce management, EIP-1559 fees (2 gwei priority floor,
30 gwei on Polygon), safe receipt polling.

**The correctness fixes that protect the parity result:**
- **Resend/double-apply bug:** retrying a poll timeout at a *fresh nonce* could
  land both copies → `classify` applied twice, silently falsifying "every
  deviation is exactly zero." Now: tx hash computed from signed bytes **before**
  broadcast (lost RPC response recoverable by lookup); stuck tx replaced at
  the **same nonce** (the chain includes it at most once).
- **Revert-name recovery:** a mined status-0 receipt is re-simulated via
  `eth_call` at its own block to recover the custom error (was collapsing to
  `UnknownRevert` — which would destroy experiment 2c).
- `Error(string)`/`Panic(uint256)` selectors added by hand (Solidity doesn't
  emit them as ABI entries; both were misfiled as transport and retried).
- Tx hashes in provider error text no longer mistaken for revert data (regex
  gated).
- `eth_getLogs` **chunked from the deploy block** (was 14 genesis-to-latest
  scans, which providers refuse).
- `head_hash()` **raises** instead of fabricating 32 zero bytes;
  `head_hash_or_null()` for reporting paths.

### `chain/async_writer.py` — off the critical path, honestly
Single-threaded FIFO queue (max 4096). Writes leave the training thread;
rounds are *provisionally* anchored at submission and **demoted** when a write
comes back failed (`drain_chain_writes()` first, then report).

**The measured liveness verdict (the split IS the result):**
- **Structural: holds.** Every round completes; sync and async produce
  identical models.
- **Wall clock: did NOT hold for sync.** Injected stall: sync 409→2002
  ms/round (~5×); async 61→1003 ms. On real QBFT: sync healthy ~14.4 s/round,
  first stalled round **188.9 s**; async healthy ~115–136 ms. *A ledger whose
  removal makes rounds an order of magnitude faster is on the critical path.*
- **Backlog collateral (the finding to protect):** async carries a backlog
  *into* the outage — writes issued while healthy are destroyed by it. At
  queue depth 17, three writes **including an ENROLL** were lost; chain-only
  reconciliation then failed (`enrolled locally but absent on chain: ['h3']`).
  Sync loses only rounds overlapping the outage; async loses a window as wide
  as the queue. Report async numbers **with** this collateral.

### `chain/testnet_preflight.py` + `chain/deploy.py`
19 checks covering every real-chain path — **run before spending faucet
funds**. `deploy.py` deploys via signed tx (no unlocked accounts), writes
`chain/deployed.json`, prints the deploy block to export. The legacy
`trust/legacy/deploy_chain.py` **refuses to run** — it deploys the wrong
contract (v1 ReputationRegistry).

---

## 13. Restart & third-party verification

### `chain/reconcile.py` — bans survive restart (N23)
Rebuilds a live `ReputationEngine` from chain events alone: replay through the
integer engine → inject state into a fresh engine via `register()` + `_dev`
patching (black-box respected).

**The two-ledger rule (critical):**

| What | Source | Why |
|---|---|---|
| s, f, clean_run, major_run, status, tier | **chain** | authoritative — the contract rejected any lifecycle-breaking write |
| raw ek_hash | **local audit log** | the chain holds only the one-way HMAC |

Seeding `_banned_ek` with HMAC digests would make every lookup miss and
**silently re-admit every banned device**. `reconcile.py` test 6 is the
permanent regression guard.

Proof line: round 11 ends at trust 0.397 → restart → round 12 resumes at
**0.400**. A wiped engine would restart at 0.292. Continuity = state came off
the chain. (Limitation: reconciliation restores **trust** state, not **model**
state — the parameter vector is checkpointed separately.)

### `chain/verifier.py` — stronger than the hash chain
Replays the emitted event log through the integer engine and compares
recomputed state **field-by-field** against stored state, using only the
public read surface (so the same code runs against a live node).

> The hash chain proves nobody **edited** the log. Verification proves the
> log's **contents imply** the recorded state.

A server that wrote a plausible event stream while storing inflated scores or
a silent un-ban **passes hash-chain verification and FAILS recomputation**.
Demonstrated by deliberate corruption (`tools/prove_it_works.py`):
```
TAMPER 1: h0.s recomputed=1874236 on_chain=2651236   → caught
TAMPER 2: a0.status recomputed=2(BANNED) on_chain=0(ACTIVE) → caught  ← the thesis claim
```
Limit: internal consistency, not ground truth.

---

## 14. The consensus stage (`qbft/`)

**The epistemic gap it closes:** on a single node you started, "the contract
refuses" is executed by a process the operator controls. Nothing distinguishes
*a contract that refuses* from *an operator who reports that it refused*.
Under 4-validator QBFT, a block needs **2f+1 = 3 signatures** — to land an
illegal transition the operator must corrupt 3 of 4 independently-run nodes.
The refusal becomes a property of a **protocol the operator does not control**.

Setup: `setup.sh 0xDEPLOYER 0xNONWRITER` (both funded in genesis — the
non-writer is essential for experiment 2c), Docker Compose with 4 Besu nodes,
`verify.sh` (two failure modes both look like success: one validator wearing
four containers; nodes never peered, height frozen at 0).

Experiments: **2a** confirmation latency (median+p95, blockperiod 5 s), **2b**
liveness with `--manual-stall` (real quorum loss), **2c** enforcement by
consensus (needs the second funded key), **2d** reorg null result (QBFT has
immediate finality).

**Status (from the Sept-11 logs):** 2b completed twice; 2c preflight **18/19**
— `UnauthorizedWriter` refused by consensus, deploy gas reproduced exactly.
**Open bug:** `head_hash()` fails on Besu's 327-byte POA `extraData` (needs
web3 `geth_poa_middleware` in `chain/evm.py`). 2a/2d not yet run. **Ceiling:**
four Docker validators on one host are consensus in *mechanism*, not in
*threat model*.

---

## 15. Orchestration, evaluation, and verification

**Runners:**
- `run_local.py` (SIM): `--clients --attackers --rounds --tier1 N
  --chain off|mock|node --restart-at N --rejoin-as LABEL --require-commit
  --attack ...`. `--tier1` matters: without it every SIM client is Tier 2 →
  REHAB=False → **probation unreachable**.
- `run_server.py` (REAL): builds RemoteClientHandles from `config.CLIENTS`,
  loads the AMD CA bundle, **pre-enrollment chain ban check** (fail-open),
  runs rounds, prints the chain report + verifier summary.

**Evaluation harnesses (`eval/`):**
- `run_experiments.py` — Chapter 4 trust-model data (chain OFF, synthetic,
  multi-seed, `--check`).
- `chain_eval.py` — Chapter 5: parity / gas / storage / latency / reconcile /
  real-mode latency.
- `exp_liveness / exp_economics / exp_commit_gas / exp_aggregator / exp_tiers /
  exp_window / exp_engine_sweep / exp_scale / exp_m3 / exp_real_mnist` — the
  paper-evidence suite.
- `make_figures.py` — the real figure generator (8 Ch.4 + 5 Ch.5 figures);
  `verify_numbers.py` — reconciles every claimed number against the CSVs.

**Verification philosophy — falsification, not assertion:**
`tools/prove_it_works.py` pairs **every positive check with a negative control
that must fail** (41 checks). Because every check can pass *vacuously* (a
verifier that always returns OK, a gate that rejects everyone, "nothing on
chain" satisfying "no raw EK on chain"). Plus `tests/test_pipeline.py`
(8 groups, all module self-tests + real-HTTP end-to-end) and
`tests/test_chain_integration.py` (9 groups). Every module also has a
`__main__` self-test (house style).

---

## 16. End-to-end walkthroughs

### A. One SIM round, chain=mock, commitment on
```
run_local builds LocalClientHandles (mock TPM signers, test CA → --tier1 clients)
wiring.build_audit → ChainRegistry(HashChain, CommitMockBackend, FederationKey)
server.enroll each → cert+activation → tier → rep.register → audit ENROLL
   → registry mirrors register(ek_hmac) to backend; wallet bound via AK signature
round r:
   handles.train → client computes G, commits keccak256(canonical(G)) BEFORE returning
   filter.classify → severities
   rep.record_event → score/state updates; non-NEUTRAL → audit EVENT
   registry buffers; on ROUND: infers NEUTRALs, dispatches classify(severity)
      → backend RECOMPUTES in fixed point, rejects illegal transitions
      → round_summary anchors the round
   weights = D(tier)·T; aggregator(updates, weights); global_params += agg
verifier replays events → 0 discrepancies
```

### B. The central demo (ban → restart → whitewash)
```
6 clients (4 honest, 2 colluding), 20 rounds, --restart-at 12 --rejoin-as newclient
r0–1:  sybil pair → CRITICAL (sustained similarity) → BANNED
r11:   trust 0.397 ... server tears down at r12
r12:   rebuild_engine from chain events alone → 0.400 (NOT a reset to 0.292)
       'newclient' enrolls with the SAME banned EK → WHITEWASH_REJECTED
forged resurrection (server writes ENROLL for banned device, fresh EK):
       hash chain: ACCEPTED, verify() still True
       chain layer: REJECTED (EkAlreadyRegistered) — status stays BANNED
```
That last pair is the paper's central demonstration: **recording vs enforcing.**

### C. REAL round over Tailscale
```
client PCs: net/agent.py --label clientN --port 8470 (real TPM, real MNIST shard)
server: run_server.py --rounds 10 --chain node
   pre-enroll: is_banned_on_chain(ek_hash) (fail-open)
   enroll: real MakeCredential/ActivateCredential against /dev/tpmrm0 → Tier 1
   each round: server POSTs /train → agent trains CNN, commits, returns update
   detection → reputation → weights → FedAvg/Krum → audit + chain mirror
   node dies mid-run? rounds continue, UNANCHORED recorded, training never stops
```

---

## 17. The measured numbers (quote carefully)

| Claim | Number |
|---|---|
| Gas cost model | `round_gas ≈ 58,281 + 38,818×clients`, R²=1.000000 (slope exact, intercept ±5) |
| Deploy gas | **2,085,425** @ solc 0.8.24 (compiler-specific) |
| Parity (off vs mock vs node) | **exactly 0.000e+00**, 6/6 configs |
| Storage drift / 30 rounds | 0.15% → state is O(devices) |
| Accuracy, no attack | 0.691 vs 0.691 (zero cost) |
| Loss recovered | poison 96.5%, sleeper 94.7%, sybil 96.3% |
| Whitewash blocked | 25/25 vs baseline 0/25 |
| Attacker cost/identity | T1 0.462, T2 0.201, T3 0.040 weight-rounds |
| Rehabilitation | 5/5 recovering vs 0/5 persistent |
| FPR | flag-level 0.6% (1/170), **sanction-level 0%** |
| Economics | 30-round federation $0.169/$0.316/$0.756 @10/20/50 clients; attack ≈ **380×** the ledger |
| Liveness | structural holds; sync ~5× wall-clock penalty; async backlog collateral |

---

## 18. Trust boundaries & limitations (stated, not hidden)

**Who is trusted for what:** server trusted for *training*; clients untrusted;
only manufacturer CA roots trusted; **with the chain layer, the server is
removed from the trusted set for the ban ledger specifically**.

**Honest limits:**
- **T26:** a compromised server key can still write *false classifications* —
  the contract constrains transitions, not input truthfulness.
- A **stealthy directed-deviation attack** from a legitimately enrolled device
  still defeats the design (architectural).
- Fail-open enrollment → staleness window under node DoS.
- Detection needs **n ≥ 3**; 2 physical TPMs is not a hardware study; 6–50
  clients is not deployment scale.
- 4 Docker validators ≠ 4 organisations.
- py-evm timings don't transfer (quote `--exp real` or labeled QBFT runs only).
- Reconciliation restores trust, not model state; X.509 validation simplified;
  plain HTTP (WireGuard-mitigated); immutable ledger vs GDPR (key rotation ≈
  erasure).

**Open work (in order):** fix the QBFT POA `head_hash` bug → Anvil with real
block time (pending-tx path never exercised) → public testnet (Sepolia
recommended) → QBFT 2a/2d + third-agent REAL demo → paper.

---

That's the whole machine: **TPM identity → detection → identity-blind
reputation → tier-coupled consequences → rehabilitation → weighted
aggregation**, with a local hash chain for tamper-evidence and an optional
enforcing contract that makes the ban ledger durable, private, and verifiable
by someone who doesn't trust you.
