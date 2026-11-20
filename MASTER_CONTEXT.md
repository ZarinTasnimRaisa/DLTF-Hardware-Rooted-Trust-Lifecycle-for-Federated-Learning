# MASTER_CONTEXT.md — DLTF, Current State

Complete context for continuing DLTF in a new session. This describes
the system AS IT STANDS NOW, with every constant read back from live code.
Read fully before touching code.

> **CONSOLIDATION NOTICE (2026-11-17).** This is the single canonical context
> document. It merges the v3.1 rewrite (formerly `docs/Important/MASTER_CONTEXT.md`)
> with the unique content of the chain-era context and the executed session
> prompt (§16 appendix), and adds the September 2026 deployment phase (§15:
> local signing, async writer, preflight, liveness, economics, QBFT).
> Superseded versions are preserved in `docs/history/`:
> `MASTER_CONTEXT_v2.1.md` (retired engine — DO NOT quote its constants or its
> "no smart contracts" instruction) and `MASTER_CONTEXT_chain-era.md`
> (pre-commitment snapshot). If a number here disagrees with the code, the
> CODE WINS and this file is stale — report it.

User: Sazzad, CS undergraduate thesis, BRAC University, defending Summer 2026.
Style: terse, direct, bottom-line-first, tables over prose, wants short answers,
corrects verbosity and factual/citation errors directly. House code style: no em
dashes, ✓/✗ in prints, minimal comments, every module has a `__main__` self-test
with assertions, comments map features to objectives O1–O4.

> **v3 REWRITE NOTICE.** The previous MASTER_CONTEXT described the v2.1
> reputation engine (per-tier priors (8,2)/(4,2)/(2,2), start trust
> 0.80/0.667/0.50, per-tier γ, `w(MINOR)=1 w(MAJOR)=3`, θ_r=0.55,
> FORGIVE_AFTER=5, FORGET=0.95 Tier-1-only). **None of those values are in the
> code any more.** §4 below is re-derived from `trust/reputation.py` as it
> actually is. It also declared "no smart contracts in the current codebase";
> that is also obsolete — see §11.

---

## 1. What DLTF is

DLTF (Decentralized Learning Trust Framework): a federated-learning security
system that decides how much to trust each client's gradient based on
hardware-proven identity, sanctions misbehavior so attackers cannot escape by
re-registering, and rehabilitates devices that provably reform.

Four objectives (cited throughout the code):
- O1 Sybil resistance — one TPM chip = one identity (credential activation).
- O2 Anti-whitewashing — bans bind to the TPM's EK hash, survive re-registration.
- O3 Quantified trust — deterministic reputation formula + measured attacker cost.
- O4 Aggregator-agnostic — trust layer outputs plain weight dicts.

Novelty (NOT detection — that uses existing techniques): (a) hardware-rooted
sanction-and-rehabilitation lifecycle, (b) the sanction *policy* is a function of
hardware trust tier (identity replacement cost), (c) attacker cost per tier is
quantified, (d) **v3 addition:** the ban ledger is independently verifiable by a
party that does not trust the server (§11), and bans persist across server
restart (N23).

**Novelty framing must stay hedged.** ZTA-FL (arXiv:2512.23809, Dec 2025) is the
closest prior work and a near-miss overlap. Use "to our knowledge"; never claim
absolute precedence. The defensible differentiators are: EK-hash-bound bans
persisting across re-enrollment AND restart, policy severity indexed to hardware
identity tier, and accuracy-slope-gated reinstatement.

---

## 2. Live deployment state

WORKING: 3 physical machines on a Tailscale WireGuard mesh (account tpm97510@),
all Ryzen boxes with AMD firmware TPMs:
- 100.95.144.127 (ubuntu)    → SERVER (runs `run_server.py`; NOT in CLIENTS)
- 100.70.28.2   (s4zz4d HP)  → client1 (runs `net/agent.py`)
- 100.64.57.82  (tafsir HP)  → client2 (runs `net/agent.py`)

> **client2 IP conflict RESOLVED:** `100.64.57.82` is correct — it matches
> `config.py`, which is what actually runs. The old `100.73.178.45` value was
> wrong. If it ever disagrees again, `tailscale ip -4` on the tafsir machine
> is authoritative.

ACHIEVED: Both clients enroll as real Tier 1 (HARDWARE) with DISTINCT EK hashes
(client1 ac6971…, client2 e7c273…), confirming one-chip-one-identity (O1). Real
409,034-param MNIST model is sent by the server. Round loop runs over real HTTP.
Audit chain writes to `results/audit.jsonl`.

Deployment facts:
- Tailscale is required (Bangladeshi CGNAT blocks direct inbound). All machines
  must be on ONE Tailscale account or only some appear in `tailscale status`.
- The SERVER dials OUT to clients on port 8470; clients never dial the server,
  so the server's own IP is not in `config.CLIENTS`.
- torch + torchvision needed on SERVER and all CLIENTS (server imports MNISTModel).
- Traffic is WireGuard-encrypted, mitigating the plain-HTTP limitation.

---

## 3. TPM / hardware attestation — RESOLVED

Both clients reach real Tier 1. Certs live per-machine in `cert/` (each chip has
its OWN cert; certs are NOT shared between machines). Verified chain:
EK cert → AMD intermediate → AMD root; `verify_ek_certificate` returns True.

Key facts and fixes already applied:
- Cert is read from disk (`cert/ek.crt`), NOT live-fetched at enroll time. AMD's
  PKI live-fetch is flaky and returned a different (failing) 1262-byte cert.
  `_try_ek_cert` in `tpm/client.py` reads the on-disk cert first; fetch is only a
  fallback.
- `run_server.py` loads `tpm/ca/amd_ftpm_ca.pem` as `ca_bundle_pem` and passes it
  to FederatedServer. Without it `cert_ok` is always False → all Tier 2.
- CA bundle must contain the RIGHT intermediate. AMD chips chain through
  different intermediates: client certs use CN=PRG-RN, but the original bundle
  only had CN=PRG-SSP. Bundle now includes BOTH intermediates + AMDTPM root.
- `verify_ek_certificate` (`tpm/common.py`) tries the strict Rust X.509 parser
  first, falls back to `openssl verify -partial_chain` on ANY failure (parse OR
  chain-walk), because AMD certs are technically malformed (non-spec DEFAULT
  encoding on a critical field) AND chain via partial_chain. Both paths needed.

Enrollment tier gate (`fl/server.py`): tier is HARDWARE only if
`cert_ok = (cert present) AND (ca_bundle loaded) AND verify_ek_certificate()`
AND credential activation passes. The tier the SERVER assigns depends on what the
AGENT provisions (its `tpm_backend`), not on files sitting in `cert/`.

**v3 addition — wallet binding** (`tpm/client.py`): `sign_message(bytes)` signs
arbitrary bytes with the AK via `tpm2_sign` (RSASSA/SHA-256), and
`verify_ak_signature(ak_pub, msg, sig)` is the server-side check. Deliberately
SEPARATE from `sign_challenge`, which produces a `tpm2_quote` over PCRs and is
not a signature over caller-supplied bytes — overloading it would have silently
produced unverifiable wallet bindings.

DATA MODEL (enrollment, JSON over HTTP, binary fields base64):
```
ek_cert    ≜ ⟨EK_pub, issuer, validity, manufacturer_sig⟩
provision  ≜ ⟨device_label, ek_hash, ak_name, ek_cert, ek_pub⟩   POST /enroll
challenge  ≜ ⟨blob⟩  blob = MakeCredential(ek_pub, secret)       POST /activate
response   ≜ ⟨secret'⟩  secret' = ActivateCredential(blob)
identity   ≜ ⟨device_label, ek_hash, tier, status⟩
ek_hash = SHA256(EK_pub) is the identity fingerprint; bans bind to it (O2).
```

> ⚠ `check_tiers.py` is referenced in old quick-starts but **is not in the
> tree**. Use `tpm/check_ek_cert.py` instead (see SETUP_GUIDE §9).

---

## 4. Reputation engine — v3, FINALIZED (`trust/reputation.py`)

Bayesian engine in subjective-logic form (Josang 2001; Josang & Ismail 2002).
Class `ReputationEngine`. Exports `Status`, `EventTier`, `PROBATION_WEIGHT_CAP`.

TRUST SCORE (Josang's probability expectation E = b + a·u):

```
T = (α₀ + s) / (α₀ + β₀ + s + f)
```

### THE v3 DESIGN DECISION: trust is TIER-NEUTRAL

This is the single biggest change from v2.1 and it is a *better* story, so lead
with it. In v2.1 the tier was baked into the prior, so Tier 1 started at 0.80
and Tier 3 at 0.50 — which made "trust" and "identity assurance" the same axis
and invited the objection that a Tier-1 attacker gets a head start it never
earned.

In v3 **every tier uses the same uniform Beta(1,1) prior and the same dynamics.**
Verified from live code:

| | HARDWARE | TPM_RESIDENT | SOFTWARE |
|---|---|---|---|
| prior (α₀, β₀) | (1, 1) | (1, 1) | (1, 1) |
| start trust T₀ | 0.500 | 0.500 | 0.500 |
| trust ceiling | 0.8333 | 0.8333 | 0.8333 |
| γ | 0.90 | 0.90 | 0.90 |

Tier enters at exactly **three** places, none of them the score:
1. **weight cap** `D` — aggregation weight `w = D(tier) · T`
2. **rehab eligibility** `REHAB` — who gets probation instead of a ban
3. **EK ban binding** — only a real EK can be banned durably

So: *behaviour determines trust; hardware determines consequences.* Verified
start weights: HW 0.500, T2 0.250, T3 0.050 — all from the same T₀ = 0.5.

### CONSTANTS (read back from `trust/reputation.py`)

```
W_PRIOR       = 2.0    [CITED]  Josang non-informative prior weight
BASE_RATE     = 0.5    [CITED]  insufficient reason
PRIOR         = (1,1)  [CITED]  = (W·a, W·(1−a)), UNIFORM across tiers
THETA         = 0.4    [CITED]  Kang 2019 Table I, positive interaction weight
TAU           = 0.6    [CITED]  Kang 2019 Table I, negative > positive
GAMMA         = 0.9    [CONVENTIONAL] uniform decay
FORGET        = 0.90   [DERIVED] = GAMMA. ONE decay primitive, not two.
FORGIVE_AFTER = 2      [CALIBRATED] probation W_MIN + 1... see note
MAJOR_RUN_TO_ESCALATE = 2   [CALIBRATED] repetition begins at 2
PROBATION_T   = 0.5    [CALIBRATED] indifference point (Kang trusted-worker)
REINSTATE_T   = 0.75   [DERIVED] closed form PROBATION_T·(1 + 1/W_PRIOR)
BAN_T         = 0.3    [CALIBRATED] backstop; probation fires first on rehab tiers
TIER_DISCOUNT = {HW 1.0 [CANONICAL], T2 0.5 [CALIBRATED], T3 0.1 [CALIBRATED]}
REHAB         = {HW True, T2 False, T3 False}
GOOD_EVIDENCE = {POSITIVE: 0.4, NEUTRAL: 0.4}
BAD_EVIDENCE  = {MINOR: 0.6, MAJOR: 0.6}     CRITICAL is a RULE, not a weight
S_MAX         = THETA/(1−GAMMA) = 4          goodwill ceiling
TRUST_CEILING = (1+S_MAX)/(W_PRIOR+S_MAX) = 0.8333
PROBATION_WEIGHT_CAP = d3 = 0.1              suspect ≤ unproven identity
```

**MINOR and MAJOR carry the SAME evidence weight (0.6).** They differ only in
that MAJOR feeds `major_run`, which drives the M3 escalation rule. This replaces
v2.1's 1-vs-3 weighting. Be ready for "then why two severities?" — the answer is
that severity selects the *rule* (repetition tracking), not the *magnitude*.

**FORGET = GAMMA = 0.90 is [DERIVED], not calibrated.** v2.1 had two independent
decay constants (0.95 for distrust, per-tier γ for trust) and justified the
asymmetry with Slovic. v3 collapses them to one primitive; the asymmetry now
comes from *when* forgetting is allowed (only after `FORGIVE_AFTER` clean rounds,
M2), not from a different rate. One fewer free parameter.

### HARDENING MECHANISMS

- **M1 bounded recency**: `s ← γ·s + θ` each good round, saturating at
  `θ/(1−γ) = 4`. A sleeper cannot bank unbounded cushion.
- **M2 earned forgetting**: `f` is sticky and never decays round-by-round; it
  fades (`×0.90`) only after `FORGIVE_AFTER = 2` consecutive clean rounds. One
  good round launders nothing — defeats on-off attacks.
- **M3 sustained escalation**: 2 consecutive MAJORs → probation/ban **bypassing
  the score**, so a high-`s` veteran sleeper is caught even while T > 0.5.
- **Cold-start gate**: the score path is gated on the opinion being
  evidence-dominated (`u < 0.5 ⇔ s + f > W_PRIOR = 2`), so a device cannot be
  sanctioned on its first noisy round. M3 is UNGATED (a rule, not a score).
- **D5 due process**: an ACTIVE rehab-tier device hitting even `BAN_T` gets
  PROBATION first; the backstop bans only from PROBATION onward.

### VERIFIED SANCTION PATHS (live code output)

| Tier | 2× MAJOR | 1× CRITICAL | 4× MINOR |
|---|---|---|---|
| HARDWARE | ACTIVE → **PROBATION** | **BANNED** | ACTIVE×3 → **PROBATION** |
| TPM_RESIDENT | ACTIVE → **BANNED** | **BANNED** | ACTIVE×3 → **BANNED** |
| SOFTWARE | ACTIVE → **BANNED** | **BANNED** | ACTIVE×3 → **BANNED** |

Cold-start gate in action (Tier 3, repeated MINOR):

```
after 1 MINOR: s+f=0.60  evidence_dominated=False  T=0.385  ACTIVE
after 2 MINOR: s+f=1.20  evidence_dominated=False  T=0.312  ACTIVE
after 3 MINOR: s+f=1.80  evidence_dominated=False  T=0.263  ACTIVE
after 4 MINOR: s+f=2.40  evidence_dominated=True   T=0.227  BANNED
```

T drops below `BAN_T` at round 2 but no sanction fires until the gate opens at
round 4. That is the cold-start protection, measured.

METHODS: `register(id,tier,ek_hash)` / `record_event(id,severity)` /
`reinstate(id, trial_rounds=0)` / `get_status` / `get_weight` / `get_all_weights`
/ `get_opinion(id) → (b,d,u,a)` / `rank(ids=None)` → Josang Def.10 ordering /
`banned_ek_hashes`.

> `reputation.py` is a **strict black box** for the chain layer. No edits.
> Interaction is via public API; state injection uses `setattr` / `_dev` patching.
> It has one latent hole: `register(id, tier)` with `ek_hash=None` resurrects a
> BANNED device as ACTIVE. Unreachable from `server.py`. The chain layer catches
> it — that is the demo. **Do not "fix" it in reputation.py.**

---

## 5. Probation engine — FINALIZED (`trust/probation.py`)

Tier-1-only rehabilitation. A probated client's updates train an ISOLATED shadow
model (frozen global snapshot + only that client's gradients). Reinstatement is
decided by the OLS slope of the shadow model's accuracy over the trial.

```
REINSTATE_SLOPE  = 0.005   → REINSTATED (calls rep.reinstate with trial rounds)
EXTEND_SLOPE     = 0.001   → one-shot EXTENDED (+3 rounds), else PERMANENT_BAN
EXTENSION_ROUNDS = 3
WINDOW_MIN, WINDOW_MAX = 4, 9    [DERIVED] OLS sign-stability floor; K1−1 ceiling
SLOPE_ESTIMATOR  = "ols"   ("theil_sen" available for noisy MNIST)
WINDOW = HMAC(device_id, entry_round) ∈ [4, 9], salt = os.urandom per process
```

The per-process HMAC salt blocks "behave just long enough" timing attacks.

SLOPE→REPUTATION COUPLING: the slope decides the BRANCH; the trial rounds are
forwarded as `rep.reinstate(id, trial_rounds=len(accuracy_series))` — EARNED
evidence (`s += trial_rounds · θ`) applied before the **REINSTATE_T = 0.75**
floor. A longer proven recovery returns with proportionally higher trust. Note
the floor is 0.75 in v3, not v2.1's 0.55. Duck-typed engine interface.

One-shot: a reinstated device that re-offends hits REHAB_EXHAUSTED → permanent
ban, no second trial.

---

## 6. Detection (`trust/filter.py`) — existing techniques, max-severity compose

```
Stage1  norm > 2.5× median                                  → MINOR
Stage2  cosine to leave-one-out median of prior-trusted < −0.45  → MAJOR
Stage3  FoolsGold-style pairwise sim ≥ 0.95 sustained 2 rounds   → CRITICAL
Stage4  self-history cosine < −0.45 sustained 2 rounds            → MAJOR
MIN_HISTORY = 3   HISTORY_WINDOW = 10   REF_MIN_WEIGHT = 0.0
```

Detection is explicitly NOT the contribution. It is the input to the trust layer.

---

## 7. Architecture

```
tpm/     identity: EK cert verify + credential activation → tier; wallet signing
trust/   reputation.py (§4), probation.py (§5), filter.py (§6)
         legacy/  v1 push-model chain attempt (superseded; see docs/history/)
fl/      model (MNIST CNN 409k), dataset (non-IID), client, aggregator
         (fedavg/krum/trimmed_mean), server (enroll + round lifecycle)
net/     handles.py (local↔remote seam), agent.py (per-client HTTP agent)
audit/   hashchain.py (HMAC-signed tamper-evident JSONL chain)
chain/   on-chain trust registry (§11): enforcement, commitment, signing,
         async writes, deployment, reconciliation, verification
contracts/  Foundry project: src/DLTFRegistry.sol + test suites (canonical)
qbft/    4-validator Besu QBFT setup (§15)
eval/    scenarios, run_experiments (Ch.4 CSVs), make_figures, chain_eval,
         exp_* harnesses (liveness, economics, commit gas, aggregator, tiers,
         window, engine sweep, scale, m3, real MNIST), verify_numbers
tests/   test_pipeline.py, test_chain_integration.py
tools/   prove_it_works.py (41 falsification checks with negative controls)
```

Trust model: server trusted for *training*; clients untrusted; only manufacturer
roots/intermediates in the CA bundle are trusted. Weight = `D(tier)·T`; banned
devices absent from weights → structurally excluded. Krum uses weights as an
eligibility mask (O4).

**v3 change to the trust model:** the chain layer removes the server from the
trusted set *for the ban ledger specifically*. See §11.

### THREE INDEPENDENT AXES

| Axis | Options | Selector |
|---|---|---|
| TPM | mock / swtpm / real | `make_signer`, `config.CLIENTS[].tpm_backend` |
| Transport | in-process / HTTP | `LocalClientHandle` / `RemoteClientHandle` |
| Chain | off / mock / node | `--chain`, `config.CHAIN["mode"]` |

All nine combinations run. SIM = `run_local.py`, REAL = `run_server.py` +
`net/agent.py`.

---

## 8. `audit/hashchain.py` — the local ledger

```python
HashChain(path=None, key=None)
.append(event_type, payload) -> entry dict
.entries(event_type=None) -> list[dict]
.verify() -> (bool, err|None)
.head_hash() -> hex
.__len__() -> int
```

Entry: `{seq, ts, type, payload, prev, hash, sig}`. GENESIS auto-appended.

> ⚠ A "minimal, compatible stand-in" version of this file has been circulating
> in the repo. It exposes `entries` as an ATTRIBUTE, returns a bare `bool` from
> `verify()`, stores `data` instead of `payload`, and has no `head_hash`. That
> version breaks `chain/registry.py`, `chain/verifier.py`, AND
> `tests/test_pipeline.py` (which calls `entries()`, unpacks `ok, err =
> verify()`, and calls `head_hash()`). Check yours:
> `grep -n "def verify\|self.entries\|def head_hash" audit/hashchain.py`

---

## 9. Related work positioning (Ch.2 / defense)

- **FoolsGold [Fung 2018]**: gradient-similarity detection only; no identity, no
  cost to re-register. DLTF includes a FoolsGold-style stage but adds
  hardware-bound identity that detection binds to.
- **Kang 2019/2020** (multi-weight subjective logic FL reputation): flagship
  citation, and in v3 the **direct source of θ = 0.4 and τ = 0.6** (Table I).
  v3 uses their weights rather than avoiding them, which is now defensible
  because the tier no longer lives in the prior — there is no tier prior for
  their values to erase. Sui 2024 documents Kang's new-vs-old-client flaw = the
  same flaw the supervisor flagged.
- **Josang 2001** (subjective logic): the formal foundation. DLTF's trust formula
  IS his E = b + a·u; his Def.10 = DLTF's `rank()`. W=2, a=0.5 are his.
- **Wang 2022** (TPM + blockchain oracle FL): uses TPM for update INTEGRITY, not
  persistent identity binding. DLTF binds identity so bans survive re-join.
  ⚠ **Still missing from REFERENCES.md.**
- **ZTA-FL (arXiv:2512.23809, Dec 2025): CLOSEST COMPETING WORK.** Name it,
  state exactly what it does, identify the precise gap. Hedge all novelty
  claims with "to our knowledge". ⚠ Missing from REFERENCES.md.
- **TrustFed (ur Rehman et al., IEEE T-II 2021)**: related trust-in-FL framework.
- **Douceur 2002** ("The Sybil Attack"): O1 foundation.
- **Theil 1950 / Sen 1968**: slope estimators, for the SLOPE_ESTIMATOR discussion.
- **Friedman & Resnick 2001** (cheap pseudonyms) + **Ostrom 1990** (graduated
  sanctions): justify tier-coupling (policy scales with identity cost).
- **Slovic 1993**: asymmetry DIRECTION only — at FORGET = GAMMA = 0.90 it does
  NOT support a rate ratio (the old 5:1 story is retired; see §4).
- ⚠ Reference [24] Domingo-Ferrer marked VERIFY.
- ⚠ Kang 2019 venue conflict: REFERENCES [21] says IEEE IoT-J 6(6); the
  parameter report cites IEEE TVT 68(3), arXiv:1809.08387. Resolve before
  submission.
- **Honesty rule**: no paper prescribes `d2=0.5`, `d3=0.1`, `FORGIVE_AFTER=2`,
  `BAN_T=0.3`, or `MAJOR_RUN_TO_ESCALATE=2`. Those are [CALIBRATED] by DLTF's own
  sweep. Claiming a citation for them = fabricated citation. Defend by
  derivation and sweep, not citation.

---

## 10. Known limitations (state ALL in thesis)

X.509 path validation simplified (name chain + signatures; no revocation / full
RFC 5280 / EK-profile OIDs). Plain HTTP at request level (mitigated by
Tailscale/WireGuard; request-level auth is future work). Tier 1 only where a
verifiable EK cert exists — the claim is "whitewashing becomes
hardware-cost-bound", never "impossible". Synthetic substrate for trust metrics;
MNIST accuracy machine-side. Small federation (2 real / ≤50 simulated). Several
constants remain [CALIBRATED] inside derived bounds — defended by the sweep.
Uncertainty `u` never reaches 0 (bounded memory) — deliberate; it is what defeats
sleepers.

**Resolved in v3:** ~~in-memory engine state (restart = re-enroll)~~ — see N23
in §11. Trust state now survives restart.

**New in v3:** reconciliation restores TRUST state, not MODEL state — the global
parameter vector is not on chain and is carried in-process across a restart. A
real deployment checkpoints it separately. Orthogonal to the trust claim, but
state it. Also, the on-chain ban check FAILS OPEN when the node is unreachable
(failing closed would hand a node-DoS attacker a federation-wide enrollment
DoS); the staleness window is a stated limitation.

---

## 11. Chain layer — OPTIONAL on-chain trust registry (v3, NEW)

> This **supersedes** the old §7 note that said "no smart contracts in the
> current codebase … do not reintroduce blockchain". The earlier Polygon
> iteration (`chain_bridge.py`, `ReputationRegistry.sol`, `deploy_chain.py`)
> is v1 and **has been moved to `trust/legacy/`** (2026-11-17 housekeeping).
> It is kept as evidence of iteration, out of the import path. Its install
> guide is archived at `docs/history/CHAIN_INTEGRATION_v1.md` — DO NOT follow
> it: `trust/legacy/deploy_chain.py` deploys the WRONG contract and now
> refuses to run.

### What it is for

The local audit log is verifiable but **centralized**: a reader must trust the
server that wrote it. The chain layer makes the O2 ban ledger checkable by a
party that does not trust the server, and makes bans survive a restart.

### Guarantees

| ID | Guarantee |
|---|---|
| N20 | Semantic API: callers submit severity, the contract recomputes. No `submitState()`, so a server cannot assert an arbitrary score. |
| N21 | Six rejection rules enforced **by EVM revert**, not by Python. |
| N22 | EK privacy: only `ek_hmac = HMAC(fed_key, "DLTF-EKv1\|" + ek_hash)` goes on chain. Raw EK hashes never leave the host. |
| N23 | **Bans survive restart.** `chain/reconcile.py` rebuilds a live `ReputationEngine` from chain events. |
| N24 | Training survives chain failure. Node down → round marked UNANCHORED, training continues. **Structural only** — see §15: synchronous writes ARE on the wall-clock critical path; the async writer removes them but carries backlog collateral. |
| N25 | Commitment layer: clients commit `keccak256(canonical(gradient))` before sending, so the server cannot fabricate an update and attribute it. |

### Rejection rules (all tested on the deployed contract)

| Rule | Custom error |
|---|---|
| BANNED → ACTIVE resurrection | `BanToActive` |
| tier change after enrollment | `TierMutation` |
| duplicate / stale round | `DuplicateRound` / `StaleRound` |
| one EK, two device ids | `EkAlreadyRegistered` |
| write from non-server address | `UnauthorizedWriter` |
| classify on unknown / banned | `DeviceUnknown` / `DeviceBanned` |

### Reconciliation reads TWO ledgers, and must

| What | Source | Why |
|---|---|---|
| `s`, `f`, `clean_run`, `major_run`, `status`, `tier` | **chain** | authoritative because the contract rejected any write breaking the lifecycle |
| raw `ek_hash` | **local audit log** | the chain only holds the one-way HMAC |

`register()` decides O2 with `ek_hash in self._banned_ek`, where `ek_hash` is the
RAW hex the handle presents. Seeding that set with HMAC digests would leave it
non-empty, make every lookup miss, and **silently re-admit every banned device**.
`chain/reconcile.py` test 6 is a permanent regression guard.

### Files

```
chain/fixedpoint.py    integer mirror of reputation.py (SCALE = 1e6)
chain/backend.py       abstract Backend ABC + Reason codes
chain/mock.py          deterministic in-memory backend (CI, no node)
chain/keys.py          FederationKey (ek_hmac privacy)
chain/registry.py      HashChain-compatible adapter; drops into audit=
chain/verifier.py      third-party recomputation from events
chain/commit.py        gradient commitment + EIP-712 batch signing
chain/reconcile.py     rebuild ReputationEngine from chain (N23)
chain/wiring.py        --chain flag -> audit object (shared by both run scripts)
chain/evm.py           live-node backend (web3.py), locally signed txs
chain/deploy.py        deploy + chain/deployed.json
chain/signer.py        local signing, nonces, EIP-1559 fees, safe polling (§15)
chain/async_writer.py  background FIFO write queue (§15)
chain/testnet_preflight.py  19 checks before spending faucet funds (§15)
contracts/src/DLTFRegistry.sol   the contract (CANONICAL location)
contracts/test/        DLTFRegistryRules.t.sol + DLTFRegistryCommit.t.sol
eval/chain_eval.py     evaluation harness
```

> The flat copies `chain/DLTFRegistry.sol`, `chain/*.t.sol` and
> `chain/foundry.toml` were removed in the 2026-11-17 cleanup: `contracts/`
> is the single Foundry project. `chain/evm.py` locates the contract by
> searching `contracts/src/` first.

`ChainRegistry` implements the HashChain surface exactly, so it drops into
`FederatedServer(audit=registry)` with **zero changes to `fl/server.py`**.

`fl/server.py` line 113 skips NEUTRAL classifications, so the adapter **infers**
NEUTRAL from the complement of logged EVENTs against the ROUND participant list.
Exact, not heuristic.

### Fixed-point parity

`chain/fixedpoint.py` is an integer mirror at `SCALE = 1e6`. Proven bound
`|T_float − T_fixed| ≤ 5e-6`, zero measured status divergence. Bit-parity with
the deployed contract verified after every write.

### Commitment layer is WIRED END TO END (v3.1)

`config.CHAIN["require_commit"]` used to be a dead knob -- nothing read it. Now:

- `chain/wiring.py` wraps the mock backend in `CommitMockBackend` on request,
  and for node mode CHECKS the deployed `requireCommit` matches (it is
  immutable, so a mismatch raises rather than being silently ignored)
- `net/handles.py` `LocalClientHandle` accepts `commit_agent` and commits
  BEFORE `train()` returns, mirroring `net/agent.py` over HTTP
- `run_local.py --require-commit` binds a wallet per device via a TPM AK
  signature, then attaches a `CommitAgent`
- `chain/verifier.py` knows `WALLET_BOUND` / `GRADIENT_COMMITTED` /
  `COMMIT_PROOF` / `COMMIT_MISMATCH` are non-state events

```bash
PYTHONPATH=. python3 run_local.py --clients 5 --attackers 2 --rounds 8 \
    --chain mock --require-commit
```
```
commitment: 5 wallets bound to TPM identities, clients now commit before sending
VERIFIED: 5 devices, 33 events replayed, 0 discrepancies
```

### ⚠ solc IS PINNED TO 0.8.24 -- do not upgrade

Measured, same contract, 0.8.24 vs 0.8.31:

| operation | 0.8.24 | 0.8.31 | delta |
|---|---:|---:|---:|
| deploy | 2,085,425 | 2,036,258 | **-49,167 (-2.36%)** |
| register | 95,332 | 95,353 | +0.02% |
| classify NEUTRAL | 36,174 | 36,214 | +0.11% |
| bytecode | 9,941 B | 9,714 B | -227 B |

Runtime gas is stable; DEPLOY moves by 49k. Upgrading invalidates the Chapter 5
deploy figure for no benefit. Ubuntu's `apt install solc` gives 0.5.16, which
cannot build this contract at all.

### ⚠ `--via-ir` IS MANDATORY

The old quick-start command **fails**:

```
Error: Stack too deep ... at DLTFRegistry.sol:666 (_classifyCore)
```

`contracts/foundry.toml` sets `via_ir = true` ("classifySigned exceeds the
16-slot stack limit otherwise") and pins solc 0.8.24 with the measurement
rationale in comments. Correct manual build:

```bash
solc --optimize --optimize-runs 200 --via-ir --bin --abi --overwrite \
     -o contracts/out contracts/src/DLTFRegistry.sol
```

Bytecode: **9,941 bytes (9.7 KB)**, EIP-170 limit 24,576. (Earlier docs said
6.5 KB and 8.9 KB; both predate `--via-ir`.)

### Measured results (`eval/chain_eval.py`, solc 0.8.24, optimizer 200, via-IR)

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
| commitGradient (CLIENT pays) | 51,653 |

**Cost model:** `round_gas = 58,282 + 38,818 × clients`, R² = 1.000000.
Affine, not proportional — `roundSummary` is a fixed per-round cost. At 6
clients: **291,180** (earlier docs said ~309,000).

| Property | Measured |
|---|---|
| Parity chain off vs mock vs node | **exactly 0.000e+00**, 6/6 configs |
| Storage drift over 30 rounds | 0.15% ⇒ device state is O(devices) |
| Packed device word | 181 bits of 256 (one SSTORE slot) |
| Reconcile 200 rounds of history | 2.3–3.3 ms rebuild, 2.2 ms verify |
| Mock-chain round overhead | ≤ 1.8 ms |

⚠ **In-process py-evm latency does not transfer, in either direction.** It is a
pure-Python interpreter: it over-states execution vs Anvil/Geth and under-states
transport (no socket, no block time). Quote absolute latency only from
`--exp real` on the physical machines.

---

## 12. Test status

**274 ✓ checks green** across 22 modules (July 30 baseline). September 2026:
**55/55 contract tests** passing through the locally signed path; the
`chain/deploy.py --self-test` ABI_PATH bug was found and fixed (§15) — check
whether earlier counts included it.

```bash
PYTHONPATH=. python3 tests/test_pipeline.py           # whole stack + chain
PYTHONPATH=. python3 tests/test_chain_integration.py  # 9 groups
PYTHONPATH=. python3 -m chain.reconcile               # 16
PYTHONPATH=. python3 -m chain.wiring                  # 10
PYTHONPATH=. python3 -m chain.evm                     # 17  (eth-tester)
PYTHONPATH=. python3 -m chain.deploy --self-test      #  7  (eth-tester)
PYTHONPATH=. python3 -m chain.evm_parity_test         # 15  (deployed contract)
PYTHONPATH=. python3 -m chain.commit_parity_test      # 17
PYTHONPATH=. python3 -m chain.batch_parity_test       # 21
```

> ✔ FIXED: `net/handles.py` now asserts `0.25 <= w <= 0.35` (line 117). The
> old `0.3 <= w <= 0.5` band was a v2.1 leftover. The remaining `0.3..0.5`
> assertions in `fl/server.py` and `tests/test_pipeline.py` are different
> self-test contexts (multi-round Tier-2 weights) and pass.

---

## 13. Quick start

### SIM (one PC, no hardware)

```bash
# baseline, no chain
PYTHONPATH=. python3 run_local.py --clients 6 --rounds 10

# Tier-1 clients so probation is reachable
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --tier1 6 --rounds 15

# full chain demo: ban -> restart -> rebuild -> whitewash
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient
```

> Without `--tier1`, every SIM client is Tier 2 → `REHAB=False` → **probation is
> unreachable**. This was a long-standing gap in the SIM harness.

### REAL (three machines, Tailscale)

```bash
# each CLIENT, leave running
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470

# SERVER: health check first
curl http://100.70.28.2:8470/health          # expect {"ok":true}
PYTHONPATH=. python3 run_server.py --rounds 10           # real MNIST, no chain
PYTHONPATH=. python3 run_server.py --rounds 10 --chain mock
```

### Live node

```bash
anvil &                                       # or: npx hardhat node
PYTHONPATH=. python3 -m chain.deploy --network localhost
PYTHONPATH=. python3 run_server.py --rounds 10 --chain node
```

### Evaluation

```bash
# Chapter 4 (chain OFF) -- MUST BE RE-RUN, see §14
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check

# Chapter 5 chain layer
PYTHONPATH=. python3 -m eval.chain_eval --exp all --seeds 3 --rounds 10 \
    --repeats 3 --max-clients 50 --storage-rounds 30 --check

# REAL-mode latency (the only quotable absolute latency)
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain node --real-rounds 10
```

---

## 14. Current state and remaining work (updated 2026-11-17)

**Cleared since the July 30 revision:**
- ✔ Chapter 4 re-run under v3 — all evaluation checks passed (see
  `docs/RESULTS_EXPLAINED.md`). No longer a blocker.
- ✔ Commitment layer wired end to end and measured on deployed bytecode (§11, §15).
- ✔ Foundry suites complete: `contracts/test/DLTFRegistryRules.t.sol` (trust-state
  rejection rules N18–N22) + `DLTFRegistryCommit.t.sol` (commitment N24–N28).
- ✔ Local signing, async writer, preflight, liveness + economics experiments (§15).
- ✔ client2 IP conflict resolved (§2); `net/handles.py` band fixed (§12).
- ✔ Housekeeping executed 2026-11-17: v1 moved to `trust/legacy/`;
  `chain/reputation.py` duplicate deleted (identical to `trust/reputation.py`,
  nothing imported it); `dsadas/`, `all files/`, `smartcontract file all/`,
  archives and run logs removed; `eval/plot_results.py` (byte-identical copy of
  `scenarios.py`) deleted and dropped from `COMPILE_ONLY`; docs consolidated
  (this file; `docs/INDEX.md`; retired docs in `docs/history/`).

**Remaining, in order of value (see CLAUDE.md §6 and RUNBOOK.md §9):**
1. **Fix the QBFT POA bug** (§15.6): `head_hash()` fails on Besu's 327-byte
   `extraData` — inject web3's `geth_poa_middleware` in `chain/evm.py` for POA
   chains. Preflight is 18/19 until this passes. Do not spend faucet funds first.
2. **Anvil with real block time** (`--block-time 12`, `--no-mining`): nothing in
   the evidence base has ever seen a pending transaction.
3. **Public testnet**: Sepolia recommended over Amoy (CLAUDE.md §6 Step 2:
   rate limits, 25 gwei priority floor). Deploy, verify source, one short
   federation; record address + tx + verified-source link.
4. **QBFT experiments 2a/2d** (confirmation latency median+p95; reorg null
   result). 2b/2c already ran 2026-09-11 (§15.6) — re-run after the POA fix.
5. **REAL-mode detection demo** needs a THIRD agent (n ≥ 3 for median-based
   stages; see `docs/REAL_MODE_RUNBOOK.md` §0).
6. **Paper** (ACM NSysS, 6–8 pages): see CLAUDE.md §6 Step 4 and
   `eval/RUNBOOK.md` for the evidence-completion plan.
7. REFERENCES.md: add Wang 2022, ZTA-FL, Douceur 2002, Theil/Sen, TrustFed;
   verify [24] Domingo-Ferrer; resolve the Kang venue conflict (§9).

---

## 15. September 2026 deployment phase (local signing → QBFT)

Source: root `RUNBOOK.md` (engineering record), `CLAUDE.md` (handoff), and the
2026-09-11 QBFT run logs (archived in `D:\DLTF-backup-2026-11-17`). Everything
below was executed, not asserted.

### 15.1 New modules

| File | What it is |
|---|---|
| `chain/signer.py` | Local transaction signing, nonce management, EIP-1559 fees, safe receipt polling |
| `chain/async_writer.py` | Single-threaded FIFO write queue so a stalled chain cannot extend a round |
| `chain/testnet_preflight.py` | 19 checks covering every real-chain path. Run before spending faucet funds |
| `eval/exp_liveness.py` | Experiment 2b: stall the chain mid-run, measure what training pays |
| `eval/exp_economics.py` | Phase 4: the gas model in currency at a stated price and date |

Environment overrides (config.py): `DLTF_CHAIN` (off/mock/node),
`DLTF_CHAIN_RPC`, `DLTF_CHAIN_NETWORK`, `DLTF_DEPLOY_BLOCK`,
`DLTF_CONTRACT_ADDRESS`, `DLTF_CHAIN_PRIVKEY` (never read from a file, never
logged), `DLTF_CHAIN_ASYNC=1` for the async writer.

### 15.2 Blockers closed

- **Local signing.** `_send` used `eth_sendTransaction`, which only Anvil,
  Hardhat and eth-tester implement; no public RPC does. Failures masqueraded
  as `node unreachable`. `EvmBackend.connect(private_key=...)` or
  `DLTF_CHAIN_PRIVKEY` now signs locally; without a key, wiring warns explicitly.
- **The wrong contract.** `trust/legacy/deploy_chain.py --mode testnet` deploys
  `ReputationRegistry.sol` (v1), NOT `DLTFRegistry.sol`. It now refuses to run
  and names the correct command (`chain/deploy.py`, which no longer needs
  unlocked accounts).
- **Remote endpoints.** RPC URL, network name and deploy block are now
  configurable by flag and environment; a contract deployed as `amoy` is
  visible to `run_local`.

### 15.3 Correctness fixes (the ones that protect the parity result)

- **Resend/double-apply bug.** Retrying a poll timeout at a fresh nonce could
  land both copies and apply `classify` twice, silently falsifying "every
  deviation is exactly zero". Now: tx hash computed from signed bytes BEFORE
  broadcast; stuck transactions replaced at the SAME nonce.
- **Revert-name recovery.** Mined status-0 receipts are re-simulated with
  `eth_call` at their own block to recover the custom error (was
  `UnknownRevert`). Verified: forced status-0 → `EkAlreadyRegistered`.
- **Selector table.** `Error(string)` and `Panic(uint256)` added by hand
  (Solidity does not emit them as ABI entries); both were misfiled as
  transport and retried.
- **Regex gating.** Tx hashes in provider error text are no longer read as
  revert data.
- **Chunked `eth_getLogs`** from the recorded deploy block (was 14
  genesis-to-latest scans); `snapshot()` does one log pass.
- **`head_hash()` raises** instead of fabricating 32 zero bytes;
  `head_hash_or_null()` exists for reporting paths.

### 15.4 Two ChainRegistry bugs the liveness experiment found

- `report()` crashed during exactly the outage it existed to report on
  (unguarded `head_hash()`/`last_round()`). Now returns `None` +
  `chain_reachable: False`.
- A round lost to an outage was counted in NEITHER `anchored_rounds` NOR
  `unanchored_rounds` (unguarded reads aborted the flush before bookkeeping).
  Reads are now guarded, every round lands in exactly one set, and a
  `_reads_down` latch makes a round pay one timeout instead of n.

### 15.5 Measured results (eth-tester, deployed bytecode, signed path)

Commitment gas: `commitBatch(4)` = 168,081 (42,020/client); `classifySigned`
= 46,647; `classify` + amortised batch = 80,268. Signed path is **42%
cheaper**. Anti-fabrication enforced on chain (`MissingCommit`); a forged
signature rejects the whole batch atomically (`SignerNotDeviceWallet`).
Event asymmetry: `GradientCommitted` is indexed on `keccak(deviceId)`, so the
payload exposes `device_key`, not the label.

**Liveness (2b, injected stall): the split verdict IS the result.**
Structural holds (every round completed, identical models sync vs async).
Wall clock did NOT hold: per-round mean healthy→stalled, sync 409→2002 ms
(~5×), async 61→1003 ms. With a realistic 120 s poll timeout the sync case
becomes tens of minutes per round: **a synchronous ledger IS on the
wall-clock critical path** (corrects the unqualified N24 claim).
**Backlog collateral (the finding to protect):** the async writer carries a
backlog INTO the outage; at queue depth 17, three writes including an ENROLL
were destroyed despite being issued before the stall, and chain-only
reconciliation failed (`enrolled locally but absent on chain: ['h3']`).
Sync loses only rounds overlapping the outage; async loses a window as wide
as the queue. The async writer is NEW code — report the collateral beside
any async number. Use `--stall-mode hang` (default); `refuse` flatters the
design (QBFT below quorum accepts into the pool and never mines = hang).

**Economics (Phase 4).** At 30 gwei, POL = USD 0.42 (price date 2026-08-31):
30-round federation costs USD 0.169 / 0.316 / 0.756 at 10 / 20 / 50 clients;
deployment USD 0.026 one-off. A HARDWARE attacker's 8 certified modules
(~USD 120) cost **~380× the ledger that sanctions them**. Prices are supplied,
never fetched; `--price-date` is mandatory.

**Three paper corrections.** (1) Gas depends on device-label length: `"g"`
95,332 vs `"d0"` 95,344 (+12 gas = one non-zero calldata byte); the affine fit
is quoted for the harness's label lengths. (2) 50-client projection:
58,281 + 38,818×50 = 1,999,181; the paper's 1,999,175 came from unrounded fit
coefficients — say so or recompute. (3) `chain/deploy.py --self-test` had been
silently failing (`load_abi()` ignored the overridden `ABI_PATH`); fixed.

### 15.6 QBFT phase — PARTIALLY EXECUTED (2026-09-11)

The 4-validator Besu network (`qbft/`) ran. From the archived logs:

- **2b liveness with `--manual-stall` (real quorum loss, stop besu-3+besu-4),
  completed twice.** Sync: healthy ~14.4 s/round; first stalled round
  188.9 s (full timeout), subsequent stalled rounds ~14–16 s (latch); restored
  ~14.4 s. Async: healthy ~115–136 ms/round. After restore: rebuilt from
  chain, 6 devices, 78 events replayed, 0 discrepancies. Rounds written while
  the chain was down are NOT recoverable (the tx never landed); what survives
  is the ban ledger and every anchored round.
- **2c preflight, writer and non-writer keys: 18 passed, 1 failed.**
  Deploy via signed tx reproduced gas 2,085,425 exactly; a second funded key
  was refused `UnauthorizedWriter` BY CONSENSUS; `commitBatch(4)` = 168,069;
  `classifySigned` = 46,613; forged commitment rejected atomically; async
  writes kept the training thread at ~114–130 ms while ledger work took
  ~13.2 s in the background.
- **OPEN BUG (the 1 failure):** `head_hash()` raises `ExtraDataLengthError`
  on Besu — POA chains put 327 bytes in `extraData`; web3 needs
  `geth_poa_middleware` injected. Fix in `chain/evm.py` before re-running
  preflight. The log's own rule: "Do NOT spend faucet funds until these pass."
- 2a (confirmation latency) and 2d (reorg null result) have no archived logs —
  treat as not yet run.

**Ceiling, state it in one clause:** four validators in Docker on one host is
consensus in mechanism, not in threat model — the enforcement path runs under
Byzantine agreement, but was not agreed to by parties with conflicting
interests.

### 15.7 What is still NOT true

Six to fifty clients is not deployment scale. Two physical TPMs is not a
hardware study. A stealthy directed-deviation attack from a legitimately
enrolled device still defeats the design. eth-tester mines instantly, so no
code here has seen a pending transaction. The Limitations sentence stays:
"evaluated on a local development node, so this demonstrates enforcement
behaviour, not the trust properties of a multi-validator deployment" — until
the QBFT results are re-run clean after the POA fix.

---

## 16. Appendix — carried forward from the chain-era documents

Unique content merged from `docs/history/MASTER_CONTEXT_chain-era.md` and
`docs/history/NEXT_SESSION_PROMPT.md` (both retired; their build tasks are
fully executed). Constants here match live code.

### 16.1 Engine update rule (explicit form)

```
POSITIVE | NEUTRAL:   s ← γ·s + θ ;  clean_run += 1 ;  major_run ← 0
                      if clean_run ≥ FORGIVE_AFTER:  f ← f · FORGET
MINOR | MAJOR:        s ← γ·s ;  f ← f + τ ;  clean_run ← 0
                      major_run ← major_run+1 if MAJOR else 0
CRITICAL:             a RULE, not a weight — immediate non-compensable ban
```

Opinion: b = s/n, d = f/n, u = (α₀+β₀)/n, a = α₀/(α₀+β₀), n = α₀+β₀+s+f.

**θ_r = 0.75 is load-bearing for the chain port:** 0.75/(1−0.75) = 3 exactly,
so the reinstatement floor `need_s = 3f + 2` is exact in integer arithmetic.
At v2.1's 0.55 the ratio 11/9 would not be exact.

**FORGET = GAMMA measured trace** (after 1 MAJOR: s=0, f=0.6, T=0.385):

```
clean 1:  s=0.400  f=0.600  T=0.467   ← f untouched, clean_run=1
clean 2:  s=0.760  f=0.540  T=0.533   ← f decays for the first time
clean 3:  s=1.084  f=0.486  T=0.584
clean 4:  s=1.376  f=0.437  T=0.623
```

The Slovic asymmetry DIRECTION is preserved through the gate, not a rate
ratio. The contract implements ONE decay operation (`x → 9x/10`).

### 16.2 State machine — every legal transition

| Transition | Trigger | Guard |
|---|---|---|
| ∅ → ACTIVE | `register()` | ek_hash ∉ banned set |
| ∅ → BANNED | `register()` | ek_hash ∈ banned set — **this is O2** |
| ACTIVE\|PROBATION → BANNED | CRITICAL | ungated, immediate |
| ACTIVE → PROBATION | backstop T ≤ 0.3 | gate open AND REHAB |
| ACTIVE\|PROBATION → BANNED | backstop T ≤ 0.3 | gate open, not REHAB or already PROBATION |
| ACTIVE\|PROBATION → PROBATION | M3 major_run ≥ 2 | ungated, REHAB |
| ACTIVE → BANNED | M3 | ungated, not REHAB |
| ACTIVE → PROBATION | T ≤ 0.5 | gate open, REHAB |
| ACTIVE → BANNED | T ≤ 0.5 | gate open, not REHAB |
| PROBATION → ACTIVE | `reinstate()` | REHAB AND status == PROBATION |

Check order is PINNED: backstop → M3 → probation threshold, each returning.
**BANNED is absorbing. There is NO code path from BANNED to ACTIVE.**

**Known latent hole (deliberate, unreachable):** `register(id, tier)` with
`ek_hash=None` overwrites the record and resurrects a BANNED device as ACTIVE
with s=f=0. Unreachable from `fl/server.py` (always passes `payload["ek_hash"]`).
Left in place: `reputation.py` is a strict black box, and the chain layer
rejects the resurrection — a live demonstration of the contract's value.
**Do not "fix" it in reputation.py.**

### 16.3 Worked example (live v3 engine output)

```
Honest T1, 12 clean rounds : 0.500 → 0.795   (climbs toward ceiling 0.833)
T1 two MAJORs              : 0.500 → 0.385 (ACTIVE) → 0.312 (PROBATION via M3)
T2 MINOR, MAJOR, MAJOR     : 0.500 → 0.385 → 0.312 (ACTIVE) → 0.263 (BANNED)
T3 first MINOR             : 0.500 → 0.385, ACTIVE — u-gate still closed
Sleeper, 30 clean + attack : banks 0.828, MAJOR#1 → 0.735 (ACTIVE),
                             MAJOR#2 → 0.651 (PROBATION: score > 0.5, M3 fires)
On-off (MAJOR then clean)  : f = 0.600 held through clean round 1,
                             decays 0.540 / 0.486 / 0.437 from round 2 on
```

### 16.4 Probation methodology notes

- OLS vs Theil-Sen is NOT a Youden's-J question; it needs a dedicated
  outlier-injection robustness experiment. Classifier metrics applied to a
  slope estimator were explicitly rejected.
- The shadow evaluator must use linear-response, not cosine similarity:
  cosine saturates within 1–2 rounds, producing a near-zero OLS slope
  regardless of gradient quality (this caused honest clients to fail probation).

### 16.5 Severity vocabulary and the transport seam

`filter.py` emits exactly NEUTRAL / MINOR / MAJOR / CRITICAL.
`reputation.EventTier` has FIVE members — POSITIVE exists and is in
GOOD_EVIDENCE but is unreachable from `filter.py`. Any ABI or contract enum
must carry all five so a future positive-evidence source needs no migration.

`FederatedServer` talks only to handle objects exposing `.device_label
.tpm_backend .enroll_payload() .activate_credential(blob) .train(r, params)`.
`LocalClientHandle(label, signer, fl_client, tpm_backend="mock")` vs
`RemoteClientHandle(label, endpoint, tpm_backend="real", timeout=30,
train_timeout=600)`. `_challenge` branches on `tpm_backend`, NOT handle class
— TPM realism and transport are independent axes.

### 16.6 Audit-log sparsity and the full event surface

`fl/server.py` skips NEUTRAL classifications when logging (`if self.audit and
cls.severity != "NEUTRAL"`). NEUTRAL is exactly what decays s, increments
clean_run and forgives f, so **the audit log alone cannot reconstruct
reputation state**. `ChainRegistry` infers NEUTRAL as the complement of
logged EVENTs against the ROUND participant list — exact, not heuristic.

Safety side-condition: a device that transitions status always has a logged
non-NEUTRAL event (NEUTRAL raises s, lowers f, zeroes major_run — it cannot
cross any threshold in the sanctioning direction). Hence no device receives
both an inferred NEUTRAL and a transition event in the same round.

Event types emitted by `fl/server.py`:

```
ENROLL, EVENT (non-NEUTRAL classifications), BAN, WHITEWASH_REJECTED,
PROBATION_ENTER, PROBATION_DECISION, REHAB_EXHAUSTED,
ROUND {"round": rid, "participants": sorted(labels), "aggregated": bool}
```

HashChain entry schema: `{seq, ts, type, payload, prev, hash, sig}`; GENESIS
auto-appended at construction.

### 16.7 Fixed-point and storage details

FP constants: `SCALE = 1_000_000`; THETA_FP = 400,000; TAU_FP = 600,000;
BAN_T = 300,000; PROBATION_T = 500,000; REINSTATE_T = 750,000;
REINSTATE_RATIO = 3 (exact at θ_r = 0.75); DECAY = 9/10 floor.
Status: ACTIVE=0, PROBATION=1, BANNED=2. Tier: HARDWARE=1, TPM_RESIDENT=2,
SOFTWARE=3. Severity: POSITIVE=0, NEUTRAL=1, MINOR=2, MAJOR=3, CRITICAL=4.

Only ONE operation truncates: `decay(x) = (9x)//10` (Solidity `/` on uint and
Python `//` on non-negative int are both floor — bit-identical by
construction). Threshold tests use cross-multiplication
(`(1+s)·SCALE ≤ t·(2+s+f)`) — exact, no division on the decision path.
Measured over 80,000 random events across all three tiers: zero status
decisions differ. The fixed-point path is AUTHORITATIVE for status.

Packed word: s(64) + f(64) + cleanRun(16) + majorRun(16) + status(8) +
tier(8) + lastRound(32) = **208 bits declared**, one 256-bit SSTORE slot.
Measured `bit_length()` varies with the last round written (169/179/181)
because lastRound occupies the top 32 bits — quote the declared 208, not the
incidental measurement. Other contract maps: `deviceEk`, `bannedEk`,
`ekToDevice`, `rehabUsed`, `roundClosed`, `lastRound`, `deviceWallet`,
`walletDevice`, `commitments`.

Canonical gradient serialization: little-endian IEEE-754 float64,
`struct.pack("<Nd", *G)`; commitment = `keccak256(canonical(gradient))`.

### 16.8 EK privacy and verification semantics

`ek_hmac = HMAC-SHA256(federation_key, b"DLTF-EKv1|" || ek_hash)`. The
federation key MUST be independent of `audit.jsonl.key` — sharing it would
let anyone permitted to verify the audit log de-anonymise every EK on the
ledger. Default `results/federation.key`, mode 0600. Key rotation invalidates
the ban list and is the closest approximation to GDPR-style erasure available
(destroying the key makes existing ek_hmacs unlinkable).

Reconciliation reads TWO ledgers: s/f/clean_run/major_run/status/tier from
the CHAIN (authoritative — the contract rejected any lifecycle-breaking
write); raw ek_hash from the LOCAL audit log (the chain holds only the
one-way HMAC). Seeding `_banned_ek` with HMAC digests would silently re-admit
every banned device; `chain/reconcile.py` test 6 is the permanent regression
guard.

Third-party verification is strictly stronger than the hash chain: the hash
chain proves nobody EDITED the log; `chain/verifier.py` proves the log's
CONTENTS IMPLY the recorded state (replay through the integer engine,
field-by-field comparison, public read surface only). A server that wrote a
plausible event stream while storing inflated scores or a silent un-ban
passes hash-chain verification and FAILS recomputation (TAMPER 1/2 in
`tools/prove_it_works.py`). Limit: internal consistency, not ground truth.

Threat-model amendment: T21–T26 (server-operator manipulation) and N18–N23
(contract-level rejections); commitment adds T27–T31 / N24–N28. **T26 is the
honest limit: a compromised server key can still write FALSE
classifications.** The contract constrains transitions, not input
truthfulness. Do not overclaim.

### 16.9 Pinned design decisions (do not revisit)

1. Semantic API, not state-driven: no `submitState()`; callers submit
   severity, the contract recomputes (N20 is structural).
2. BANNED is absorbing; the latent `ek_hash=None` hole stays (see 16.2).
3. **Mock chain is deterministic:** no timestamps in hashed bodies (unlike
   audit/hashchain.py which hashes `time.time()`). Same sequence → same head.
4. NEUTRAL inference is exact (16.6).
5. **Consequence events ignored:** BAN and WHITEWASH_REJECTED are cascaded
   by the backend; the adapter does not re-dispatch them.
6. Training survives chain failure (structural); see §15.5 for the
   wall-clock nuance and async backlog collateral.
7. EK privacy: raw EK hashes never go on chain; federation key separate
   from audit key.
8. FORGET = GAMMA = 0.90, one decay primitive, [DERIVED].

Off by default is a hard constraint: with `--chain off`, the pipeline,
sweeps and both run scripts behave exactly as before. No gradients on chain
(hashes and scalars only). `reputation.py` is a strict black box.

Toolchain: Foundry or Hardhat. NOT Truffle or Ganache (both archived by
ConsenSys, Dec 2023).

### 16.10 The central demonstration (verified SIM lifecycle)

```
6 clients (4 honest, 2 colluding), SOFTWARE tier, 5 rounds
  both attackers banned at r1 via M3
  36 mirrored writes, 5/5 rounds anchored, 0 failures
restart, rebuild from chain events alone:
  VERIFIED: 6 devices, 30 events replayed, 0 discrepancies
  adv0 recomputed: status=BANNED s=0 f=1200000 major_run=2
whitewash — adv0 returns as 'newclient', same EK:
  WHITEWASH_REJECTED, no device record, is_banned_on_chain = True
forged resurrection — server writes ENROLL for banned adv0, fresh EK:
  hash chain:  ACCEPTED, verify() still True
  chain layer: REJECTED (EkAlreadyRegistered), status unchanged BANNED
```

That last pair is the paper's central demonstration: the concrete capability
difference between recording and enforcing.

### 16.11 BRACU thesis LaTeX template constraints (thesis track only)

No `booktabs`, `longtable`, `amssymb`, `tikz`, `listings`, `float`,
`subcaption`. Tables use `\hline` only. Figures are external PNGs.
biblatex-biber IEEE style. (The ACM NSysS paper track uses acmart sigconf
v2.19 and allows booktabs — keep the two instruction sets separate; see
CLAUDE.md §2 and `docs/history/LATEX_CHANGES*.md`.)
