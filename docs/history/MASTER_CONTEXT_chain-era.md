> **RETIRED (2026-11-17) - HISTORICAL SNAPSHOT.** The v3 + chain-core era context (pre-commitment, pre-September). Its unique content (state machine, design decisions, audit seam, fixed-point details) was merged into root MASTER_CONTEXT.md section 16. Its file-status table ("NOT STARTED") is obsolete - everything listed was built.

# MASTER_CONTEXT.md — DLTF Thesis, Current State

Complete context for continuing the DLTF thesis in a new session. This describes
the system AS IT STANDS NOW. Read fully before touching code.

User: Sazzad, CS undergraduate thesis, BRAC University, defending Summer 2026.
Style: terse, direct, bottom-line-first, tables over prose, wants short answers,
corrects verbosity and factual/citation errors directly. House code style: no em
dashes, ✓/✗ in prints, minimal comments, every module has a `__main__` self-test
with assertions, comments map features to objectives O1–O4.

**Doc revision:** rewritten after the reputation engine v2.1 → v3 migration and
the chain-layer addition. Every constant in §4 was read from live code, not
from an earlier draft. If a number here disagrees with the code, the CODE WINS
and this file is stale — report it.

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
sanction-and-rehabilitation lifecycle, (b) the sanction policy itself is a
function of hardware trust tier (identity replacement cost), (c) attacker cost
per tier is quantified, (d) EK-hash-bound bans that persist across
re-enrollment AND across server restart.

**Novelty framing must stay hedged.** ZTA-FL (arXiv:2512.23809, Dec 2025) is the
closest prior work and is a near-miss overlap. Use "to our knowledge"; never
claim absolute precedence. The defensible differentiators are: EK-hash-bound
bans persisting across re-enrollment, policy severity indexed to hardware
identity tier, and accuracy-slope-gated reinstatement.

---

## 2. Live deployment state

WORKING: 3 physical machines on a Tailscale WireGuard mesh (account tpm97510@),
all Ryzen boxes with AMD firmware TPMs:
- 100.95.144.127 (ubuntu)    → SERVER (runs run_server.py; NOT in CLIENTS list)
- 100.70.28.2   (s4zz4d HP)  → client1 (runs net/agent.py)
- 100.64.57.82  (tafsir HP)  → client2 (runs net/agent.py)

**RESOLVED CONFLICT:** client2's IP is `100.64.57.82`. This matches `config.py`
line 26 and `SETUP_GUIDE.md` line 90. An earlier revision of this file said
`100.73.178.82`, which was wrong. If it ever disagrees again, `tailscale ip -4`
on the tafsir machine is authoritative.

ACHIEVED: Both clients enroll as real Tier 1 (HARDWARE) with DISTINCT EK hashes
(client1 ac6971…, client2 e7c273…), confirming one-chip-one-identity (O1). Real
409,034-param MNIST model is sent by the server. Round loop runs over real HTTP.
Audit chain writes to results/audit.jsonl.

Deployment facts:
- Tailscale is required (Bangladeshi CGNAT blocks direct inbound). All machines
  must be on ONE Tailscale account or only some appear in `tailscale status`.
- The SERVER dials OUT to clients on port 8470; clients never dial the server,
  so the server's own IP is not in config.CLIENTS.
- torch + torchvision needed on SERVER and all CLIENTS (server imports MNISTModel).
- Traffic is WireGuard-encrypted, mitigating the plain-HTTP limitation.

Run order (real, over Tailscale):
  0. All machines on one Tailscale account; `tailscale status` shows all three.
  1. Each CLIENT: `PYTHONPATH=. python3 -m net.agent --label clientN --port 8470`
     (no --stub for real MNIST; first start downloads MNIST). LEAVE RUNNING.
  2. SERVER: `curl http://<clientIP>:8470/health` each (expect {"ok":true}), then
     `PYTHONPATH=. python3 run_server.py --rounds 5` (must print "real MNIST
     model: 409034 parameters").

---

## 3. TPM / hardware attestation — RESOLVED

Both clients reach real Tier 1. Certs live per-machine in `cert/` (each chip has
its OWN cert; certs are NOT shared between machines). Verified chain:
EK cert → AMD intermediate → AMD root; `verify_ek_certificate` returns True.

Key facts and fixes already applied:
- Cert is read from disk (`cert/ek.crt`), NOT live-fetched at enroll time. AMD's
  PKI live-fetch is flaky and returned a different (failing) 1262-byte cert.
  `_try_ek_cert` in tpm/client.py now reads the on-disk cert first, fetch is only
  a fallback.
- `run_server.py` loads `tpm/ca/amd_ftpm_ca.pem` as the server's `ca_bundle_pem`
  and passes it to FederatedServer (without this, cert_ok is always False → all
  Tier 2).
- CA bundle must contain the RIGHT intermediate. AMD chips chain through
  different intermediates: client certs use CN=PRG-RN, but the original bundle
  only had CN=PRG-SSP. Bundle now includes BOTH intermediates + AMDTPM root, so
  the server trusts any AMD chip chaining through either.
- `verify_ek_certificate` (tpm/common.py): tries the strict Rust X.509 parser
  first, falls back to `openssl verify -partial_chain` on ANY failure (parse OR
  chain-walk), because AMD certs are technically malformed (non-spec DEFAULT
  encoding on a critical field) AND chain via partial_chain. Both paths needed.

Enrollment tier gate (fl/server.py): tier is HARDWARE only if
`cert_ok = (cert present) AND (ca_bundle loaded) AND verify_ek_certificate()`
AND credential activation passes. The tier the SERVER assigns depends on what the
AGENT provisions (its tpm_backend), not on files sitting in cert/. config.py
must set `tpm_backend: "real"` and `tcti: "device:/dev/tpmrm0"` for a client to
present its cert.

Diagnostic: `check_tiers.py` (project root) enrolls both clients and prints tier
only, no training — use this to verify tiers before any training run.
**STATUS: verify this file exists.** It is referenced here and in the run
commands but was flagged missing in a prior audit.

DATA MODEL (enrollment, JSON over HTTP, binary fields base64):
  ek_cert    ≜ ⟨EK_pub, issuer, validity, manufacturer_sig⟩
  provision  ≜ ⟨device_label, ek_hash, ak_name, ek_cert, ek_pub⟩  (POST /enroll)
  challenge  ≜ ⟨blob⟩  where blob = MakeCredential(ek_pub, secret) (POST /activate)
  response   ≜ ⟨secret'⟩  where secret' = ActivateCredential(blob)
  identity   ≜ ⟨device_label, ek_hash, tier, status⟩
  ek_hash = SHA256(EK_pub) is the identity fingerprint; bans bind to it (O2).

---

## 4. Reputation engine — v3, IDENTITY-BLIND (trust/reputation.py)

**⚠ THIS SECTION WAS REWRITTEN. The v2.1 engine described in earlier revisions
(tier priors α₀ = 8/4/2, start trust 0.80/0.667/0.50, θ_r = 0.55,
FORGIVE_AFTER = 5, FORGET Tier-1-only, BAD_EVIDENCE {MINOR:1, MAJOR:3}) NO
LONGER EXISTS.** The v3 engine is identity-blind. Do not quote v2.1 numbers.

Bayesian engine in subjective-logic form (Jøsang 2001; Jøsang & Ismail 2002).
Class name ReputationEngine. Exports Status, EventTier, PROBATION_WEIGHT_CAP.

TRUST SCORE (Jøsang's probability expectation E = b + a·u):

    T = (α₀ + s) / (α₀ + β₀ + s + f)     with α₀ = β₀ = 1

s = accumulated good evidence, f = accumulated bad evidence.
Opinion (b, d, u, a) exposed: b = s/n, d = f/n, u = (α₀+β₀)/n, a = α₀/(α₀+β₀),
n = α₀+β₀+s+f. Aggregation weight w = cap(tier)·T, 0 if banned.

### THE v3 DESIGN DECISION: identity-blind score, tier-coupled POLICY

Every tier starts at trust 0.5 with prior Beta(1,1) and u = 1. The tier does
NOT enter the score. Tiers differ ONLY through three policy levers:

  1. the aggregation weight cap D = {1.0, 0.5, 0.1}
  2. whether rehabilitation is available (REHAB: Tier 1 only)
  3. nothing else

Rationale: identity proof is not behavioral proof. A verified TPM says the
machine is accountable, not that it is honest. Giving Tier 1 a head start on the
SCORE conflated the two. v3 separates them: identity determines CONSEQUENCE
severity, behavior alone determines the score.

### UPDATE RULE

    POSITIVE | NEUTRAL:   s ← γ·s + θ ;  clean_run += 1 ;  major_run ← 0
                          if clean_run ≥ FORGIVE_AFTER:  f ← f · FORGET
    MINOR | MAJOR:        s ← γ·s ;  f ← f + τ ;  clean_run ← 0
                          major_run ← major_run+1 if MAJOR else 0
    CRITICAL:             a RULE, not a weight — immediate non-compensable ban

### CONSTANT VALUES (read from live code, authoritative)

| Constant | Value | Grade | Provenance |
|---|---|---|---|
| `PRIOR` (α₀, β₀) | (1.0, 1.0) | CANONICAL | Jøsang non-informative prior |
| `W_PRIOR` | 2.0 | CANONICAL | α₀+β₀ |
| `THETA` (θ) | 0.4 | CANONICAL | Kang 2019 Tab. I positive weight |
| `TAU` (τ) | 0.6 | CANONICAL | Kang 2019 Tab. I negative weight; τ > θ |
| `GAMMA` (γ) | 0.90 | CONVENTIONAL | standard exponential-forgetting rate |
| `FORGET` | **0.90** | **[DERIVED] = GAMMA** | see below |
| `FORGIVE_AFTER` | 2 | CALIBRATED | one clean round launders nothing |
| `MAJOR_RUN_TO_ESCALATE` | 2 | CALIBRATED | matches detector's sustained window |
| `PROBATION_T` (θ_p) | 0.5 | CALIBRATED | indifference point |
| `BAN_T` (θ_b) | 0.3 | CALIBRATED | backstop |
| `REINSTATE_T` (θ_r) | **0.75** | [DERIVED] | closed form 0.5·(1 + 1/W) |
| `TIER_DISCOUNT` | 1.0 / 0.5 / 0.1 | CANONICAL / CALIB / CALIB | |
| `REHAB` | HARDWARE only | policy | Ostrom graduated sanctions |
| `PROBATION_WEIGHT_CAP` | 0.1 | CALIBRATED | probation ≤ Tier-3 influence |
| `GOOD_EVIDENCE` | {POSITIVE, NEUTRAL} | — | POSITIVE unreachable from filter.py |

Derived quantities:
  s_max = θ/(1−γ) = 4.0           T_max = 5/6 = 0.8333 (trust ceiling)
  u-gate: evidence dominates when s + f > W_PRIOR = 2.0

**θ_r = 0.75 NOT 0.55.** An earlier revision of this file said 0.55. That was
the v2.1 value. v3's closed form is 0.5·(1 + 1/W) = 0.5·1.5 = 0.75. This matters
beyond documentation: 0.75/(1−0.75) = 3 exactly, so the reinstatement floor
`need_s = 3f + 2` is exact in integer arithmetic. At 0.55 the ratio 11/9 would
not be exact and the on-chain port would need a stated rounding direction.

### FORGET = GAMMA = 0.90 — [DERIVED], and why the old story was wrong

An earlier revision claimed `FORGET = 1 − (1−γ)/2 = 0.95`, justified as
"distrust fades at half the rate trust decays" citing Slovic 1993. **That
justification does not hold at 0.90.** At FORGET = GAMMA the two rates are
IDENTICAL, not halved.

The asymmetry is real but comes from a different mechanism: `FORGIVE_AFTER = 2`
gates the decay. `s` decays every round unconditionally; `f` decays only from
the second consecutive clean round onward. Measured:

    after 1 MAJOR:  s=0.000  f=0.600  T=0.385
      clean 1:      s=0.400  f=0.600  T=0.467   ← f untouched, clean_run=1
      clean 2:      s=0.760  f=0.540  T=0.533   ← f decays for the first time
      clean 3:      s=1.084  f=0.486  T=0.584
      clean 4:      s=1.376  f=0.437  T=0.623

Defense framing: `FORGET` is not a free parameter. It is forced by the decision
to use a single decay primitive. The Slovic 1993 asymmetry DIRECTION is
preserved through the gate, not through a rate ratio. The on-chain contract
therefore implements ONE decay operation (`x → 9x/10`) instead of two.

**Self-test consequence:** the shipped `reputation.py` had `assert abs(FORGET −
0.95) < 1e-12` at line 446 while the constant was 0.90 — the self-test crashed
on import. Fixed. The D4 cold-start band at line 481 was also calibrated at
0.95 and needed re-deriving: `0.68 < t12 < 0.74` → `0.71 < t12 < 0.76`.
Self-test is now 16/16 green.

### HARDENING MECHANISMS

  M1 bounded recency: s ← γs + θ saturates at 4.0, so a sleeper cannot bank
     unbounded cushion; trust ceiling 0.833.
  M2 gated forgetting: f never decays round-by-round; fades ×0.90 only after 2
     consecutive clean rounds. One good round launders nothing.
  M3 sustained escalation: 2 consecutive MAJORs → probation/ban bypassing the
     score, catching a high-s veteran sleeper whose score is still > 0.5.
  D5 due process: a Tier-1 device crossing the ban threshold goes to PROBATION
     first, never straight to BANNED (except on CRITICAL).

### STATE MACHINE — every legal transition

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
Reinstatement is PROBATION → ACTIVE, never BANNED → ACTIVE.

**KNOWN LATENT HOLE (unreachable, documented):** `register(device_id, tier)`
with `ek_hash=None` overwrites the device record unconditionally and resurrects
a BANNED device as ACTIVE with s = f = 0. Verified reproducible in isolation.
Unreachable from `fl/server.py`, which always passes `payload["ek_hash"]`, and
both handle classes always populate it. Left in place deliberately:
`reputation.py` is a strict black box, and the chain layer rejects the
resurrection, which makes it a live demonstration of the contract's value
rather than a bug to paper over.

METHODS: register(id,tier,ek_hash) / record_event(id,severity) /
reinstate(id, trial_rounds=0) / get_status / get_weight / get_all_weights /
get_opinion(id) → (b,d,u,a) / rank(ids=None) → Jøsang Def.10 ordering /
banned_ek_hashes.

---

## 5. Probation engine — FINALIZED (trust/probation.py)

Tier-1-only rehabilitation. A probated client's updates train an ISOLATED shadow
model (frozen global snapshot + only that client's gradients). Reinstatement is
decided by the OLS slope of the shadow model's accuracy over the trial.

  REINSTATE_SLOPE = 0.005  → REINSTATED (calls rep.reinstate with trial rounds)
  EXTEND_SLOPE = 0.001     → one-shot EXTENDED (+3 rounds), else PERMANENT_BAN
  EXTENSION_ROUNDS = 3
  SLOPE_ESTIMATOR = "ols"
  WINDOW = HMAC(device_id, entry_round) ∈ [WINDOW_MIN=4, WINDOW_MAX=9]
     [DERIVED] 4 = OLS sign-stability floor, 9 = resolve within trust memory.
     HMAC_SALT = os.urandom per process, so "behave just long enough" timing
     attacks are blocked. Tests pin it to a constant for determinism.
  Outcomes: PENDING | EXTENDED | REINSTATED | PERMANENT_BAN
  TERMINAL = {REINSTATED, PERMANENT_BAN}

One-shot rehabilitation: a device already REINSTATED once that re-offends gets
PERMANENT_BAN, not a second trial.

SLOPE→REPUTATION COUPLING: the slope decides the BRANCH; trial rounds are
forwarded to `rep.reinstate(id, trial_rounds=len(accuracy_series))` as EARNED
EVIDENCE (s += θ·trial_rounds) before the θ_r = 0.75 floor. A longer proven
recovery returns with proportionally higher trust. No new constants.

**SLOPE_ESTIMATOR note:** OLS vs Theil-Sen is NOT a Youden's-J question. It
requires a dedicated outlier-injection robustness experiment. Applying
classifier metrics to a slope estimator was explicitly rejected.

**Shadow evaluator must use linear-response, not cosine similarity.** Cosine
saturates within 1–2 rounds, producing a near-zero OLS slope regardless of
gradient quality, which caused honest clients to fail probation. Match the
pattern in `probation.py`'s own self-tests.

---

## 6. Worked example — REGENERATED under v3 (real engine output)

All figures below were produced by the live v3 engine. The v2.1 worked example
in earlier revisions (enroll 0.80, two MAJORs 0.80→0.615→0.500) is retired.

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

Note the T3 line: a fresh Tier-3 device's first MINOR takes it to 0.385, which
is BELOW θ_b = 0.3? No — 0.385 > 0.3, and the u-gate (s+f > 2) is still closed,
so no sanction fires. This is D4: identity-blind starts must not ban on a single
noisy round.

---

## 7. Architecture (6 layers + eval + tests)

```
tpm/     identity: EK cert verify + credential activation → tier
trust/   reputation.py (§4), probation.py (§5), filter.py (detection)
fl/      model (MNIST CNN 409k), dataset (non-IID), client, aggregator
         (fedavg/krum/trimmed_mean), server (enroll + round lifecycle)
net/     handles.py (local↔remote seam), agent.py (per-client HTTP agent)
audit/   hashchain.py (HMAC-signed tamper-evident JSONL chain)
chain/   OPTIONAL on-chain trust registry (§8) — off by default
eval/    scenarios, run_experiments (Chapter-4 CSVs + --check), plot_results
tests/   test_pipeline.py (all module self-tests + compile + HTTP/audit e2e)
```

Detection (filter.py, existing techniques, max-severity compose):
  Stage1 norm > 2.5× median → MINOR
  Stage2 cosine to leave-one-out median of prior-trusted < −0.45 → MAJOR
  Stage3 FoolsGold-style pairwise sim ≥ 0.95 sustained 2 rounds → CRITICAL
  Stage4 self-history cosine < −0.45 sustained 2 rounds → MAJOR

Severity vocabulary: `filter.py` emits exactly NEUTRAL / MINOR / MAJOR /
CRITICAL. `reputation.EventTier` has FIVE members — POSITIVE also exists and is
in GOOD_EVIDENCE but is currently unreachable from `filter.py`. Any ABI or
contract enum must carry all five so a future positive-evidence source does not
require a migration.

Transport seam: `FederatedServer` talks only to handle objects exposing
`.device_label .tpm_backend .enroll_payload() .activate_credential(blob)
.train(r, params)`. `LocalClientHandle(label, signer, fl_client,
tpm_backend="mock")` vs `RemoteClientHandle(label, endpoint,
tpm_backend="real", timeout=30, train_timeout=600)`. `_challenge` branches on
`tpm_backend`, NOT on handle class — TPM realism and transport are independent
axes.

**AUDIT-LOG SPARSITY — important, affects any log consumer.**
`fl/server.py` line 113 reads `if self.audit and cls.severity != "NEUTRAL"`.
NEUTRAL classifications are NEVER written to the audit log. This is a
deliberate space optimisation and is sound for tamper-evidence, but NEUTRAL is
exactly what decays s, increments clean_run, and forgives f. **The audit log
alone is therefore insufficient to reconstruct reputation state.** The chain
adapter recovers the missing information by inference (§8), not by modifying
the server.

Trust model: **server partially trusted** (see §8 threat-model amendment);
clients untrusted; only manufacturer roots/intermediates in the CA bundle are
trusted. Weight = cap(tier)·T; banned devices absent from weights →
structurally excluded from aggregation. Krum uses weights as an eligibility
mask (O4).

---

## 8. Chain layer — OPTIONAL on-chain trust registry (chain/, contracts/)

**Supersedes the earlier instruction "do not reintroduce blockchain."** That
instruction reflected a trusted-server threat model under which anchoring added
nothing. This work extends the threat model to a partially-adversarial server
OPERATOR, which is what makes the layer defensible. The scope is explicitly:
evaluate the MECHANISM. A local Hardhat/Anvil node has no decentralisation
properties; trust properties would be contingent on deployment across
independent validators. State this before anyone asks.

### Core principle: on-chain policy ENFORCEMENT, not on-chain logging

The hash chain records whatever the server writes. The contract REJECTS writes
that violate the trust lifecycle. That rejection capability is the entire
justification.

Six rules the server cannot break while the layer is enabled:

| Rule | Custom error |
|---|---|
| BANNED → ACTIVE by any path | `BanToActive` |
| tier change after enrollment | `TierMutation` |
| reputation delta outside the rule | structural — no delta API surface |
| duplicate or out-of-order round id | `DuplicateRound` / `StaleRound` |
| two device_ids claiming one EK | `EkAlreadyRegistered` |
| write from a non-server address | `UnauthorizedWriter` |

### Threat-model amendment (Chapter 3 §3.1.1, append-only)

New threat IDs T21–T26 for server-operator manipulation; new requirement IDs
N18–N23 for the contract-level rejections. **T26 is the honest limit: a
compromised server key can still write FALSE classifications.** The contract
constrains transitions, not input truthfulness. Do not overclaim.

### Fixed-point arithmetic

Solidity has no floats. `chain/fixedpoint.py` mirrors the float engine at
SCALE = 10⁶, chosen so every constant is exactly representable
(θ → 400000, τ → 600000, thresholds 300000/500000/750000): zero constant error.

Only ONE operation truncates: `decay(x) = (9x)//10`. Solidity's `/` on uint is
floor; Python's `//` on non-negative int is floor. Bit-identical by
construction. Threshold tests use cross-multiplication
(`(1+s)·SCALE ≤ t·(2+s+f)`) and are exact — no division on the decision path.
Reinstatement floor `need_S = 3F + 2·SCALE` is exact because θ_r = 0.75 gives
the integer ratio 3.

Proven bound `|T_float − T_fixed| ≤ 5×10⁻⁶`. Measured over 80,000 random events
across all three tiers: **zero status decisions differ.** The fixed-point path
is AUTHORITATIVE for status; the float engine remains the research artifact.

### Storage and cost

One packed 256-bit slot per device: s(64) + f(64) + clean_run(16) +
major_run(16) + status(8) + tier(8) + lastRound(32) = 208 bits, 48 spare. One
warm SSTORE per device per round. Contract bytecode 6.5 KB (EIP-170 limit 24 KB).

| Operation | Gas |
|---|---:|
| deploy (one-time) | 1,397,314 |
| register (fresh) | 95,047 |
| register (banned EK → whitewash) | 27,153 |
| classify NEUTRAL (warm) | 36,593 |
| classify MAJOR (warm) | 36,380 |
| classify CRITICAL → BAN | 64,346 |
| roundSummary | 91,277 |

Per-round marginal cost, 6 clients: ~309,000 gas ≈ $0.012 at 20 gwei / $2000 ETH.

### EK privacy — raw EK hashes NEVER go on chain

A real EK hash on an immutable ledger is a permanent physical-machine
fingerprint. The chain stores

    ek_hmac = HMAC-SHA256(federation_key, b"DLTF-EKv1|" || ek_hash)

The federation key MUST be independent of `audit.jsonl.key` — sharing it would
let anyone permitted to verify the audit log de-anonymise every EK on the
ledger. Default `results/federation.key`, mode 0600. Key rotation invalidates
the ban list and is the closest approximation to GDPR-style erasure available.

### The NEUTRAL inference (how the adapter works around §7's sparsity)

`ChainRegistry` buffers each round and, at `ROUND`, infers the NEUTRAL set as
the complement of the logged `EVENT` set, using the `participants` list the
`ROUND` record already carries. **Exact, not heuristic.**

Safety side-condition: a device that transitions status always has a logged
non-NEUTRAL event, because NEUTRAL raises s, lowers f, and zeroes major_run — it
cannot cross the backstop, M3, or the probation threshold in the sanctioning
direction. Hence no device receives both an inferred NEUTRAL and a transition
event in the same round, and per-device ordering is preserved.

### Never on the critical path

Every mirror call is wrapped. A rule rejection, RPC timeout, or any exception is
recorded with reason and detail, marks the round UNANCHORED, and does NOT
propagate. Rejections stay counted and inspectable
(`ChainRegistry.rejections`), so enforcement remains observable, but a node
outage cannot stall aggregation. At enrollment the layer fails **OPEN**: if the
node is unreachable, `is_banned_on_chain()` returns False rather than refusing.
Failing closed would hand any adversary who can DoS the node a
federation-wide enrollment DoS. Staleness window is a stated limitation.

### Third-party verification

`chain/verifier.py` replays the emitted event log through the integer engine and
compares recomputed state field-by-field against stored state. It uses ONLY the
public read surface (`events()`, `get_device()`, `is_banned_ek()`), so the same
code runs against a live node.

This is strictly stronger than the hash chain. The hash chain proves nobody
EDITED the log. Verification proves the log's CONTENTS IMPLY the recorded state.
A server that wrote a plausible event stream while storing inconsistent state —
inflated score, or a silently un-banned device — passes hash-chain verification
and FAILS recomputation. Both cases are demonstrated in the self-test.

Limit: verification establishes internal consistency, not ground truth.

### Three independent axes — do not couple them

| Axis | Values | Control |
|---|---|---|
| TPM identity | mock / real | `make_signer()`, `config.CLIENTS[].tpm_backend` |
| Transport + data | in-process / HTTP + MNIST | Local vs RemoteClientHandle |
| Chain | off / mock / node | `DLTF_CHAIN` env + `config.py` |

The chain layer is identical code in both SIM and REAL modes; it sees only
`(event_type, payload)`. The only legitimate difference is mock vs TPM-derived
EK hashes — both are just bytes to the contract.

### Toolchain

**Foundry** (or Hardhat). **NOT Truffle or Ganache** — both archived by
ConsenSys in December 2023.

### Chain-layer file status

| File | Status | Checks |
|---|---|---|
| `chain/fixedpoint.py` | done | 14 |
| `chain/backend.py` | done | 5 |
| `chain/mock.py` | done | 20 |
| `chain/keys.py` | done | 11 |
| `chain/registry.py` | done | 14 |
| `chain/verifier.py` | done | 11 |
| `chain/evm_parity_test.py` | done | 15 (live EVM) |
| `contracts/src/DLTFRegistry.sol` | done, compiles 6.5 KB | — |
| `contracts/test/DLTFRegistry.t.sol` | written, not run (no Foundry here) | — |
| `chain/evm.py` | NOT STARTED | — |
| `chain/deploy.py` | NOT STARTED | — |
| `chain/reconcile.py` | NOT STARTED (logic in verifier.replay_events) | — |
| `config.py` chain block | NOT STARTED | — |
| `run_local.py` CLI flags | NOT STARTED | — |

Total green: 106 checks (chain layer) + 16 (reputation) = 122.

### Verified end-to-end SIM lifecycle

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

---

## 9. Related work positioning (thesis Ch.2 / defense)

  FoolsGold [Fung 2018]: gradient-similarity detection only; no identity, no
    cost to re-register. DLTF includes a FoolsGold-style stage but adds
    hardware-bound identity that detection binds to.
  Kang 2019/2020 (multi-weight subjective logic FL reputation): flagship
    citation and the source of θ/τ = 0.4/0.6 (Tab. I). Two principles used:
    negative weighted > positive, recent > past. Sui 2024 review documents
    Kang's new-vs-old-client flaw = the same flaw the supervisor flagged.
  Jøsang 2001 (subjective logic): the formal foundation. DLTF's trust formula IS
    his E = b + a·u; his Def.10 (least-uncertainty ordering) = DLTF's rank().
  **ZTA-FL (arXiv:2512.23809, Dec 2025): CLOSEST COMPETING WORK.** Name it,
    state exactly what it does, identify the precise gap. Hedge all novelty
    claims with "to our knowledge".
  TrustFed (ur Rehman et al., IEEE T-II 2021): related trust-in-FL framework.
  Wang 2022 (TPM + blockchain oracle FL): uses TPM for update INTEGRITY, not
    persistent identity binding. **STATUS: present here but MISSING from
    REFERENCES.md — add it.**
  Douceur 2002 ("The Sybil Attack"): O1 foundation.
  Friedman & Resnick 2001 (cheap pseudonyms) + Ostrom 1990 (graduated
    sanctions): justify tier-coupling (policy scales with identity cost).
  Theil 1950 / Sen 1968: slope estimators, for the SLOPE_ESTIMATOR discussion.
  Slovic 1993: asymmetry DIRECTION only — see §4, it does not support a rate
    ratio at FORGET = 0.90.
  **Reference [24] Domingo-Ferrer is marked VERIFY — resolve before submission.**
  Honesty rule: NO paper prescribes DLTF's specific constants. Claiming a paper
    gives them = fabricated citation. Defend by derivation, not citation.

---

## 10. Known limitations (state ALL in thesis)

X.509 path validation simplified (name chain + signatures; no revocation / full
RFC 5280 / EK-profile OIDs). Plain HTTP at request level (mitigated by
Tailscale/WireGuard; request-level auth is future work). Tier 1 only where a
verifiable EK cert exists — claim is "whitewashing becomes hardware-cost-bound",
never "impossible". Local audit log is centralized (verifiable, not consensus).
Synthetic substrate for trust metrics; MNIST accuracy machine-side. Small
federation (2 real / ~10–50 simulated).

Chain-layer specific:
- A local Hardhat/Anvil node has NO decentralisation properties.
- A compromised server key can still write false classifications (T26).
- Immutable ledger vs GDPR erasure; key rotation is the only approximation.
- Fixed-point quantisation of a float trust model (bounded 5×10⁻⁶, zero
  measured status divergence, but non-zero in principle).
- Cached-snapshot staleness under fail-open enrollment.
- Single-federation evaluation.
- REAL mode limited to 2 physical clients — a feasibility claim, not a scaling
  claim.

Engine-specific:
- In-memory engine state means restart = re-enroll **with the chain layer
  disabled.** With the chain enabled this limitation is REMOVED — that is the
  point of reconciliation (N23).
- Several constants remain CALIBRATED inside derived bounds (caps,
  FORGIVE_AFTER, θ_b backstop) — defended by threshold sweep, not citation.
- Uncertainty u never reaches 0 (bounded memory) — deliberate, defeats sleepers.

---

## 11. PENDING / next steps

### Blocking before Chapter 5

  ⚠ **RE-RUN Chapter-4 evaluations. MANDATORY, not housekeeping.** Every CSV
    under `results/` was generated at FORGET = 0.95 under the v2.1 engine. Under
    v3 + FORGET = 0.90 every trust trajectory shifts.
    `PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5
    --rounds 30 --out results --check`, then `make_figures.py` / `plot_results`.

  ⚠ Apply the 6 `reputation.py` edits (FORGET provenance, D4 band, self-test
    assertions). Confirm `PYTHONPATH=. python3 -m trust.reputation` → 16 ticks.

  ⚠ Confirm `PYTHONPATH=. python3 tests/test_pipeline.py` → "PIPELINE GREEN".

### Carried-forward conflicts

  - `check_tiers.py` — referenced in §3 and run commands; confirm it exists.
  - `reputation_beta.py` — RETIRED, does not exist. `run_local.py` still accepts
    `--engine beta`, prints the choice, then ignores it and always builds
    `ReputationEngine()`. DELETE the flag (lines 34 and 52).
  - Live poison-injection command is undocumented — write it into the runbook.
  - `grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/` — CRITICAL is not a
    BAD_EVIDENCE key; any code reading it will KeyError.

### SIM-mode gap that blocks probation testing

  **`run_local.py` produces ONLY Tier-2 clients.** No `ca_bundle_pem` is passed,
  so `cert_ok = False` → `assess_tier(False, True)` → `TPM_RESIDENT` →
  `REHAB = False`. Every SIM client bans outright; PROBATION_ENTER,
  PROBATION_DECISION and REHAB_EXHAUSTED never fire, and transitions 4/6/8/10 in
  §4 are unreachable. Fix: adopt the `generate_test_ca` / `issue_ek_cert`
  pattern from `fl/server.py::_self_test`, plus a `--tier1 N` flag. Also
  `run_local.py` constructs `FederatedServer` without `audit=`, so SIM mode
  currently records nothing.

### Chain layer remaining

  `chain/evm.py`, `chain/deploy.py`, `chain/reconcile.py`, the `config.py` chain
  block (all defaulting to disabled), and `run_local.py --chain off|mock|node
  --restart-at N --rejoin-as LABEL`. Target acceptance test:

    PYTHONPATH=. DLTF_CHAIN=mock python3 run_local.py \
        --clients 6 --attackers 2 --rounds 20 \
        --chain mock --restart-at 12 --rejoin-as newclient

### Other

  - Live attack demo over Tailscale: one client sends poisoned updates → real
    flag → ban → EK-bound whitewash rejection.
  - `fl/model.py` self-test needs torch (machine-side).
  - Literature freshness check on 2024–2026 papers before defense.
  - Chapter writing order: 3 → 4 → 5 → 2 → 1 → 6.

---

## 12. Quick-start commands

```bash
# Baseline (chain off — MUST behave exactly as before)
PYTHONPATH=. python3 tests/test_pipeline.py
PYTHONPATH=. python3 check_tiers.py                 # tiers only, no training
PYTHONPATH=. python3 run_local.py
PYTHONPATH=. python3 run_server.py --rounds 5       # real MNIST over Tailscale
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470   # on each client

# Trust layer self-tests
PYTHONPATH=. python3 -m trust.reputation            # 16 ticks
PYTHONPATH=. python3 -m trust.probation

# Chain layer self-tests (no node needed)
PYTHONPATH=. python3 -m chain.fixedpoint            # 14 ticks
PYTHONPATH=. python3 -m chain.backend               #  5 ticks
PYTHONPATH=. python3 -m chain.mock                  # 20 ticks
PYTHONPATH=. python3 -m chain.keys                  # 11 ticks
PYTHONPATH=. python3 -m chain.registry              # 14 ticks
PYTHONPATH=. python3 -m chain.verifier              # 11 ticks

# Contract (needs solc 0.8.24)
solc --optimize --optimize-runs 200 --bin --abi --overwrite \
     -o contracts/out contracts/src/DLTFRegistry.sol
PYTHONPATH=. python3 -m chain.evm_parity_test        # 15 ticks, live EVM
cd contracts && forge test -vvv                      # independent check

# Evaluation (chain OFF — sweeps must stay reproducible)
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```
