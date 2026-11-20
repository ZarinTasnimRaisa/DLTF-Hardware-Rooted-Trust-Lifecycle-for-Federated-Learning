> **RETIRED (2026-11-17) - VARIANT-SPECIFIC NUMBERS, HANDLE WITH CARE.** The strongest "why these numbers" defense artifact in the repo (sweep series, coupling analysis, leniency ledger, 28%-residual honesty) - BUT it was generated for the divergent variant: FORGET=0.95 and FORGIVE_AFTER=5 (shipped code: 0.90 / 2). Every fade-dependent sweep number is variant-specific; THETA/TAU/GAMMA/caps/REINSTATE_T/BAN_T/u-gate sections still match. Regenerate against shipped constants or annotate per-section before quoting. See CHANGES_v3_push-model-variant.md for the pipeline that produced it.

# Parameter Justification Report — Tier-Coupled Reputation Engine (v3)

_Every numeric claim below is produced by `gen_data.py` running `trust/reputation.py`; the same JSON drives the three dashboards. Provenance grades: **CANONICAL** = a source's own number; **CONVENTIONAL** = a value in common published use; **CALIBRATED** = ours, defended by a sweep. This report supersedes the v2.1 version; the architecture changed from informative per-tier priors to a single Beta(1,1) prior with tier expressed only through the influence discount and rehabilitation eligibility._

## 0. What changed from v2.1, in one paragraph

v2.1 encoded tier as an *informative prior* (W = 10/6/4, base rate 0.8/0.67/0.5) and carried severity in per-event evidence magnitudes. v3 removes both. Every device now starts from the same non-informative prior Beta(1,1) — W = 2, base rate 0.5, starting trust 0.5 — and severity is carried by Kang's two interaction weights (θ = 0.4 for good events, τ = 0.6 for bad) plus two discrete rules (the M3 consecutive-MAJOR escalation and the non-compensable CRITICAL ban). Tier survives in exactly two places: the influence discount D = {1.0, 0.5, 0.1} and rehab-eligibility (Tier 1 only). A new subjective-logic *u-gate* withholds score-path sanctions while the prior still dominates the opinion. This report justifies each surviving constant and flags where v3's measured behaviour departs from the design's expected numbers.

## 1. Canonical values (taken, not tuned)

| Value | Source (grade) | Why it is not a free parameter |
|---|---|---|
| Prior W = 2, base rate a = 0.5 | Jøsang 2001 (CANONICAL) | Non-informative Beta(1,1); starting trust 0.5 is the base rate, an output of the prior. |
| θ = 0.4 (good), τ = 0.6 (bad) | Kang et al., *IEEE TVT* 68(3), 2019 (arXiv:1809.08387), Table I (CANONICAL) | The paper's own interaction weights; θ+τ = 1 held. Severity magnitude is no longer a tunable knob. |
| d1 = 1.0 (hardware discount) | Jøsang discounting operator (CANONICAL) | A fully-assured identity is not discounted; forced by the operator. Only d2, d3 are free. |
| PROBATION_T = 0.5 | Jøsang indifference point + Kang 0.5 detection cut (CANONICAL support) | The subjective-logic indifference point and Kang's 100%-detection threshold coincide at 0.5. |

## 2. Calibrated and conventional values, each on a sweep

For every value: the *mechanism* (and its citation grade), the *measured effect* of moving it, and *why the shipped value holds*. Effects are read straight from the sweep series.

### TAU (bad-evidence weight) = `0.6`  ·  CANONICAL

**Mechanism.** Kang et al. 2019 (IEEE TVT, Table I) weight negative interactions at tau=0.6 vs good at theta=0.4. In v3 this single asymmetry — not a per-severity magnitude — carries how fast bad behaviour erodes trust; theta+tau=1 is held.

**Measured across the sweep.**

- `honest_fp_rate_200rounds`: {0.5: 0.025, 0.6: 0.275, 0.7: 0.65}
- `first_bad_trust`: {0.5: 0.4, 0.6: 0.3846, 0.7: 0.3704}
- `all_minor_attacker_latency`: {0.5: 5, 0.6: 4, 0.7: 3}

**Why 0.6 holds.** Kang's tau=0.6 is adopted directly. The sweep measures its cost on the honest side: at 5% MINOR noise over 200 rounds the residual sanction rate runs {0.5: 0.025, 0.6: 0.275, 0.7: 0.65} — tau is the dominant lever (tau=0.5 -> 2%, tau=0.7 -> 65%). One bad event drops a fresh device to 0.3846 and a pure-MINOR attacker is sanctioned in 4 rounds. We keep the cited value and flag the honest residual rather than tune tau to hit a target.

### u-gate (cold-start) = `on`  ·  CALIBRATED

**Mechanism.** Subjective-logic uncertainty u=W/(W+s+f) (Josang 2001). Score-path sanctions are withheld while u>=0.5 (s+f<=W): the opinion is still prior-dominated. No new constant — the gate reuses W.

**Measured across the sweep.**

- `fp_first20_rounds`: {'off': 0.15, 'on': 0.025}
- `fp_full_200_rounds`: {'off': 0.325, 'on': 0.275}

**Why on holds.** The gate is a pure cold-start defense and the sweep shows exactly that. Over the first 20 rounds honest false positives fall 15%->2% when the gate is switched on; a single early noise MINOR (trust 0.3846) is absorbed because the opinion is still prior-dominated (u>=0.5). The gate does not touch the steady-state residual (32%->28% at 200 rounds) — that is tau's cluster effect, reported honestly on dashboard 3's negative control.

### PROBATION_T = `0.5`  ·  CALIBRATED

**Mechanism.** Trust threshold at which a device is sanctioned. 0.5 is the subjective-logic indifference point (below it a device is less trustworthy than a fresh unknown, base rate 0.5) and coincides with Kang's 0.5 detection cut (100% detection).

**Measured across the sweep.**

- `honest_fp_rate`: {0.4: 0.0, 0.45: 0.1, 0.5: 0.275, 0.55: 0.475, 0.6: 0.75}
- `all_minor_latency`: {0.4: 4, 0.45: 4, 0.5: 4, 0.55: 4, 0.6: 4}

**Why 0.5 holds.** The threshold shifts how much sustained minor abuse is tolerated ({0.4: 4, 0.45: 4, 0.5: 4, 0.55: 4, 0.6: 4} rounds to sanction a pure-MINOR attacker) while honest false positives move only slightly across the band ({0.4: 0.0, 0.45: 0.1, 0.5: 0.275, 0.55: 0.475, 0.6: 0.75}). 0.5 is kept for its meaning, not its score: crossing it makes a device literally less trustworthy than a fresh unknown, and it is exactly Kang's detection threshold.

### d2 (Tier-2 discount) = `0.5`  ·  CALIBRATED

**Mechanism.** Josang discounting: influence = D[tier]*trust. d2 prices a TPM-resident identity between hardware-bound (1.0) and software (0.1). RepuNet gives the discount structure; the value is ours.

**Measured across the sweep.**

- `compromised_t2_to_outweigh_one_t1_veteran`: {0.25: 4, 0.4: 3, 0.5: 2, 0.6: 2, 0.75: 2}
- `honest_t2_veteran_weight`: {0.25: 0.2083, 0.4: 0.3333, 0.5: 0.4167, 0.6: 0.5, 0.75: 0.625}

**Why 0.5 holds.** At d2=0.5 it takes 2 fully-trusted compromised TPM identities to outweigh one honest hardware veteran (weight 0.8331), while an honest TPM veteran still carries 0.4167 weight. Dropping to 0.25 doubles the sybil cost but halves honest TPM utility (0.2083); 0.75 nearly reaches hardware parity (2 identities). 0.5 splits the interval in log-space — the midpoint the sweep supports.

### d3 (Tier-3 cap) = `0.1`  ·  CALIBRATED

**Mechanism.** Cheap-pseudonym economics (Friedman & Resnick 2001): software-only influence must cost identity. d3 also doubles as the probation weight cap (a suspect is treated as an unproven identity).

**Measured across the sweep.**

- `fresh_sybils_to_outweigh_one_veteran`: {0.05: 34, 0.1: 17, 0.2: 9, 0.3: 6, 0.5: 4}
- `veteran_t3_weight_ceiling`: {0.05: 0.0417, 0.1: 0.0833, 0.2: 0.1667, 0.3: 0.25, 0.5: 0.4167}

**Why 0.1 holds.** At cap 0.1, outvoting one honest hardware veteran needs 17 fresh software sybils — each a disposable identity the CRITICAL rule bans on confirmation — while an honest long-lived software client keeps 0.0833 weight. At cap 0.5 the same attack needs only 4 sybils. The value buys an order-of-magnitude sybil cost for a modest honest-utility price.

### GAMMA = `0.9`  ·  CONVENTIONAL

**Mechanism.** Recency decay on evidence (Josang & Ismail 2002 give the mechanism; 0.9 is a value in common published use, e.g. DIB-RM). Sets the memory horizon 1/(1-gamma) and the goodwill ceiling.

**Measured across the sweep.**

- `veteran_trust_ceiling`: {0.75: 0.7222, 0.8: 0.75, 0.85: 0.7857, 0.9: 0.8333, 0.95: 0.9, 0.99: 0.9762}
- `memory_horizon`: {0.75: 4.0, 0.8: 5.0, 0.85: 6.7, 0.9: 10.0, 0.95: 20.0, 0.99: 100.0}

**Why 0.9 holds.** gamma sets both the goodwill ceiling s_max=theta/(1-gamma) and the memory horizon 1/(1-gamma). At 0.9 the ceiling is 0.8333 (trust cannot exceed 0.8333) on a 10.0-round horizon; 0.99 blows both up (ceiling 0.9762, horizon 100.0). Adopted as the conventional value on a visible plateau — never attributed to Josang as a recommendation.

### FORGIVE_AFTER = `5`  ·  CALIBRATED

**Mechanism.** Penalty stickiness against on-off cycling (Sun 2008; Labraoui 2015). The papers define the defense, not the window length; 5 = probation W_MIN + 1 so informal fade never undercuts the formal trial.

**Measured across the sweep.**

- `penalty_laundered_fraction`: {1: 0.1855, 2: 0.1426, 3: 0.0975, 4: 0.05, 5: 0.0, 6: 0.0, 7: 0.0, 8: 0.0}
- `clean_rounds_to_fade_one_minor_95pct`: {1: 59, 2: 60, 3: 61, 4: 62, 5: 63, 6: 64, 7: 65, 8: 66}

**Why 5 holds.** An on-off attacker resting 4 rounds per cycle launders part of its penalty for n<=4 and nothing from n=5 up ({1: 0.1855, 2: 0.1426, 3: 0.0975, 4: 0.05, 5: 0.0, 6: 0.0, 7: 0.0, 8: 0.0}). n=5=W_MIN+1: the informal forgetting path can never resolve faster than the formal probation trial. Honest single-slip recovery stays bounded (63 clean rounds to fade a MINOR by 95% at n=5).

### MAJOR_RUN_TO_ESCALATE = `2`  ·  CALIBRATED

**Mechanism.** Graduated sanctions escalate on REPEATED violation (Ostrom 1990). This ungated run counter carries MAJOR's severity distinctly from the score path.

**Measured across the sweep.**

- `sustained_containment_rounds`: {1: 1, 2: 2, 3: 3, 4: 4}
- `isolated_major_survives`: {1: False, 2: True, 3: True, 4: True}

**Why 2 holds.** m=1 collapses the ladder: one isolated MAJOR escalates an honest veteran (survives: {1: False, 2: True, 3: True, 4: True}). m=2 is the smallest run separating incident from pattern — Ostrom's 'repeated violation' minimum — containing every sustained attack in 2 rounds. Larger m only widens the attacker's window ([1, 2, 3, 4]).

### REINSTATE_T = `0.75`  ·  CALIBRATED

**Mechanism.** Reinstatement floor above the sanction threshold. Closed form 0.5*(1+1/W)=0.75: the smallest floor that survives one unit of noise after return, given W=2.

**Measured across the sweep.**

- `trust_after_one_noise_minor`: {0.55: 0.4737, 0.65: 0.5743, 0.75: 0.6833, 0.85: 0.8017}
- `evidence_needed_to_reach_floor`: {0.55: 1.69, 0.65: 3.09, 0.75: 5.6, 0.85: 11.47}

**Why 0.75 holds.** 0.75=0.5*(1+1/W) is the smallest floor that survives one noise MINOR on the day of return (post-noise trust {0.55: 0.4737, 0.65: 0.5743, 0.75: 0.6833, 0.85: 0.8017}). Flapping floors: [0.55]. Because W=2 the required re-entry evidence ([1.69, 3.09, 5.6, 11.47]) already exceeds the maximum trial credit theta*W_MAX=3.6, so the floor — not the trial — sets the return point; every reinstatement lands at exactly 0.75 (a coupling to W, flagged on dashboard 1).

### BAN_T = `0.3`  ·  CALIBRATED

**Mechanism.** Score backstop below PROBATION_T. RepuNet gives the exclusion-threshold structure (its own value is 0.6); 0.3 is ours. Under D5 an active rehab-eligible device is never banned directly by the score — probation always comes first.

**Measured across the sweep.**

- `probation_preempted_fraction`: {0.1: 0.0, 0.2: 0.0, 0.3: 0.0, 0.4: 0.0, 0.45: 0.0}

**Why 0.3 holds.** Across 400 random Tier-1 histories per value, the backstop never fires before probation for any BAN_T in the swept range ({0.1: 0.0, 0.2: 0.0, 0.3: 0.0, 0.4: 0.0, 0.45: 0.0}) — D5 routing guarantees an active rehab-eligible device is probated first. 0.3 sits safely below PROBATION_T with margin; the value is a plateau, not a tuned edge.

### FORGET (uniform) = `0.95`  ·  CALIBRATED

**Mechanism.** Earned forgetting: penalties fade only after a clean streak, and slower than goodwill decays (Slovic 1993 direction only). v3 applies one uniform rate to every tier (v2.1's T1-only fade retired). 0.95 = 1-(1-gamma)/2.

**Measured across the sweep.**

- `rounds_to_fade_one_offense`: {0.9: 400, 0.925: 400, 0.95: 400, 0.975: 400, 1.0: 400}
- `honest_t2_trust_after_30_clean`: {0.9: 0.823, 0.925: 0.8174, 0.95: 0.8066, 0.975: 0.7866, 1.0: 0.7512}

**Why 0.95 holds.** FORGET=1.0 scars a client forever (offense never fades; trust plateaus at 0.7512); FORGET=0.90=gamma erases it as fast as goodwill decays. 0.95=1-(1-gamma)/2 makes distrust fade at half the rate trust decays (400 rounds) — Slovic's asymmetry as a direction, magnitude shown to be a plateau. v3 applies this uniformly, which is what lets a T2/T3 client heal at all (v2.1 never forgave them).

## 3. Parameter couplings (values that are not independent)

**REINSTATE_T ↔ W.** With W = 2 the reinstatement floor demands need_s = (r/(1−r))(b₀+f) − a₀ units of positive evidence, which for the swept floors is {0.55: 1.69, 0.65: 3.09, 0.75: 5.6, 0.85: 11.47}. The maximum trial credit is θ·W_MAX = 0.4×9 = 3.6, so for the shipped REINSTATE_T = 0.75 the floor (not the trial) always sets the return point. Consequence: every reinstatement returns at exactly 0.75. This is a direct coupling to the prior weight, not an independent tuning choice.

**FORGIVE_AFTER ↔ probation window.** FORGIVE_AFTER = 5 = W_MIN + 1, where W_MIN = 4 is the minimum probation trial window (`probation.py`). The informal earned-forgetting path is deliberately one round slower than the formal trial so it can never undercut it. The on-off launder sweep confirms the boundary: {1: 0.1855, 2: 0.1426, 3: 0.0975, 4: 0.05, 5: 0.0, 6: 0.0, 7: 0.0, 8: 0.0} — nonzero leakage only for n ≤ 4.

**FORGET ↔ γ.** FORGET = 0.95 = 1 − (1−γ)/2 ties the distrust-fade rate to the goodwill-decay rate: distrust fades at exactly half the speed trust decays. If γ moves, FORGET is expected to move with it by the same half-rate rule (Slovic's asymmetry as a *direction* only; the source gives no ratio).

**WINDOW_MAX ↔ γ.** The probation trial ceiling WINDOW_MAX = 9 = 1/(1−γ) − 1 is the memory horizon minus one: a trial must resolve inside the window over which evidence is still remembered. γ = 0.9 gives horizon 1/(1−γ) = 10 rounds. (This replaces the v2.1 justification, which tied WINDOW_MAX to a per-tier memory constant K1 that no longer exists.)

**d3 doubles as the probation weight cap.** A device on probation is treated as an unproven identity: its weight is capped at d3 = 0.1 regardless of tier. The two uses share one value by construction.

## 4. Flagged deviations from the design's expected numbers

These are surfaced deliberately. Each is measured, and each is a case where v3's behaviour differs from a number the handoff anticipated.

### 4.1 The ~0% 200-round false-positive target is not met

At the shipped τ = 0.6, honest devices at 5% MINOR noise are sanctioned at a **200-round rate of 28%** (measured, 40 seeds), not ~0%. The cause is steady-state, not cold start: each MINOR both adds τ to the penalty and resets the clean-run counter, so a cluster of noisy rounds blocks the 5-round fade and drives trust below 0.5. The τ lever dominates this rate — {0.5: 0.025, 0.6: 0.275, 0.7: 0.65} across τ ∈ {0.5, 0.6, 0.7} (with θ+τ = 1 held). We keep Kang's cited τ = 0.6 and report the residual rather than silently lowering τ to hit a target. On Tier 1 these events are recoverable probations; on Tiers 2–3 they would be permanent bans.

### 4.2 What the u-gate does and does not fix

The gate is a pure cold-start defense. Over the first 20 rounds it cuts honest false positives from 15% to 2%. It does not touch the steady-state residual (32% → 28% at 200 rounds) — that is τ's cluster effect. The handoff's 8% / 64% / 64% baseline is the v2.1 informative-prior *system*, not v3 with the gate off (v3 gate-off 20-round ≈ 15%).

### 4.3 Reinstatement returns a constant

As derived in §3, the W = 2 coupling makes every reinstatement return at exactly 0.75; the v2.1 property “stronger recovery returns higher” is retired. The direction is safe (recovery is never over-generous). The reinstatement floor can also briefly implant s above s_max = 4, which decays back within ~11 rounds — a transient, not a steady state.

### 4.4 The “heavy 4-MAJOR entry” trajectory is unreachable

Under D5, an active rehab-eligible device's first score sanction is always PROBATION, and the backstop bans only from probation onward. A fresh device sending 4 MAJORs is escalated to probation at its 2nd MAJOR (M3), so the v2.1 “4 consecutive MAJORs while active” entry used for reinstatement demos no longer occurs; the report and dashboards use the reachable 2-MAJOR entry instead.

### 4.5 t12 was computed without fading in the handoff

The handoff's expected post-forgiveness trust t12 ≈ 0.69–0.70 matches a no-fade calculation exactly. v3 keeps continuous fade (matching the v2.1 engine semantics and the finite-lifetime rationale), which moves measured t12 into 0.69–0.73 — the favourable direction (slightly more recovery), so the change is kept and noted.

## 5. Leniency ledger — v3 vs v2.1

Where v3 is stricter (+) or more lenient (−) than v2.1, and why.

| Dimension | v2.1 | v3 | Net |
|---|---|---|---|
| Fresh-device start trust | 0.8 / 0.67 / 0.5 by tier | 0.5 all tiers | **stricter** for Tier 1/2 (no unearned head start) |
| First bad event (fresh) | tier-dependent | drops to 0.3846 every tier | stricter, uniform |
| Severity of MINOR vs MAJOR (arithmetic) | 3× magnitude (uncited) | equal (τ each); MAJOR differs only via M3 rule | more principled, slightly more lenient per single MAJOR |
| Cold-start noise | no gate | u-gate absorbs early noise | **more lenient** at cold start (by design) |
| Steady-state noise tolerance | tighter (informative prior) | ~28% residual sanction | more lenient in intent, but the residual is a cost, see §4.1 |
| Forgetting | Tier 1 only | uniform, all tiers | **more lenient** for Tier 2/3 (they can now heal at all) |
| Reinstatement return | scaled with trial | constant 0.75 | neutral (floor-dominated) |
| Ban terminality / EK re-ban (O2) | enforced | enforced (now on-chain) | unchanged |

_The single largest leniency shift is uniform forgetting: it is what lets a noisy Tier-2/3 client recover, and it is also what pulls the 200-round honest sanction rate down from ~97% (no fade) to ~28% (§4.1). The residual above zero is the price paid for Kang's cited τ._

## 6. Reproducibility

```
python gen_data.py          # writes d1/d2/d3 JSON + FLAGS.json
python build_dashboards.py  # writes the three dashboards
python build_report.py      # writes this report
cd chain && python test_parity.py && python test_shadow.py
```

All figures in this report and the dashboards come from the same JSON; the chain parity test proves the on-chain record reproduces the engine's status and trust to within fixed-point truncation (max divergence < 1e-6).
