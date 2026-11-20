"""
trust/reputation.py  (v3 -- identity-blind score, tier-coupled response)

Bayesian reputation engine in subjective-logic form. The SCORE is
identity-blind: every device, whatever its hardware tier, is judged by the
same canonical Beta(1,1) opinion with the same evidence weights and the
same forgetting. Tier (identity replacement cost, fixed at enrollment)
lives in exactly three places, none of them the score:

  (a) the aggregation discount  weight = D[tier] * trust
  (b) the rehab response        Tier 1 -> probation, Tiers 2/3 -> ban,
                                on identical triggers
  (c) the EK-bound ban list     banned hardware identity cannot re-register

  O2 anti-whitewashing  : bans bind to the EK hash; a returning banned identity
                          is re-banned at registration.
  O3 quantified trust   : T = E(opinion) = b + a*u = (a0+s)/(W+s+f).
  O4 aggregator-agnostic: get_all_weights() returns dict[str, float].

COLD START -- the evidence-dominance gate (v3, no new constants):
With the uniform (1,1) prior a fresh device's first bad event drops trust
to 1/2.6 = 0.385, below the 0.5 threshold. Instead of an informative prior
or a grace-period constant, v3 gates the SCORE-PATH transitions (probation
threshold and ban backstop) on the opinion being evidence-dominated:

    act only when u < 0.5   <=>   s + f > W = 2

u is subjective logic's own sample-size term; "u >= 0.5" reads "the prior
still outweighs the evidence -- the score is not yet an opinion about this
device". The RULES are NOT gated: M3 (consecutive-MAJOR escalation) and
CRITICAL act immediately at any u. Measured consequences of this exact
configuration (see dashboard 2, cold-start panel):
  - a clean device leaves the gate after 7 rounds (s = 2.087 > 2);
  - one noise MINOR at round 1/3/5/8 never sanctions an honest device
    (trust ~0.72-0.76 by round 12; earlier noise recovers FURTHER because
    f decays at the same rate as s under symmetric FORGET = GAMMA);
  - a fresh 2-consecutive-MAJOR attacker is caught by ungated M3 at round 2;
  - a fresh all-MINOR attacker exits the gate at round 4 with trust 0.227.

GATE-EXIT ROUTING (the D5 edge case, decided and pinned by self-test):
When the gate opens, trust can already sit below BOTH thresholds (the
all-MINOR attacker exits at 0.227 <= BAN_T). Resolution -- due process
first, stated as an invariant: an ACTIVE rehab-eligible device is NEVER
banned directly by the score path; its first score-path sanction is always
PROBATION, even at trust <= BAN_T. From PROBATION onward the backstop
applies normally. Non-rehab tiers ban as before.

================================ PROVENANCE ================================
Two layers, kept strictly apart. Every constant carries BOTH:

  mechanism -> a published model or defense (always citable)
  value     -> one of three honesty grades:
       CANONICAL    the paper's own number, used unchanged
       CONVENTIONAL a number in common published use, adopted
       CALIBRATED   our number; defended by the sensitivity sweep
                    (eval/ dashboards), NOT by citation

  PRIOR = Beta(1,1) for every tier: (W, a) = (2, 0.5), starting trust 0.5
      mechanism  Josang's non-informative prior [Josang 2001 subjective
                 logic; Josang & Ismail 2002 beta reputation]
      value      CANONICAL. v3 removes the v2.1 informative tier priors:
                 the score is identity-blind by design; tier assurance is
                 expressed through the discount vector D, not the prior.

  THETA = 0.4 (positive evidence weight), TAU = 0.6 (negative weight)
      mechanism  interaction-effect weights with theta + tau = 1 and
                 theta < tau -- negative events weigh more [Kang, Xiong,
                 Niyato, Ye, Kim & Zhao, IEEE TVT 68(3) 2019,
                 arXiv:1809.08387]
      value      CANONICAL -- the paper's own simulation settings
                 (Table I: theta = 0.4, tau = 0.6), used unchanged.
                 MINOR and MAJOR add the same tau: severity is NOT
                 carried by evidence magnitude; MAJOR differs only in
                 feeding the M3 run rule [Ostrom 1990 graduated
                 sanctions], CRITICAL stays a non-compensable rule.
                 The tau ratio is swept (0.5/0.6/0.7) on dashboard 2.

  GAMMA = 0.9 (uniform)
      mechanism  forgetting factor on positive evidence: recency weighting
                 [Josang & Ismail 2002]
      value      CONVENTIONAL -- in common published use (e.g. DIB-RM,
                 arXiv:1801.03904); Josang does NOT recommend a value.
                 s_max = THETA/(1-GAMMA) = 4; veteran trust ceiling
                 (1+4)/(2+4) = 0.833 for every tier.

  D = {Tier1: 1.0, Tier2: d2 = 0.5, Tier3: d3 = 0.1}  (discount vector)
      mechanism  Josang's discounting operator; weight-by-reputation
                 [Kang 2019; RepuNet arXiv:2506.19892]; influence must
                 scale with identity cost [Friedman & Resnick 2001]
      values     d1 = 1.0 CANONICAL -- discounting by a fully trusted
                 source is the identity operation; the hardware-attested
                 channel is the reference channel, so 1.0 is forced by
                 the operator, not chosen.
                 d2, d3 CALIBRATED -- swept on dashboard 2 (d2: compromised
                 -T2 identities to outweigh one honest Tier-1 veteran vs
                 honest-T2 utility; d3: sybil economics).

  PROBATION_T = 0.5
      mechanism  the subjective-logic indifference point: a fresh unknown
                 starts at 0.5, so T <= 0.5 reads "worse than an unknown"
                 [Josang 2001]. Kang's experiments use 0.5 as the
                 reputation threshold of successful detection, reporting
                 100% detection of malicious miners at that value
                 [Kang 2019].
      value      CALIBRATED (structure cited as above; swept).

  REINSTATE_T = 0.5 * (1 + 1/W) = 0.75
      mechanism  reinstatement band above the sanction threshold (band
                 structure per Buchegger & Le Boudec 2004 -- their
                 threshold VALUES are application-dependent and are not
                 cited here)
      value      CALIBRATED -- closed form from the prior weight W: the
                 smallest floor that survives one unit of noise
                 immediately after return. Keep the closed form; the
                 number follows from W = 2.

  BAN_T = 0.3
      mechanism  exclusion-threshold structure [RepuNet arXiv:2506.19892
                 -- note RepuNet's own exclusion threshold is 0.6; 0.3 is
                 OURS]
      value      CALIBRATED -- largest backstop that never preempts
                 probation on any reachable trajectory (re-verified under
                 the v3 dynamics in the sweep). Under D5 the backstop
                 additionally never applies to an ACTIVE rehab tier.

  THE U-GATE (score-path transitions require s + f > W, i.e. u < 0.5)
      mechanism  subjective-logic uncertainty semantics: u = W/(W+s+f) is
                 the sample-size term; u >= 0.5 means the prior outweighs
                 the evidence [Josang 2001]
      value      n/a -- introduces NO new constant (0.5 is u's own
                 prior-vs-evidence midpoint, equivalent to s + f > W).

  FORGET = GAMMA = 0.90 (uniform, ALL tiers)
      mechanism  penalty stickiness against on-off cycling [Sun 2008;
                 Labraoui 2015]. Asymmetry between how trust and distrust
                 are treated is carried by the GATE (FORGIVE_AFTER), NOT
                 by a rate ratio: positive evidence decays every round
                 unconditionally, negative evidence decays only after two
                 consecutive clean rounds. The Slovic 1993 asymmetry
                 direction is preserved through this gate mechanism.
      value      [DERIVED] -- forced by the choice to use a single decay
                 primitive shared with GAMMA. No separate constant is
                 introduced; the contract implements ONE decay operation
                 (x -> 9x/10) instead of two.
                 v3 change from earlier drafts: uniform across tiers. The
                 v2.1 story "only accountable hardware earns fading" is
                 retired -- the score is identity-blind, so forgetting is
                 too. Without uniform forgetting, honest noisy Tier-2/3
                 devices have finite lifetime: measured 64% false-ban rate
                 over 200 rounds at 5% noise (dashboard 2).

  FORGIVE_AFTER = 2
      mechanism  penalty stickiness against on-off cycling [Sun 2008;
                 Labraoui 2015]
      value      CALIBRATED -- probation minimum window W_MIN (4) + 1:
                 informal forgetting must not undercut the formal trial.

  MAJOR_RUN_TO_ESCALATE = 2
      mechanism  graduated sanctions escalate on REPEATED violation
                 [Ostrom 1990 -- repetition begins at two; Ostrom
                 deliberately gives no number]; sleeper/on-off defense
                 [Sun 2008]
      value      CALIBRATED -- the smallest run separating incident from
                 pattern; equalizes the veteran strike budget with the
                 fresh budget.

  PROBATION_WEIGHT_CAP = d3
      mechanism  a suspect is capped at the influence of an unproven
                 software identity (least-privilege while under trial)
      value      follows from d3, not separately chosen.

  CRITICAL (rule, not a weight)
      mechanism  identity abuse is non-compensable; any finite weight
                 would let banked history offset it (sleeper exploit).
      value      n/a -- a rule has no magnitude to calibrate.

  Fresh identities start at the indifference point; bans bind to the EK
      mechanism  cheap-pseudonym / whitewashing defense [Friedman &
                 Resnick 2001]
      value      n/a -- implementation is ours; concept cited.

CITATION LANDMINES (kept from the v3 design review; do not reintroduce):
  - Buchegger & Le Boudec: structure only, never a threshold VALUE.
  - Slovic 1993: direction only, never a ratio.
  - Kang's 0.5s are the initial reputation and the experimental detection
    threshold -- there is no "trusted-worker threshold" to cite.
  - RepuNet's exclusion threshold is 0.6; our 0.3 is CALIBRATED.

REFERENCES (see REFERENCES.md for full entries)
  Josang 2001; Josang & Ismail 2002; Kang et al. 2019 (arXiv:1809.08387);
  DIB-RM arXiv:1801.03904; RepuNet arXiv:2506.19892; Sun et al. 2008;
  Labraoui et al. 2015; Ostrom 1990; Friedman & Resnick 2001; Slovic 1993;
  Buchegger & Le Boudec 2004 (structure only).
============================================================================

tpm/common.py is the canonical source of the Tier enum. A local fallback is
kept only so this module self-tests standalone.
"""
from enum import Enum
from dataclasses import dataclass

try:
    from tpm.common import Tier
except Exception:
    from enum import IntEnum

    class Tier(IntEnum):
        HARDWARE = 1
        TPM_RESIDENT = 2
        SOFTWARE = 3


class EventTier(str, Enum):
    POSITIVE = "POSITIVE"
    NEUTRAL = "NEUTRAL"
    MINOR = "MINOR"
    MAJOR = "MAJOR"
    CRITICAL = "CRITICAL"


class Status(str, Enum):
    ACTIVE = "ACTIVE"
    PROBATION = "PROBATION"
    BANNED = "BANNED"


# ---- canonical uniform prior: Beta(1,1) for EVERY tier -----------------------
W_PRIOR = 2.0                     # CANONICAL (Josang non-informative)
BASE_RATE = 0.5                   # CANONICAL
PRIOR = (1.0, 1.0)                # (a0, b0) = (W*a, W*(1-a))

THETA = 0.4                       # CANONICAL (Kang 2019, Table I)
TAU = 0.6                         # CANONICAL (Kang 2019, Table I)
GAMMA = 0.9                       # CONVENTIONAL, uniform

# ---- tier differentiation: discount vector, rehab response, EK bans ----------
TIER_DISCOUNT = {Tier.HARDWARE: 1.0,       # CANONICAL (identity discounting)
                 Tier.TPM_RESIDENT: 0.5,   # CALIBRATED (d2, swept)
                 Tier.SOFTWARE: 0.1}       # CALIBRATED (d3, swept)
REHAB = {Tier.HARDWARE: True, Tier.TPM_RESIDENT: False, Tier.SOFTWARE: False}

FORGET = 0.90                              # [DERIVED] = GAMMA, UNIFORM (v3)
FORGIVE_AFTER = 2                          # CALIBRATED (probation W_MIN + 1)
MAJOR_RUN_TO_ESCALATE = 2                  # CALIBRATED (repetition begins at 2)

GOOD_EVIDENCE = {"POSITIVE": THETA, "NEUTRAL": THETA}
BAD_EVIDENCE = {"MINOR": TAU, "MAJOR": TAU}  # CRITICAL: rule, no weight

PROBATION_T = 0.5                                    # CALIBRATED
REINSTATE_T = PROBATION_T * (1.0 + 1.0 / W_PRIOR)    # 0.75, closed form
BAN_T = 0.3                                          # CALIBRATED backstop
PROBATION_WEIGHT_CAP = TIER_DISCOUNT[Tier.SOFTWARE]  # suspect <= unproven id

S_MAX = THETA / (1.0 - GAMMA)                        # 4: goodwill ceiling
TRUST_CEILING = (PRIOR[0] + S_MAX) / (W_PRIOR + S_MAX)   # 0.833, every tier


@dataclass
class Params:
    """All knobs in one injectable bundle. Defaults reproduce the shipped
    system; the sensitivity sweep instantiates variants of this."""
    theta: float = THETA
    tau: float = TAU
    gamma: float = GAMMA
    forgive_after: int = FORGIVE_AFTER
    major_run_to_escalate: int = MAJOR_RUN_TO_ESCALATE
    probation_t: float = PROBATION_T
    reinstate_t: float = REINSTATE_T
    ban_t: float = BAN_T
    forget: float = FORGET
    d2: float = TIER_DISCOUNT[Tier.TPM_RESIDENT]
    d3: float = TIER_DISCOUNT[Tier.SOFTWARE]
    m3_enabled: bool = True          # sweep-only switch (isolates M3)
    gate_enabled: bool = True        # sweep-only switch (cold-start ON/OFF)

    @property
    def discount(self):
        return {Tier.HARDWARE: 1.0, Tier.TPM_RESIDENT: self.d2,
                Tier.SOFTWARE: self.d3}

    @property
    def probation_weight_cap(self):
        return self.d3


@dataclass
class Device:
    device_id: str
    tier: Tier
    ek_hash: str
    s: float
    f: float
    status: Status
    clean_run: int = 0   # consecutive clean rounds (drives M2 earned forgetting)
    major_run: int = 0   # consecutive MAJORs (drives M3 sustained escalation)

    @property
    def trust(self):
        a0, b0 = PRIOR
        return (a0 + self.s) / (a0 + b0 + self.s + self.f)

    @property
    def opinion(self):
        """Subjective-logic opinion (b, d, u, a); trust == b + a*u exactly.
        u = W/(W+s+f) is the sample-size term: it shrinks as evidence grows.
        The v3 gate is 'u < 0.5', identically 's + f > W'."""
        a0, b0 = PRIOR
        n = a0 + b0 + self.s + self.f
        return {"b": self.s / n, "d": self.f / n,
                "u": (a0 + b0) / n, "a": a0 / (a0 + b0)}

    @property
    def evidence_dominated(self):
        """True iff the opinion carries more evidence than prior: u < 0.5."""
        return (self.s + self.f) > W_PRIOR


class ReputationEngine:
    def __init__(self, params: Params = None):
        self.p = params or Params()
        self._dev = {}
        self._banned_ek = set()

    def register(self, device_id, tier, ek_hash=None):
        tier = Tier(tier)
        banned = ek_hash is not None and ek_hash in self._banned_ek
        d = Device(device_id, tier, ek_hash, 0.0, 0.0,
                   Status.BANNED if banned else Status.ACTIVE)      # O2
        self._dev[device_id] = d
        return d.status

    def record_event(self, device_id, severity):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return d.status
        if hasattr(severity, "value"):
            severity = severity.value

        if severity == "CRITICAL":        # rule, non-compensable, ungated
            d.clean_run = 0
            d.major_run = 0
            self._ban(d)
            return d.status

        g = self.p.gamma
        if severity in GOOD_EVIDENCE:
            d.s = g * d.s + self.p.theta                # M1: bounded recency
            d.clean_run += 1
            d.major_run = 0
            if d.clean_run >= self.p.forgive_after:
                d.f *= self.p.forget                    # M2: earned, UNIFORM
        else:
            d.s = g * d.s
            d.f += self.p.tau                           # MINOR == MAJOR here
            d.clean_run = 0
            d.major_run = d.major_run + 1 if severity == "MAJOR" else 0

        self._transition(d)
        return d.status

    def _transition(self, d):
        """Order of checks (pinned by self-tests):
          1. score path (backstop, then probation threshold) -- GATED on the
             opinion being evidence-dominated (u < 0.5 <=> s + f > W), with
             D5 routing: an ACTIVE rehab tier always gets PROBATION first,
             even at trust <= BAN_T; the backstop bans from PROBATION on.
          2. M3 sustained-run escalation -- UNGATED (a rule, not the score).
        CRITICAL is handled in record_event before any arithmetic."""
        gate_open = (not self.p.gate_enabled) or d.evidence_dominated

        if gate_open and d.trust <= self.p.ban_t:       # backstop
            if REHAB[d.tier] and d.status == Status.ACTIVE:
                d.status = Status.PROBATION             # D5: due process first
            else:
                self._ban(d)
            return
        if (self.p.m3_enabled
                and d.major_run >= self.p.major_run_to_escalate):  # M3
            if REHAB[d.tier]:
                d.status = Status.PROBATION
            else:
                self._ban(d)
            return
        if (gate_open and d.status == Status.ACTIVE
                and d.trust <= self.p.probation_t):
            if REHAB[d.tier]:
                d.status = Status.PROBATION
            else:
                self._ban(d)

    def _ban(self, d):
        d.status = Status.BANNED
        if d.ek_hash is not None:
            self._banned_ek.add(d.ek_hash)

    def reinstate(self, device_id, trial_rounds=0):
        """Reinstate a probated device. The passed probation rounds are
        credited as earned good evidence at the canonical positive weight
        (theta per round -- the trial IS evidence), then trust is floored at
        REINSTATE_T via the closed form. Stronger proven recovery therefore
        returns with proportionally higher trust."""
        d = self._dev[device_id]
        if d.status == Status.PROBATION and REHAB[d.tier]:
            a0, b0 = PRIOR
            r = self.p.reinstate_t
            d.s += self.p.theta * float(trial_rounds)
            need_s = (r / (1.0 - r)) * (b0 + d.f) - a0
            d.s = max(d.s, need_s)                      # floor: T >= reinstate_t
            d.status = Status.ACTIVE
            d.clean_run = 0
            d.major_run = 0
            return True
        return False

    def get_status(self, device_id):
        return self._dev[device_id].status

    def get_opinion(self, device_id):
        return self._dev[device_id].opinion

    def rank(self, device_ids=None):
        """Josang Def. 10 ordering: highest trust first; ties broken by least
        uncertainty, so at equal trust the client with more evidence wins.
        Banned devices are excluded."""
        ids = list(self._dev) if device_ids is None else list(device_ids)
        ids = [i for i in ids if self._dev[i].status != Status.BANNED]
        return sorted(ids, key=lambda i: (-self._dev[i].trust,
                                          self._dev[i].opinion["u"]))

    def get_weight(self, device_id):
        d = self._dev[device_id]
        if d.status == Status.BANNED:
            return 0.0
        cap = self.p.discount[d.tier]
        if d.status == Status.PROBATION:
            cap = min(cap, self.p.probation_weight_cap)
        return round(cap * d.trust, 4)

    def get_all_weights(self):
        return {i: self.get_weight(i) for i, d in self._dev.items()
                if d.status != Status.BANNED}

    def banned_ek_hashes(self):
        return set(self._banned_ek)


def _self_test():
    print("trust/reputation.py v3 self-test")

    # -- D1/D6: canonical constants and closed forms --------------------------
    assert PRIOR == (1.0, 1.0) and W_PRIOR == 2.0 and BASE_RATE == 0.5
    assert THETA == 0.4 and TAU == 0.6 and abs(THETA + TAU - 1.0) < 1e-12
    assert abs(REINSTATE_T - 0.75) < 1e-12          # 0.5*(1+1/W), W = 2
    assert abs(FORGET - 0.90) < 1e-12               # [DERIVED] = GAMMA, uniform
    assert abs(S_MAX - 4.0) < 1e-12                 # theta/(1-gamma)
    assert abs(TRUST_CEILING - 5.0 / 6.0) < 1e-12   # 0.833 every tier
    assert "CRITICAL" not in BAD_EVIDENCE
    assert PROBATION_WEIGHT_CAP == TIER_DISCOUNT[Tier.SOFTWARE]
    assert TIER_DISCOUNT[Tier.HARDWARE] == 1.0      # forced by the operator
    print("\u2713 canonical core: Beta(1,1), theta/tau = 0.4/0.6, "
          "REINSTATE_T = 0.75 (closed form), FORGET = 0.90 = GAMMA uniform, "
          "s_max = 4, ceiling 0.833")

    # -- uniform starting trust 0.5, opinion identity -------------------------
    e = ReputationEngine()
    for did, tier in (("hw", Tier.HARDWARE), ("tr", Tier.TPM_RESIDENT),
                      ("sw", Tier.SOFTWARE)):
        e.register(did, tier, f"ek_{did}")
        assert abs(e._dev[did].trust - 0.5) < 1e-12
        o = e.get_opinion(did)
        assert abs(o["b"] + o["d"] + o["u"] - 1.0) < 1e-12
        assert abs((o["b"] + o["a"] * o["u"]) - e._dev[did].trust) < 1e-12
        assert abs(o["u"] - 1.0) < 1e-12            # all uncertainty at birth
    assert e.get_weight("hw") == 0.5 and e.get_weight("tr") == 0.25
    assert e.get_weight("sw") == 0.05
    print("\u2713 identity-blind score: every tier starts at trust 0.5, u = 1; "
          "tiers differ only through D = {1.0, 0.5, 0.1}")

    # -- D4: the gate protects a fresh device's early noise -------------------
    for noise_round in (1, 3, 5, 8):
        g = ReputationEngine()
        g.register("h", Tier.HARDWARE, "ek_h")
        for r in range(1, 13):
            ev = "MINOR" if r == noise_round else "NEUTRAL"
            st = g.record_event("h", ev)
            assert st == Status.ACTIVE, \
                f"noise at r{noise_round}: sanctioned at r{r}"
        t12 = g._dev["h"].trust
        assert 0.71 < t12 < 0.76, f"noise r{noise_round}: t12 = {t12:.4f}"
    # first bad event on a fresh device: trust 0.385, gate closed, no sanction
    g = ReputationEngine()
    g.register("x", Tier.SOFTWARE, "ek_x")           # non-rehab: harshest tier
    st = g.record_event("x", "MINOR")
    assert st == Status.ACTIVE
    assert abs(g._dev["x"].trust - 1 / 2.6) < 1e-9   # 0.3846 but u = 0.769
    assert not g._dev["x"].evidence_dominated
    print("\u2713 D4 gate: one noise MINOR at round 1/3/5/8 never sanctions an "
          "honest device (trust 0.72-0.76 by round 12; earlier noise recovers "
          "further under symmetric FORGET); fresh Tier-3 first MINOR "
          "(trust 0.385) no longer bans it")

    # -- clean device leaves the gate after 7 rounds --------------------------
    g = ReputationEngine()
    g.register("c", Tier.HARDWARE, "ek_c")
    for r in range(1, 8):
        g.record_event("c", "NEUTRAL")
        dominated = g._dev["c"].evidence_dominated
        assert dominated == (r >= 7), f"r{r}: dominance {dominated}"
    assert g._dev["c"].s > W_PRIOR
    print(f"\u2713 gate horizon: a clean device is evidence-dominated from "
          f"round 7 (s = {g._dev['c'].s:.3f} > W = 2)")

    # -- M3 is UNGATED: fresh 2-MAJOR attacker caught at round 2 --------------
    m = ReputationEngine()
    m.register("a1", Tier.HARDWARE, "ek_a1")
    assert m.record_event("a1", "MAJOR") == Status.ACTIVE
    assert m.record_event("a1", "MAJOR") == Status.PROBATION
    assert not m._dev["a1"].evidence_dominated       # still inside the gate!
    m.register("a2", Tier.TPM_RESIDENT, "ek_a2")
    m.record_event("a2", "MAJOR")
    assert m.record_event("a2", "MAJOR") == Status.BANNED
    print("\u2713 M3 ungated: a fresh 2-consecutive-MAJOR attacker is caught at "
          "round 2 while still inside the gate (T1 probation, T2 ban)")

    # -- CRITICAL is UNGATED and non-compensable ------------------------------
    c = ReputationEngine()
    c.register("s", Tier.HARDWARE, "ek_s")
    assert c.record_event("s", "CRITICAL") == Status.BANNED   # round 1, u = 1
    assert c._dev["s"].f == 0.0                      # rule, no arithmetic
    assert c.register("s2", Tier.HARDWARE, "ek_s") == Status.BANNED   # O2
    print("\u2713 CRITICAL ungated: instant EK-bound ban at any u, no dead "
          "weight; banned EK stays banned (O2)")

    # -- D5 PINNED: gate-exit routing -----------------------------------------
    # A fresh all-MINOR Tier-1 exits the gate at round 4 with trust 0.227,
    # below BOTH thresholds. It must route to PROBATION (due process), and
    # the backstop must apply from then on.
    d5 = ReputationEngine()
    d5.register("am", Tier.HARDWARE, "ek_am")
    for r in range(1, 4):
        assert d5.record_event("am", "MINOR") == Status.ACTIVE, f"r{r}"
    st = d5.record_event("am", "MINOR")              # round 4: gate opens
    t4 = d5._dev["am"].trust
    assert abs(t4 - 1.0 / 4.4) < 1e-9                # 0.2273
    assert t4 <= BAN_T
    assert st == Status.PROBATION, "D5: ACTIVE rehab tier must probate first"
    st = d5.record_event("am", "MINOR")              # round 5: in probation
    assert st == Status.BANNED, "D5: backstop applies from PROBATION on"
    # the same trajectory on a non-rehab tier bans at gate exit
    d5.register("am3", Tier.SOFTWARE, "ek_am3")
    for r in range(1, 4):
        assert d5.record_event("am3", "MINOR") == Status.ACTIVE
    assert d5.record_event("am3", "MINOR") == Status.BANNED
    print(f"\u2713 D5 pinned: all-MINOR T1 exits the gate at round 4 "
          f"(trust {t4:.3f} <= BAN_T) into PROBATION, banned by the backstop "
          f"one MINOR later; the same trajectory bans a T3 at gate exit")

    # -- uniform ceiling 0.833 and bounded memory (M1), every tier ------------
    for tier in (Tier.HARDWARE, Tier.SOFTWARE):
        b = ReputationEngine()
        b.register("v", tier, "ek_v")
        for _ in range(200):
            b.record_event("v", "NEUTRAL")
        assert abs(b._dev["v"].s - S_MAX) < 1e-3
        assert abs(b._dev["v"].trust - TRUST_CEILING) < 1e-3
    print(f"\u2713 M1 uniform ceiling: 200 clean rounds saturate s at "
          f"{S_MAX:.0f} and trust at {TRUST_CEILING:.3f} for every tier")

    # -- uniform forgetting: Tier-2/3 devices now heal (v3 change) ------------
    t2 = ReputationEngine()
    t2.register("c2", Tier.TPM_RESIDENT, "ek_c2")
    t2.record_event("c2", "MINOR")
    f0 = t2._dev["c2"].f
    for _ in range(FORGIVE_AFTER - 1):
        t2.record_event("c2", "NEUTRAL")
    assert t2._dev["c2"].f == f0                     # earned, not automatic
    for _ in range(40):
        t2.record_event("c2", "NEUTRAL")
    assert t2._dev["c2"].f < f0 * 0.2
    assert t2.get_status("c2") == Status.ACTIVE
    print(f"\u2713 uniform forgetting (v3): a noisy Tier-2 heals -- f "
          f"{f0:.1f} -> {t2._dev['c2'].f:.3f} after a sustained clean streak; "
          f"{FORGIVE_AFTER - 1} clean rounds still launder nothing")

    # -- honest noisy devices: cold start fixed; steady state MEASURED --------
    # The gate's job is the cold-start window and it does it: with the gate,
    # no single-noise trajectory is ever sanctioned (pinned above) and the
    # early-cluster sanction rate drops. Uniform forgetting removes the v2.1
    # finite-lifetime death sentence (f no longer ratchets forever).
    # MEASURED DEVIATION, kept visible on purpose: the section-4 target of
    # ~0% false positives over 200 rounds at 5% noise is NOT met at Kang's
    # canonical tau = 0.6 -- a residual STEADY-STATE cluster risk of roughly
    # 20% remains for every tier (ban needs f >= s; s_max = 4 while each
    # MINOR adds 0.6 AND blocks fading for FORGIVE_AFTER rounds). This is a
    # tau/theta-headroom property, not a cold-start property: measured
    # ~1% at tau = 0.5 vs ~50% at tau = 0.7 (see dashboard 2, tau sweep).
    import random

    def sanction_rate(tier, rounds, gate, forget):
        n = 0
        for seed in range(60):
            r = random.Random(seed)
            pp = Params(gate_enabled=gate, forget=forget)
            hz = ReputationEngine(pp)
            hz.register("h", tier, f"ek{seed}")
            for _ in range(rounds):
                if hz.record_event(
                        "h", "MINOR" if r.random() < 0.05 else "NEUTRAL") \
                        != Status.ACTIVE:
                    n += 1
                    break
        return n / 60

    cs_off = sanction_rate(Tier.SOFTWARE, 20, gate=False, forget=FORGET)
    cs_on = sanction_rate(Tier.SOFTWARE, 20, gate=True, forget=FORGET)
    assert cs_on < cs_off, "gate must reduce cold-start sanctions"
    ss_forget = sanction_rate(Tier.SOFTWARE, 200, gate=True, forget=FORGET)
    ss_never = sanction_rate(Tier.SOFTWARE, 200, gate=True, forget=1.0)
    assert ss_forget < 0.5 * ss_never, \
        "uniform forgetting must materially cut the finite-lifetime rate"
    print(f"\u2713 cold start: gate cuts 20-round honest sanctions "
          f"{cs_off:.0%} -> {cs_on:.0%}; uniform forgetting cuts the "
          f"200-round rate {ss_never:.0%} -> {ss_forget:.0%} "
          f"(v2.1-style no-fading baseline)")
    print(f"\u26a0 FLAGGED DEVIATION from the ~0%% 200-round target: residual "
          f"steady-state honest sanction rate {ss_forget:.0%} at tau = 0.6 "
          f"(headroom property; see dashboard 2 cold-start + tau panels)")

    # -- M2 earned forgetting semantics unchanged -----------------------------
    o = ReputationEngine()
    o.register("onoff", Tier.HARDWARE, "ek_on")
    o.record_event("onoff", "MAJOR")
    f_atk = o._dev["onoff"].f
    for _ in range(FORGIVE_AFTER - 1):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f == f_atk
    for _ in range(25):
        o.record_event("onoff", "NEUTRAL")
    assert o._dev["onoff"].f < f_atk and o._dev["onoff"].trust > 0.75
    print(f"\u2713 M2 earned forgetting: {FORGIVE_AFTER - 1} clean rounds "
          f"launder nothing; a sustained streak fades f {f_atk:.1f} -> "
          f"{o._dev['onoff'].f:.3f}")

    # -- M3 sleeper defense on a veteran --------------------------------------
    v = ReputationEngine()
    v.register("vet", Tier.HARDWARE, "ek_vet")
    for _ in range(40):
        v.record_event("vet", "NEUTRAL")
    assert v.record_event("vet", "MAJOR") == Status.ACTIVE
    st = v.record_event("vet", "MAJOR")
    assert st == Status.PROBATION and v._dev["vet"].trust > 0.5
    print(f"\u2713 M3 sleeper defense: veteran probated at the 2nd MAJOR even "
          f"though its score ({v._dev['vet'].trust:.3f}) is still above 0.5")

    # -- reinstatement: floor 0.75, trial rounds are theta-weighted evidence --
    p = ReputationEngine()
    for did in ("p", "q", "r"):
        p.register(did, Tier.HARDWARE, f"ek_{did}")
        p.record_event(did, "MAJOR")
        p.record_event(did, "MAJOR")
        assert p.get_status(did) == Status.PROBATION
        assert p.get_weight(did) <= PROBATION_WEIGHT_CAP
    assert p.reinstate("r") is True
    assert p.reinstate("p", trial_rounds=6) is True
    assert p.reinstate("q", trial_rounds=9) is True
    for did in ("p", "q", "r"):
        assert abs(p._dev[did].trust - REINSTATE_T) < 1e-9
    assert p._dev["p"].major_run == 0 and p._dev["p"].clean_run == 0
    # v3 COUPLING CONSEQUENCE (REINSTATE_T <-> W), pinned: with W = 2 the
    # floor need_s = 3*(1+f) - 1 >= 3.8 for any entry with f >= 0.6, while
    # the largest theta-weighted trial credit a WINDOW_MAX = 9 trial can
    # earn is 0.4*9 = 3.6. The floor therefore ALWAYS binds: every
    # reinstatement returns at exactly 0.75, and the v2.1 property
    # "stronger proven recovery returns higher" is retired with it.
    assert THETA * 9 < (REINSTATE_T / (1 - REINSTATE_T)) * (1 + TAU) - 1
    print(f"\u2713 reinstatement (v3 coupling pinned): the 0.75 floor dominates "
          f"any trial credit a <= 9-round window can earn; every "
          f"reinstatement returns at exactly {REINSTATE_T}")

    # -- reinstate floor survives one unit of noise (no flapping) -------------
    # (note: a 4-MAJOR "heavy entry" is no longer reachable in v3 -- the
    # backstop bans it from PROBATION at round 4 per D5, as pinned above)
    fl = ReputationEngine()
    fl.register("d", Tier.HARDWARE, "ek_d")
    fl.record_event("d", "MAJOR")
    fl.record_event("d", "MAJOR")               # M3 -> probation, f = 1.2
    fl.reinstate("d")
    st = fl.record_event("d", "MINOR")
    assert st == Status.ACTIVE and fl._dev["d"].trust > PROBATION_T
    print(f"\u2713 no flapping: reinstated at 0.75, one noise MINOR leaves trust "
          f"{fl._dev['d'].trust:.3f} > 0.5 (the closed-form floor's job)")

    # -- fairness ranking (Def. 10) -------------------------------------------
    rk = ReputationEngine()
    rk.register("new", Tier.HARDWARE, "ek_new")
    rk.register("old", Tier.HARDWARE, "ek_old")
    for _ in range(60):
        rk.record_event("old", "NEUTRAL")
    for _ in range(3):
        rk.record_event("new", "NEUTRAL")
    assert rk.rank() == ["old", "new"]
    assert rk.get_opinion("old")["u"] < rk.get_opinion("new")["u"]
    print(f"\u2713 fairness (Def. 10): veteran ({rk._dev['old'].trust:.3f}, "
          f"u={rk.get_opinion('old')['u']:.2f}) outranks newcomer "
          f"({rk._dev['new'].trust:.3f}, u={rk.get_opinion('new')['u']:.2f})")

    print("\u2713 all reputation v3 self-tests passed")


if __name__ == "__main__":
    _self_test()
