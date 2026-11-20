"""
chain/fixedpoint.py

Integer mirror of trust/reputation.py, shared verbatim by the Python client
and contracts/DLTFRegistry.sol. Solidity has no floats; this module is the
single definition of the arithmetic both sides must agree on.

DESIGN: ONE SCALE, NO DIVISION ON THE DECISION PATH
-----------------------------------------------------------------------------
SCALE = 10**6. Justified, not arbitrary: every constant in the trust model is
an exact decimal with a small denominator, so at 1e6 all of them are exactly
representable and contribute ZERO quantisation error:

    THETA 0.4 -> 400_000        PROBATION_T 0.5  -> 500_000
    TAU   0.6 -> 600_000        BAN_T       0.3  -> 300_000
    W     2.0 -> 2_000_000      REINSTATE_T 0.75 -> 750_000

1e6 also keeps every intermediate under 1e13, far inside uint256, so the
contract needs no overflow guards on the hot path.

DECAY IS A SINGLE OPERATION [DERIVED]
-----------------------------------------------------------------------------
GAMMA = FORGET = 0.90 in trust/reputation.py, so positive and negative
evidence decay at the same RATE and the contract needs one primitive:

    decay(x) = (9 * x) // 10

Floor division on non-negative integers. Solidity's `/` on uint is floor;
Python's `//` on int is floor. The two agree bit-for-bit by construction, not
approximately. This is the ONLY truncating operation in the module.

Asymmetry between trust and distrust is NOT carried by the rate. It is carried
by FORGIVE_AFTER = 2: s decays every round unconditionally, f decays only from
the second consecutive clean round onward. Nothing here encodes a rate ratio.

THRESHOLDS BY CROSS-MULTIPLICATION -- EXACT, NO DIVISION
-----------------------------------------------------------------------------
trust = (a0 + s) / (a0 + b0 + s + f). Computing that as a fixed-point quotient
would truncate on every comparison. Instead compare by cross-multiplying:

    trust <= t   <=>   (A0 + S) * SCALE  <=  T * (2*SCALE + S + F)
    gate open    <=>   S + F > 2*SCALE

Pure integer comparison. Exact. The thresholds themselves therefore introduce
no error at all -- all quantisation is confined to decay().

REINSTATEMENT FLOOR IS EXACT
-----------------------------------------------------------------------------
need_s = (r/(1-r)) * (b0 + f) - a0 with r = REINSTATE_T = 0.75 gives the
integer ratio 3, so

    need_S = 3 * (SCALE + F) - SCALE = 3*F + 2*SCALE

No division. (Had REINSTATE_T been 0.55, the ratio 11/9 would not be exact and
this would need a stated rounding direction. It is 0.75; it is exact.)

QUANTISATION RELATIONSHIP TO THE FLOAT ENGINE -- STATED, NOT HIDDEN
-----------------------------------------------------------------------------
Exact agreement with trust/reputation.py is IMPOSSIBLE and this module does
not pretend otherwise. decay() truncates; float multiplication rounds. The
divergence is bounded, one-sided per-variable, and provable:

  each decay() loses < 1 unit, so the error recurrence is  e' <= 0.9*e + 1,
  with fixed point e_inf <= 10 units = 1e-5 in real terms, on each of s and f.

  |dT/ds| = (b0+f)/D^2 <= 1/4   and   |dT/df| = (a0+s)/D^2 <= 1/4

  => |T_float - T_fixed| <= 2 * (1/4) * 1e-5 = 5e-6.

Per-variable the error is one-sided (truncation only ever lowers S and F), but
the effect on trust is NOT: a lower S lowers trust, a lower F raises it.

CONSEQUENCE FOR THE SYSTEM: the fixed-point path is AUTHORITATIVE for status.
Python submits integer state, the contract recomputes it independently and
reverts on mismatch. The float engine stays the research artifact. Status can
only diverge when float trust lands within 5e-6 of a threshold; _self_test()
measures that rate over random event sequences rather than asserting an
epsilon and looking away.

INTENTIONAL DIVERGENCE: RESURRECTION IS REFUSED
-----------------------------------------------------------------------------
trust/reputation.py `register()` overwrites its device record unconditionally,
so register(dev, tier) with ek_hash=None resurrects a BANNED device as ACTIVE
with s = f = 0. Unreachable from fl/server.py today (it always passes a real
ek_hash) but it is a genuine BANNED -> ACTIVE path in the code. This engine
refuses it: BANNED is absorbing, per device_id AND per ek_hash. The contract
reverts it. reputation.py is not modified -- black-box discipline holds.

  python3 -m chain.fixedpoint
"""
from enum import IntEnum

SCALE = 10 ** 6

# ---- exactly representable constants (zero quantisation error) --------------
THETA_FP = 400_000                  # 0.4  CANONICAL (Kang 2019 Tab. I)
TAU_FP = 600_000                    # 0.6  CANONICAL
A0_FP = B0_FP = SCALE               # Beta(1,1) CANONICAL (Josang)
W_PRIOR_FP = A0_FP + B0_FP          # 2.0

PROBATION_T_FP = 500_000            # 0.5  CALIBRATED
BAN_T_FP = 300_000                  # 0.3  CALIBRATED
REINSTATE_T_FP = 750_000            # 0.75 [DERIVED] 0.5*(1+1/W)

DECAY_NUM, DECAY_DEN = 9, 10        # GAMMA == FORGET == 0.90 [DERIVED]
FORGIVE_AFTER = 2
MAJOR_RUN_TO_ESCALATE = 2

REINSTATE_RATIO = 3                 # r/(1-r) at r = 0.75, exact integer


class TierFP(IntEnum):
    HARDWARE = 1
    TPM_RESIDENT = 2
    SOFTWARE = 3


class StatusFP(IntEnum):            # contract enum, ABI-stable ordering
    ACTIVE = 0
    PROBATION = 1
    BANNED = 2


class SeverityFP(IntEnum):
    """Five members. filter.py emits only the last four, but POSITIVE is a
    legal input to record_event and is in GOOD_EVIDENCE, so the ABI carries
    it: a future positive-evidence source must not require a contract
    migration."""
    POSITIVE = 0
    NEUTRAL = 1
    MINOR = 2
    MAJOR = 3
    CRITICAL = 4


GOOD = {SeverityFP.POSITIVE, SeverityFP.NEUTRAL}

TIER_DISCOUNT_FP = {TierFP.HARDWARE: 1_000_000,
                    TierFP.TPM_RESIDENT: 500_000,
                    TierFP.SOFTWARE: 100_000}
REHAB_FP = {TierFP.HARDWARE: True,
            TierFP.TPM_RESIDENT: False,
            TierFP.SOFTWARE: False}
PROBATION_WEIGHT_CAP_FP = TIER_DISCOUNT_FP[TierFP.SOFTWARE]


# ---- primitives: the contract implements exactly these ----------------------

def decay(x):
    """The one truncating operation. Solidity: `x * 9 / 10` on uint."""
    return (x * DECAY_NUM) // DECAY_DEN


def denom(s_fp, f_fp):
    return W_PRIOR_FP + s_fp + f_fp


def trust_le(s_fp, f_fp, t_fp):
    """trust <= t, by cross-multiplication. Exact, no division."""
    return (A0_FP + s_fp) * SCALE <= t_fp * denom(s_fp, f_fp)


def evidence_dominated(s_fp, f_fp):
    """The v3 u-gate: u < 0.5  <=>  s + f > W."""
    return (s_fp + f_fp) > W_PRIOR_FP


def trust_fp(s_fp, f_fp):
    """Trust as a SCALE-fixed integer. Reporting only -- never used for a
    threshold decision, because this division truncates and trust_le() does
    not."""
    return ((A0_FP + s_fp) * SCALE) // denom(s_fp, f_fp)


def reinstate_floor(f_fp):
    """need_S such that trust >= REINSTATE_T. Exact: 3*F + 2*SCALE."""
    return REINSTATE_RATIO * (SCALE + f_fp) - A0_FP


# ---- state ------------------------------------------------------------------

class DeviceFP:
    """Packs into one 256-bit slot on chain:
         s uint64 | f uint64 | clean_run uint16 | major_run uint16
         status uint8 | tier uint8 | lastRound uint32
       = 64+64+16+16+8+8+32 = 208 bits. One warm SSTORE per device per round.
    """
    __slots__ = ("device_id", "tier", "ek_hmac", "s", "f",
                 "clean_run", "major_run", "status", "last_round")

    def __init__(self, device_id, tier, ek_hmac, status):
        self.device_id = device_id
        self.tier = TierFP(tier)
        self.ek_hmac = ek_hmac
        self.s = 0
        self.f = 0
        self.clean_run = 0
        self.major_run = 0
        self.status = status
        self.last_round = -1

    @property
    def trust(self):
        return trust_fp(self.s, self.f)

    def pack(self):
        assert self.s < 1 << 64 and self.f < 1 << 64
        assert self.clean_run < 1 << 16 and self.major_run < 1 << 16
        lr = self.last_round & 0xFFFFFFFF
        return (self.s | (self.f << 64) | (self.clean_run << 128)
                | (self.major_run << 144) | (int(self.status) << 160)
                | (int(self.tier) << 168) | (lr << 176))

    @staticmethod
    def unpack(word, device_id=None, ek_hmac=None):
        d = DeviceFP.__new__(DeviceFP)
        d.device_id, d.ek_hmac = device_id, ek_hmac
        d.s = word & ((1 << 64) - 1)
        d.f = (word >> 64) & ((1 << 64) - 1)
        d.clean_run = (word >> 128) & 0xFFFF
        d.major_run = (word >> 144) & 0xFFFF
        d.status = StatusFP((word >> 160) & 0xFF)
        d.tier = TierFP((word >> 168) & 0xFF)
        lr = (word >> 176) & 0xFFFFFFFF
        d.last_round = -1 if lr == 0xFFFFFFFF else lr
        return d


class DivergenceError(Exception):
    """Raised when a submitted state does not match the recomputed rule.
    This is the Python-side mirror of the contract's revert."""


class FixedEngine:
    """Integer mirror of ReputationEngine. Same public surface for the calls
    the chain layer needs; transition ORDER is pinned to reputation.py
    _transition(): backstop -> M3 -> probation threshold, each returning."""

    def __init__(self, gate_enabled=True, m3_enabled=True):
        self.gate_enabled = gate_enabled
        self.m3_enabled = m3_enabled
        self._dev = {}
        self._banned_ek = set()

    # -- registration ---------------------------------------------------------

    def register(self, device_id, tier, ek_hmac=None):
        """BANNED is absorbing per device_id AND per ek_hmac. This is the
        intentional divergence from reputation.py documented above."""
        prior = self._dev.get(device_id)
        if prior is not None and prior.status == StatusFP.BANNED:
            return StatusFP.BANNED                      # no resurrection
        if prior is not None and prior.tier != TierFP(tier):
            raise DivergenceError(
                f"tier is immutable after enrollment: {device_id} "
                f"{prior.tier.name} -> {TierFP(tier).name}")
        banned = ek_hmac is not None and ek_hmac in self._banned_ek
        d = DeviceFP(device_id, tier, ek_hmac,
                     StatusFP.BANNED if banned else StatusFP.ACTIVE)
        self._dev[device_id] = d
        return d.status

    # -- the rule -------------------------------------------------------------

    def record_event(self, device_id, severity, round_id=None):
        d = self._dev[device_id]
        if d.status == StatusFP.BANNED:
            return d.status
        sev = SeverityFP(severity) if not isinstance(severity, SeverityFP) \
            else severity

        if sev == SeverityFP.CRITICAL:          # rule: ungated, non-compensable
            d.clean_run = 0
            d.major_run = 0
            self._ban(d)
        elif sev in GOOD:
            d.s = decay(d.s) + THETA_FP
            d.clean_run += 1
            d.major_run = 0
            if d.clean_run >= FORGIVE_AFTER:
                d.f = decay(d.f)
            self._transition(d)
        else:                                    # MINOR | MAJOR
            d.s = decay(d.s)
            d.f += TAU_FP
            d.clean_run = 0
            d.major_run = d.major_run + 1 if sev == SeverityFP.MAJOR else 0
            self._transition(d)

        if round_id is not None:
            d.last_round = round_id
        return d.status

    def _transition(self, d):
        gate = (not self.gate_enabled) or evidence_dominated(d.s, d.f)

        if gate and trust_le(d.s, d.f, BAN_T_FP):                # backstop
            if REHAB_FP[d.tier] and d.status == StatusFP.ACTIVE:
                d.status = StatusFP.PROBATION                    # D5 due process
            else:
                self._ban(d)
            return
        if self.m3_enabled and d.major_run >= MAJOR_RUN_TO_ESCALATE:   # M3
            if REHAB_FP[d.tier]:
                d.status = StatusFP.PROBATION
            else:
                self._ban(d)
            return
        if (gate and d.status == StatusFP.ACTIVE
                and trust_le(d.s, d.f, PROBATION_T_FP)):
            if REHAB_FP[d.tier]:
                d.status = StatusFP.PROBATION
            else:
                self._ban(d)

    def _ban(self, d):
        d.status = StatusFP.BANNED
        if d.ek_hmac is not None:
            self._banned_ek.add(d.ek_hmac)

    def reinstate(self, device_id, trial_rounds=0):
        d = self._dev[device_id]
        if d.status != StatusFP.PROBATION or not REHAB_FP[d.tier]:
            return False
        d.s += THETA_FP * int(trial_rounds)
        d.s = max(d.s, reinstate_floor(d.f))
        d.status = StatusFP.ACTIVE
        d.clean_run = 0
        d.major_run = 0
        return True

    # -- queries --------------------------------------------------------------

    def get_status(self, device_id):
        return self._dev[device_id].status

    def get_trust(self, device_id):
        return self._dev[device_id].trust

    def get_weight(self, device_id):
        """OFF-CHAIN ONLY. reputation.get_weight rounds to 4 decimals with
        Python's round-half-to-EVEN, which has no cheap integer equivalent.
        Weights never cross the seam; this exists for the parity report."""
        d = self._dev[device_id]
        if d.status == StatusFP.BANNED:
            return 0
        cap = TIER_DISCOUNT_FP[d.tier]
        if d.status == StatusFP.PROBATION:
            cap = min(cap, PROBATION_WEIGHT_CAP_FP)
        return (cap * (A0_FP + d.s)) // denom(d.s, d.f)

    def banned_ek_hmacs(self):
        return set(self._banned_ek)

    def snapshot(self):
        return {i: d.pack() for i, d in self._dev.items()}


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import random
    print("chain/fixedpoint.py self-test")

    # -- constants are exactly representable ---------------------------------
    assert THETA_FP + TAU_FP == SCALE
    assert W_PRIOR_FP == 2 * SCALE
    assert BAN_T_FP * 10 == 3 * SCALE and PROBATION_T_FP * 2 == SCALE
    assert REINSTATE_T_FP * 4 == 3 * SCALE
    assert REINSTATE_T_FP * REINSTATE_RATIO == (SCALE - REINSTATE_T_FP) * 9
    print("\u2713 every constant exact at SCALE = 1e6 (zero constant error)")

    # -- one decay primitive, floor direction pinned -------------------------
    assert decay(0) == 0 and decay(10) == 9 and decay(9) == 8   # floor, not round
    assert decay(1) == 0                                        # truncates to 0
    assert DECAY_NUM / DECAY_DEN == 0.9
    print("\u2713 decay() = (9x)//10, floor; GAMMA == FORGET so ONE primitive")

    # -- threshold comparison exact, and consistent with the quotient --------
    for s, f in ((0, 0), (400_000, 600_000), (4_000_000, 0), (0, 6_000_000)):
        for t in (BAN_T_FP, PROBATION_T_FP, REINSTATE_T_FP):
            lhs = (A0_FP + s) * SCALE
            assert trust_le(s, f, t) == (lhs <= t * denom(s, f))
    assert trust_le(0, 0, PROBATION_T_FP)          # fresh device: exactly 0.5
    assert not trust_le(0, 0, BAN_T_FP)
    print("\u2713 trust_le() by cross-multiplication: exact, division-free")

    # -- reinstatement floor is exact ----------------------------------------
    for f in (0, 600_000, 3_000_000):
        need = reinstate_floor(f)
        assert not trust_le(need, f, REINSTATE_T_FP - 1)
        assert trust_le(need - 1, f, REINSTATE_T_FP)
    print("\u2713 reinstate_floor() = 3F + 2*SCALE, exact at r = 0.75")

    # -- gate boundary --------------------------------------------------------
    assert not evidence_dominated(W_PRIOR_FP, 0)      # s+f == W: still closed
    assert evidence_dominated(W_PRIOR_FP + 1, 0)      # strict >
    print("\u2713 u-gate is strict s + f > W, boundary inclusive of the prior")

    # -- pack / unpack round-trips -------------------------------------------
    e = FixedEngine()
    e.register("p", TierFP.HARDWARE, "ek_p")
    for sev in (SeverityFP.NEUTRAL, SeverityFP.MAJOR, SeverityFP.NEUTRAL):
        e.record_event("p", sev, round_id=7)
    d = e._dev["p"]
    r = DeviceFP.unpack(d.pack())
    assert (r.s, r.f, r.clean_run, r.major_run, r.status, r.tier,
            r.last_round) == (d.s, d.f, d.clean_run, d.major_run, d.status,
                              d.tier, d.last_round)
    assert d.pack() < 1 << 208
    print("\u2713 device state packs into ONE 256-bit slot and round-trips")

    # -- BANNED is absorbing; resurrection refused ---------------------------
    e = FixedEngine()
    e.register("z", TierFP.SOFTWARE, "ek_z")
    e.record_event("z", SeverityFP.CRITICAL)
    assert e.get_status("z") == StatusFP.BANNED
    assert e.register("z", TierFP.SOFTWARE) == StatusFP.BANNED      # ek None
    assert e.register("z", TierFP.SOFTWARE, "ek_fresh") == StatusFP.BANNED
    assert e.record_event("z", SeverityFP.NEUTRAL) == StatusFP.BANNED
    assert e.register("z2", TierFP.HARDWARE, "ek_z") == StatusFP.BANNED  # O2
    print("\u2713 BANNED absorbing by device_id AND ek_hmac; no resurrection "
          "path (the reputation.py hole is closed here)")

    # -- tier immutability ----------------------------------------------------
    e = FixedEngine()
    e.register("t", TierFP.TPM_RESIDENT, "ek_t")
    try:
        e.register("t", TierFP.HARDWARE, "ek_t")
        raise AssertionError("tier change should have been refused")
    except DivergenceError:
        pass
    print("\u2713 tier immutable after enrollment (DivergenceError = revert)")

    # ==== PARITY AGAINST THE FLOAT ENGINE ===================================
    try:
        from trust.reputation import (ReputationEngine, Tier, Status, FORGET,
                                      GAMMA)
    except Exception as exc:                        # standalone run
        print(f"\u26a0 trust.reputation unavailable ({exc}); parity skipped")
        print("\u2713 all fixedpoint self-tests passed (parity skipped)")
        return

    assert abs(FORGET - 0.90) < 1e-12 and abs(GAMMA - 0.90) < 1e-12, \
        f"fixedpoint assumes GAMMA == FORGET == 0.90, found {GAMMA}/{FORGET}"
    print("\u2713 float engine agrees: GAMMA == FORGET == 0.90")

    SEVS = ["POSITIVE", "NEUTRAL", "MINOR", "MAJOR"]     # CRITICAL is a rule
    TIERS = [(Tier.HARDWARE, TierFP.HARDWARE),
             (Tier.TPM_RESIDENT, TierFP.TPM_RESIDENT),
             (Tier.SOFTWARE, TierFP.SOFTWARE)]
    N, ROUNDS = 2000, 40
    max_err = 0.0
    worst = None
    status_div = 0
    onesided_s = onesided_f = True
    rng = random.Random(20260724)

    for n in range(N):
        ft, xt = TIERS[n % 3]
        fe = ReputationEngine()
        xe = FixedEngine()
        fe.register("d", ft, "ek_d")
        xe.register("d", xt, "ek_d")
        for r in range(ROUNDS):
            sev = rng.choice(SEVS)
            fs = fe.record_event("d", sev)
            xs = xe.record_event("d", SeverityFP[sev], round_id=r)
            if (fs == Status.BANNED) != (xs == StatusFP.BANNED) or \
               (fs == Status.PROBATION) != (xs == StatusFP.PROBATION):
                status_div += 1
                break
            fd = fe._dev["d"]
            if xe._dev["d"].s > round(fd.s * SCALE) + 1:
                onesided_s = False
            if xe._dev["d"].f > round(fd.f * SCALE) + 1:
                onesided_f = False
            err = abs(fd.trust - xe.get_trust("d") / SCALE)
            if err > max_err:
                max_err, worst = err, (ft.name, r, sev, fd.trust)
            if fs == Status.BANNED:
                break

    seqs = N * ROUNDS
    assert max_err <= 5e-6, f"bound violated: {max_err:.3e} at {worst}"
    assert onesided_s and onesided_f, "truncation should never raise S or F"
    print(f"\u2713 parity over {N} sequences x {ROUNDS} rounds "
          f"({seqs:,} events, all 3 tiers): "
          f"max |T_float - T_fixed| = {max_err:.3e} <= 5e-6 (proven bound)")
    print(f"\u2713 truncation is one-sided per variable: S_fp <= S_float, "
          f"F_fp <= F_float always")
    print(f"\u2713 status divergence: {status_div} / {seqs:,} events "
          f"({100.0 * status_div / seqs:.4f}%)")
    if status_div:
        print("  \u26a0 non-zero: fixed-point path is AUTHORITATIVE for status; "
              "the float engine is the research artifact (see docstring)")

    # -- reinstatement parity -------------------------------------------------
    fe, xe = ReputationEngine(), FixedEngine()
    fe.register("p", Tier.HARDWARE, "ek_p")
    xe.register("p", TierFP.HARDWARE, "ek_p")
    for _ in range(3):
        fe.record_event("p", "MAJOR")
        xe.record_event("p", SeverityFP.MAJOR)
    assert fe.get_status("p") == Status.PROBATION
    assert xe.get_status("p") == StatusFP.PROBATION
    assert fe.reinstate("p", trial_rounds=5) and xe.reinstate("p", trial_rounds=5)
    assert fe.get_status("p") == Status.ACTIVE
    assert abs(fe._dev["p"].trust - xe.get_trust("p") / SCALE) <= 5e-6
    assert not trust_le(xe._dev["p"].s, xe._dev["p"].f, REINSTATE_T_FP - 1)
    print("\u2713 reinstatement parity: 3 MAJOR -> PROBATION -> reinstate(5), "
          "both land at/above the 0.75 floor")

    print("\u2713 all fixedpoint self-tests passed")


if __name__ == "__main__":
    _self_test()
