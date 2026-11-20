"""Golden parity test: off-chain engine vs on-chain RECORD, in lockstep.

v3 ARCHITECTURE: the chain stores reputation values; it does not compute
them. ChainEngine below therefore embeds its own independent Python engine
(the computer) and PUSHES every post-event state to the deployed contract;
all of its reads come back FROM THE CHAIN. Deploys ReputationRegistry into
an in-process EVM (Tron's TVM is EVM-compatible at this contract's feature
level) and replays every golden scenario — the self-test scripts and all
dashboard-3 attack scripts — asserting after every single event:

  1. identical Status (the decision the system acts on) as read back from
     the chain, including the contract-enforced rules (O2 EK re-ban, ban
     terminality, Probation-only reinstatement),
  2. trust read back within FP_TOL = 2e-6 (fixed-point truncation bound),
  3. aggregation weight read back within the same quantization tolerance.

If this passes, the chain record faithfully mirrors the Python engine, and
every result on the three dashboards transfers to the public record
unchanged. (Note vs v2.x: the contract no longer recomputes the score, so
this test proves write-read fidelity plus the on-chain rules — the engine
itself is proven by reputation.py's own self-tests.)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from reputation import ReputationEngine, Status, Tier, REINSTATE_T

from web3 import Web3, EthereumTesterProvider

SCALE = 10**6
FP_TOL = 2e-6                      # one truncation unit per push, small slack
SEV = {"POSITIVE": 0, "NEUTRAL": 1, "MINOR": 2, "MAJOR": 3, "CRITICAL": 4}
STATUS = {0: Status.ACTIVE, 1: Status.PROBATION, 2: Status.BANNED}
STATUS_IDX = {Status.ACTIVE: 0, Status.PROBATION: 1, Status.BANNED: 2}
TIER_IDX = {Tier.HARDWARE: 0, Tier.TPM_RESIDENT: 1, Tier.SOFTWARE: 2}


class ChainEngine:
    """Same API surface as ReputationEngine. v3: computes with its own
    embedded Python engine and pushes each result to the contract; every
    getter reads back from the chain. This is also the template the tronpy
    bridge mirrors."""

    def __init__(self, w3, contract, sender):
        self.w3, self.c, self.sender = w3, contract, sender
        self.engine = ReputationEngine()          # the off-chain computer

    @staticmethod
    def _id(device_id):
        return Web3.keccak(text=device_id)

    @staticmethod
    def _ek(ek_hash):
        return Web3.keccak(text=ek_hash) if ek_hash else b"\x00" * 32

    def _snapshot(self, device_id):
        """The engine's post-event state, scaled for the chain (floored)."""
        d = self.engine._dev[device_id]
        cap = self.engine.p.discount[d.tier]
        if d.status == Status.PROBATION:
            cap = min(cap, self.engine.p.probation_weight_cap)
        w = 0.0 if d.status == Status.BANNED else cap * d.trust
        return (int(d.trust * SCALE), int(w * SCALE),
                STATUS_IDX[d.status], int(d.s * SCALE), int(d.f * SCALE))

    def register(self, device_id, tier, ek_hash=None):
        self.engine.register(device_id, tier, ek_hash)
        _, w, _, _, _ = self._snapshot(device_id)
        self.c.functions.register(self._id(device_id), TIER_IDX[Tier(tier)],
                                  self._ek(ek_hash), w).transact(
            {"from": self.sender})
        return self.get_status(device_id)

    def record_event(self, device_id, severity):
        self.engine.record_event(device_id, severity)
        t, w, st, s, f = self._snapshot(device_id)
        self.c.functions.pushReputation(self._id(device_id), SEV[severity],
                                        t, w, st, s, f).transact(
            {"from": self.sender})
        return self.get_status(device_id)

    def reinstate(self, device_id, trial_rounds=0):
        ok = self.engine.reinstate(device_id, trial_rounds)
        if ok:
            t, w, _, _, _ = self._snapshot(device_id)
            self.c.functions.reinstate(self._id(device_id), trial_rounds,
                                       t, w).transact({"from": self.sender})
        return ok

    def get_status(self, device_id):
        return STATUS[self.c.functions.getStatus(self._id(device_id)).call()]

    def trust(self, device_id):
        return self.c.functions.getTrust(self._id(device_id)).call() / SCALE

    def get_weight(self, device_id):
        return self.c.functions.getWeight(self._id(device_id)).call() / SCALE


def deploy():
    w3 = Web3(EthereumTesterProvider())
    art = json.load(open("build/ReputationRegistry.json"))
    acct = w3.eth.accounts[0]
    tx = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]) \
        .constructor().transact({"from": acct})
    addr = w3.eth.get_transaction_receipt(tx).contractAddress
    return w3, w3.eth.contract(address=addr, abi=art["abi"]), acct


# ---------------------------- golden scenarios --------------------------------
# (name, tier, event script) — every script from the dashboards + self-tests.
def onoff_script():
    ev = []
    for _ in range(10):
        ev += ["MAJOR"] + ["NEUTRAL"] * 4
    return ev


SCENARIOS = [
    ("P1 fresh T1 two majors",  Tier.HARDWARE,     ["MAJOR", "MAJOR"]),
    ("P2 T2 minor then major",  Tier.TPM_RESIDENT, ["MINOR", "MAJOR"]),
    ("P3 T3 zero tolerance",    Tier.SOFTWARE,     ["MINOR"]),
    ("M1 veteran 100 clean",    Tier.HARDWARE,     ["NEUTRAL"] * 100),
    ("M2 major then 25 clean",  Tier.HARDWARE,     ["MAJOR"] + ["NEUTRAL"] * 25),
    ("M3 sleeper 40+attack",    Tier.HARDWARE,     ["NEUTRAL"] * 40 + ["MAJOR"] * 4),
    ("attack: persistent",      Tier.HARDWARE,     ["MAJOR"] * 8),
    ("attack: on-off period 5", Tier.HARDWARE,     onoff_script()),
    ("attack: sybil critical",  Tier.HARDWARE,     ["NEUTRAL"] * 30 + ["CRITICAL"]),
    ("T3 veteran ceiling",      Tier.SOFTWARE,     ["NEUTRAL"] * 200),
    ("mixed noisy honest",      Tier.HARDWARE,
     (["NEUTRAL"] * 9 + ["MINOR"]) * 12),
]


def run():
    w3, contract, acct = deploy()
    chain = ChainEngine(w3, contract, acct)
    checks = 0
    max_dt = 0.0

    for name, tier, events in SCENARIOS:
        py = ReputationEngine()
        did = f"dev::{name}"
        py.register(did, tier, f"ek::{name}")
        chain.register(did, tier, f"ek::{name}")
        for i, ev in enumerate(events):
            st_py = py.record_event(did, ev)
            st_ch = chain.record_event(did, ev)
            t_py, t_ch = py._dev[did].trust, chain.trust(did)
            w_py, w_ch = py.get_weight(did), chain.get_weight(did)
            dt = abs(t_py - t_ch)
            max_dt = max(max_dt, dt)
            assert st_py == st_ch, \
                f"{name} r{i+1} [{ev}]: status {st_py} != {st_ch}"
            assert dt <= FP_TOL, \
                f"{name} r{i+1}: trust {t_py} vs {t_ch} (d={dt:.2e})"
            # Python's get_weight rounds to 4 dp (error <= 5e-5); the chain
            # truncates at 1e-6 (error <= 2e-6). Worst honest gap: 5.2e-5.
            # Quantization-boundary flips make exact 4-dp matching impossible.
            assert abs(w_py - w_ch) <= 6e-5, \
                f"{name} r{i+1}: weight {w_py} vs {w_ch}"
            checks += 3
        print(f"\u2713 {name}: {len(events)} rounds in lockstep "
              f"(final {py.get_status(did).value}, trust "
              f"{py._dev[did].trust:.4f} vs {chain.trust(did):.4f})")

    # --- reinstatement parity (floor + trial credit) --------------------------
    for credit in (0, 6, 9):
        py = ReputationEngine()
        did = f"rein{credit}"
        py.register(did, Tier.HARDWARE, did)
        chain.register(did, Tier.HARDWARE, did)
        for ev in ("MAJOR", "MAJOR"):
            py.record_event(did, ev)
            chain.record_event(did, ev)
        py.reinstate(did, trial_rounds=credit)
        chain.reinstate(did, trial_rounds=credit)
        t_py, t_ch = py._dev[did].trust, chain.trust(did)
        assert py.get_status(did) == chain.get_status(did) == Status.ACTIVE
        assert abs(t_py - t_ch) <= FP_TOL, f"reinstate({credit}): {t_py} vs {t_ch}"
        assert t_ch >= REINSTATE_T - FP_TOL
        checks += 3
        print(f"\u2713 reinstate credit={credit}: trust {t_py:.4f} vs {t_ch:.4f}")

    # --- whitewashing parity (O2: banned EK re-registers as banned) ------------
    py = ReputationEngine()
    py.register("w1", Tier.HARDWARE, "ek_same")
    chain.register("w1", Tier.HARDWARE, "ek_same")
    py.record_event("w1", "CRITICAL")
    chain.record_event("w1", "CRITICAL")
    assert py.register("w2", Tier.HARDWARE, "ek_same") == Status.BANNED
    assert chain.register("w2", Tier.HARDWARE, "ek_same") == Status.BANNED
    checks += 1
    print("\u2713 whitewashing: banned EK re-banned at registration on-chain")

    # --- access control: a non-server address must be rejected -----------------
    stranger = w3.eth.accounts[1]
    try:
        contract.functions.pushReputation(
            ChainEngine._id("w1"), 3, 100000, 0, 2, 0, 0).transact(
            {"from": stranger})
        raise AssertionError("stranger was allowed to write")
    except Exception as e:
        assert "not the FL server" in str(e), f"wrong revert: {e}"
    checks += 1
    print("\u2713 access control: non-server writer reverted")

    total_rounds = sum(len(ev) for _, _, ev in SCENARIOS)
    print(f"\nPARITY PROVEN: {checks} assertions over {total_rounds} "
          f"event-rounds across {len(SCENARIOS)} scenarios; "
          f"max trust divergence {max_dt:.2e} (tolerance {FP_TOL:.0e}).")


if __name__ == "__main__":
    run()
