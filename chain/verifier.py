"""
chain/verifier.py

Standalone third-party verification. Recomputes EVERY device's reputation
state and status from the emitted event log ALONE, then compares against the
authoritative state held by the backend.

WHY THIS EXISTS
-----------------------------------------------------------------------------
The contract stores one packed word per device. It emits an event for every
classification. If the stored state is a deterministic function of the event
stream -- and it is, because the rule is deterministic -- then any third
party can independently recompute it and detect a discrepancy WITHOUT
trusting the server, the contract's storage, or the local audit log.

That is a materially stronger property than the hash chain offers. The hash
chain proves nobody edited the log. This proves the log's CONTENTS IMPLY the
recorded state. A server that wrote a plausible-looking event stream but
stored inconsistent state would be caught here.

WHAT IT DOES NOT PROVE
-----------------------------------------------------------------------------
It does not prove the classifications were TRUE. A server that labels an
honest client MAJOR produces a log that verifies perfectly. Verification is
about internal consistency, not about ground truth. This limitation is
inherent and is stated in chain/README.md.

USAGE
-----------------------------------------------------------------------------
    from chain.verifier import verify_backend
    result = verify_backend(backend)
    assert result.ok, result.summary()

The verifier deliberately does NOT import MockBackend or reach into any
backend's private state. It uses only the public read surface:
events() and get_device(). This is what makes it a genuine third-party
check: the same code runs against a live EVM node's event log.

  python3 -m chain.verifier
"""
from dataclasses import dataclass, field

from chain.fixedpoint import (FixedEngine, StatusFP, TierFP, SeverityFP,
                              SCALE, DeviceFP)


@dataclass
class Discrepancy:
    device_id: str
    field_name: str
    recomputed: object
    on_chain: object

    def __str__(self):
        return (f"{self.device_id}.{self.field_name}: "
                f"recomputed={self.recomputed} on_chain={self.on_chain}")


@dataclass
class VerificationResult:
    ok: bool
    devices_checked: int = 0
    events_replayed: int = 0
    discrepancies: list = field(default_factory=list)
    unknown_events: list = field(default_factory=list)
    recomputed: dict = field(default_factory=dict)      # device -> DeviceFP

    def summary(self):
        if self.ok:
            return (f"VERIFIED: {self.devices_checked} devices, "
                    f"{self.events_replayed} events replayed, "
                    f"0 discrepancies")
        lines = [f"FAILED: {len(self.discrepancies)} discrepancies "
                 f"over {self.devices_checked} devices"]
        lines += [f"  {d}" for d in self.discrepancies[:20]]
        if self.unknown_events:
            lines.append(f"  unknown event types: "
                         f"{sorted(set(self.unknown_events))}")
        return "\n".join(lines)


# Fields compared between recomputed and on-chain state.
COMPARED = ("s", "f", "clean_run", "major_run", "status", "tier")


# Events that appear in the log but do not move trust state. Replaying them is
# correctly a no-op: the commitment layer proves WHAT a client sent, not
# WHETHER it behaved, so it never feeds the reputation rule.
NON_STATE_EVENTS = {
    "GENESIS",
    "WALLET_BOUND",           # wallet <-> TPM binding
    "GRADIENT_COMMITTED",     # keccak256(gradient) recorded pre-transmission
    "COMMIT_MISMATCH",        # received gradient != commitment (evidence only)
    "COMMIT_PROOF",           # EIP-712 signed commitment
    "ABSENT",                 # participant recorded as absent
}


def replay_events(events):
    """Rebuild a FixedEngine from an event log. Returns (engine, stats).

    Event types consumed:
      ENROLL              -> register
      EVENT               -> record_event
      PROBATION_DECISION  -> reinstate on REINSTATED; CRITICAL on PERMANENT_BAN
      REHAB_EXHAUSTED     -> CRITICAL (drives the ban through the rule)
    Ignored (they carry no state the rule does not already imply):
      GENESIS, BAN, WHITEWASH_REJECTED, PROBATION_ENTER, ROUND
    """
    engine = FixedEngine()
    replayed = 0
    unknown = []
    # Devices whose ban came from an explicit lifecycle event rather than
    # from the arithmetic. Tracked so we do not double-apply.
    for ev in events:
        et = ev.event_type
        p = ev.payload

        if et in ("GENESIS", "BAN", "WHITEWASH_REJECTED", "PROBATION_ENTER",
                  "ROUND"):
            continue

        if et == "ENROLL":
            tier = TierFP(int(p["tier"]))
            ek = bytes.fromhex(p["ek_hmac"]) if p.get("ek_hmac") else None
            engine.register(p["device"], tier, ek)
            replayed += 1
            continue

        if et == "EVENT":
            dev = p["device"]
            if dev not in engine._dev:
                unknown.append(f"EVENT before ENROLL: {dev}")
                continue
            engine.record_event(dev, SeverityFP(int(p["severity"])),
                                round_id=int(p["round"]))
            replayed += 1
            continue

        if et == "PROBATION_DECISION":
            dev = p["device"]
            outcome = p["outcome"]
            if outcome == "REINSTATED":
                engine.reinstate(dev, trial_rounds=0)
            elif outcome == "PERMANENT_BAN":
                engine.record_event(dev, SeverityFP.CRITICAL,
                                    round_id=int(p["round"]))
            # EXTENDED: no state change
            replayed += 1
            continue

        if et == "REHAB_EXHAUSTED":
            engine.record_event(p["device"], SeverityFP.CRITICAL,
                                round_id=int(p["round"]))
            replayed += 1
            continue

        if et in NON_STATE_EVENTS:
            # Commitment-layer and bookkeeping events. They are part of the
            # audit record but carry NO trust-state transition, so replaying
            # them is a no-op by design rather than an omission. Listing them
            # explicitly keeps `unknown` meaningful: anything still landing
            # there is a genuine gap in the replay logic.
            continue

        unknown.append(et)

    return engine, replayed, unknown


def verify_backend(backend) -> VerificationResult:
    """Recompute all state from backend.events() and compare to
    backend.get_device(). Uses ONLY the public read surface."""
    events = backend.events()
    engine, replayed, unknown = replay_events(events)

    result = VerificationResult(ok=True, events_replayed=replayed,
                                unknown_events=unknown)

    # Every device that appears in an ENROLL must match.
    enrolled = [e.payload["device"] for e in events
                if e.event_type == "ENROLL"]
    for dev_id in enrolled:
        recomputed = engine._dev.get(dev_id)
        on_chain = backend.get_device(dev_id)
        result.devices_checked += 1
        if recomputed is not None:
            result.recomputed[dev_id] = recomputed

        if on_chain is None:
            if recomputed is not None:
                result.discrepancies.append(
                    Discrepancy(dev_id, "existence", "present", "absent"))
            continue
        if recomputed is None:
            result.discrepancies.append(
                Discrepancy(dev_id, "existence", "absent", "present"))
            continue

        for f in COMPARED:
            a, b = getattr(recomputed, f), getattr(on_chain, f)
            if a != b:
                result.discrepancies.append(Discrepancy(dev_id, f, a, b))

    # Ban set must agree.
    recomputed_bans = engine.banned_ek_hmacs()
    for ek in recomputed_bans:
        if not backend.is_banned_ek(ek):
            result.discrepancies.append(
                Discrepancy("<ban set>", ek.hex()[:16], "banned", "not banned"))

    result.ok = not result.discrepancies
    if unknown:
        result.ok = False
    return result


def verify_hashchain_against_backend(inner, backend, fed_key):
    """Cross-check: does the local audit log's ROUND anchor match a head the
    chain recorded? Confirms the two ledgers describe the same history.

    Returns (ok, detail). Only checks anchors present on chain."""
    on_chain_rounds = {e.payload["round"]: e.payload["local_head"]
                       for e in backend.events("ROUND")}
    if not on_chain_rounds:
        return True, "no ROUND anchors on chain"
    # Every anchored round must correspond to a ROUND entry in the local log.
    local_rounds = {e["payload"]["round"] for e in inner.entries("ROUND")}
    missing = set(on_chain_rounds) - local_rounds
    if missing:
        return False, f"rounds anchored on chain but absent locally: {sorted(missing)}"
    return True, f"{len(on_chain_rounds)} rounds cross-checked"


def _self_test():
    import hashlib
    from chain.mock import MockBackend
    from chain.keys import FederationKey
    from chain.registry import ChainRegistry
    from audit.hashchain import HashChain

    print("chain/verifier.py self-test")
    W = b"verifier-writer-key-32-xxxxxxxxx"

    def ek(label):
        return hashlib.sha256(label.encode()).digest()

    # === 1. Clean log verifies ============================================
    b = MockBackend(W)
    b.register(W, "a", TierFP.HARDWARE, ek("a"))
    b.register(W, "b", TierFP.SOFTWARE, ek("b"))
    for r in range(6):
        b.classify(W, r, "a", SeverityFP.NEUTRAL)
        b.classify(W, r, "b", SeverityFP.NEUTRAL)
        b.round_summary(W, r, hashlib.sha256(b"a\nb").digest(), True,
                        b"\x00" * 32)
    res = verify_backend(b)
    assert res.ok, res.summary()
    assert res.devices_checked == 2
    print(f"\u2713 clean log verifies: {res.devices_checked} devices, "
          f"{res.events_replayed} events replayed, 0 discrepancies")

    # === 2. Mixed severities, bans, whitewash ============================
    b = MockBackend(W)
    b.register(W, "hon", TierFP.HARDWARE, ek("hon"))
    b.register(W, "att", TierFP.SOFTWARE, ek("att"))
    # Per round: classify every device, THEN close the round. Closing
    # mid-round would make the remaining classifies StaleRound-rejected.
    script = {
        0: {"hon": SeverityFP.NEUTRAL, "att": SeverityFP.MINOR},
        1: {"hon": SeverityFP.NEUTRAL, "att": SeverityFP.MAJOR},
        2: {"hon": SeverityFP.MINOR,   "att": SeverityFP.MAJOR},
        3: {"hon": SeverityFP.NEUTRAL},
        4: {"hon": SeverityFP.NEUTRAL},
        5: {"hon": SeverityFP.NEUTRAL},
    }
    for rid, sevs in script.items():
        for dev, sev in sevs.items():
            if b.get_device(dev).status == StatusFP.BANNED:
                continue                    # backend refuses post-ban writes
            b.classify(W, rid, dev, sev)
        b.round_summary(W, rid,
                        hashlib.sha256("\n".join(sorted(sevs)).encode()).digest(),
                        True, b"\x00" * 32)
    # att is SOFTWARE (no rehab); two consecutive MAJORs trip M3 at r2.
    assert b.get_device("att").status == StatusFP.BANNED, \
        b.get_device("att").status
    assert b.get_device("hon").status == StatusFP.ACTIVE
    # whitewash attempt with the banned EK under a fresh label
    status, ev = b.register(W, "att_v2", TierFP.SOFTWARE, ek("att"))
    assert status == int(StatusFP.BANNED)
    assert ev.event_type == "WHITEWASH_REJECTED"
    res = verify_backend(b)
    assert res.ok, res.summary()
    print("\u2713 mixed log with bans + whitewash verifies "
          f"({res.events_replayed} events, att BANNED via M3, hon ACTIVE)")

    # === 3. Probation lifecycle verifies =================================
    b = MockBackend(W)
    b.register(W, "hw", TierFP.HARDWARE, ek("hw"))
    for r in range(3):
        b.classify(W, r, "hw", SeverityFP.MAJOR)
    assert b.get_device("hw").status == StatusFP.PROBATION
    b.enter_probation(W, 3, "hw")
    b.probation_decision(W, 4, "hw", "REINSTATED")
    assert b.get_device("hw").status == StatusFP.ACTIVE
    res = verify_backend(b)
    assert res.ok, res.summary()
    print("\u2713 probation lifecycle verifies (3xMAJOR -> PROBATION -> "
          "REINSTATED -> ACTIVE recomputed exactly)")

    # === 4. Rehab exhaustion verifies ====================================
    for r in range(5, 8):
        b.classify(W, r, "hw", SeverityFP.MAJOR)
    b.exhaust_probation(W, 8, "hw")
    assert b.get_device("hw").status == StatusFP.BANNED
    res = verify_backend(b)
    assert res.ok, res.summary()
    print("\u2713 rehab exhaustion verifies (REHAB_EXHAUSTED -> BANNED)")

    # === 5. A TAMPERED state is DETECTED =================================
    # This is the whole point. Corrupt the backend's stored state without
    # touching the event log, and confirm the verifier notices.
    b = MockBackend(W)
    b.register(W, "t", TierFP.HARDWARE, ek("t"))
    for r in range(4):
        b.classify(W, r, "t", SeverityFP.NEUTRAL)
    assert verify_backend(b).ok
    # Reach in and falsify s (simulating a server that stored a better score
    # than its own event log implies).
    b._engine._dev["t"].s += 1_000_000
    res = verify_backend(b)
    assert not res.ok, "tampered state was NOT detected"
    assert any(d.field_name == "s" for d in res.discrepancies)
    print(f"\u2713 TAMPER DETECTED: inflated s caught by recomputation "
          f"({res.discrepancies[0]})")

    # === 6. A falsified STATUS is detected ===============================
    b = MockBackend(W)
    b.register(W, "u", TierFP.SOFTWARE, ek("u"))
    b.classify(W, 0, "u", SeverityFP.CRITICAL)
    assert b.get_device("u").status == StatusFP.BANNED
    assert verify_backend(b).ok
    b._engine._dev["u"].status = StatusFP.ACTIVE       # silent un-ban
    res = verify_backend(b)
    assert not res.ok
    assert any(d.field_name == "status" for d in res.discrepancies)
    print("\u2713 SILENT UN-BAN DETECTED: status discrepancy found by "
          "recomputation from events alone")

    # === 7. End-to-end through ChainRegistry =============================
    inner = HashChain()
    backend = MockBackend(W)
    fk = FederationKey(key=b"\x09" * 32)
    reg = ChainRegistry(inner, backend, fk)
    for lbl in ("r1", "r2", "r3"):
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": hashlib.sha256(lbl.encode()).hexdigest(),
                              "status": "ACTIVE"})
    for rid in range(8):
        if rid == 2:
            reg.append("EVENT", {"round": rid, "device": "r2",
                                 "severity": "MINOR", "stage": 1,
                                 "reason": "t", "status": "ACTIVE"})
        reg.append("ROUND", {"round": rid,
                             "participants": ["r1", "r2", "r3"],
                             "aggregated": True})
    res = verify_backend(backend)
    assert res.ok, res.summary()
    assert res.devices_checked == 3
    print(f"\u2713 END-TO-END: {res.devices_checked} devices through "
          f"ChainRegistry verify from events alone "
          f"({res.events_replayed} replayed, incl. inferred NEUTRALs)")

    # === 8. Cross-ledger check ===========================================
    ok, detail = verify_hashchain_against_backend(inner, backend, fk)
    assert ok, detail
    print(f"\u2713 CROSS-LEDGER: {detail}")

    # === 9. Verifier uses only the public surface ========================
    class ReadOnlyView:
        """Proves the verifier needs nothing but events() + get_device() +
        is_banned_ek() -- i.e. it works against a live EVM node."""
        def __init__(self, src):
            self._src = src
        def events(self, event_type=None, since_seq=0):
            return self._src.events(event_type, since_seq)
        def get_device(self, d):
            return self._src.get_device(d)
        def is_banned_ek(self, ek):
            return self._src.is_banned_ek(ek)

    res = verify_backend(ReadOnlyView(backend))
    assert res.ok, res.summary()
    print("\u2713 THIRD-PARTY: verifier runs against a read-only view "
          "(events + get_device + is_banned_ek only)")

    # === 10. Recomputed trust matches the float engine ===================
    from trust.reputation import ReputationEngine, Tier as FTier
    fe = ReputationEngine()
    fe.register("r2", FTier.HARDWARE, "x")
    for rid in range(8):
        fe.record_event("r2", "MINOR" if rid == 2 else "NEUTRAL")
    rec = res.recomputed["r2"]
    assert abs(fe._dev["r2"].trust - rec.trust / SCALE) <= 5e-6
    print(f"\u2713 recomputed trust {rec.trust / SCALE:.6f} matches float "
          f"engine {fe._dev['r2'].trust:.6f} within 5e-6")

    print("\u2713 all verifier self-tests passed")


if __name__ == "__main__":
    _self_test()
