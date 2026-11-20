"""
chain/mock.py

Deterministic in-memory implementation of chain.backend.Backend. Serves three
distinct purposes:

  1. CI / pipeline tests -- CI must never need a live node.
  2. Rule development -- every rejection rule is exercised here first, then
     the Solidity port must reproduce the same reverts under the same names.
  3. Reconciliation harness -- rebuild state from events alone, proving the
     verifier.py path before evm.py exists.

HOUSE STYLE: MockTPMSigner
-----------------------------------------------------------------------------
Like tpm/client.py MockTPMSigner, MockBackend is intentionally the SAME shape
as the real backend it stands in for, so tests written against it port
directly. Nothing about MockBackend should imply the mock; only the ctor and
one .is_mock property give it away.

DETERMINISM -- WHAT DIFFERS FROM audit/hashchain.py
-----------------------------------------------------------------------------
Two intentional divergences from audit/hashchain.py (which is what
registry.py adapts INTO):

  1. NO TIMESTAMPS in hashed bodies. The chain is meant to be REPLAYABLE:
     the same event sequence produces the same head hash on every run,
     across machines, across restarts. audit/hashchain.py hashes time.time()
     to attribute WHEN; this chain hashes ONLY WHAT and IN WHAT ORDER.

  2. Head-hash chain is over event bodies, not JSONL lines. The mock will
     later be checked against evm.py's on-chain event log, which has no
     concept of a JSON line.

Consequence: the chain head is a deterministic function of the event
sequence. `--check` reproducibility is preserved with the mock chain
enabled, unlike with the real chain (block numbers, gas, timestamps).

STATE STORAGE -- ONE PACKED WORD PER DEVICE PER ROUND (C2)
-----------------------------------------------------------------------------
DeviceFP.pack() (chain/fixedpoint.py) fits every device's full state into
208 bits; one 256-bit slot per device on chain. MockBackend stores the
unpacked form for read convenience, but at snapshot() time it emits the
packed word -- that value is exactly what the Solidity port will SSTORE.

  python3 -m chain.mock
"""
import hashlib
import json
from typing import Optional

from chain.backend import Backend, Event, ChainRejection, Reason
from chain.fixedpoint import (FixedEngine, DeviceFP, StatusFP, TierFP,
                              SeverityFP, DivergenceError)


VALID_OUTCOMES = {"REINSTATED", "EXTENDED", "PERMANENT_BAN"}


def _canon(obj) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. Bytes are hex-
    encoded (SortedDict-safe). Matches what a Solidity contract would emit
    via abi.encode; we do not need byte-identical layout since the on-chain
    log has its own encoding, but we DO need identical canonicalisation
    across every Python run."""
    def default(v):
        if isinstance(v, (bytes, bytearray)):
            return v.hex()
        if isinstance(v, (set, frozenset)):
            return sorted(v)
        raise TypeError(f"non-canonical type: {type(v).__name__}")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=default).encode()


def _link_hash(prev: bytes, seq: int, event_type: str, payload: dict) -> bytes:
    body = _canon({"seq": seq, "type": event_type, "payload": payload,
                   "prev": prev.hex()})
    return hashlib.sha256(body).digest()


class MockBackend(Backend):

    is_mock = True

    def __init__(self, writer: bytes, gate_enabled: bool = True,
                 m3_enabled: bool = True):
        if not isinstance(writer, (bytes, bytearray)) or len(writer) == 0:
            raise ValueError("writer must be non-empty bytes")
        self._writer = bytes(writer)
        self._engine = FixedEngine(gate_enabled=gate_enabled,
                                   m3_enabled=m3_enabled)
        self._events: list = []
        self._head: bytes = b"\x00" * 32
        self._last_round: int = -1
        self._round_closed = set()          # round_ids already round_summary'd
        # Whether an ENROLL was ever recorded per device, distinct from
        # engine state (the engine has no "device exists" concept for BANNED
        # via ek-collision -- see register() below).
        self._enrolled: dict = {}           # device_id -> tier
        # Devices whose probation was REINSTATED once already (per the
        # one-shot rehabilitation rule in trust/probation.py).
        self._rehab_used: set = set()
        self._available = True
        self._emit("GENESIS", {"chain_id": "mock", "version": 1})

    # ---- helpers -----------------------------------------------------------

    def _check_writer(self, writer: bytes):
        if writer != self._writer:
            raise ChainRejection(Reason.UNAUTHORIZED_WRITER)

    def _emit(self, event_type: str, payload: dict) -> Event:
        seq = len(self._events)
        h = _link_hash(self._head, seq, event_type, payload)
        ev = Event(seq=seq, event_type=event_type, payload=payload,
                   prev_hash=self._head, hash=h)
        self._events.append(ev)
        self._head = h
        return ev

    def _require_device(self, device_id: str):
        d = self._engine._dev.get(device_id)
        if d is None:
            raise ChainRejection(Reason.DEVICE_UNKNOWN, device_id)
        return d

    # ---- writes ------------------------------------------------------------

    def register(self, writer, device_id, tier, ek_hmac):
        self._check_writer(writer)

        # Case A: EK is on the ban list -> WHITEWASH_REJECTED, no device
        # record created. Registry receives BANNED and refuses local enroll.
        if self._engine.is_banned_ek_hmac(ek_hmac) if hasattr(
                self._engine, "is_banned_ek_hmac") else \
                (ek_hmac in self._engine.banned_ek_hmacs()):
            ev = self._emit("WHITEWASH_REJECTED",
                            {"device": device_id, "ek_hmac": ek_hmac.hex()})
            return (int(StatusFP.BANNED), ev)

        # Case B: device_id already registered. Same tier + same EK => the
        # server is retrying an idempotent enroll; return existing state.
        prior = self._enrolled.get(device_id)
        prior_dev = self._engine._dev.get(device_id)
        if prior is not None:
            if prior != int(tier):
                raise ChainRejection(
                    Reason.TIER_MUTATION,
                    f"{device_id}: {TierFP(prior).name} -> {TierFP(tier).name}")
            if prior_dev is not None and prior_dev.ek_hmac != ek_hmac:
                raise ChainRejection(
                    Reason.EK_REGISTERED,
                    f"{device_id} already registered with different EK")
            # idempotent re-enroll: no event, return existing status
            return (int(prior_dev.status), self._events[-1])

        # Case C: another device already claims this EK (and it's not banned)
        for did, d in self._engine._dev.items():
            if d.ek_hmac == ek_hmac and did != device_id:
                raise ChainRejection(
                    Reason.EK_REGISTERED,
                    f"ek_hmac already registered to {did}")

        # Case D: fresh registration
        try:
            status = self._engine.register(device_id, tier, ek_hmac)
        except DivergenceError as e:
            # Should not fire in Case D but defense in depth
            raise ChainRejection(Reason.TIER_MUTATION, str(e))
        self._enrolled[device_id] = int(tier)
        ev = self._emit("ENROLL", {"device": device_id, "tier": int(tier),
                                   "ek_hmac": ek_hmac.hex(),
                                   "status": int(status)})
        return (int(status), ev)

    def classify(self, writer, round_id, device_id, severity,
                 stage=0, reason=""):
        self._check_writer(writer)
        d = self._require_device(device_id)
        if d.status == StatusFP.BANNED:
            raise ChainRejection(Reason.DEVICE_BANNED, device_id)
        if round_id <= self._last_round:
            raise ChainRejection(
                Reason.STALE_ROUND,
                f"round {round_id} <= last committed {self._last_round}")

        prev_status = d.status
        new_status = self._engine.record_event(device_id, severity,
                                               round_id=round_id)
        payload = {"round": round_id, "device": device_id,
                   "severity": int(severity), "stage": int(stage),
                   "reason": str(reason), "status": int(new_status)}
        ev = self._emit("EVENT", payload)

        # Cascade: if the classify caused a ban, emit BAN too
        if prev_status != StatusFP.BANNED and new_status == StatusFP.BANNED:
            self._emit("BAN", {"round": round_id, "device": device_id,
                               "ek_hmac": d.ek_hmac.hex()
                               if d.ek_hmac else None})
        return (int(new_status), ev)

    def enter_probation(self, writer, round_id, device_id):
        self._check_writer(writer)
        d = self._require_device(device_id)
        if d.status != StatusFP.PROBATION:
            raise ChainRejection(
                Reason.NOT_ON_PROBATION,
                f"{device_id} in status {d.status.name}, expected PROBATION")
        if device_id in self._rehab_used:
            # A previously-reinstated device that re-entered probation must
            # go through exhaust_probation, not enter_probation.
            raise ChainRejection(
                Reason.NOT_ON_PROBATION,
                f"{device_id} already used its one-shot rehabilitation; "
                "call exhaust_probation")
        return self._emit("PROBATION_ENTER",
                          {"round": round_id, "device": device_id})

    def exhaust_probation(self, writer, round_id, device_id):
        self._check_writer(writer)
        d = self._require_device(device_id)
        if device_id not in self._rehab_used:
            raise ChainRejection(
                Reason.NOT_ON_PROBATION,
                f"{device_id} has not used its rehabilitation yet")
        # Mirror trust/probation.py: emit REHAB_EXHAUSTED and force a BAN
        rehab = self._emit("REHAB_EXHAUSTED",
                           {"round": round_id, "device": device_id,
                            "ek_hmac": d.ek_hmac.hex() if d.ek_hmac else None})
        # Drive the ban through the rule (record_event CRITICAL)
        self._engine.record_event(device_id, SeverityFP.CRITICAL,
                                  round_id=round_id)
        ban = self._emit("BAN", {"round": round_id, "device": device_id,
                                 "ek_hmac": d.ek_hmac.hex()
                                 if d.ek_hmac else None})
        return (int(StatusFP.BANNED), [rehab, ban])

    def probation_decision(self, writer, round_id, device_id, outcome):
        self._check_writer(writer)
        d = self._require_device(device_id)
        if outcome not in VALID_OUTCOMES:
            raise ChainRejection(Reason.OUTCOME_INVALID, outcome)
        if d.status != StatusFP.PROBATION:
            raise ChainRejection(
                Reason.NOT_ON_PROBATION,
                f"{device_id} in status {d.status.name}")
        ev = self._emit("PROBATION_DECISION",
                        {"round": round_id, "device": device_id,
                         "outcome": outcome})
        events = [ev]

        if outcome == "REINSTATED":
            self._engine.reinstate(device_id, trial_rounds=0)
            self._rehab_used.add(device_id)
        elif outcome == "PERMANENT_BAN":
            self._engine.record_event(device_id, SeverityFP.CRITICAL,
                                      round_id=round_id)
            events.append(self._emit(
                "BAN", {"round": round_id, "device": device_id,
                        "ek_hmac": d.ek_hmac.hex() if d.ek_hmac else None}))
        # EXTENDED: no state change on chain, just the record.
        return (int(self._engine.get_status(device_id)), events)

    def round_summary(self, writer, round_id, participants_hash, aggregated,
                      local_head):
        self._check_writer(writer)
        if round_id in self._round_closed:
            raise ChainRejection(Reason.DUPLICATE_ROUND, str(round_id))
        # Round summary must not be older than the last committed one, but
        # equal to _last_round is allowed if it's the round currently being
        # classified (i.e. classify(round_id) was called this round).
        if round_id < self._last_round:
            raise ChainRejection(
                Reason.STALE_ROUND,
                f"summary for {round_id} < last {self._last_round}")
        # Must have seen at least one classify for this round, else nothing
        # to summarise. This is the "no empty round" check.
        seen = any(e.event_type == "EVENT"
                   and e.payload.get("round") == round_id
                   for e in self._events)
        if not seen and round_id != 0:
            # round 0 is allowed to be empty (a warm-up round with no active
            # devices); later rounds must have activity to be summarised.
            raise ChainRejection(Reason.ROUND_UNKNOWN, str(round_id))
        ev = self._emit("ROUND", {"round": round_id,
                                  "participants_hash": participants_hash.hex(),
                                  "aggregated": bool(aggregated),
                                  "local_head": local_head.hex()})
        self._round_closed.add(round_id)
        self._last_round = max(self._last_round, round_id)
        return ev

    # ---- reads -------------------------------------------------------------

    def get_device(self, device_id):
        d = self._engine._dev.get(device_id)
        if d is None:
            return None
        # Return an unpacked copy so callers cannot mutate our state
        return DeviceFP.unpack(d.pack(), device_id=device_id,
                               ek_hmac=d.ek_hmac)

    def is_banned_ek(self, ek_hmac):
        return ek_hmac in self._engine.banned_ek_hmacs()

    def last_round(self):
        return self._last_round

    def events(self, event_type=None, since_seq=0):
        if event_type is None:
            return [e for e in self._events if e.seq >= since_seq]
        return [e for e in self._events
                if e.event_type == event_type and e.seq >= since_seq]

    def head_hash(self):
        return self._head

    def snapshot(self):
        return {
            "devices": {i: d.pack() for i, d in self._engine._dev.items()},
            "banned_eks": {ek.hex() for ek in self._engine.banned_ek_hmacs()},
            "last_round": self._last_round,
            "head": self._head.hex(),
            "seq": len(self._events),
            "rehab_used": set(self._rehab_used),
        }

    def is_available(self):
        return self._available

    # ---- test hooks --------------------------------------------------------

    def _force_unavailable(self, on: bool):
        """Test-only: simulate a node outage. EvmBackend will set this on
        JSON-RPC timeouts."""
        self._available = not on


# ---- self-test ---------------------------------------------------------------

def _self_test():
    print("chain/mock.py self-test")

    W = b"server-key-32-bytes-xxxxxxxxxxxx"
    OTHER = b"someone-else-xxxxxxxxxxxxxxxxxxx"

    # === 1. Basic enrollment + one classify ================================
    b = MockBackend(W)
    ek = b"ek_alpha"
    status, ev = b.register(W, "alpha", TierFP.HARDWARE, ek)
    assert status == int(StatusFP.ACTIVE)
    assert ev.event_type == "ENROLL"
    assert len(b.events("ENROLL")) == 1
    print("\u2713 register(): ACTIVE, ENROLL emitted")

    status, ev = b.classify(W, 0, "alpha", SeverityFP.NEUTRAL)
    assert status == int(StatusFP.ACTIVE) and ev.event_type == "EVENT"
    print("\u2713 classify(): NEUTRAL, EVENT emitted, status unchanged")

    # === 2. Six rejection rules ============================================
    # 2a. UNAUTHORIZED_WRITER
    try:
        b.classify(OTHER, 1, "alpha", SeverityFP.NEUTRAL)
        raise AssertionError("unauthorized writer accepted")
    except ChainRejection as e:
        assert e.reason == Reason.UNAUTHORIZED_WRITER
    print("\u2713 REJECT: non-server writer -> UnauthorizedWriter")

    # 2b. BAN_TO_ACTIVE via re-registration attempt
    # Ban alpha via CRITICAL, then try to re-register with new EK
    b.classify(W, 1, "alpha", SeverityFP.CRITICAL)
    assert b.get_device("alpha").status == StatusFP.BANNED
    ek_fresh = b"ek_alpha_fresh"
    # Re-registering same device_id with a different EK is a TIER-agnostic
    # BAN_TO_ACTIVE attempt (the device_id is banned, EK doesn't matter).
    # Our engine refuses via BANNED-absorbing register(); the mock surfaces
    # this as EK_REGISTERED because the engine slot is still there. Either
    # way, the write must not succeed.
    try:
        b.register(W, "alpha", TierFP.HARDWARE, ek_fresh)
        # If we got here, the status MUST still be BANNED (no resurrection)
        assert b.get_device("alpha").status == StatusFP.BANNED
        print("\u2713 REJECT: re-registering banned device_id with new EK "
              "does not resurrect (status remains BANNED)")
    except ChainRejection as e:
        assert e.reason in (Reason.BAN_TO_ACTIVE, Reason.EK_REGISTERED)
        print(f"\u2713 REJECT: re-registering banned device_id -> {e.reason}")

    # 2c. TIER_MUTATION
    b2 = MockBackend(W)
    b2.register(W, "beta", TierFP.TPM_RESIDENT, b"ek_beta")
    try:
        b2.register(W, "beta", TierFP.HARDWARE, b"ek_beta")
        raise AssertionError("tier mutation accepted")
    except ChainRejection as e:
        assert e.reason == Reason.TIER_MUTATION
    print("\u2713 REJECT: tier change after enrollment -> TierMutation")

    # 2d. DUPLICATE_ROUND and STALE_ROUND
    b3 = MockBackend(W)
    b3.register(W, "g", TierFP.HARDWARE, b"ek_g")
    b3.classify(W, 0, "g", SeverityFP.NEUTRAL)
    b3.round_summary(W, 0, hashlib.sha256(b"g").digest(), True, b"\x00" * 32)
    try:
        b3.round_summary(W, 0, hashlib.sha256(b"g").digest(), True,
                         b"\x00" * 32)
        raise AssertionError("duplicate round accepted")
    except ChainRejection as e:
        assert e.reason == Reason.DUPLICATE_ROUND
    print("\u2713 REJECT: round_summary same round_id twice -> DuplicateRound")

    try:
        b3.classify(W, 0, "g", SeverityFP.NEUTRAL)   # stale
        raise AssertionError("stale round classify accepted")
    except ChainRejection as e:
        assert e.reason == Reason.STALE_ROUND
    print("\u2713 REJECT: classify with round_id <= last -> StaleRound")

    # 2e. EK_REGISTERED (whitewash via server-fabricated duplicate)
    b4 = MockBackend(W)
    b4.register(W, "d1", TierFP.HARDWARE, b"ek_shared")
    try:
        b4.register(W, "d2", TierFP.HARDWARE, b"ek_shared")
        raise AssertionError("duplicate EK accepted")
    except ChainRejection as e:
        assert e.reason == Reason.EK_REGISTERED
    print("\u2713 REJECT: two device_ids claiming one EK -> EkAlreadyRegistered")

    # 2f. WHITEWASH_REJECTED (banned EK returning under new label)
    b4.classify(W, 0, "d1", SeverityFP.CRITICAL)
    assert b4.get_device("d1").status == StatusFP.BANNED
    status, ev = b4.register(W, "d1_v2", TierFP.HARDWARE, b"ek_shared")
    assert status == int(StatusFP.BANNED)
    assert ev.event_type == "WHITEWASH_REJECTED"
    assert b4.get_device("d1_v2") is None      # no device record created
    print("\u2713 WHITEWASH: banned EK under new label -> WHITEWASH_REJECTED, "
          "no device record created")

    # === 3. Probation lifecycle ============================================
    b5 = MockBackend(W)
    b5.register(W, "hw", TierFP.HARDWARE, b"ek_hw")
    for r in range(3):
        b5.classify(W, r, "hw", SeverityFP.MAJOR)
    d = b5.get_device("hw")
    assert d.status == StatusFP.PROBATION, f"expected PROBATION, got {d.status}"
    b5.enter_probation(W, 3, "hw")
    b5.probation_decision(W, 10, "hw", "REINSTATED")
    assert b5.get_device("hw").status == StatusFP.ACTIVE
    print("\u2713 PROBATION: T1 -> 3 MAJOR -> PROBATION -> REINSTATED -> ACTIVE")

    # Re-offend: must go through exhaust_probation, not enter_probation
    for r in range(11, 14):
        b5.classify(W, r, "hw", SeverityFP.MAJOR)
    assert b5.get_device("hw").status == StatusFP.PROBATION
    try:
        b5.enter_probation(W, 14, "hw")
        raise AssertionError("enter_probation after rehab used should revert")
    except ChainRejection as e:
        assert e.reason == Reason.NOT_ON_PROBATION
    status, evs = b5.exhaust_probation(W, 14, "hw")
    assert status == int(StatusFP.BANNED)
    assert [e.event_type for e in evs] == ["REHAB_EXHAUSTED", "BAN"]
    print("\u2713 REHAB EXHAUSTED: re-offense after REINSTATED -> BAN "
          "(one-shot rehabilitation, per trust/probation.py)")

    # === 4. Determinism: same event sequence -> same head hash =============
    def scripted(seed_writer):
        b = MockBackend(seed_writer)
        b.register(seed_writer, "a", TierFP.HARDWARE, b"ek_a")
        b.register(seed_writer, "b", TierFP.TPM_RESIDENT, b"ek_b")
        b.classify(seed_writer, 0, "a", SeverityFP.NEUTRAL)
        b.classify(seed_writer, 0, "b", SeverityFP.MINOR)
        b.round_summary(seed_writer, 0,
                        hashlib.sha256(b"a|b").digest(), True, b"L0" + b"\x00" * 30)
        return b

    h1 = scripted(W).head_hash()
    h2 = scripted(W).head_hash()
    assert h1 == h2, "head hash not deterministic across runs"
    print(f"\u2713 DETERMINISM: same sequence -> same head hash "
          f"({h1[:8].hex()}...)")

    # Different writer key -> different head (writer is not in the hash,
    # so this actually should MATCH -- writer changes only which writes are
    # accepted, not what gets hashed. Confirm that invariant.)
    h3 = scripted(OTHER).head_hash()
    assert h3 == h1, "writer should not affect head hash"
    print("\u2713 head hash independent of writer identity (writer gates "
          "acceptance, not content)")

    # === 5. Reconciliation: rebuild from events ============================
    b_orig = scripted(W)
    # Now simulate a fresh MockBackend, replay events, verify snapshots match
    b_replay = MockBackend(W)
    # Replay by calling the same API in the same order. This mimics what
    # registry.py + verifier.py will do at startup.
    b_replay.register(W, "a", TierFP.HARDWARE, b"ek_a")
    b_replay.register(W, "b", TierFP.TPM_RESIDENT, b"ek_b")
    b_replay.classify(W, 0, "a", SeverityFP.NEUTRAL)
    b_replay.classify(W, 0, "b", SeverityFP.MINOR)
    b_replay.round_summary(W, 0, hashlib.sha256(b"a|b").digest(), True,
                           b"L0" + b"\x00" * 30)
    s1 = b_orig.snapshot()
    s2 = b_replay.snapshot()
    assert s1["devices"] == s2["devices"], "device state divergence"
    assert s1["banned_eks"] == s2["banned_eks"]
    assert s1["last_round"] == s2["last_round"]
    assert s1["head"] == s2["head"]
    print("\u2713 RECONCILIATION: replay of event sequence rebuilds identical "
          "snapshot (devices, bans, last_round, head)")

    # === 6. Ban survives "restart" =========================================
    b6 = MockBackend(W)
    b6.register(W, "victim", TierFP.HARDWARE, b"ek_v")
    b6.classify(W, 0, "victim", SeverityFP.CRITICAL)
    assert b6.get_device("victim").status == StatusFP.BANNED
    snap = b6.snapshot()

    # "Restart": build a fresh backend, replay from the event log
    b6_new = MockBackend(W)
    for e in b6.events()[1:]:              # skip GENESIS
        et = e.event_type
        p = e.payload
        if et == "ENROLL":
            b6_new.register(W, p["device"], p["tier"],
                            bytes.fromhex(p["ek_hmac"]))
        elif et == "EVENT":
            b6_new.classify(W, p["round"], p["device"], p["severity"],
                            stage=p["stage"], reason=p["reason"])
        # BAN is a cascade, not a user call -> emitted automatically
    snap2 = b6_new.snapshot()
    assert snap["devices"] == snap2["devices"]
    assert snap["banned_eks"] == snap2["banned_eks"]
    print("\u2713 BAN survives restart: fresh backend + event replay -> "
          "victim still BANNED, ek_v still on ban list")

    # And a whitewash after restart still fires
    status, ev = b6_new.register(W, "victim_v2", TierFP.HARDWARE, b"ek_v")
    assert status == int(StatusFP.BANNED)
    assert ev.event_type == "WHITEWASH_REJECTED"
    print("\u2713 post-restart whitewash: banned EK still rejected under new label")

    # === 7. Availability toggle (degradation path) ==========================
    b7 = MockBackend(W)
    assert b7.is_available() is True
    b7._force_unavailable(True)
    assert b7.is_available() is False
    # writes still work at the mock level (unavailability is a signal to the
    # registry, not an enforced block -- the registry chooses to degrade)
    b7._force_unavailable(False)
    print("\u2713 is_available toggle: registry.py can detect degradation")

    # === 8. Snapshot packed word is one slot ===============================
    b8 = MockBackend(W)
    b8.register(W, "x", TierFP.HARDWARE, b"ek_x")
    for r in range(3):
        b8.classify(W, r, "x", SeverityFP.NEUTRAL)
    packed = b8.snapshot()["devices"]["x"]
    assert packed.bit_length() <= 208, \
        f"packed word too large: {packed.bit_length()} bits"
    print(f"\u2713 STORAGE: packed device state = {packed.bit_length()} bits "
          f"(<= 208, fits one 256-bit SSTORE slot with 48 bits spare)")

    # === 9. Genesis emitted at construction =================================
    b9 = MockBackend(W)
    assert len(b9.events()) == 1 and b9.events()[0].event_type == "GENESIS"
    assert b9.events()[0].prev_hash == b"\x00" * 32
    print("\u2713 GENESIS emitted at construction (prev_hash = zeros)")

    print("\u2713 all mock backend self-tests passed")


if __name__ == "__main__":
    _self_test()
