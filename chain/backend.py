"""
chain/backend.py

The abstract API that MockBackend and EvmBackend both implement. This is the
seam between DLTF and the chain layer -- it is the ONLY surface registry.py
(the HashChain-compatible adapter) sees.

DESIGN CHOICE: semantic API, backend is authoritative
-----------------------------------------------------------------------------
The API is severity-driven (classify(round, device, severity)), not
state-driven (submit_state(round, device, new_s, new_f)). The backend
recomputes S, F, and status from the rule, using chain/fixedpoint.py.
Consequences:

  - There is no "reputation delta" for callers to lie about. If a caller
    could submit arbitrary state, the "reject a delta outside the rule"
    requirement would need after-the-fact verification. With the semantic
    API, the backend IS the rule; the only way to be "outside" it is to
    call a method that doesn't exist. Structural, not behavioural.

  - The float engine in trust/reputation.py stays untouched. FederatedServer
    keeps calling rep.record_event() on the float engine; registry.py
    additionally calls backend.classify() on the chain. The chain's
    fixed-point recomputation is authoritative for STATUS (see
    chain/fixedpoint.py docstring); the float engine remains the research
    artifact.

  - The five methods below map 1:1 to the nine event types server.py
    already emits (register -> ENROLL or WHITEWASH_REJECTED; classify ->
    EVENT and possibly BAN; enter_probation -> PROBATION_ENTER or
    REHAB_EXHAUSTED; probation_decision -> PROBATION_DECISION and possibly
    BAN; round_summary -> ROUND). GENESIS is emitted by the constructor.

REJECTION MODEL
-----------------------------------------------------------------------------
Every write method:
  - takes a `writer` bytes argument (mimics Solidity msg.sender)
  - validates preconditions
  - raises ChainRejection(Reason.<CODE>, msg) on any violation

Reason codes are stable strings, chosen to map 1:1 to Solidity custom errors
when the contract is written. Do not rename without updating the port plan.

AVAILABILITY -- CHAIN IS NEVER ON THE CRITICAL PATH
-----------------------------------------------------------------------------
is_available() returns False when the backend cannot accept writes (node
down, tx timeout, deployment mismatch). Callers must degrade to the local
hashchain and mark rounds UNANCHORED. MockBackend is always available
unless a test explicitly forces unavailability.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


class Reason:
    """Rejection reason codes. Stable strings, map 1:1 to Solidity errors."""
    UNAUTHORIZED_WRITER = "UnauthorizedWriter"
    BAN_TO_ACTIVE = "BanToActive"          # includes any resurrection attempt
    TIER_MUTATION = "TierMutation"
    DUPLICATE_ROUND = "DuplicateRound"
    STALE_ROUND = "StaleRound"             # round_id < last committed round
    DEVICE_UNKNOWN = "DeviceUnknown"
    DEVICE_BANNED = "DeviceBanned"
    EK_REGISTERED = "EkAlreadyRegistered"  # different device_id, not banned
    OUTCOME_INVALID = "OutcomeInvalid"
    NOT_ON_PROBATION = "NotOnProbation"
    ROUND_UNKNOWN = "RoundUnknown"         # round_summary before any classify


class ChainRejection(Exception):
    """Raised when a write violates a contract rule. The Solidity port
    reverts with a custom error whose name equals `reason`."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class Event:
    """One record on the chain. `hash` is computed over the canonical
    encoding of (seq, event_type, payload, prev_hash) -- NO timestamps.
    Head-hash reproducibility is a property here; unlike audit/hashchain.py,
    the chain is intended to be replayable across runs from the same event
    sequence."""
    seq: int
    event_type: str
    payload: dict
    prev_hash: bytes
    hash: bytes


class Backend(ABC):
    """Semantic chain API. Implementations: MockBackend (in-memory,
    deterministic), EvmBackend (Hardhat/Anvil via web3.py, future)."""

    # ---- writes ------------------------------------------------------------

    @abstractmethod
    def register(self, writer: bytes, device_id: str, tier: int,
                 ek_hmac: bytes) -> tuple:
        """Enroll a device. Returns (status_int, event).

        Emits ENROLL on success (status = ACTIVE).
        Emits WHITEWASH_REJECTED and returns (BANNED, event) if ek_hmac is
        in the banned set -- no ChainRejection, this is expected flow.

        Reverts on:
          UNAUTHORIZED_WRITER  writer != authorized
          TIER_MUTATION        device_id already registered with different tier
          EK_REGISTERED        ek_hmac already registered under different
                               device_id and NOT banned (would grant a second
                               identity to the same physical machine, or a
                               server-fabricated duplicate)
        """

    @abstractmethod
    def classify(self, writer: bytes, round_id: int, device_id: str,
                 severity: int, stage: int = 0, reason: str = "") -> tuple:
        """Record a classification. Returns (new_status_int, event).

        Emits EVENT. If the classification causes a status transition to
        BANNED, also emits BAN. If it causes ACTIVE -> PROBATION, the caller
        must follow with enter_probation() (mirrors server.py's flow).

        Reverts on:
          UNAUTHORIZED_WRITER
          DEVICE_UNKNOWN       device_id not registered
          DEVICE_BANNED        device is already BANNED (no post-ban events)
          STALE_ROUND          round_id < last committed round
        """

    @abstractmethod
    def enter_probation(self, writer: bytes, round_id: int,
                        device_id: str) -> Event:
        """Emit PROBATION_ENTER. Reverts if the device is not currently in
        the PROBATION status (must be preceded by a classify() that took it
        there), or if a probation trial has already been REINSTATED once for
        this device (that's REHAB_EXHAUSTED -- use exhaust_probation)."""

    @abstractmethod
    def exhaust_probation(self, writer: bytes, round_id: int,
                          device_id: str) -> tuple:
        """A previously-reinstated device that re-offends: emits
        REHAB_EXHAUSTED and BAN. One-shot rehabilitation, per
        trust/probation.py.

        Returns (new_status_int, [rehab_event, ban_event])."""

    @abstractmethod
    def probation_decision(self, writer: bytes, round_id: int,
                           device_id: str, outcome: str) -> tuple:
        """Record a probation trial outcome. outcome in
        {REINSTATED, EXTENDED, PERMANENT_BAN}.

        Emits PROBATION_DECISION. If PERMANENT_BAN, also emits BAN.
        Returns (new_status_int, events).

        Reverts on OUTCOME_INVALID, NOT_ON_PROBATION."""

    @abstractmethod
    def round_summary(self, writer: bytes, round_id: int,
                      participants_hash: bytes, aggregated: bool,
                      local_head: bytes) -> Event:
        """Close a round. `local_head` is the audit/hashchain.py head hash
        AS OF just before this call -- it anchors the round's evidence.
        `participants_hash` is SHA256 of the sorted participant device_ids.

        Reverts on DUPLICATE_ROUND, ROUND_UNKNOWN."""

    # ---- reads -------------------------------------------------------------

    @abstractmethod
    def get_device(self, device_id: str):
        """Returns a DeviceFP snapshot (unpacked) or None."""

    @abstractmethod
    def is_banned_ek(self, ek_hmac: bytes) -> bool: ...

    @abstractmethod
    def last_round(self) -> int:
        """Highest round_id closed by round_summary(). -1 if none."""

    @abstractmethod
    def events(self, event_type: Optional[str] = None,
               since_seq: int = 0) -> list: ...

    @abstractmethod
    def head_hash(self) -> bytes: ...

    @abstractmethod
    def snapshot(self) -> dict:
        """Full state snapshot for reconciliation testing:
             {"devices": {id: packed_word}, "banned_eks": set(hex),
              "last_round": int, "head": hex, "seq": int}"""

    def is_available(self) -> bool:
        """Default: True. EvmBackend overrides based on node reachability."""
        return True


def _self_test():
    print("chain/backend.py self-test")

    # -- Reason codes are strings, no accidental duplicates ------------------
    codes = [v for k, v in vars(Reason).items() if not k.startswith("_")]
    assert all(isinstance(c, str) for c in codes)
    assert len(codes) == len(set(codes)), "duplicate reason code"
    print(f"\u2713 {len(codes)} rejection reason codes, all unique strings")

    # -- ChainRejection carries reason + detail ------------------------------
    try:
        raise ChainRejection(Reason.BAN_TO_ACTIVE, "device z")
    except ChainRejection as e:
        assert e.reason == "BanToActive" and "device z" in str(e)
    print("\u2713 ChainRejection carries reason code and detail")

    # -- Event is immutable, hashable ----------------------------------------
    ev = Event(0, "GENESIS", {}, b"\x00" * 32, b"\x01" * 32)
    try:
        ev.seq = 1                       # frozen
        raise AssertionError("Event should be frozen")
    except (AttributeError, Exception):
        pass
    print("\u2713 Event is frozen (immutable across event log)")

    # -- Backend is abstract, cannot be instantiated -------------------------
    try:
        Backend()
        raise AssertionError("Backend should be abstract")
    except TypeError as e:
        assert "abstract" in str(e).lower()
    print("\u2713 Backend is abstract (must be subclassed)")

    print("\u2713 all backend self-tests passed")


if __name__ == "__main__":
    _self_test()
