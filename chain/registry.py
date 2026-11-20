"""
chain/registry.py

The HashChain-compatible adapter. Drops into FederatedServer(audit=...) with
ZERO changes to fl/server.py.

    from audit.hashchain import HashChain
    from chain.registry import ChainRegistry
    from chain.mock import MockBackend
    from chain.keys import FederationKey

    reg = ChainRegistry(HashChain(path="results/audit.jsonl"),
                        MockBackend(writer=b"..."),
                        FederationKey(path="results/federation.key"))
    server = FederatedServer(..., audit=reg)

It exposes exactly the HashChain surface (append, entries, verify,
head_hash, __len__) and forwards every call to the inner chain FIRST, so
the local audit log is byte-identical to what it would be with chain off.
It then MIRRORS the semantic meaning of each event onto a chain Backend.

THE NEUTRAL PROBLEM -- AND WHY WE BUFFER
-----------------------------------------------------------------------------
fl/server.py line 113 reads:

    if self.audit and cls.severity != "NEUTRAL":
        self.audit.append("EVENT", ...)

NEUTRAL classifications are NEVER appended. But NEUTRAL is exactly what
decays s, increments clean_run, and (at clean_run >= FORGIVE_AFTER) decays
f. A chain backend fed only non-NEUTRAL events would diverge immediately.

We do not modify fl/server.py. Instead we BUFFER each round and infer:

    ROUND payload carries {"participants": sorted(updates), ...}
    any participant with no EVENT this round WAS NEUTRAL

The inference is exact, not heuristic: the server classifies every
participant, and appends an EVENT for every non-NEUTRAL classification.
The complement is precisely the NEUTRAL set.

ORDERING
-----------------------------------------------------------------------------
Cross-device order is irrelevant (the reputation engine is per-device
independent). Per-device order is preserved because buffered events keep
their arrival order, and inferred NEUTRALs only apply to devices with NO
other event that round.

Proof that no device gets both an inferred NEUTRAL and a transition event:
PROBATION_ENTER fires only on ACTIVE -> PROBATION. Under the rule, NEUTRAL
raises s, lowers f, and zeroes major_run -- it cannot cross the backstop,
M3, or probation threshold in the sanctioning direction. So a device that
transitions in a round necessarily has a logged (non-NEUTRAL) EVENT.

DRIVERS VS CONSEQUENCES
-----------------------------------------------------------------------------
Some hashchain events are CAUSES that we dispatch; others are EFFECTS the
backend already emits as a cascade. Dispatching an effect would double-count.

  driver      -> backend call
  ---------------------------------------------------
  ENROLL      -> register()
  EVENT       -> classify()
  (inferred)  -> classify(NEUTRAL)
  PROBATION_ENTER   -> enter_probation()
  REHAB_EXHAUSTED   -> exhaust_probation()
  PROBATION_DECISION-> probation_decision()
  ROUND       -> round_summary()

  consequence -> IGNORED (backend cascades it)
  ---------------------------------------------------
  BAN                 (classify/decision emits Ban)
  WHITEWASH_REJECTED  (register emits WhitewashRejected)

NEVER ON THE CRITICAL PATH
-----------------------------------------------------------------------------
Every mirror call is wrapped. A ChainRejection, an RPC timeout, or any
other exception:
  - is recorded in self.rejections / self.failures (loudly, with detail)
  - marks the round UNANCHORED
  - does NOT propagate

This is a hard requirement from the spec: a stalled round breaks the live
demo. The enforcement value is not lost -- a rejection is a LOUD, counted,
inspectable event -- but it never halts training.

Callers can assert on rejections in tests:
    assert reg.rejections[-1].reason == Reason.BAN_TO_ACTIVE

  python3 -m chain.registry
"""
import hashlib
from dataclasses import dataclass, field
from typing import Optional

from chain.backend import Backend, ChainRejection, Reason
from chain.fixedpoint import SeverityFP, StatusFP, TierFP


# Events the backend cascades on its own -- dispatching them would double-count.
CONSEQUENCE_EVENTS = {"BAN", "WHITEWASH_REJECTED"}

# Round-scoped events we buffer until ROUND arrives.
BUFFERED_EVENTS = {"EVENT", "BAN", "PROBATION_ENTER", "REHAB_EXHAUSTED",
                   "PROBATION_DECISION"}

TIER_BY_NAME = {t.name: t for t in TierFP}
SEVERITY_BY_NAME = {s.name: s for s in SeverityFP}


@dataclass
class Rejection:
    """A chain write the contract refused. This is the enforcement signal."""
    seq: int
    round_id: Optional[int]
    event_type: str
    reason: str
    detail: str

    def __str__(self):
        r = f"r{self.round_id}" if self.round_id is not None else "enroll"
        return f"[{r}] {self.event_type} -> {self.reason}: {self.detail}"


@dataclass
class Failure:
    """A chain write that failed for a non-rule reason (node down, timeout).
    Distinguished from Rejection because the remedy differs: a Rejection
    means the server tried something illegal; a Failure means the chain was
    unavailable."""
    seq: int
    round_id: Optional[int]
    event_type: str
    error: str


@dataclass
class RoundBuffer:
    round_id: int
    items: list = field(default_factory=list)      # (event_type, payload)


def participants_hash(participants) -> bytes:
    """SHA256 over the sorted, newline-joined participant labels. Stable and
    order-independent."""
    joined = "\n".join(sorted(participants)).encode()
    return hashlib.sha256(joined).digest()


class ChainRegistry:
    """HashChain-compatible facade that mirrors trust events onto a chain."""

    def __init__(self, inner, backend: Backend, fed_key, writer=None,
                 strict=False, verbose=False,
                 async_writes=False, async_queue=4096):
        """
        inner    : an audit.hashchain.HashChain (or anything with the same
                   append/entries/verify/head_hash surface). Required -- the
                   local log is never bypassed.
        backend  : a chain.backend.Backend (MockBackend or EvmBackend).
        fed_key  : a chain.keys.FederationKey, for ek_hash -> ek_hmac.
        writer   : the authorized writer identity. Defaults to the backend's
                   own writer when it exposes one (MockBackend does).
        strict   : if True, re-raise ChainRejection instead of recording it.
                   FOR TESTS ONLY. Production must leave this False; the spec
                   forbids the chain being on the critical path.
        verbose  : print rejections as they happen.
        """
        if inner is None:
            raise ValueError("inner HashChain is required (never bypass the "
                             "local audit log)")
        self.inner = inner
        self.backend = backend
        self.fed_key = fed_key
        self.writer = writer if writer is not None \
            else getattr(backend, "_writer", None)
        if self.writer is None:
            raise ValueError("writer identity could not be determined; "
                             "pass writer=...")
        self.strict = strict
        self.verbose = verbose

        self.rejections: list = []
        self.failures: list = []
        self.unanchored_rounds: set = set()
        self.anchored_rounds: set = set()

        self._ek_by_device: dict = {}          # label -> raw ek_hash
        self._tier_by_device: dict = {}        # label -> TierFP
        self._buf: Optional[RoundBuffer] = None
        self._mirrored = 0                     # successful backend writes

        # Optional background writer. OFF by default, so every existing
        # parity, latency and gas result is reproduced by exactly the code
        # that produced it. ON, ledger writes leave the training thread and
        # the round no longer waits on block time -- which is what makes the
        # "never on the critical path" claim true in wall clock and not just
        # in structure. See chain/async_writer.py.
        self._writer_thread = None
        if async_writes:
            from chain.async_writer import AsyncWriter
            self._writer_thread = AsyncWriter(
                max_queue=async_queue,
                on_result=self._on_async_result).start()

    # ==== HashChain surface ================================================

    def append(self, event_type, payload):
        """Forward to the inner chain first (so the local log is unchanged),
        then mirror onto the chain backend."""
        entry = self.inner.append(event_type, payload)
        try:
            self._mirror(event_type, payload, entry.get("seq", -1))
        except ChainRejection:
            raise                              # only reachable when strict
        except Exception as exc:                # never break the round
            self._record_failure(entry.get("seq", -1), event_type, exc)
        return entry

    def entries(self, event_type=None):
        return self.inner.entries(event_type)

    def verify(self):
        return self.inner.verify()

    def head_hash(self):
        return self.inner.head_hash()

    def __len__(self):
        return len(self.inner)

    # ==== mirroring ========================================================

    def _mirror(self, event_type, payload, seq):
        if event_type in CONSEQUENCE_EVENTS:
            return                             # backend cascades these

        if event_type == "ENROLL":
            self._dispatch_enroll(payload, seq)
            return

        if event_type in BUFFERED_EVENTS:
            rid = payload.get("round")
            if self._buf is None or self._buf.round_id != rid:
                # A new round started without a ROUND close for the previous
                # one (server crash mid-round, or round 0). Flush what we
                # have as unanchored, then open a fresh buffer.
                if self._buf is not None:
                    self.unanchored_rounds.add(self._buf.round_id)
                self._buf = RoundBuffer(round_id=rid)
            self._buf.items.append((event_type, payload))
            return

        if event_type == "ROUND":
            self._flush_round(payload, seq)
            return

        # GENESIS or an unrecognised type: nothing semantic to mirror.

    def _dispatch_enroll(self, payload, seq):
        label = payload["device"]
        ek_hash = payload["ek_hash"]
        tier = TIER_BY_NAME.get(payload["tier"])
        if tier is None:
            self._record_failure(seq, "ENROLL",
                                 ValueError(f"unknown tier {payload['tier']!r}"))
            return
        self._ek_by_device[label] = ek_hash
        self._tier_by_device[label] = tier
        ek_hmac = self.fed_key.ek_hmac(ek_hash)
        self._guard(seq, None, "ENROLL",
                    lambda: self.backend.register(self.writer, label,
                                                  int(tier), ek_hmac))

    def _flush_round(self, round_payload, seq):
        rid = round_payload["round"]
        participants = round_payload.get("participants", [])
        aggregated = bool(round_payload.get("aggregated", False))

        buf = self._buf if (self._buf and self._buf.round_id == rid) \
            else RoundBuffer(round_id=rid)
        self._buf = None

        ok = True
        # Set once a read fails, so the rest of the flush stops probing a
        # chain that has already proved unreachable. Without it a round with
        # n participants pays n timeouts instead of one.
        self._reads_down = False

        try:
            # 1. Inferred NEUTRALs: participants with no EVENT this round.
            had_event = {p for (t, p_) in buf.items if t == "EVENT"
                         for p in (p_["device"],)}
            for label in sorted(set(participants) - had_event):
                readable, dev = self._device_state(label, seq, rid)
                if not readable:
                    # Could not establish whether this device is enrolled or
                    # banned. Skipping the write is the safe direction -- a
                    # blind classify against unknown state risks a revert we
                    # would then have to explain -- but the round is no longer
                    # fully anchored and must say so.
                    ok = False
                    continue
                if dev is None:
                    continue                   # never enrolled on chain
                if dev.status == StatusFP.BANNED:
                    continue                   # backend refuses post-ban writes
                ok &= self._guard(
                    seq, rid, "EVENT(inferred NEUTRAL)",
                    lambda l=label: self.backend.classify(
                        self.writer, rid, l, SeverityFP.NEUTRAL,
                        stage=0, reason="inferred"))

            # 2. Buffered events in arrival order.
            for etype, p in buf.items:
                if etype in CONSEQUENCE_EVENTS:
                    continue
                ok &= self._dispatch_buffered(etype, p, seq, rid)

            # 3. Close the round.
            local_head = self._local_head_bytes()
            ok &= self._guard(
                seq, rid, "ROUND",
                lambda: self.backend.round_summary(
                    self.writer, rid, participants_hash(participants),
                    aggregated, local_head))
        except Exception as exc:                # noqa: BLE001
            # Anything escaping the guards is a failure of THIS round, not a
            # reason to lose track of it.
            self._record_failure(seq, "ROUND", exc, rid)
            ok = False
        finally:
            # A round must land in exactly one of the two sets. It previously
            # could land in NEITHER: the unguarded get_device() reads above
            # raised TransportError during an outage, which aborted the flush
            # before this line and left the round invisible to report().
            # Training survived -- append() catches everything -- but the
            # round was counted as neither anchored nor unanchored, so the
            # outage looked smaller than it was.
            (self.anchored_rounds if ok else self.unanchored_rounds).add(rid)
            self._reads_down = False

    def _device_state(self, label, seq, rid):
        """(readable, device_or_None).

        Reads are part of the mirroring path and can fail exactly like writes,
        so they get the same treatment: recorded, not raised.
        """
        if getattr(self, "_reads_down", False):
            return False, None
        try:
            return True, self.backend.get_device(label)
        except ChainRejection as exc:
            self.rejections.append(Rejection(
                seq=seq, round_id=rid, event_type="READ(get_device)",
                reason=exc.reason, detail=exc.detail))
            return False, None
        except Exception as exc:                # noqa: BLE001
            self._reads_down = True
            self._record_failure(seq, "READ(get_device)", exc, rid)
            return False, None

    def _dispatch_buffered(self, etype, p, seq, rid):
        label = p["device"]
        if etype == "EVENT":
            sev = SEVERITY_BY_NAME.get(p["severity"])
            if sev is None:
                self._record_failure(
                    seq, etype, ValueError(f"unknown severity {p['severity']!r}"))
                return False
            return self._guard(
                seq, rid, etype,
                lambda: self.backend.classify(
                    self.writer, rid, label, sev,
                    stage=int(p.get("stage", 0) or 0),
                    reason=str(p.get("reason", ""))))

        if etype == "PROBATION_ENTER":
            return self._guard(
                seq, rid, etype,
                lambda: self.backend.enter_probation(self.writer, rid, label))

        if etype == "REHAB_EXHAUSTED":
            return self._guard(
                seq, rid, etype,
                lambda: self.backend.exhaust_probation(self.writer, rid, label))

        if etype == "PROBATION_DECISION":
            return self._guard(
                seq, rid, etype,
                lambda: self.backend.probation_decision(
                    self.writer, rid, label, p["outcome"]))
        return True

    def _local_head_bytes(self) -> bytes:
        try:
            h = self.inner.head_hash()
            return bytes.fromhex(h) if isinstance(h, str) else bytes(h)
        except Exception:
            return b"\x00" * 32

    # ==== error handling ===================================================

    def _on_async_result(self, res):
        """Drain a background write's outcome back into the SAME bookkeeping
        a synchronous write uses, so an asynchronous failure is exactly as
        visible: the round is unanchored and the error is in .failures.

        Note the asymmetry that follows and is unavoidable: with async writes
        a round is provisionally counted anchored at submission and demoted
        when the write comes back failed. anchored_rounds is therefore only
        final after drain_chain_writes(). Callers that report before draining
        would overstate anchoring, which is why run_local drains first."""
        if res.ok:
            self._mirrored += 1
            return
        self.anchored_rounds.discard(res.round_id)
        exc = res.error
        if isinstance(exc, ChainRejection):
            self.rejections.append(Rejection(
                seq=res.seq, round_id=res.round_id, event_type=res.event_type,
                reason=exc.reason, detail=exc.detail))
            if res.round_id is not None:
                self.unanchored_rounds.add(res.round_id)
        else:
            self._record_failure(res.seq, res.event_type, exc, res.round_id)

    def drain_chain_writes(self, timeout=120):
        """Wait for the backlog. Returns True if it cleared.

        The one place blocking on the ledger is correct: training is over and
        what is being waited for is auditability.
        """
        if self._writer_thread is None:
            return True
        return self._writer_thread.drain(timeout=timeout)

    def stop_chain_writes(self, timeout=5.0):
        if self._writer_thread is not None:
            self._writer_thread.stop(timeout=timeout)

    def _guard(self, seq, rid, etype, fn) -> bool:
        """Run a backend write. Record and swallow rule rejections and
        transport failures. Returns True on success."""
        if self._writer_thread is not None:
            # Optimistic: assume it will land, demote in _on_async_result if
            # it does not. Returning False here instead would mark every round
            # unanchored on a healthy chain.
            return self._writer_thread.submit(seq, rid, etype, fn)
        try:
            fn()
            self._mirrored += 1
            return True
        except ChainRejection as exc:
            rej = Rejection(seq=seq, round_id=rid, event_type=etype,
                            reason=exc.reason, detail=exc.detail)
            self.rejections.append(rej)
            if self.verbose:
                print(f"  \u26a0 CHAIN REJECTED {rej}")
            if rid is not None:
                self.unanchored_rounds.add(rid)
            if self.strict:
                raise
            return False
        except Exception as exc:
            self._record_failure(seq, etype, exc, rid)
            return False

    def _record_failure(self, seq, etype, exc, rid=None):
        f = Failure(seq=seq, round_id=rid, event_type=etype,
                    error=f"{type(exc).__name__}: {exc}")
        self.failures.append(f)
        if self.verbose:
            print(f"  \u26a0 CHAIN FAILURE [{etype}] {f.error}")
        if rid is not None:
            self.unanchored_rounds.add(rid)

    # ==== reporting ========================================================

    def report(self):
        """Never raises.

        It used to call head_hash() and last_round() unguarded, so reporting
        during an outage raised TransportError out of report() -- meaning a
        run in which training correctly survived a dead chain would end in a
        traceback at the reporting step, and read as a failure of the very
        claim it had just demonstrated. That is precisely the liveness
        experiment's condition, so the bug was worst exactly where it
        mattered.

        Unknown values are reported as None, never as a plausible-looking
        default: a zero head is not a head.
        """
        try:
            head = self.backend.head_hash().hex()
        except Exception:
            head = None
        try:
            last = self.backend.last_round()
        except Exception:
            last = None
        out = {
            "mirrored_writes": self._mirrored,
            "rejections": len(self.rejections),
            "failures": len(self.failures),
            "anchored_rounds": sorted(self.anchored_rounds),
            "unanchored_rounds": sorted(self.unanchored_rounds),
            "chain_head": head,
            "chain_reachable": head is not None,
            "backend_last_round": last,
        }
        if self._writer_thread is not None:
            out["async_writes"] = self._writer_thread.report()
        return out

    def is_banned_on_chain(self, ek_hash) -> bool:
        """Pre-enrollment check for run_server.py / run_local.py. Fails OPEN
        (returns False) when the chain is unavailable -- failing closed would
        hand an attacker a federation-wide DoS via the node."""
        try:
            if not self.backend.is_available():
                return False
            return self.backend.is_banned_ek(self.fed_key.ek_hmac(ek_hash))
        except Exception:
            return False


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import tempfile
    import os
    from audit.hashchain import HashChain
    from chain.mock import MockBackend
    from chain.keys import FederationKey

    print("chain/registry.py self-test")
    W = b"registry-writer-key-32-xxxxxxxxx"

    def build(strict=False):
        chain = HashChain()
        backend = MockBackend(W)
        fk = FederationKey(key=b"\x07" * 32)
        return ChainRegistry(chain, backend, fk, strict=strict)

    # === 1. HashChain surface is intact ====================================
    reg = build()
    reg.append("ENROLL", {"device": "a", "tier": "HARDWARE",
                          "ek_hash": "aa" * 32, "status": "ACTIVE"})
    ok, err = reg.verify()
    assert ok and err is None
    assert len(reg) == 2                            # GENESIS + ENROLL
    assert len(reg.entries("ENROLL")) == 1
    assert isinstance(reg.head_hash(), str)
    print("\u2713 HashChain surface intact: append/entries/verify/head_hash/len")

    # === 2. ENROLL mirrors to the chain ====================================
    dev = reg.backend.get_device("a")
    assert dev is not None and dev.status == StatusFP.ACTIVE
    assert dev.tier == TierFP.HARDWARE
    print("\u2713 ENROLL mirrored: device registered on chain with same tier")

    # === 3. ek_hash is NEVER written raw ===================================
    enroll_ev = [e for e in reg.backend.events("ENROLL")][0]
    on_chain_ek = enroll_ev.payload["ek_hmac"]
    assert on_chain_ek != "aa" * 32, "raw ek_hash leaked to chain!"
    assert on_chain_ek == reg.fed_key.ek_hmac("aa" * 32).hex()
    print("\u2713 PRIVACY: chain stores HMAC(fed_key, DOMAIN||ek_hash), "
          "never the raw EK hash")

    # === 4. THE NEUTRAL INFERENCE ==========================================
    # Two participants; only one gets an EVENT. The other must be inferred
    # NEUTRAL, or state diverges.
    reg = build()
    for lbl in ("p1", "p2"):
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": lbl.encode().hex() * 8,
                              "status": "ACTIVE"})
    # round 0: p1 MINOR (logged), p2 NEUTRAL (NOT logged by server.py)
    reg.append("EVENT", {"round": 0, "device": "p1", "severity": "MINOR",
                         "stage": 1, "reason": "t", "status": "ACTIVE"})
    reg.append("ROUND", {"round": 0, "participants": ["p1", "p2"],
                         "aggregated": True})
    d1 = reg.backend.get_device("p1")
    d2 = reg.backend.get_device("p2")
    assert d1.f == 600_000 and d1.s == 0, (d1.s, d1.f)      # MINOR
    assert d2.s == 400_000 and d2.f == 0, (d2.s, d2.f)      # inferred NEUTRAL
    assert d2.clean_run == 1
    print("\u2713 NEUTRAL INFERENCE: participant with no EVENT correctly "
          f"classified NEUTRAL (s={d2.s}, clean_run={d2.clean_run})")

    # === 5. Parity with the float engine over many rounds ==================
    from trust.reputation import ReputationEngine, Tier as FTier
    from chain.fixedpoint import SCALE
    reg = build()
    fe = ReputationEngine()
    labels = ["h1", "h2", "h3"]
    for lbl in labels:
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": hashlib.sha256(lbl.encode()).hexdigest(),
                              "status": "ACTIVE"})
        fe.register(lbl, FTier.HARDWARE,
                    hashlib.sha256(lbl.encode()).hexdigest())

    script = {                       # round -> {label: severity}
        0: {"h1": "NEUTRAL", "h2": "MINOR",   "h3": "NEUTRAL"},
        1: {"h1": "NEUTRAL", "h2": "NEUTRAL", "h3": "NEUTRAL"},
        2: {"h1": "MINOR",   "h2": "NEUTRAL", "h3": "NEUTRAL"},
        3: {"h1": "NEUTRAL", "h2": "NEUTRAL", "h3": "MINOR"},
        4: {"h1": "NEUTRAL", "h2": "NEUTRAL", "h3": "NEUTRAL"},
        5: {"h1": "NEUTRAL", "h2": "NEUTRAL", "h3": "NEUTRAL"},
    }
    for rid, sevs in script.items():
        for lbl, sev in sevs.items():
            fe.record_event(lbl, sev)
            if sev != "NEUTRAL":                 # mirror server.py's filter
                reg.append("EVENT", {"round": rid, "device": lbl,
                                     "severity": sev, "stage": 1,
                                     "reason": "t",
                                     "status": fe.get_status(lbl).value})
        reg.append("ROUND", {"round": rid, "participants": sorted(sevs),
                             "aggregated": True})

    for lbl in labels:
        fd = fe._dev[lbl]
        cd = reg.backend.get_device(lbl)
        assert abs(fd.trust - cd.trust / SCALE) <= 5e-6, (
            lbl, fd.trust, cd.trust / SCALE)
        assert fe.get_status(lbl).name == cd.status.name
    print("\u2713 PARITY over 6 rounds x 3 devices: chain trust matches float "
          "engine within 5e-6, statuses identical")

    # === 6. BAN cascade is not double-counted =============================
    reg = build()
    reg.append("ENROLL", {"device": "z", "tier": "SOFTWARE",
                          "ek_hash": "cc" * 32, "status": "ACTIVE"})
    reg.append("EVENT", {"round": 0, "device": "z", "severity": "CRITICAL",
                         "stage": 3, "reason": "poison", "status": "BANNED"})
    reg.append("BAN", {"round": 0, "device": "z", "ek_hash": "cc" * 32})
    reg.append("ROUND", {"round": 0, "participants": ["z"],
                         "aggregated": False})
    assert reg.backend.get_device("z").status == StatusFP.BANNED
    assert len(reg.backend.events("BAN")) == 1, "BAN double-counted"
    assert not reg.rejections, [str(r) for r in reg.rejections]
    print("\u2713 BAN cascade: server's explicit BAN append is not "
          "re-dispatched (exactly one Ban on chain)")

    # === 7. WHITEWASH: banned EK returning under a new label ==============
    status_before = reg.backend.is_banned_ek(reg.fed_key.ek_hmac("cc" * 32))
    assert status_before is True
    reg.append("ENROLL", {"device": "z_v2", "tier": "SOFTWARE",
                          "ek_hash": "cc" * 32, "status": "BANNED"})
    reg.append("WHITEWASH_REJECTED", {"device": "z_v2", "ek_hash": "cc" * 32})
    assert reg.backend.get_device("z_v2") is None
    assert len(reg.backend.events("WHITEWASH_REJECTED")) == 1
    assert reg.is_banned_on_chain("cc" * 32) is True
    print("\u2713 WHITEWASH: banned EK under new label -> chain refuses, "
          "is_banned_on_chain() True")

    # === 8. ENFORCEMENT: an illegal write is REJECTED, loudly ==============
    # This is the delta over the hash chain. Forge a resurrection: append an
    # ENROLL for a banned device with a fresh EK. The hash chain records it
    # without complaint; the registry catches the rejection.
    n_before = len(reg.rejections)
    reg.append("ENROLL", {"device": "z", "tier": "SOFTWARE",
                          "ek_hash": "dd" * 32, "status": "ACTIVE"})
    assert len(reg.rejections) == n_before + 1, "resurrection was NOT rejected"
    rej = reg.rejections[-1]
    assert rej.reason in (Reason.BAN_TO_ACTIVE, Reason.EK_REGISTERED), rej.reason
    # The local hash chain DID accept it -- that is the point.
    assert len(reg.entries("ENROLL")) == 3
    assert reg.verify()[0] is True
    # And the chain state is unchanged: still BANNED.
    assert reg.backend.get_device("z").status == StatusFP.BANNED
    print(f"\u2713 ENFORCEMENT DELTA: hash chain accepted the resurrection "
          f"write; chain REJECTED it ({rej.reason}) and state stayed BANNED")

    # === 9. Never on the critical path ====================================
    # A rejection must not raise, and the round must still close.
    reg = build()
    reg.append("ENROLL", {"device": "q", "tier": "HARDWARE",
                          "ek_hash": "ee" * 32, "status": "ACTIVE"})
    # Forge an out-of-order round: close 5, then classify at 3.
    reg.append("EVENT", {"round": 5, "device": "q", "severity": "MINOR",
                         "stage": 1, "reason": "t", "status": "ACTIVE"})
    reg.append("ROUND", {"round": 5, "participants": ["q"], "aggregated": True})
    reg.append("EVENT", {"round": 3, "device": "q", "severity": "MINOR",
                         "stage": 1, "reason": "t", "status": "ACTIVE"})
    reg.append("ROUND", {"round": 3, "participants": ["q"], "aggregated": True})
    stale = [r for r in reg.rejections if r.reason == Reason.STALE_ROUND]
    assert stale, [str(r) for r in reg.rejections]
    assert 3 in reg.unanchored_rounds and 5 in reg.anchored_rounds
    print("\u2713 NEVER-HALT: stale round rejected, no exception raised, "
          "round marked UNANCHORED (r3 unanchored, r5 anchored)")

    # === 10. strict=True re-raises (tests only) ===========================
    reg = build(strict=True)
    reg.append("ENROLL", {"device": "s1", "tier": "HARDWARE",
                          "ek_hash": "11" * 32, "status": "ACTIVE"})
    try:
        reg.append("ENROLL", {"device": "s2", "tier": "HARDWARE",
                              "ek_hash": "11" * 32, "status": "ACTIVE"})
        raise AssertionError("strict mode should have raised")
    except ChainRejection as e:
        assert e.reason == Reason.EK_REGISTERED
    print("\u2713 strict=True re-raises ChainRejection (test harness mode)")

    # === 11. Degradation when the backend is unavailable ==================
    reg = build()
    reg.append("ENROLL", {"device": "u", "tier": "HARDWARE",
                          "ek_hash": "ff" * 32, "status": "ACTIVE"})
    reg.backend._force_unavailable(True)
    assert reg.is_banned_on_chain("ff" * 32) is False      # fails OPEN
    reg.backend._force_unavailable(False)
    print("\u2713 AVAILABILITY: is_banned_on_chain fails OPEN when the chain "
          "is unavailable (no federation-wide DoS)")

    # === 12. Persistence: works with a real on-disk hashchain =============
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "audit.jsonl")
        chain = HashChain(path=p)
        backend = MockBackend(W)
        fk = FederationKey(path=os.path.join(d, "federation.key"))
        reg = ChainRegistry(chain, backend, fk)
        reg.append("ENROLL", {"device": "disk", "tier": "HARDWARE",
                              "ek_hash": "ab" * 32, "status": "ACTIVE"})
        reg.append("EVENT", {"round": 0, "device": "disk",
                             "severity": "MINOR", "stage": 1,
                             "reason": "t", "status": "ACTIVE"})
        reg.append("ROUND", {"round": 0, "participants": ["disk"],
                             "aggregated": True})
        assert os.path.exists(p)
        reloaded = HashChain(path=p)
        assert len(reloaded) == 4 and reloaded.verify()[0]
        rep = reg.report()
        assert rep["anchored_rounds"] == [0] and rep["rejections"] == 0
        # The ROUND anchor carries the local hashchain head.
        round_ev = reg.backend.events("ROUND")[0]
        assert len(round_ev.payload["local_head"]) == 64
        print("\u2713 PERSISTENCE: on-disk audit log verifies; ROUND event "
              "anchors the local hashchain head")

    # === 13. report() shape ===============================================
    r = reg.report()
    for k in ("mirrored_writes", "rejections", "failures", "anchored_rounds",
              "unanchored_rounds", "chain_head", "backend_last_round"):
        assert k in r, k
    print(f"\u2713 report(): {r['mirrored_writes']} mirrored writes, "
          f"{r['rejections']} rejections, head {r['chain_head'][:8]}...")

    print("\u2713 all registry self-tests passed")


if __name__ == "__main__":
    _self_test()
