"""
chain/reconcile.py

Rebuild a live ReputationEngine from persisted state after a server restart.
This is what makes N23 real: bans survive the process dying.

WHY TWO SOURCES
-----------------------------------------------------------------------------
Neither ledger alone is sufficient, and the split is not arbitrary:

  chain backend   AUTHORITATIVE for the numbers. s, f, clean_run, major_run,
                  status and tier are recomputed from the emitted event log by
                  chain/verifier.py::replay_events(). They are authoritative
                  precisely because the contract REJECTED any write that broke
                  the lifecycle -- a rebuilt engine inherits that enforcement.

  local audit log AUTHORITATIVE for raw EK hashes. The chain never stores them:
                  it stores ek_hmac = HMAC(fed_key, "DLTF-EKv1|" || ek_hash),
                  which is one-way by design (§8, EK privacy).

The consequence is load-bearing. ReputationEngine.register() decides O2 by
testing `ek_hash in self._banned_ek`, where ek_hash is the RAW hex string the
handle presents at enrollment. Seeding _banned_ek with HMAC digests would
silently defeat whitewash rejection: the set would be non-empty, every lookup
would miss, and every banned device would re-enroll ACTIVE. So the ban set is
rebuilt from the local log's ENROLL/BAN payloads, which carry ek_hash raw.

  scalars + status  <- chain      (enforced, tamper-evident)
  raw ek_hash       <- audit log  (private, never leaves the host)

FIXED -> FLOAT
-----------------------------------------------------------------------------
The chain holds integers at SCALE = 1e6. reputation.py holds floats. The
conversion is exact for every value the rule can produce EXCEPT where decay()
truncated, and the proven bound there is |T_float - T_fixed| <= 5e-6 with zero
measured status divergence (see chain/fixedpoint.py self-test). We take the
FIXED value as authoritative and divide, so the rebuilt engine matches the
chain rather than re-accumulating float error from a replay.

reputation.py IS A STRICT BLACK BOX
-----------------------------------------------------------------------------
No edits. We use the public register() to create each Device with correct
tier and ek_hash (and therefore correct O2 wiring), then patch the scalar
fields on the returned records -- the same _dev-patching pattern the shipped
self-tests already use.

  python3 -m chain.reconcile
"""
from dataclasses import dataclass, field

from chain.fixedpoint import SCALE, StatusFP, TierFP
from chain.verifier import replay_events
from trust.reputation import ReputationEngine, Status, Tier


# Enum bridges. Kept explicit rather than by-value so a future ABI reordering
# on either side is a loud KeyError, not a silent mis-mapping.
TIER_FP_TO_FLOAT = {TierFP.HARDWARE: Tier.HARDWARE,
                    TierFP.TPM_RESIDENT: Tier.TPM_RESIDENT,
                    TierFP.SOFTWARE: Tier.SOFTWARE}

STATUS_FP_TO_FLOAT = {StatusFP.ACTIVE: Status.ACTIVE,
                      StatusFP.PROBATION: Status.PROBATION,
                      StatusFP.BANNED: Status.BANNED}

TIER_BY_NAME = {t.name: t for t in Tier}


@dataclass
class ReconcileReport:
    """What the rebuild actually recovered. Printed by run_local.py and
    asserted on by the tests."""
    devices: int = 0
    banned: int = 0
    probation: int = 0
    active: int = 0
    events_replayed: int = 0
    rounds_seen: int = 0
    banned_eks: int = 0
    unknown_events: list = field(default_factory=list)
    missing_on_chain: list = field(default_factory=list)
    missing_locally: list = field(default_factory=list)

    @property
    def ok(self):
        return not (self.unknown_events or self.missing_on_chain
                    or self.missing_locally)

    def summary(self):
        head = (f"rebuilt from chain: {self.devices} devices "
                f"({self.active} active, {self.probation} probation, "
                f"{self.banned} banned), {self.events_replayed} events "
                f"replayed, {self.banned_eks} banned EKs")
        if self.ok:
            return head
        lines = [head]
        if self.unknown_events:
            lines.append(f"  unknown events: {sorted(set(self.unknown_events))}")
        if self.missing_on_chain:
            lines.append(f"  enrolled locally but absent on chain: "
                         f"{self.missing_on_chain}")
        if self.missing_locally:
            lines.append(f"  on chain but absent locally: "
                         f"{self.missing_locally}")
        return "\n".join(lines)


def _enrollments_from_log(inner):
    """label -> {tier, ek_hash}, last ENROLL wins.

    A re-enrollment of a banned device appends a second ENROLL with the same
    raw ek_hash; taking the last is correct because tier is immutable on
    chain, so both records agree on tier by construction."""
    out = {}
    for e in inner.entries("ENROLL"):
        p = e["payload"]
        out[p["device"]] = {"tier": p["tier"], "ek_hash": p["ek_hash"]}
    return out


def _banned_eks_from_log(inner):
    """Raw EK hashes that the local log says are banned.

    Two sources, unioned:
      BAN                 explicit ban at classification time
      WHITEWASH_REJECTED  a return attempt, which implies the EK was already
                          banned (and covers a log whose BAN predates the
                          current file, e.g. after rotation)
    """
    banned = set()
    for t in ("BAN", "WHITEWASH_REJECTED"):
        for e in inner.entries(t):
            ek = e["payload"].get("ek_hash")
            if ek:
                banned.add(ek)
    return banned


def rebuild_engine(backend, inner, params=None):
    """Reconstruct a ReputationEngine. Returns (engine, ReconcileReport).

    backend : a chain.backend.Backend (MockBackend or EvmBackend). Read via
              the public surface only: events(), get_device(), is_banned_ek().
    inner   : the local audit.hashchain.HashChain, for raw ek_hash recovery.
    params  : optional trust.reputation.Params, forwarded to the new engine.
    """
    fixed, replayed, unknown = replay_events(backend.events())

    engine = ReputationEngine(params) if params is not None else ReputationEngine()
    report = ReconcileReport(events_replayed=replayed,
                             unknown_events=list(unknown))

    enrollments = _enrollments_from_log(inner)
    log_banned = _banned_eks_from_log(inner)

    # --- 1. Seed the ban set BEFORE registering ------------------------------
    # Order matters: register() consults _banned_ek to decide O2. Seeding
    # first means a returning banned identity is re-banned by the engine's
    # own rule rather than by our patch, which keeps the black box honest.
    engine._banned_ek |= log_banned

    # --- 2. Register every device the local log knows about ------------------
    for label, meta in enrollments.items():
        tier = TIER_BY_NAME.get(meta["tier"])
        if tier is None:
            report.unknown_events.append(f"unknown tier {meta['tier']!r}")
            continue
        engine.register(label, tier, meta["ek_hash"])

    # --- 3. Overwrite scalar state with the chain's authoritative values -----
    for label, fdev in fixed._dev.items():
        if label not in engine._dev:
            # On chain but never enrolled locally: the audit log is short a
            # record. Register from chain-side tier so the device still
            # exists, but flag it -- we have no raw ek_hash for it, so its
            # O2 binding is unrecoverable from this pair of ledgers.
            report.missing_locally.append(label)
            engine.register(label, TIER_FP_TO_FLOAT[fdev.tier], None)

        d = engine._dev[label]
        d.s = fdev.s / SCALE
        d.f = fdev.f / SCALE
        d.clean_run = int(fdev.clean_run)
        d.major_run = int(fdev.major_run)
        d.status = STATUS_FP_TO_FLOAT[fdev.status]
        d.tier = TIER_FP_TO_FLOAT[fdev.tier]

        # A device the chain says is BANNED contributes its EK to the ban set
        # even if the local log's BAN line is missing. The chain is
        # authoritative for status; the log is authoritative for the hash.
        if d.status == Status.BANNED and d.ek_hash is not None:
            engine._banned_ek.add(d.ek_hash)

    # --- 4. Devices enrolled locally that the chain never saw ----------------
    # Typically a round that was rejected or went UNANCHORED. They stay
    # registered at ACTIVE with zero evidence, which is the correct
    # conservative reading: no chain evidence means no chain-proven sanction.
    for label in enrollments:
        if label not in fixed._dev:
            report.missing_on_chain.append(label)

    # --- 5. Tally ------------------------------------------------------------
    report.devices = len(engine._dev)
    report.banned_eks = len(engine._banned_ek)
    for d in engine._dev.values():
        if d.status == Status.BANNED:
            report.banned += 1
        elif d.status == Status.PROBATION:
            report.probation += 1
        else:
            report.active += 1
    report.rounds_seen = len({e.payload.get("round")
                              for e in backend.events("ROUND")})
    return engine, report


def rebuild_from_registry(registry, params=None):
    """Convenience wrapper: pull both ledgers straight off a ChainRegistry."""
    return rebuild_engine(registry.backend, registry.inner, params=params)


def rebuild_enrolled_map(inner, engine):
    """Reconstruct FederatedServer.enrolled from the local log + engine.

    A fresh FederatedServer starts with enrolled = {}, and run_round() filters
    participants on `h.device_label in self.enrolled`. Without this the
    rebuilt server would silently drop EVERY client and quietly train on
    nothing, which looks like success. Shape matches fl/server.py exactly:

        {label: {"tier": Tier, "ek_hash": str, "status": Status}}
    """
    out = {}
    for label, meta in _enrollments_from_log(inner).items():
        tier = TIER_BY_NAME.get(meta["tier"])
        if tier is None or label not in engine._dev:
            continue
        out[label] = {"tier": tier,
                      "ek_hash": meta["ek_hash"],
                      "status": engine.get_status(label)}
    return out


def restore_server(server, engine, inner):
    """Install a rebuilt engine into a fresh FederatedServer, including the
    enrollment map and the probation manager's engine reference."""
    server.rep = engine
    server.enrolled = rebuild_enrolled_map(inner, engine)
    if getattr(server, "probation", None) is not None:
        server.probation.rep = engine
    return server


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import hashlib
    from audit.hashchain import HashChain
    from chain.mock import MockBackend
    from chain.keys import FederationKey
    from chain.registry import ChainRegistry
    from chain.verifier import verify_backend

    print("chain/reconcile.py self-test")
    W = b"reconcile-writer-key-32-xxxxxxxx"

    def ekh(label):
        return hashlib.sha256(label.encode()).hexdigest()

    def build():
        return ChainRegistry(HashChain(), MockBackend(W),
                             FederationKey(key=b"\x11" * 32))

    # === 1. Round-trip: a clean federation rebuilds exactly ================
    reg = build()
    labels = ["h1", "h2", "h3"]
    for lbl in labels:
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": ekh(lbl), "status": "ACTIVE"})
    for rid in range(6):
        reg.append("ROUND", {"round": rid, "participants": labels,
                             "aggregated": True})

    engine, rep = rebuild_engine(reg.backend, reg.inner)
    assert rep.ok, rep.summary()
    assert rep.devices == 3 and rep.active == 3 and rep.banned == 0
    assert rep.rounds_seen == 6
    for lbl in labels:
        assert engine.get_status(lbl) == Status.ACTIVE
        assert engine._dev[lbl].clean_run == 6
    print(f"\u2713 clean rebuild: {rep.devices} devices, {rep.events_replayed} "
          f"events replayed, all ACTIVE with clean_run=6")

    # === 2. Rebuilt scalars match the chain within the proven bound ========
    for lbl in labels:
        chain_dev = reg.backend.get_device(lbl)
        assert abs(engine._dev[lbl].s - chain_dev.s / SCALE) < 1e-12
        assert abs(engine._dev[lbl].f - chain_dev.f / SCALE) < 1e-12
        assert abs(engine._dev[lbl].trust - chain_dev.trust / SCALE) <= 5e-6
    print("\u2713 scalar fidelity: s/f exact after /SCALE, trust within the "
          "proven 5e-6 fixed-point bound")

    # === 3. Rebuilt engine matches a LIVE engine fed the same events =======
    # The real parity check: run a float engine alongside, then confirm the
    # rebuild lands in the same place.
    reg = build()
    live = ReputationEngine()
    for lbl in labels:
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": ekh(lbl), "status": "ACTIVE"})
        live.register(lbl, Tier.HARDWARE, ekh(lbl))
    script = {0: {"h2": "MINOR"}, 1: {}, 2: {"h1": "MINOR"},
              3: {"h3": "MAJOR"}, 4: {}, 5: {}}
    for rid, sevs in script.items():
        for lbl in labels:
            sev = sevs.get(lbl, "NEUTRAL")
            live.record_event(lbl, sev)
            if sev != "NEUTRAL":
                reg.append("EVENT", {"round": rid, "device": lbl,
                                     "severity": sev, "stage": 1,
                                     "reason": "t",
                                     "status": live.get_status(lbl).value})
        reg.append("ROUND", {"round": rid, "participants": labels,
                             "aggregated": True})

    rebuilt, rep = rebuild_engine(reg.backend, reg.inner)
    assert rep.ok, rep.summary()
    for lbl in labels:
        assert rebuilt.get_status(lbl) == live.get_status(lbl)
        assert abs(rebuilt._dev[lbl].trust - live._dev[lbl].trust) <= 5e-6
        assert rebuilt._dev[lbl].clean_run == live._dev[lbl].clean_run
        assert rebuilt._dev[lbl].major_run == live._dev[lbl].major_run
    print("\u2713 PARITY: rebuilt engine matches a live engine field-for-field "
          "(status, trust within 5e-6, clean_run, major_run)")

    # === 4. THE POINT: a ban survives the restart =========================
    reg = build()
    reg.append("ENROLL", {"device": "atk", "tier": "SOFTWARE",
                          "ek_hash": ekh("atk"), "status": "ACTIVE"})
    reg.append("EVENT", {"round": 0, "device": "atk", "severity": "CRITICAL",
                         "stage": 3, "reason": "poison", "status": "BANNED"})
    reg.append("BAN", {"round": 0, "device": "atk", "ek_hash": ekh("atk")})
    reg.append("ROUND", {"round": 0, "participants": ["atk"],
                         "aggregated": False})

    rebuilt, rep = rebuild_engine(reg.backend, reg.inner)
    assert rebuilt.get_status("atk") == Status.BANNED
    assert rebuilt.get_weight("atk") == 0.0
    assert ekh("atk") in rebuilt.banned_ek_hashes()
    assert rep.banned == 1
    print("\u2713 N23: BANNED status and zero weight survive the rebuild")

    # === 5. WHITEWASH after restart is rejected by the REBUILT engine =====
    # The attacker returns under a fresh label with the same silicon. The
    # rebuilt engine must re-ban it at register() -- via the engine's own O2
    # rule, using the RAW ek_hash recovered from the local log.
    status = rebuilt.register("atk_v2", Tier.SOFTWARE, ekh("atk"))
    assert status == Status.BANNED, status
    assert rebuilt.get_weight("atk_v2") == 0.0
    print("\u2713 O2 ACROSS RESTART: banned EK re-enrolling under a NEW label "
          "is rejected by the rebuilt engine")

    # === 6. The ban set holds RAW hashes, not HMACs ========================
    # Regression guard for the bug this module exists to avoid. If _banned_ek
    # were seeded from the chain's ban set it would contain HMAC digests,
    # every raw lookup would miss, and case 5 would silently pass ACTIVE.
    ek_hmac = reg.fed_key.ek_hmac(ekh("atk"))
    assert ekh("atk") in rebuilt._banned_ek
    assert ek_hmac.hex() not in rebuilt._banned_ek
    assert ek_hmac not in rebuilt._banned_ek
    # and the chain independently agrees the HMAC is banned
    assert reg.backend.is_banned_ek(ek_hmac) is True
    print("\u2713 PRIVACY SPLIT: engine ban set holds RAW ek_hash (O2 works); "
          "chain ban set holds only the HMAC (EK never on chain)")

    # === 7. Probation state survives ======================================
    reg = build()
    reg.append("ENROLL", {"device": "hw", "tier": "HARDWARE",
                          "ek_hash": ekh("hw"), "status": "ACTIVE"})
    for rid in range(3):
        reg.append("EVENT", {"round": rid, "device": "hw", "severity": "MAJOR",
                             "stage": 2, "reason": "t", "status": "ACTIVE"})
        reg.append("ROUND", {"round": rid, "participants": ["hw"],
                             "aggregated": True})
    assert reg.backend.get_device("hw").status == StatusFP.PROBATION
    rebuilt, rep = rebuild_engine(reg.backend, reg.inner)
    assert rebuilt.get_status("hw") == Status.PROBATION
    assert rep.probation == 1
    # PROBATION caps weight at d3 = 0.1
    assert rebuilt.get_weight("hw") <= 0.1
    print("\u2713 PROBATION survives the rebuild (status + 0.1 weight cap)")

    # === 8. Reinstatement replays correctly ================================
    reg.append("PROBATION_ENTER", {"round": 3, "device": "hw"})
    reg.append("PROBATION_DECISION", {"round": 3, "device": "hw",
                                      "outcome": "REINSTATED"})
    reg.append("ROUND", {"round": 3, "participants": ["hw"],
                         "aggregated": True})
    rebuilt, rep = rebuild_engine(reg.backend, reg.inner)
    assert rebuilt.get_status("hw") == Status.ACTIVE
    assert rebuilt._dev["hw"].trust >= 0.75 - 5e-6
    print("\u2713 REINSTATED replays: back to ACTIVE at/above the 0.75 floor")

    # === 9. Tier is preserved (drives REHAB and the weight cap) ============
    reg = build()
    for lbl, tier in (("t1", "HARDWARE"), ("t2", "TPM_RESIDENT"),
                      ("t3", "SOFTWARE")):
        reg.append("ENROLL", {"device": lbl, "tier": tier,
                              "ek_hash": ekh(lbl), "status": "ACTIVE"})
    reg.append("ROUND", {"round": 0, "participants": ["t1", "t2", "t3"],
                         "aggregated": True})
    rebuilt, _ = rebuild_engine(reg.backend, reg.inner)
    assert rebuilt._dev["t1"].tier == Tier.HARDWARE
    assert rebuilt._dev["t2"].tier == Tier.TPM_RESIDENT
    assert rebuilt._dev["t3"].tier == Tier.SOFTWARE
    # the discount vector follows the tier, so weights must differ
    w = {l: rebuilt.get_weight(l) for l in ("t1", "t2", "t3")}
    assert w["t1"] > w["t2"] > w["t3"], w
    print(f"\u2713 tier preserved: weights track D = 1.0/0.5/0.1 ({w})")

    # === 10. rebuild_from_registry convenience wrapper =====================
    e2, r2 = rebuild_from_registry(reg)
    assert r2.devices == 3 and r2.ok
    assert e2._dev["t1"].tier == Tier.HARDWARE
    print("\u2713 rebuild_from_registry() pulls both ledgers off a "
          "ChainRegistry")

    # === 11. The rebuilt engine is a WORKING engine, not a snapshot ========
    # It must keep classifying correctly after the restart.
    before = e2._dev["t1"].trust
    e2.record_event("t1", "NEUTRAL")
    assert e2._dev["t1"].trust > before
    e2.record_event("t3", "MAJOR")
    e2.record_event("t3", "MAJOR")
    assert e2.get_status("t3") == Status.BANNED      # M3, no rehab on Tier 3
    print("\u2713 LIVE AFTER REBUILD: engine keeps applying the rule "
          "(NEUTRAL raises trust, M3 bans a Tier-3 attacker)")

    # === 12. Rebuild does not disturb the chain ============================
    assert verify_backend(reg.backend).ok
    print("\u2713 read-only: verifier still reports 0 discrepancies after "
          "reconciliation")

    # === 13. Missing-ledger asymmetry is reported, not silently swallowed ==
    reg = build()
    # Simulate a chain write that never landed (node down at enrollment):
    # the LOCAL log records it, the chain event log never sees it.
    reg.inner.append("ENROLL", {"device": "only_local", "tier": "HARDWARE",
                                "ek_hash": ekh("only_local"),
                                "status": "ACTIVE"})
    engine, rep = rebuild_engine(reg.backend, reg.inner)
    assert "only_local" in rep.missing_on_chain
    assert not rep.ok
    # It is still registered, conservatively, at ACTIVE with zero evidence:
    # absence of chain evidence is not evidence of a sanction.
    assert engine.get_status("only_local") == Status.ACTIVE
    assert engine._dev["only_local"].s == 0.0
    print("\u2713 asymmetry surfaced: device in the local log but absent on "
          "chain is REPORTED, not silently dropped")

    # === 14. rebuild_enrolled_map restores the participant filter ==========
    # Without this a rebuilt server drops every client from run_round() and
    # trains on nothing while looking healthy.
    reg = build()
    for lbl, tier in (("e1", "HARDWARE"), ("e2", "SOFTWARE")):
        reg.append("ENROLL", {"device": lbl, "tier": tier,
                              "ek_hash": ekh(lbl), "status": "ACTIVE"})
    reg.append("ROUND", {"round": 0, "participants": ["e1", "e2"],
                         "aggregated": True})
    engine, _ = rebuild_engine(reg.backend, reg.inner)
    emap = rebuild_enrolled_map(reg.inner, engine)
    assert set(emap) == {"e1", "e2"}
    assert emap["e1"]["tier"] == Tier.HARDWARE
    assert emap["e1"]["ek_hash"] == ekh("e1")
    assert emap["e2"]["status"] == Status.ACTIVE
    # shape must match what fl/server.py writes at enroll()
    assert set(emap["e1"]) == {"tier", "ek_hash", "status"}
    print("\u2713 rebuild_enrolled_map: participant filter restored with the "
          "exact shape fl/server.py writes")

    # === 15. restore_server installs engine + map + probation reference =====
    from fl.server import FederatedServer
    fresh = FederatedServer([0.0] * 4)
    assert fresh.enrolled == {}
    restore_server(fresh, engine, reg.inner)
    assert set(fresh.enrolled) == {"e1", "e2"}
    assert fresh.rep is engine
    assert fresh.probation.rep is engine
    assert fresh.rep.get_status("e1") == Status.ACTIVE
    print("\u2713 restore_server: engine, enrolled map and probation manager "
          "all point at the rebuilt state")

    print("\u2713 all reconcile self-tests passed")


if __name__ == "__main__":
    _self_test()
