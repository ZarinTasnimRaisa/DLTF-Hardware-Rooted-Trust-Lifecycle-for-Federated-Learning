"""
tools/prove_it_works.py

    PYTHONPATH=. python3 tools/prove_it_works.py

WHY THIS EXISTS, AND WHY IT IS NOT test_pipeline.py
-----------------------------------------------------------------------------
A passing test suite proves the code does not crash. It does not prove the
system does what you think, because a test can pass VACUOUSLY:

  - "chain recorded the round"        passes if the chain recorded NOTHING and
                                     the round was silently marked unanchored
  - "verifier found 0 discrepancies"  passes if the verifier is broken and
                                     always returns OK
  - "attackers were banned"           passes if EVERYTHING is banned, including
                                     honest clients
  - "trust survived the restart"      passes if trust was reset to a value that
                                     happens to look plausible
  - "banned EK was rejected"          passes if enrollment rejects EVERYONE

Every check below is therefore PAIRED with a negative control: a case that
MUST fail. If a positive check passes and its negative control ALSO passes,
the check is meaningless and this script says so.

The sharpest one is CHECK 7. It deliberately corrupts the chain and confirms
the verifier NOTICES. Without that, "0 discrepancies" is unfalsifiable.

Exit code 0 = every check passed AND every negative control failed as required.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np

from audit.hashchain import HashChain
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from tpm.client import make_signer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from trust.reputation import ReputationEngine, Status, Tier

from chain.keys import FederationKey
from chain.mock import MockBackend
from chain.reconcile import rebuild_engine, restore_server
from chain.registry import ChainRegistry
from chain.verifier import verify_backend

W = b"prove-it-works-writer-32-bytes-x!"
DIM, BULK = 16, [0, 1, 2]

PASS, FAIL = [], []


def ok(label, detail=""):
    PASS.append(label)
    print(f"  \u2713 {label}" + (f"\n      {detail}" if detail else ""))


def bad(label, detail=""):
    FAIL.append(label)
    print(f"  \u2717 {label}" + (f"\n      {detail}" if detail else ""))


def check(label, condition, detail=""):
    (ok if condition else bad)(label, detail)
    return bool(condition)


def honest(idx):
    def f(r, p):
        rng = np.random.default_rng(100 * r + idx)
        v = np.zeros(DIM)
        for k in BULK:
            v[k] = 1.0
        v = v / np.linalg.norm(v)
        return (v + 0.3 * rng.standard_normal(DIM)).tolist(), 64
    return f


def sybil(r, p):
    rng = np.random.default_rng(9000 + r)
    v = np.zeros(DIM); v[7] = v[8] = 1.0
    v = v / np.linalg.norm(v)
    return (v + 0.02 * rng.standard_normal(DIM)).tolist(), 64


def federation(n_honest, n_attackers=0, tier1=0):
    ca_pem = ca_key = ca_cert = None
    if tier1:
        ca_key, ca_cert = generate_test_ca()
        ca_pem = ca_bundle_pem(ca_cert)
    handles, signers = [], {}
    specs = [(f"h{k}", honest(k)) for k in range(n_honest)]
    specs += [(f"a{k}", sybil) for k in range(n_attackers)]
    for i, (label, trainer) in enumerate(specs):
        cert = None
        if i < tier1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        s = make_signer("mock", label, ek_cert_der=cert)
        signers[label] = s
        handles.append(LocalClientHandle(label, s, FLClient(label, trainer)))
    return handles, signers, ca_pem


def chain_stack(path=None):
    backend = MockBackend(W)
    reg = ChainRegistry(HashChain(path=path), backend,
                        FederationKey(key=b"\x5a" * 32), writer=W)
    return reg, backend


def run(server, handles, rounds, start=0):
    out = []
    for r in range(start, start + rounds):
        out.append(server.run_round(r, handles))
    return out


# =============================================================================

def check1_detection_fires_and_does_not_overfire():
    """Detection must catch attackers AND leave honest clients alone.
    A detector that flags everything is as useless as one that flags nothing."""
    print("\n[1] Detection: fires on attackers, silent on honest clients")

    h, _, _ = federation(4, 2)
    s = FederatedServer([0.0] * DIM)
    for x in h:
        s.enroll(x)
    reps = run(s, h, 6)
    flagged = {d for rep in reps for d, e in rep["events"].items()
               if e["severity"] != "NEUTRAL"}
    banned = {l for l in s.rep._dev if s.rep.get_status(l) == Status.BANNED}
    check("POSITIVE: attackers detected and banned",
          banned == {"a0", "a1"}, f"banned = {sorted(banned)}")
    check("no honest client was flagged",
          not any(x.startswith("h") for x in flagged),
          f"flagged = {sorted(flagged)}")

    # NEGATIVE CONTROL: an all-honest federation must produce NO bans.
    h2, _, _ = federation(5)
    s2 = FederatedServer([0.0] * DIM)
    for x in h2:
        s2.enroll(x)
    run(s2, h2, 6)
    banned2 = {l for l in s2.rep._dev if s2.rep.get_status(l) == Status.BANNED}
    check("NEGATIVE CONTROL: honest-only federation produces zero bans",
          not banned2,
          f"banned = {sorted(banned2)} (any entry here = false positives)")


def check2_chain_actually_records():
    """The failure mode this catches: the registry silently swallows every
    write, marks rounds unanchored, and the run still 'succeeds'."""
    print("\n[2] The chain is actually recording, not silently no-op'ing")

    reg, backend = chain_stack()
    h, _, _ = federation(4, 2)
    s = FederatedServer([0.0] * DIM, audit=reg)
    for x in h:
        s.enroll(x)
    run(s, h, 5)

    n = len(backend.events())
    check("POSITIVE: chain event log is non-empty", n > 0, f"{n} events")
    check("every round anchored, none unanchored",
          reg.anchored_rounds == {0, 1, 2, 3, 4} and not reg.unanchored_rounds,
          f"anchored={sorted(reg.anchored_rounds)} "
          f"unanchored={sorted(reg.unanchored_rounds)}")
    check("no contract rejections and no transport failures",
          not reg.rejections and not reg.failures,
          f"{len(reg.rejections)} rejections, {len(reg.failures)} failures")

    # the log must GROW with rounds, not sit at a constant
    run(s, h, 3, start=5)
    n2 = len(backend.events())
    check("event log grows as rounds proceed", n2 > n, f"{n} -> {n2} events")

    # NEGATIVE CONTROL: with the chain off, nothing must be recorded.
    from chain.wiring import build_audit
    audit_off, backend_off, _ = build_audit("off")
    check("NEGATIVE CONTROL: chain off constructs no backend at all",
          audit_off is None and backend_off is None,
          "so a non-empty log above cannot be an artefact of the harness")


def check3_bans_are_enforced_not_just_recorded():
    """A ban that is recorded but not enforced is decoration. The banned
    device must be ABSENT from the weights dict, not merely down-weighted."""
    print("\n[3] Bans are enforced in aggregation, not just logged")

    h, _, _ = federation(4, 2)
    s = FederatedServer([0.0] * DIM)
    for x in h:
        s.enroll(x)
    reps = run(s, h, 6)
    last = reps[-1]["weights"]

    check("POSITIVE: banned devices absent from the weights dict",
          "a0" not in last and "a1" not in last,
          f"final weights = {sorted(last)}")
    check("get_weight() returns exactly 0.0 for a banned device",
          s.rep.get_weight("a0") == 0.0,
          f"a0 weight = {s.rep.get_weight('a0')}")
    check("honest clients retain non-zero weight",
          all(last[f"h{k}"] > 0 for k in range(4)),
          f"h0 = {last['h0']:.4f}")

    # NEGATIVE CONTROL: an ACTIVE device must be present.
    check("NEGATIVE CONTROL: an ACTIVE device IS present in weights",
          "h0" in last,
          "so absence above is a ban, not an empty dict")


def check4_restart_preserves_state_and_is_not_a_reset():
    """The subtle failure: reconciliation returns a FRESH engine whose values
    look plausible. Compare against what a genuine reset would produce."""
    print("\n[4] Restart rebuilds real state (not a plausible-looking reset)")

    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.jsonl")
        reg, backend = chain_stack(path)
        h, _, _ = federation(4, 2)
        s = FederatedServer([0.0] * DIM, audit=reg)
        for x in h:
            s.enroll(x)
        run(s, h, 10)
        before = {l: s.rep._dev[l].trust for l in s.rep._dev}
        w_before = s.rep.get_weight("h0")

        # what a genuine reset would look like
        fresh = ReputationEngine()
        fresh.register("h0", Tier.TPM_RESIDENT, "x")
        fresh.record_event("h0", "NEUTRAL")
        w_reset = fresh.get_weight("h0")

        del s
        reg2 = ChainRegistry(HashChain(path=path), backend, reg.fed_key,
                             writer=W)
        engine, report = rebuild_engine(backend, reg2.inner)
        s = FederatedServer([0.0] * DIM, audit=reg2,
                            reputation_engine=engine)
        restore_server(s, engine, reg2.inner)
        w_after = s.rep.get_weight("h0")

        check("POSITIVE: every device recovered",
              set(engine._dev) == set(before),
              f"{report.devices} devices, {report.events_replayed} events")
        check("trust values match pre-restart within the 5e-6 fixed-point bound",
              all(abs(engine._dev[l].trust - t) <= 5e-6
                  for l, t in before.items()),
              f"h0: {before['h0']:.6f} -> {engine._dev['h0'].trust:.6f}")
        check("NOT A RESET: recovered weight differs from a fresh engine's",
              abs(w_after - w_reset) > 0.05,
              f"recovered {w_after:.4f} vs fresh-start {w_reset:.4f} "
              f"(pre-restart was {w_before:.4f})")
        check("bans survived the restart",
              engine.get_status("a0") == Status.BANNED
              and engine.get_status("a1") == Status.BANNED,
              f"a0={engine.get_status('a0').value}")
        check("participant filter restored (server would otherwise train on nothing)",
              len(s.enrolled) == 6, f"{len(s.enrolled)} enrolled")

        rep = s.run_round(10, h)
        check("rebuilt server keeps training",
              bool(rep["weights"]) and "a0" not in rep["weights"],
              f"round 10 weights = {sorted(rep['weights'])}")


def check5_whitewash_rejected_but_newcomers_admitted():
    """Both directions. A gate that rejects everyone 'blocks whitewashing'
    while also destroying the federation."""
    print("\n[5] Whitewash blocked, yet genuine newcomers still admitted")

    reg, backend = chain_stack()
    h, signers, _ = federation(4, 2)
    s = FederatedServer([0.0] * DIM, audit=reg)
    for x in h:
        s.enroll(x)
    run(s, h, 5)
    banned_ek = s.enrolled["a0"]["ek_hash"]

    class Returning:
        device_label = "a0_reborn"
        tpm_backend = "mock"
        def enroll_payload(self):
            p = signers["a0"].provision()
            return {"device_label": "a0_reborn", "ek_hash": p.ek_hash,
                    "ak_name": p.ak_name, "ek_cert_b64": None}
        def activate_credential(self, blob):
            return make_signer("mock", "a0_reborn").activate_credential(blob)
        def train(self, r, p):
            return {"update": [0.0] * DIM, "num_samples": 1}

    r = s.enroll(Returning())
    check("POSITIVE: banned EK under a NEW label is rejected",
          r["status"] == "BANNED", f"status = {r['status']}")
    check("chain independently agrees the EK is banned",
          reg.is_banned_on_chain(banned_ek) is True)

    # NEGATIVE CONTROL: a genuinely new device must be admitted.
    newcomer = LocalClientHandle("h_new", make_signer("mock", "h_new"),
                                 FLClient("h_new", honest(9)))
    r2 = s.enroll(newcomer)
    check("NEGATIVE CONTROL: an unseen EK is ADMITTED as ACTIVE",
          r2["status"] == "ACTIVE",
          f"status = {r2['status']} (BANNED here = the gate rejects everyone)")
    check("chain says the newcomer's EK is NOT banned",
          reg.is_banned_on_chain(s.enrolled["h_new"]["ek_hash"]) is False)


def check6_chain_does_not_alter_training():
    """If the chain fed back into training, every Chapter 4 number would be
    invalid. This must be an EXACT zero, not 'small'."""
    print("\n[6] The chain observes without altering training")

    def trajectory(use_chain):
        h, _, _ = federation(4, 2)
        reg = chain_stack()[0] if use_chain else None
        s = FederatedServer([0.0] * DIM, audit=reg)
        for x in h:
            s.enroll(x)
        w = [rep["weights"] for rep in run(s, h, 8)]
        return w, list(s.global_params)

    w_off, p_off = trajectory(False)
    w_on, p_on = trajectory(True)

    dev_w = max((abs(a[k] - b[k]) for a, b in zip(w_off, w_on) for k in a),
                default=0.0)
    dev_p = max((abs(x - y) for x, y in zip(p_off, p_on)), default=0.0)

    check("POSITIVE: weight trajectories are EXACTLY identical",
          dev_w == 0.0, f"max deviation = {dev_w:.3e}")
    check("final model parameters are EXACTLY identical",
          dev_p == 0.0, f"max deviation = {dev_p:.3e}")
    check("same set of devices banned either way",
          [sorted(a) for a in w_off] == [sorted(b) for b in w_on])


def check7_the_verifier_actually_detects_tampering():
    """THE SHARPEST CHECK. 'VERIFIED: 0 discrepancies' is meaningless unless
    the verifier can be shown to NOTICE corruption. So corrupt the chain and
    confirm it complains."""
    print("\n[7] The verifier detects tampering (so '0 discrepancies' means something)")

    reg, backend = chain_stack()
    h, _, _ = federation(4, 2)
    s = FederatedServer([0.0] * DIM, audit=reg)
    for x in h:
        s.enroll(x)
    run(s, h, 6)

    res = verify_backend(backend)
    check("POSITIVE: untampered chain verifies cleanly",
          res.ok, res.summary())

    # --- corrupt a stored trust value ---
    dev = backend._engine._dev["h0"]
    original_s = dev.s
    dev.s = original_s + 777_000
    res_bad = verify_backend(backend)
    caught_s = not res_bad.ok
    check("TAMPER 1: inflating a device's stored trust IS detected",
          caught_s, res_bad.summary()[:110])
    dev.s = original_s

    # --- corrupt a status: silently un-ban an attacker ---
    from chain.fixedpoint import StatusFP
    atk = backend._engine._dev["a0"]
    orig_status = atk.status
    atk.status = StatusFP.ACTIVE
    res_bad2 = verify_backend(backend)
    caught_status = not res_bad2.ok
    check("TAMPER 2: silently un-banning an attacker IS detected",
          caught_status, res_bad2.summary()[:110])
    atk.status = orig_status

    # --- restore and re-verify ---
    check("chain verifies again once the tampering is reverted",
          verify_backend(backend).ok)

    if not (caught_s and caught_status):
        bad("VERIFIER IS UNFALSIFIABLE",
            "it returned OK on corrupted state, so its clean result proves "
            "nothing")

    # --- local audit log tamper-evidence ---
    reg.inner._entries[2]["payload"] = {"device": "forged"}
    okv, err = reg.inner.verify()
    check("local audit log detects an edited entry",
          not okv, f"verify() -> ({okv}, {err})")


def check8_tier_changes_consequences_not_trust():
    """The central design claim: identical behaviour, identical trust,
    DIFFERENT consequences."""
    print("\n[8] Tier changes consequences, not the trust score")

    e = ReputationEngine()
    for t in (Tier.HARDWARE, Tier.TPM_RESIDENT, Tier.SOFTWARE):
        e.register(t.name, t, f"ek_{t.name}")
    trusts = {t.name: e._dev[t.name].trust
              for t in (Tier.HARDWARE, Tier.TPM_RESIDENT, Tier.SOFTWARE)}
    check("POSITIVE: all tiers start at the SAME trust (tier-neutral)",
          len(set(round(v, 9) for v in trusts.values())) == 1,
          f"{ {k: round(v,4) for k,v in trusts.items()} }")

    weights = {t.name: e.get_weight(t.name)
               for t in (Tier.HARDWARE, Tier.TPM_RESIDENT, Tier.SOFTWARE)}
    check("NEGATIVE CONTROL: weights DIFFER despite equal trust",
          len(set(round(v, 6) for v in weights.values())) == 3,
          f"{ {k: round(v,4) for k,v in weights.items()} } "
          f"(cap D = 1.0 / 0.5 / 0.1)")

    e2 = ReputationEngine()
    e2.register("hw", Tier.HARDWARE, "a")
    e2.register("t2", Tier.TPM_RESIDENT, "b")
    for _ in range(2):
        e2.record_event("hw", "MAJOR")
        e2.record_event("t2", "MAJOR")
    check("SAME offence, DIFFERENT outcome: Tier 1 -> PROBATION, Tier 2 -> BANNED",
          e2.get_status("hw") == Status.PROBATION
          and e2.get_status("t2") == Status.BANNED,
          f"hw={e2.get_status('hw').value}  t2={e2.get_status('t2').value}")

    e3 = ReputationEngine()
    e3.register("hw", Tier.HARDWARE, "c")
    e3.record_event("hw", "CRITICAL")
    check("but CRITICAL is ungated: even Tier 1 is banned outright",
          e3.get_status("hw") == Status.BANNED,
          "identity abuse is non-compensable regardless of hardware")


def check9_cold_start_gate_protects_new_devices():
    """A new device with one noisy round must not be sanctioned, even though
    its score has already dropped below the ban threshold."""
    print("\n[9] Cold-start gate: score alone cannot sanction a new device")

    e = ReputationEngine()
    e.register("n", Tier.SOFTWARE, "ek")
    rows, sanctioned_early = [], False
    for i in range(4):
        e.record_event("n", "MINOR")
        d = e._dev["n"]
        rows.append((i + 1, d.s + d.f, d.evidence_dominated, d.trust,
                     d.status.value))
        if i < 3 and d.status != Status.ACTIVE:
            sanctioned_early = True

    for n, ev, dom, t, st in rows:
        print(f"      after {n} MINOR: s+f={ev:.2f} "
              f"evidence_dominated={dom!s:<5} T={t:.3f} {st}")

    # T crosses BAN_T = 0.3 at round 3 (0.263), while the gate stays shut
    # until round 4. That one-round overlap is the protection.
    crossed_at = next((n for n, ev, dom, t, st in rows if t < 0.3), None)
    gate_opens_at = next((n for n, ev, dom, t, st in rows if dom), None)
    check("POSITIVE: trust falls below BAN_T (0.3) before the gate opens",
          crossed_at is not None and gate_opens_at is not None
          and crossed_at < gate_opens_at,
          f"T < 0.3 from round {crossed_at}, gate opens at round "
          f"{gate_opens_at} -> {gate_opens_at - crossed_at} round(s) of "
          f"protection a score-only rule would not give")
    check("NEGATIVE CONTROL: yet NO sanction fires while the gate is closed",
          not sanctioned_early,
          "so the gate, not luck, is what protects a noisy newcomer")
    check("sanction fires once evidence dominates (s+f > 2)",
          rows[3][4] == "BANNED" and rows[3][2] is True)


def check10_ek_privacy_holds():
    """Raw EK hashes must never reach the chain, while the ban check must
    still work. Both, or the design has failed one way or the other."""
    print("\n[10] EK privacy: raw hashes never on chain, bans still work")

    reg, backend = chain_stack()
    h, _, _ = federation(3, 2)
    s = FederatedServer([0.0] * DIM, audit=reg)
    for x in h:
        s.enroll(x)
    run(s, h, 5)

    raw = [v["ek_hash"] for v in s.enrolled.values()]
    blob = "".join(str(e.payload) for e in backend.events())
    leaked = [r for r in raw if r in blob]
    check("POSITIVE: no raw EK hash appears anywhere in the chain log",
          not leaked, f"{len(raw)} EKs checked, {len(leaked)} leaked")

    banned_raw = s.enrolled["a0"]["ek_hash"]
    hmac = reg.fed_key.ek_hmac(banned_raw)
    check("the HMAC of the banned EK IS on chain and flagged banned",
          backend.is_banned_ek(hmac) is True)
    check("NEGATIVE CONTROL: the ban check still works despite the hashing",
          reg.is_banned_on_chain(banned_raw) is True,
          "privacy did not cost us O2")
    check("an unrelated EK is NOT reported banned",
          reg.is_banned_on_chain("ff" * 32) is False,
          "so 'True' above is a real lookup, not a constant")


CHECKS = [check1_detection_fires_and_does_not_overfire,
          check2_chain_actually_records,
          check3_bans_are_enforced_not_just_recorded,
          check4_restart_preserves_state_and_is_not_a_reset,
          check5_whitewash_rejected_but_newcomers_admitted,
          check6_chain_does_not_alter_training,
          check7_the_verifier_actually_detects_tampering,
          check8_tier_changes_consequences_not_trust,
          check9_cold_start_gate_protects_new_devices,
          check10_ek_privacy_holds]


if __name__ == "__main__":
    print("=" * 74)
    print("DLTF -- FALSIFICATION HARNESS")
    print("Every positive check is paired with a negative control that MUST")
    print("fail. A check whose control also passes is meaningless.")
    print("=" * 74)

    crashed = []
    for fn in CHECKS:
        try:
            fn()
        except Exception as e:
            import traceback
            traceback.print_exc()
            crashed.append(f"{fn.__name__}: {e}")

    print("\n" + "=" * 74)
    print(f"  {len(PASS)} checks passed, {len(FAIL)} failed, "
          f"{len(crashed)} crashed")
    if FAIL:
        print("\n  FAILED:")
        for f in FAIL:
            print(f"    \u2717 {f}")
    if crashed:
        print("\n  CRASHED:")
        for c in crashed:
            print(f"    \u2717 {c}")
    print("=" * 74)
    if not FAIL and not crashed:
        print("\u2713 SYSTEM BEHAVES AS INTENDED")
        print("  Detection fires only on attackers. The chain genuinely")
        print("  records. Bans are enforced, survive restart, and block")
        print("  whitewashing without blocking newcomers. The chain does not")
        print("  perturb training. The verifier provably detects tampering.")
        print("  Tier changes consequences, not trust. New devices are")
        print("  protected. EK privacy holds without costing O2.")
    else:
        print("\u2717 SOMETHING IS NOT AS INTENDED -- see above")
    sys.exit(1 if (FAIL or crashed) else 0)
