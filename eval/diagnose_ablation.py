"""
diagnose_ablation.py -- why did turning M3 and the cold-start gate OFF change
nothing?

The ablation in exp_engine_sweep.py returned identical numbers to four decimal
places for every variant, and the constant sweep was flat across gamma, theta,
tau, forgive_after, major_run_to_escalate, probation_t, ban_t, d2 and d3. That
is not a "the design is robust" result. Nine parameters cannot all be
irrelevant. There are exactly three explanations and this script separates
them:

  H1  THE INJECTION IS BROKEN. FederatedServer is not using the Params bundle
      passed to it, so every run used the defaults. Test: drive the constants
      to absurd values. probation_t = ban_t = 0.99 must ban every device
      including honest ones on the first classification. If honest_fpr stays
      0.000, the Params never reached the engine and every sweep row in
      exp_engine_sweep.csv is meaningless.

  H2  A STRONGER PATH FIRES FIRST. If the detector emits CRITICAL, the engine
      bans immediately -- ahead of M3, ahead of the score, ahead of every
      threshold. No constant can matter in that case. Test: print the actual
      severity stream per device per round and see what the attackers receive.

  H3  THE MECHANISMS ARE GENUINELY REDUNDANT HERE. The scenarios are blatant
      enough that several independent paths reach the same sanction, so
      removing one changes nothing. This is a real (and reportable) finding,
      but it can only be concluded after H1 and H2 are ruled out.

Why it matters for the paper. Section "Trust Dynamics" claims the sleeper is
caught BY M3 -- "sanctioned on its second consecutive MAJOR regardless" -- and
presents that as the case a score-only design fails. The ablation says the
sleeper is caught just as well with M3 disabled. Either the claim needs
rewording or the experiment does not exercise the mechanism it describes.
Publishing the claim without resolving this is the kind of thing a reviewer
who runs the artifact will find.

Run:
    python -m eval.diagnose_ablation
    python -m eval.diagnose_ablation --attack sleeper --rounds 30
"""

import argparse

from trust.reputation import Params, ReputationEngine
from fl.server import FederatedServer
from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from eval.scenarios import (SyntheticWorld, ATTACKS, behavior, make_handle)

SEV_NAME = {0: "POSITIVE", 1: "NEUTRAL", 2: "MINOR", 3: "MAJOR", 4: "CRITICAL"}


def _build(world, attack, seed, params, n_honest=7, attacker_tier=2):
    kind, n_att, start = ATTACKS[attack]
    ca_key, ca_cert = generate_test_ca()
    server = FederatedServer(initial_params=[0.0] * world.dim,
                             ca_bundle_pem=ca_bundle_pem(ca_cert),
                             shadow_eval_fn=world.accuracy,
                             reputation_engine=ReputationEngine(params))
    handles, attackers = [], []
    for k in range(n_honest):
        handles.append(make_handle("h%d" % k,
                                   behavior(world, "honest", seed * 100 + k)))
    for k in range(n_att):
        label = "a%d" % k
        cert, fail = None, False
        if attacker_tier == 1:
            cert, _ = issue_ek_cert(ca_key, ca_cert, label)
        elif attacker_tier == 3:
            fail = True
        handles.append(make_handle(
            label, behavior(world, kind, seed * 100 + 50 + k,
                            attack_start=start, group_seed=seed + 1),
            ek_cert_der=cert, fail_activation=fail))
        attackers.append(label)
    for h in handles:
        server.enroll(h)
    return server, handles, attackers, start


# ------------------------------------------------------------------ H1
def h1_injection_reaches_engine(attack, rounds, seed=0):
    """Absurd thresholds must produce absurd behaviour. If they do not, the
    Params bundle is not reaching the engine."""
    print("\n" + "=" * 68)
    print("H1  does the Params bundle actually reach the engine?")
    print("=" * 68)

    cases = [
        ("defaults", Params()),
        ("probation_t=0.99, ban_t=0.99  (expect EVERY device banned)",
         Params(probation_t=0.99, ban_t=0.99)),
        ("probation_t=0.0, ban_t=0.0    (expect NOTHING banned)",
         Params(probation_t=0.0, ban_t=0.0)),
        ("theta=0.0                     (no positive evidence ever)",
         Params(theta=0.0)),
    ]
    for label, p in cases:
        world = SyntheticWorld(seed)
        server, handles, attackers, _ = _build(world, attack, seed, p)
        banned = set()
        for r in range(rounds):
            server.run_round(r, handles)
        for h in handles:
            d = server.rep._dev.get(h.device_label)
            st = getattr(d, "status", None)
            if st is not None and str(st).upper().find("BAN") >= 0:
                banned.add(h.device_label)
        honest_banned = len([b for b in banned if b not in attackers])
        print("  %-58s banned=%-2d (honest=%d)"
              % (label, len(banned), honest_banned))

    print("\n  VERDICT: if the 0.99 row did not ban far more devices than the\n"
          "  default row, the injection is broken and every row of\n"
          "  engine_sweep.csv and engine_ablation.csv must be discarded.\n"
          "  If it DID (9 banned, 7 honest), Params reaches the engine and the\n"
          "  flat sweep is real behaviour -- continue to H2.\n"
          "  Note also the 0.0 row: with both thresholds at zero no SCORE can\n"
          "  fall below them, yet attackers are still banned. Whatever bans\n"
          "  them is therefore not the score.")


# ------------------------------------------------------------------ H2
def h2_severity_stream(attack, rounds, seed=0):
    """What severity does each device actually receive, round by round? If the
    attackers get CRITICAL, no engine constant can influence the outcome."""
    print("\n" + "=" * 68)
    print("H2  what severities are actually emitted?  attack=%s" % attack)
    print("=" * 68)

    world = SyntheticWorld(seed)
    server, handles, attackers, start = _build(world, attack, seed, Params())
    print("  attackers: %s   attack starts at round %s" % (attackers, start))

    counts = {}
    first_sanction = {}
    for r in range(rounds):
        rep = server.run_round(r, handles)
        events = rep.get("events", {})
        for dev, sev in _iter_events(events):
            counts.setdefault(dev, {}).setdefault(sev, 0)
            counts[dev][sev] += 1
            if dev in attackers and sev in (3, 4) and dev not in first_sanction:
                first_sanction[dev] = (r, sev)
        if r < 8 or (start is not None and start - 1 <= r <= start + 3):
            shown = {d: SEV_NAME.get(s, s) for d, s in _iter_events(events)
                     if d in attackers}
            if shown:
                print("    round %-3d %s" % (r, shown))

    print("\n  severity totals for attackers:")
    for a in attackers:
        c = counts.get(a, {})
        pretty = {SEV_NAME.get(k, k): v for k, v in sorted(c.items())}
        print("    %-6s %s" % (a, pretty))
        if a in first_sanction:
            r, sev = first_sanction[a]
            print("           first %s at round %d" % (SEV_NAME.get(sev), r))

    crit = any(4 in counts.get(a, {}) for a in attackers)
    if crit:
        print("\n  VERDICT: at least one attacker receives CRITICAL. A CRITICAL\n"
              "  bans immediately, ahead of M3 and ahead of every threshold, so\n"
              "  the ablation SHOULD be a null result for this scenario -- and\n"
              "  the paper must not attribute the catch to M3 here.")
    else:
        print("\n  VERDICT: no CRITICAL emitted. The ban came from M3 or from the\n"
              "  score, so disabling M3 SHOULD have changed something. If it did\n"
              "  not, return to H1.")


NAME_TO_SEV = {"POSITIVE": 0, "NEUTRAL": 1, "MINOR": 2, "MAJOR": 3,
               "CRITICAL": 4}


def _sev_to_int(s):
    """Severities arrive as int, as a plain string ('NEUTRAL'), as an enum
    repr ('Severity.NEUTRAL'), or as an enum object. Normalise all of them."""
    if isinstance(s, bool):
        return None
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        token = s.strip().upper().split(".")[-1]
        if token.isdigit():
            return int(token)
        return NAME_TO_SEV.get(token)
    name = getattr(s, "name", None)
    if isinstance(name, str):
        return NAME_TO_SEV.get(name.upper())
    value = getattr(s, "value", None)
    if isinstance(value, int):
        return value
    return None


def _iter_events(events):
    """events shape varies; accept dict{dev:sev}, dict{dev:{severity:..}} or
    a list of records. Severity may be int, str or enum."""
    if isinstance(events, dict):
        for dev, val in events.items():
            sev = _sev_to_int(val)
            if sev is None and isinstance(val, dict):
                sev = _sev_to_int(val.get("severity", val.get("sev")))
            if sev is None:
                sev = _sev_to_int(getattr(val, "severity", None))
            if sev is not None:
                yield dev, sev
    elif isinstance(events, (list, tuple)):
        for rec in events:
            if isinstance(rec, dict):
                dev = rec.get("device", rec.get("device_id"))
                sev = _sev_to_int(rec.get("severity", rec.get("sev")))
                if dev is not None and sev is not None:
                    yield dev, sev


# ------------------------------------------------------------------ H3
def h3_m3_isolated(attack, rounds, seed=0):
    """Compare M3 on/off on the SLEEPER specifically, printing the round each
    attacker is first sanctioned rather than only the final tally. A mechanism
    can change WHEN without changing WHETHER, and final accuracy hides that."""
    print("\n" + "=" * 68)
    print("H3  does M3 change the TIMING even if not the outcome?")
    print("=" * 68)
    for label, p in [("M3 on ", Params()), ("M3 off", Params(m3_enabled=False))]:
        world = SyntheticWorld(seed)
        server, handles, attackers, _ = _build(world, attack, seed, p)
        banned_at = {}
        for r in range(rounds):
            server.run_round(r, handles)
            for a in attackers:
                if a in banned_at:
                    continue
                d = server.rep._dev.get(a)
                if d is not None and str(getattr(d, "status", "")).upper().find("BAN") >= 0:
                    banned_at[a] = r
        print("  %s  ban round per attacker: %s" % (label, banned_at or "none banned"))
    print("\n  If the ban rounds are identical, M3 is not on the critical path\n"
          "  for this scenario and the paper's sleeper claim needs rewording.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default="sleeper")
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if args.attack not in ATTACKS:
        raise SystemExit("unknown attack %r; available: %s"
                         % (args.attack, sorted(ATTACKS)))

    h1_injection_reaches_engine(args.attack, args.rounds, args.seed)
    h2_severity_stream(args.attack, args.rounds, args.seed)
    h3_m3_isolated(args.attack, args.rounds, args.seed)


if __name__ == "__main__":
    main()
