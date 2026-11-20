"""
net/agent.py

Per-client HTTP agent for the LAN deployment. Runs on each client PC and exposes
that machine's TPM signer and trainer to the server's RemoteClientHandle.

  GET  /health    -> {"ok": true, "device": label}
  POST /enroll    -> enrollment payload (ek_hash, ak_name, certs)
  POST /activate  -> {"secret": b64}   credential activation answer
  POST /train     -> {"update": [...], "num_samples": n}

Run on a client box (label must exist in config.CLIENTS):
  python3 -m net.agent --label client1 --port 8470            # torch trainer
  python3 -m net.agent --label client1 --port 8470 --stub     # smoke test

All agents partition MNIST identically (same seed, same client count from
config), each taking its own shard, so no data distribution step is needed.
Plain HTTP on a trusted LAN; TLS/auth is deployment hardening (limitations).
Run bare (no args) to self-test over a real localhost HTTP loop.
"""
import sys
import json
import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tpm.common import b64e
from tpm.client import make_signer
from fl.client import FLClient
from net.handles import _payload_from_provision


class DLTFAgent:
    """Client-side HTTP agent.

    commit_agent is OPTIONAL and defaults to None, so the agent behaves
    exactly as before when the commitment layer is off. When set, the
    gradient hash is committed BEFORE the update leaves the machine -- that
    ordering is the whole point: a commitment made after transmission proves
    nothing, because the server would already have had the chance to
    substitute a gradient.
    """

    def __init__(self, device_label, signer, fl_client, commit_agent=None):
        self.label = device_label
        self.signer = signer
        self.fl = fl_client
        self.commit_agent = commit_agent

    def dispatch(self, path, body):
        if path == "/enroll":
            return _payload_from_provision(self.label, self.signer.provision())
        if path == "/activate":
            return {"secret": b64e(self.signer.activate_credential(body["blob"]))}
        if path == "/bind-wallet":
            # Prove control of BOTH the TPM and the wallet, so the server
            # cannot bind a wallet it controls to someone else's device.
            from chain.commit import wallet_bind_challenge
            challenge = wallet_bind_challenge(self.label, body["wallet"])
            return {"device_label": self.label, "wallet": body["wallet"],
                    "signature": b64e(self.signer.sign_message(challenge))}
        if path == "/train":
            result = self.fl.train(body["round"], body["params"])
            if self.commit_agent is not None:
                # Commit the EXACT update being returned, before returning it.
                receipt = self.commit_agent.commit(body["round"],
                                                  result["update"])
                result["commit"] = {
                    "round": receipt.round_id,
                    "device_label": receipt.device_label,
                    "wallet": receipt.wallet,
                    "grad_hash": receipt.grad_hash.hex(),
                    "ok": receipt.ok,
                    "error": receipt.error,
                }
            return result
        raise KeyError(path)

    def serve(self, host="0.0.0.0", port=8470):
        httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        print(f"✓ agent '{self.label}' listening on {host}:{httpd.server_address[1]}")
        httpd.serve_forever()

    def serve_in_thread(self, host="127.0.0.1", port=0):
        httpd = ThreadingHTTPServer((host, port), _make_handler(self))
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        return httpd, httpd.server_address[1]


def _make_handler(agent):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"ok": True, "device": agent.label})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            chunks, remaining = [], n
            while remaining > 0:
                part = self.rfile.read(min(remaining, 1 << 20))
                if not part:
                    break
                chunks.append(part)
                remaining -= len(part)
            body = json.loads(b"".join(chunks).decode() or "{}")
            try:
                self._send(200, agent.dispatch(self.path, body))
            except KeyError:
                self._send(404, {"error": "not found"})
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send(500, {"error": str(e)})
    return Handler


def _cfg(entry, key, default=None):
    if isinstance(entry, dict):
        return entry.get(key, default)
    return getattr(entry, key, default)


# ---- live attack profiles (for the Tailscale poison-injection demo) ---------
#
# Each profile wraps an HONEST trainer and corrupts its output, so the attack is
# a perturbation of real training rather than a synthetic vector. Profiles are
# named for the DETECTOR STAGE they are meant to trip (trust/filter.py):
#
#   scale     Stage 1  norm > 2.5x median            -> MINOR
#   flip      Stage 2  cosine to robust ref < -0.45  -> MAJOR
#   sybil     Stage 3  pairwise sim >= 0.95, 2 rounds -> CRITICAL
#             MUST be run on TWO clients with the SAME --attack-seed.
#             VERIFIED: two peers -> CRITICAL (similarity 1.00); a LONE
#             sybil -> NEUTRAL. Collusion is what Stage 3 detects, so a
#             single colluder is undetectable BY DEFINITION, not by defect.
#             With only 2 physical machines, running sybil on both leaves
#             zero honest clients -- see the runbook for how to handle that.
#   sleeper            behaves honestly for --attack-after rounds, then flips.
#             VERIFIED to surface as MAJOR via Stage 2, not Stage 4: both
#             stages return MAJOR and the max-severity compose reports the
#             first match. The point of this profile is not which stage fires
#             but that the device BANKS TRUST FIRST -- it tests M1 saturation
#             and M3 escalation against a high-s veteran, which is the case a
#             score-only defence misses.
#
# Reference: MAJOR twice in a row also trips M3 escalation in the reputation
# engine, which is what routes a Tier-1 device to PROBATION rather than a ban.

ATTACK_PROFILES = ("none", "scale", "flip", "sybil", "sleeper")


def make_attacker(inner, profile, seed=1337, after=3, magnitude=10.0):
    """Wrap a trainer so its update is corrupted per `profile`."""
    import numpy as np

    if profile in (None, "none"):
        return inner

    def attacked(round_id, params):
        out = inner(round_id, params)
        update, n = out if isinstance(out, tuple) else (out, 64)
        v = np.asarray(update, dtype=np.float64)

        if profile == "scale":
            v = v * magnitude

        elif profile == "flip":
            v = -v * 1.5

        elif profile == "sybil":
            # Deterministic in (seed, round) ONLY -- identical across every
            # client using the same --attack-seed. That collision is what
            # Stage 3 detects.
            rng = np.random.default_rng(seed * 100_000 + round_id)
            base = np.zeros(len(v))
            k = max(1, len(v) // 4)
            base[:k] = 1.0
            base = base / np.linalg.norm(base)
            v = base + 0.01 * rng.standard_normal(len(v))

        elif profile == "sleeper":
            if round_id >= after:
                v = -v * 1.5
            # else: behave honestly, banking trust first

        return v.tolist(), n

    return attacked


def build_agent_from_config(label, stub=False, epochs=1, lr=0.05,
                            attack="none", attack_seed=1337,
                            attack_after=3, attack_magnitude=10.0,
                            commit_agent=None):
    import config
    entries = list(config.CLIENTS)
    idx = next((i for i, c in enumerate(entries) if _cfg(c, "device_label") == label), None)
    if idx is None:
        raise SystemExit(f"✗ label '{label}' not in config.CLIENTS")
    entry = entries[idx]
    signer = make_signer(_cfg(entry, "tpm_backend", "real"), label, tcti=_cfg(entry, "tcti"))
    if stub:
        trainer = lambda r, p: ([0.0] * len(p), 1)
    else:
        from fl.model import MNISTModel
        from fl.client import TorchTrainer
        from fl.dataset import load_mnist, build_client_loaders
        train_ds, _ = load_mnist()
        loaders, _ = build_client_loaders(train_ds, num_clients=len(entries), seed=0)
        trainer = TorchTrainer(MNISTModel, loaders[idx], epochs=epochs, lr=lr)

    if attack not in ATTACK_PROFILES:
        raise SystemExit(f"✗ unknown --attack {attack!r}; "
                         f"have {list(ATTACK_PROFILES)}")
    if attack != "none":
        trainer = make_attacker(trainer, attack, seed=attack_seed,
                                after=attack_after,
                                magnitude=attack_magnitude)
        print(f"⚠ ATTACK MODE: {label} running profile '{attack}'"
              + (f" (seed {attack_seed}, collusion key)" if attack == "sybil"
                 else "")
              + (f" (honest until round {attack_after})" if attack == "sleeper"
                 else ""))

    return DLTFAgent(label, signer, FLClient(label, trainer),
                     commit_agent=commit_agent)


def main(argv):
    ap = argparse.ArgumentParser(description="DLTF client agent")
    ap.add_argument("--label", required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8470)
    ap.add_argument("--stub", action="store_true", help="zero-update trainer for smoke tests")
    ap.add_argument("--epochs", type=int, default=1)
    ap.add_argument("--lr", type=float, default=0.05)
    ap.add_argument("--attack", default="none", choices=list(ATTACK_PROFILES),
                    help="live poison-injection profile for the demo. "
                         "'sybil' must be run on TWO clients with the SAME "
                         "--attack-seed to trip Stage 3.")
    ap.add_argument("--attack-seed", type=int, default=1337,
                    help="collusion key: sybil peers sharing this value emit "
                         "identical updates")
    ap.add_argument("--attack-after", type=int, default=3,
                    help="[sleeper] behave honestly until this round")
    ap.add_argument("--attack-magnitude", type=float, default=10.0,
                    help="[scale] multiplier applied to the honest update")
    args = ap.parse_args(argv)
    build_agent_from_config(args.label, args.stub, args.epochs, args.lr,
                            attack=args.attack,
                            attack_seed=args.attack_seed,
                            attack_after=args.attack_after,
                            attack_magnitude=args.attack_magnitude
                            ).serve(args.host, args.port)


def _self_test():
    import urllib.request
    from net.handles import RemoteClientHandle
    from fl.server import FederatedServer
    from tpm.common import make_credential

    print("net/agent.py self-test (real HTTP on localhost)")
    DIM = 4

    def trainer(idx):
        return lambda r, p: ([0.1 * (idx + 1)] * DIM, 32)

    agents, servers, handles = [], [], []
    for k in range(2):
        a = DLTFAgent(f"r{k}", make_signer("mock", f"r{k}"), FLClient(f"r{k}", trainer(k)))
        httpd, port = a.serve_in_thread()
        agents.append(a); servers.append(httpd)
        handles.append(RemoteClientHandle(f"r{k}", f"http://127.0.0.1:{port}",
                                          tpm_backend="mock"))

    with urllib.request.urlopen(handles[0].endpoint + "/health", timeout=5) as r:
        assert json.loads(r.read())["device"] == "r0"
    print("✓ /health answers over HTTP")

    blob, secret = make_credential("mock", device_label="r0")
    assert handles[0].activate_credential(blob) == secret
    print("✓ credential secret survives the b64/JSON wire round-trip")

    fed = FederatedServer(initial_params=[0.0] * DIM)
    res = [fed.enroll(h) for h in handles]
    assert all(x["tier"] == "TPM_RESIDENT" for x in res)
    report = fed.run_round(0, handles)
    assert report["aggregated"] is True and fed.global_params[0] > 0.0
    print("✓ FederatedServer enrolled and ran a round entirely over HTTP")

    out = handles[0].train(1, [0.0] * DIM)
    assert out["update"] == [0.1] * DIM and out["num_samples"] == 32
    print("✓ /train returns the trainer's update faithfully")

    for httpd in servers:
        httpd.shutdown()
    print("✓ all agent self-tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        _self_test()
    else:
        main(sys.argv[1:])