"""
audit/hashchain.py -- compatible replacement.

The version shipped in the project drop was flagged 'placeholder' at the top.
Its interface (entries as attribute, verify() -> bool, 'data' key, no
head_hash) does not match what the chain layer expects. This drop-in matches
the surface actually used by fl/server.py, chain/registry.py, and
chain/verifier.py.
"""
import hashlib
import hmac
import json
import os
import time

GENESIS = "0" * 64


class HashChain:
    def __init__(self, path=None, key=None):
        self.path = path
        self.key = key or os.environ.get("DLTF_AUDIT_KEY",
                                         "dev-key-change-me").encode()
        self._entries = []
        self._prev = GENESIS
        self._append_raw("GENESIS", {})
        if self.path and os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    e = json.loads(line)
                    self._entries.append(e)
                    self._prev = e["hash"]

    def _sign(self, body):
        blob = json.dumps(body, sort_keys=True, default=str).encode()
        return hmac.new(self.key, self._prev.encode() + blob,
                        hashlib.sha256).hexdigest()

    def _append_raw(self, event_type, payload):
        seq = len(self._entries)
        ts = 0.0 if event_type == "GENESIS" else time.time()
        rec = {"seq": seq, "ts": ts, "type": event_type,
               "payload": payload, "prev": self._prev}
        rec["hash"] = self._sign({k: v for k, v in rec.items() if k != "hash"})
        rec["sig"] = rec["hash"]
        self._entries.append(rec)
        self._prev = rec["hash"]
        if self.path and event_type != "GENESIS":
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, sort_keys=True, default=str) + "\n")
        return rec

    def append(self, event_type, payload):
        return self._append_raw(event_type, payload)

    def entries(self, event_type=None):
        if event_type is None:
            return list(self._entries)
        return [e for e in self._entries if e["type"] == event_type]

    def verify(self):
        prev = GENESIS
        for e in self._entries:
            body = {k: v for k, v in e.items() if k not in ("hash", "sig")}
            want = hmac.new(self.key,
                            prev.encode()
                            + json.dumps(body, sort_keys=True,
                                         default=str).encode(),
                            hashlib.sha256).hexdigest()
            if want != e["hash"] or e["prev"] != prev:
                return False, f"entry {e.get('seq', '?')} broken"
            prev = e["hash"]
        return True, None

    def head_hash(self):
        return self._prev

    def __len__(self):
        return len(self._entries)
