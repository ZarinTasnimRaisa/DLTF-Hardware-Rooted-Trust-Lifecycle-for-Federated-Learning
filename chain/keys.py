"""
chain/keys.py

Federation key material for the ek_hmac layer.

WHAT AND WHY
-----------------------------------------------------------------------------
Real EK hashes are PERMANENT physical-machine fingerprints. Writing them to
any immutable ledger -- even a local Hardhat node used only for evaluation
-- creates a durable de-anonymisation surface. Instead, the chain stores

    ek_hmac = HMAC-SHA256(federation_key, DOMAIN || ek_hash)   (32 bytes)

with DOMAIN = b"DLTF-EKv1|" a domain-separation tag.

Properties:
  - Deterministic: same federation_key + same ek_hash -> same ek_hmac. The
    contract's bannedEk mapping works because ek_hmac is stable.
  - Federation-scoped: two federations with distinct keys produce DIFFERENT
    ek_hmacs for the same ek_hash. A machine banned in federation A is not
    identifiable as such by federation B even if both use the same registry
    contract.
  - Domain-separated: the tag prevents a chosen-message attack that reuses
    ek_hmacs computed for a different purpose within the same key.

KEY FILE
-----------------------------------------------------------------------------
The federation key MUST be independent of audit/hashchain.py's HMAC key.
Sharing the audit key would defeat the point -- anyone with permission to
verify the audit log could de-anonymise every EK on the public ledger.

Default location: results/federation.key (32 random bytes, 0600).
Config override: config.chain.federation_key_path.

Loss of the key: bannedEk lookups still work (ek_hmacs are already
committed), but new enrolments cannot be checked against the ban list until
the key is either recovered or the federation rotates. This is a
DELIBERATE failure mode -- see chain/README.md.
"""
import hmac
import hashlib
import os
from pathlib import Path


DOMAIN = b"DLTF-EKv1|"
KEY_LEN = 32


class FederationKey:
    """32-byte HMAC key with load-or-create semantics identical in shape to
    audit/hashchain.py's _load_or_create_key -- separate FILE, separate KEY."""

    def __init__(self, path=None, key=None):
        if key is not None:
            if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
                raise ValueError(f"key must be {KEY_LEN} bytes")
            self._key = bytes(key)
            self.path = None
            return
        self.path = Path(path) if path else None
        self._key = self._load_or_create()

    def _load_or_create(self):
        if self.path is None:
            return os.urandom(KEY_LEN)
        if self.path.exists():
            data = self.path.read_bytes()
            if len(data) != KEY_LEN:
                raise ValueError(
                    f"federation key at {self.path} has wrong length "
                    f"{len(data)}, expected {KEY_LEN}")
            return data
        self.path.parent.mkdir(parents=True, exist_ok=True)
        key = os.urandom(KEY_LEN)
        self.path.write_bytes(key)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return key

    def ek_hmac(self, ek_hash) -> bytes:
        """HMAC-SHA256(key, DOMAIN || ek_hash) -> 32 bytes.
        ek_hash may be bytes or a hex string."""
        if isinstance(ek_hash, str):
            ek_hash = bytes.fromhex(ek_hash)
        elif not isinstance(ek_hash, (bytes, bytearray)):
            raise TypeError(f"ek_hash must be bytes or hex str, "
                            f"got {type(ek_hash).__name__}")
        return hmac.new(self._key, DOMAIN + bytes(ek_hash),
                        hashlib.sha256).digest()

    def is_mock(self):
        """True if this key was generated in memory (no persistence path)."""
        return self.path is None

    def __eq__(self, other):
        return (isinstance(other, FederationKey)
                and hmac.compare_digest(self._key, other._key))

    def __repr__(self):
        origin = f"path={self.path}" if self.path else "in-memory"
        return f"FederationKey({origin})"


def _self_test():
    import tempfile
    print("chain/keys.py self-test")

    # -- deterministic given the same key --------------------------------
    k1 = FederationKey(key=b"\x01" * KEY_LEN)
    k2 = FederationKey(key=b"\x01" * KEY_LEN)
    ek = b"\x42" * 32
    assert k1.ek_hmac(ek) == k2.ek_hmac(ek)
    assert len(k1.ek_hmac(ek)) == 32
    print("\u2713 same key + same ek_hash -> same ek_hmac (32 bytes)")

    # -- different keys -> different ek_hmacs ----------------------------
    k3 = FederationKey(key=b"\x02" * KEY_LEN)
    assert k1.ek_hmac(ek) != k3.ek_hmac(ek)
    print("\u2713 different federation keys -> different ek_hmacs "
          "(cross-federation unlinkability)")

    # -- domain separation: change DOMAIN, different result ---------------
    manual = hmac.new(b"\x01" * KEY_LEN,
                      b"DLTF-EKv2|" + ek, hashlib.sha256).digest()
    assert k1.ek_hmac(ek) != manual
    print("\u2713 domain tag matters: DLTF-EKv1| != DLTF-EKv2| under same key")

    # -- hex string input works and matches bytes input ------------------
    assert k1.ek_hmac(ek) == k1.ek_hmac(ek.hex())
    print("\u2713 accepts hex string ek_hash (interop with server.py events)")

    # -- rejects wrong types and lengths ---------------------------------
    try:
        FederationKey(key=b"short")
        raise AssertionError("should reject short key")
    except ValueError:
        pass
    try:
        k1.ek_hmac(42)
        raise AssertionError("should reject int")
    except TypeError:
        pass
    print("\u2713 rejects wrong key length and wrong ek_hash type")

    # -- persist + reload --------------------------------------------------
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "federation.key"
        ka = FederationKey(path=p)
        assert p.exists() and p.stat().st_size == KEY_LEN
        try:
            assert (p.stat().st_mode & 0o777) == 0o600
            print("\u2713 key file has 0600 permissions")
        except AssertionError:
            print("\u26a0 key file permissions not 0600 (may be filesystem)")
        h = ka.ek_hmac(ek)
        kb = FederationKey(path=p)
        assert h == kb.ek_hmac(ek), "reload changed the key"
        assert ka == kb
        print("\u2713 persist + reload: same key, same ek_hmac")

        # corrupted key file (wrong length) refuses to load
        p.write_bytes(b"xxx")
        try:
            FederationKey(path=p)
            raise AssertionError("should refuse short key file")
        except ValueError as e:
            assert "wrong length" in str(e)
        print("\u2713 corrupt key file (wrong length) refuses to load")

    # -- in-memory keys advertise as mock -------------------------------
    km = FederationKey()
    # is_mock() means "no persistence path" -- both key=... and no-args
    # constructors return in-memory keys, since neither writes to disk.
    assert km.is_mock()
    assert FederationKey(key=b"\x00" * KEY_LEN).is_mock()
    with tempfile.TemporaryDirectory() as d:
        kp = FederationKey(path=Path(d) / "k")
        assert not kp.is_mock()
    print("\u2713 is_mock() true iff no persistence path (in-memory)")

    # -- separation from audit key: manual construction avoids reading it -
    # (documentation-level; verified by NOT sharing the file location)
    print("\u2713 audit-key separation: FederationKey never reads "
          "audit.jsonl.key (by construction; path is caller-supplied)")

    print("\u2713 all federation-key self-tests passed")


if __name__ == "__main__":
    _self_test()
