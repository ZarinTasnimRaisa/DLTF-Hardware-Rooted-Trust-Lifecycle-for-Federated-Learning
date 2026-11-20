"""
tpm/client.py

Client-side TPM signer with pluggable backends, selected by config.tpm_backend:

  mock   pure-Python, deterministic per device label. Passes credential
         activation against the mock MakeCredential in common.py, so the local
         federation runs with no hardware. No real security (by construction).
  swtpm  tpm2-tools against a software TPM socket. Machine-side.
  real   tpm2-tools against /dev/tpmrm0. Machine-side. This is the only backend
         that can reach Tier 1, and only where the platform ships a verifiable
         EK certificate.

Enrollment contract used by fl/server.py:
  prov = signer.provision()                       # ek_cert (maybe None), ek_hash, ak_name
  blob, secret = make_credential(...)             # server challenge
  ok = signer.activate_credential(blob) == secret # proof of TPM residency
  tier = assess_tier(cert_verified, ok)           # cert raises the ceiling to Tier 1

The real/swtpm command sequences cannot run in this sandbox (no tpm2-tools); the
mock path is exercised by the self-test.
"""
import os
import hmac
import hashlib
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass

from tpm.common import (b64d, b64e, sha256_hex, run, mock_key, mock_ek_hash)


@dataclass
class ProvisionResult:
    ek_hash: str
    ak_name: str
    ek_cert_der: bytes = None      # None when the platform has no fetchable EK cert
    ek_pub_path: str = None        # used by the server's real make_credential
    ak_pub_path: str = None


class TPMSigner(ABC):
    @abstractmethod
    def provision(self):
        ...

    @abstractmethod
    def activate_credential(self, blob_b64):
        ...

    @abstractmethod
    def sign_challenge(self, nonce):
        """Return a signature over nonce for optional per-round liveness checks."""
        ...

    def sign_message(self, message: bytes) -> bytes:
        """Sign ARBITRARY bytes with the attestation key. Used for wallet
        binding (chain/commit.py::wallet_bind_challenge).

        Deliberately separate from sign_challenge(): on real hardware that one
        produces a tpm2_quote over PCRs with the nonce in the qualifying-data
        field, which is NOT a signature over caller-supplied bytes and cannot
        be verified as one. Overloading it would have silently produced
        unverifiable wallet bindings."""
        raise NotImplementedError(f"{type(self).__name__} cannot sign "
                                  f"arbitrary messages")

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature this signer produced. Present so
        chain/commit.py::verify_wallet_binding can accept a signer directly
        in SIM. In REAL mode the server has no signer object, only the AK
        public key -- use verify_ak_signature() instead."""
        raise NotImplementedError(f"{type(self).__name__} cannot verify")


class MockTPMSigner(TPMSigner):
    def __init__(self, device_label, ek_cert_der=None):
        self.label = device_label
        self._cert = ek_cert_der

    def provision(self):
        if self._cert is not None:
            ek_hash = _ek_hash_from_cert(self._cert)
        else:
            ek_hash = mock_ek_hash(self.label)
        ak_name = sha256_hex(b"DLTF-MOCK-AK|" + self.label.encode())
        return ProvisionResult(ek_hash=ek_hash, ak_name=ak_name, ek_cert_der=self._cert)

    def activate_credential(self, blob_b64):
        raw = b64d(blob_b64)
        nonce, ct = raw[:16], raw[16:]
        ks = hmac.new(mock_key(self.label), nonce, hashlib.sha256).digest()[:len(ct)]
        return bytes(a ^ b for a, b in zip(ct, ks))

    def sign_challenge(self, nonce):
        return b64e(hmac.new(mock_key(self.label), nonce, hashlib.sha256).digest())

    # ---- wallet binding (arbitrary-message signing) ----
    # Domain-separated from sign_challenge so a harvested liveness signature
    # can never be replayed as a wallet binding, and vice versa.
    _MSG_TAG = b"DLTF-MOCK-MSG|"

    def sign_message(self, message: bytes) -> bytes:
        return hmac.new(mock_key(self.label), self._MSG_TAG + message,
                        hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        expect = hmac.new(mock_key(self.label), self._MSG_TAG + message,
                          hashlib.sha256).digest()
        return hmac.compare_digest(expect, signature)


def verify_mock_challenge(device_label, nonce, sig_b64):
    """Server-side check for a mock liveness signature."""
    expect = hmac.new(mock_key(device_label), nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expect, b64d(sig_b64))


def _ek_hash_from_cert(cert_der):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_der_x509_certificate(cert_der)
    pub = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(pub)


# ---- hardware backends (machine-side, require tpm2-tools) ---------------------

class _Tpm2Signer(TPMSigner):
    """Shared tpm2-tools workflow for swtpm and real TPMs."""

    def __init__(self, device_label, tcti=None):
        self.label = device_label
        self.tcti = tcti
        self.workdir = tempfile.mkdtemp(prefix=f"dltf_{device_label}_")
        self._ek_ctx = os.path.join(self.workdir, "ek.ctx")
        self._ak_ctx = os.path.join(self.workdir, "ak.ctx")
        self._ek_pub = os.path.join(self.workdir, "ek.pub")
        self._ak_pub = os.path.join(self.workdir, "ak.pub")
        self._ak_name = os.path.join(self.workdir, "ak.name")

    def _t(self, cmd):
        return cmd + (["-T", self.tcti] if self.tcti else [])

    def provision(self):
        run(self._t(["tpm2_createek", "-c", self._ek_ctx, "-G", "rsa", "-u", self._ek_pub]))
        run(self._t(["tpm2_createak", "-C", self._ek_ctx, "-c", self._ak_ctx,
                     "-G", "rsa", "-g", "sha256", "-s", "rsassa",
                     "-u", self._ak_pub, "-n", self._ak_name]))
        with open(self._ak_name, "rb") as f:
            ak_name = f.read().hex()
        with open(self._ek_pub, "rb") as f:
            ek_hash = sha256_hex(f.read())
        ek_cert = self._try_ek_cert()
        return ProvisionResult(ek_hash=ek_hash, ak_name=ak_name, ek_cert_der=ek_cert,
                               ek_pub_path=self._ek_pub, ak_pub_path=self._ak_pub)

    def _try_ek_cert(self):
        # Prefer a verified on-disk cert (AMD PKI live-fetch is flaky); fetch as fallback.
        for p in ("cert/ek.crt", "ek.crt"):
            if os.path.exists(p):
                with open(p, "rb") as f:
                    return f.read()
        out = os.path.join(self.workdir, "ek.crt")
        try:
            run(self._t(["tpm2_getekcertificate", "-u", self._ek_pub, "-o", out, "-X"]))
            with open(out, "rb") as f:
                return f.read()
        except Exception:
            return None

    def activate_credential(self, blob_b64):
        blob = os.path.join(self.workdir, "cred.blob")
        secret = os.path.join(self.workdir, "cred.secret")
        session = os.path.join(self.workdir, "session.ctx")
        with open(blob, "wb") as f:
            f.write(b64d(blob_b64))
        run(self._t(["tpm2_startauthsession", "--policy-session", "-S", session]))
        try:
            run(self._t(["tpm2_policysecret", "-S", session, "-c", "endorsement"]))
            run(self._t(["tpm2_activatecredential", "-c", self._ak_ctx, "-C", self._ek_ctx,
                         "-i", blob, "-o", secret, "-P", f"session:{session}"]))
        finally:
            run(self._t(["tpm2_flushcontext", session]))
        with open(secret, "rb") as f:
            return f.read()

    def sign_challenge(self, nonce):
        msg = os.path.join(self.workdir, "quote.msg")
        sig = os.path.join(self.workdir, "quote.sig")
        pcr = os.path.join(self.workdir, "quote.pcr")
        run(self._t(["tpm2_quote", "-c", self._ak_ctx, "-l", "sha256:0",
                     "-q", nonce.hex(), "-m", msg, "-s", sig, "-o", pcr]))
        with open(sig, "rb") as f:
            return b64e(f.read())

    def sign_message(self, message: bytes) -> bytes:
        """tpm2_sign over arbitrary bytes with the AK. RSASSA/SHA-256, so the
        server can verify with the AK public key alone.

        MACHINE-SIDE ONLY: needs tpm2-tools and a TPM, so it is exercised on
        the experiment machines, not in the sandbox self-test."""
        msg_path = os.path.join(self.workdir, "bind.msg")
        sig_path = os.path.join(self.workdir, "bind.sig")
        with open(msg_path, "wb") as f:
            f.write(message)
        run(self._t(["tpm2_sign", "-c", self._ak_ctx, "-g", "sha256",
                     "-s", "rsassa", "-f", "plain",
                     "-o", sig_path, msg_path]))
        with open(sig_path, "rb") as f:
            return f.read()

    def ak_public_pem(self) -> bytes:
        """AK public key in PEM, for the server to keep at enrollment so it
        can verify wallet bindings later without the signer object."""
        pem = os.path.join(self.workdir, "ak.pem")
        run(self._t(["tpm2_readpublic", "-c", self._ak_ctx, "-f", "pem",
                     "-o", pem]))
        with open(pem, "rb") as f:
            return f.read()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return verify_ak_signature(self.ak_public_pem(), message, signature)


class SwtpmSigner(_Tpm2Signer):
    def __init__(self, device_label, tcti="swtpm:host=127.0.0.1,port=2321"):
        super().__init__(device_label, tcti)


class RealTPMSigner(_Tpm2Signer):
    def __init__(self, device_label, tcti="device:/dev/tpmrm0"):
        super().__init__(device_label, tcti)


def verify_ak_signature(ak_pub_pem_or_der, message: bytes,
                        signature: bytes) -> bool:
    """Server-side wallet-binding check for REAL mode.

    The server does NOT have the client's signer object -- it has the AK
    public key recorded at enrollment. RSASSA-PKCS1v15 over SHA-256, matching
    _Tpm2Signer.sign_message()'s tpm2_sign flags."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    try:
        try:
            pub = serialization.load_pem_public_key(ak_pub_pem_or_der)
        except ValueError:
            pub = serialization.load_der_public_key(ak_pub_pem_or_der)
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(signature, message, padding.PKCS1v15(),
                       hashes.SHA256())
        return True
    except Exception:
        return False


def make_signer(backend, device_label, tcti=None, ek_cert_der=None):
    if backend == "mock":
        return MockTPMSigner(device_label, ek_cert_der=ek_cert_der)
    if backend == "swtpm":
        return SwtpmSigner(device_label, tcti) if tcti else SwtpmSigner(device_label)
    if backend == "real":
        return RealTPMSigner(device_label, tcti) if tcti else RealTPMSigner(device_label)
    raise ValueError(f"unknown tpm backend: {backend}")


def _self_test():
    print("tpm/client.py self-test")
    from tpm.common import make_credential, assess_tier, Tier, generate_test_ca, issue_ek_cert

    # Mock enrollment without an EK cert -> activation passes -> Tier 2.
    signer = make_signer("mock", "client3")
    prov = signer.provision()
    assert prov.ek_cert_der is None
    blob, secret = make_credential("mock", device_label="client3")
    ok = signer.activate_credential(blob) == secret
    assert ok
    tier = assess_tier(prov.ek_cert_der is not None, ok).tier
    assert tier == Tier.TPM_RESIDENT
    print("✓ mock enroll, no cert -> activation passes -> Tier 2 (TPM_RESIDENT)")

    # An impostor with the wrong label cannot answer the challenge.
    impostor = make_signer("mock", "attacker")
    assert impostor.activate_credential(blob) != secret
    print("✓ wrong-label device fails credential activation")

    # Mock enrollment WITH a test EK cert -> Tier 1, enabling the rehab lifecycle.
    ca_key, ca_cert = generate_test_ca()
    der, ek_hash = issue_ek_cert(ca_key, ca_cert, "client0")
    hw = make_signer("mock", "client0", ek_cert_der=der)
    prov_hw = hw.provision()
    assert prov_hw.ek_cert_der is not None and prov_hw.ek_hash == ek_hash
    blob0, secret0 = make_credential("mock", device_label="client0")
    ok0 = hw.activate_credential(blob0) == secret0
    tier0 = assess_tier(True, ok0).tier      # cert verified upstream by the server
    assert tier0 == Tier.HARDWARE
    print("✓ mock enroll with test EK cert -> Tier 1 (HARDWARE) for eval")

    # Liveness signature round-trips and rejects tampering.
    nonce = os.urandom(16)
    sig = signer.sign_challenge(nonce)
    assert verify_mock_challenge("client3", nonce, sig)
    assert not verify_mock_challenge("client3", os.urandom(16), sig)
    print("✓ mock liveness challenge verifies and rejects a wrong nonce")

    assert isinstance(make_signer("swtpm", "c"), SwtpmSigner)
    assert isinstance(make_signer("real", "c"), RealTPMSigner)
    print("✓ factory returns swtpm/real signers (command paths run machine-side)")

    # ---- wallet binding (chain commitment layer) ----
    from chain.commit import wallet_bind_challenge, verify_wallet_binding
    wallet = "0x" + "ab" * 20
    ch = wallet_bind_challenge("client3", wallet)
    sig = signer.sign_message(ch)
    assert verify_wallet_binding(signer, "client3", wallet, sig)
    print("✓ wallet binding: AK signature over the domain-separated challenge verifies")

    # wrong wallet, wrong device, and a tampered signature must all fail
    assert not verify_wallet_binding(signer, "client3", "0x" + "cd" * 20, sig)
    assert not verify_wallet_binding(impostor, "client3", wallet, sig)
    assert not verify_wallet_binding(signer, "client3", wallet, sig[:-1] + b"\x00")
    print("✓ wallet binding rejects a different wallet, a different device, and a tampered signature")

    # sign_message must be domain-separated from sign_challenge, or a
    # liveness signature could be replayed as a wallet binding
    nonce = b"\x01" * 16
    assert b64d(signer.sign_challenge(nonce)) != signer.sign_message(nonce)
    print("✓ sign_message is domain-separated from sign_challenge (no cross-replay)")

    # a signer with no arbitrary-message capability fails loudly, not silently
    class Bare(TPMSigner):
        def provision(self): ...
        def activate_credential(self, b): ...
        def sign_challenge(self, n): ...
    try:
        Bare().sign_message(b"x"); raise AssertionError("should have raised")
    except NotImplementedError:
        print("✓ a signer lacking sign_message raises NotImplementedError, never a silent pass")
    print("✓ all client self-tests passed")


if __name__ == "__main__":
    _self_test()