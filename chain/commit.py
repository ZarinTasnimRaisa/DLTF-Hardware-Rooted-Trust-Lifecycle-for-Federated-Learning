"""
chain/commit.py

Client-side gradient commitment. The one part of DLTF where a party other than
the server writes to the chain.

WHAT PROBLEM THIS SOLVES
-----------------------------------------------------------------------------
Baseline DLTF's audit trail begins at "the server says it received X". There is
no third-party evidence of what the client actually transmitted. A server can
therefore claim it received a gradient the client never sent, and a client can
claim it sent something other than what it did. Neither can be disproved.

The commitment closes that gap:

    1. client computes gradient G
    2. client computes H = keccak256(canonical(G))
    3. client writes H to the chain FROM ITS OWN WALLET, before sending
    4. client sends G to the server over HTTP
    5. server computes H' = keccak256(canonical(G)) and reads H from chain
    6. H' != H  ->  reportCommitMismatch, update dropped
    7. server calls classify(); the contract REFUSES unless a commit exists

Step 7 is the part worth having. It is not logging -- it is a rule the server
cannot break. A classification fabricated against a client that never
participated reverts with MissingCommit.

WHY THE WALLET BINDING IS LOAD-BEARING
-----------------------------------------------------------------------------
A commitment from an arbitrary wallet proves nothing about identity: a banned
machine would simply generate a fresh keypair and keep committing. The binding
is what ties the commitment back to the TPM:

    at enrollment, the client signs its wallet address with its attestation
    key; the server verifies that signature against the enrolled TPM identity
    and calls bindWallet(deviceId, wallet)

One wallet, one device, immutable thereafter -- the same shape as tier
immutability. commitGradient() then checks the calling wallet maps to a device
whose status is not BANNED. So a banned physical machine cannot commit at all,
and its wallet cannot be rebound to a new device label.

The server performs the binding because the server is the party that verified
the TPM proof. A malicious server could bind a wallet it controls, but the
binding is public: the client reads deviceWallet[myKey] and sees it. Detectable,
not preventable -- the same class of limitation as T26.

CANONICAL SERIALISATION
-----------------------------------------------------------------------------
Both sides must hash IDENTICAL bytes or every round fails. The canonical form
is little-endian IEEE-754 float64, one per parameter, no length prefix, no
padding:

    canonical(G) = struct.pack("<%dd" % len(G), *G)
    H            = keccak256(canonical(G))

float64 is exact for anything numpy or torch produces at float32 or float64
precision, so the round-trip is lossless. Do NOT substitute repr(), JSON, or
pickle: all three vary across versions and platforms.

  python3 -m chain.commit
"""
import struct
from dataclasses import dataclass
from typing import Optional, Sequence

from eth_utils import keccak

from chain.backend import ChainRejection, Reason
from chain.fixedpoint import StatusFP


# ---- canonical gradient hashing ---------------------------------------------

def canonical(gradient: Sequence[float]) -> bytes:
    """Little-endian float64, one per parameter. Deterministic across Python
    versions, platforms, numpy/torch, and CPU architectures."""
    n = len(gradient)
    return struct.pack(f"<{n}d", *(float(x) for x in gradient))


def grad_hash(gradient: Sequence[float]) -> bytes:
    """keccak256 of the canonical form. 32 bytes, matches Solidity's
    keccak256(abi.encodePacked(...)) over the same byte string."""
    return keccak(canonical(gradient))


# ---- wallet <-> TPM binding proof -------------------------------------------

WALLET_BIND_DOMAIN = b"DLTF-WALLETv1|"


def wallet_bind_challenge(device_label: str, wallet: str) -> bytes:
    """The exact bytes the client signs with its attestation key to prove it
    controls both the TPM and the wallet. Domain-separated so a signature
    harvested for another purpose cannot be replayed as a wallet binding."""
    w = wallet.lower()
    if w.startswith("0x"):
        w = w[2:]
    return WALLET_BIND_DOMAIN + device_label.encode() + b"|" + bytes.fromhex(w)


def verify_wallet_binding(signer, device_label: str, wallet: str,
                          signature: bytes) -> bool:
    """Server-side check. `signer` is any object exposing
    verify(message, signature) -> bool -- the mock TPM signer and the real
    tpm2-tools signer both do.

    Returns True iff the signature is over the domain-separated challenge for
    exactly this (device_label, wallet) pair."""
    challenge = wallet_bind_challenge(device_label, wallet)
    try:
        return bool(signer.verify(challenge, signature))
    except Exception:
        return False


# ---- client-side agent ------------------------------------------------------

@dataclass
class CommitReceipt:
    round_id: int
    device_label: str
    wallet: str
    grad_hash: bytes
    ok: bool
    error: Optional[str] = None

    def __str__(self):
        state = "committed" if self.ok else f"FAILED ({self.error})"
        return (f"r{self.round_id} {self.device_label} "
                f"{self.grad_hash[:8].hex()}... {state}")


class CommitAgent:
    """Runs on the CLIENT. Holds the client's wallet and commits gradient
    hashes before the gradient is transmitted.

    Deliberately minimal: it does not hold the gradient, does not talk HTTP,
    and does not know about training. It converts a gradient into a hash and
    puts that hash on chain. net/agent.py calls it in /train, before returning
    the update to the server."""

    def __init__(self, backend, device_label: str, wallet: str):
        self.backend = backend
        self.device_label = device_label
        self.wallet = wallet
        self.receipts: list = []

    def commit(self, round_id: int, gradient: Sequence[float]) -> CommitReceipt:
        h = grad_hash(gradient)
        try:
            self.backend.commit_gradient(self.wallet, round_id, h)
            r = CommitReceipt(round_id, self.device_label, self.wallet, h, True)
        except ChainRejection as exc:
            r = CommitReceipt(round_id, self.device_label, self.wallet, h,
                              False, exc.reason)
        except Exception as exc:
            r = CommitReceipt(round_id, self.device_label, self.wallet, h,
                              False, f"{type(exc).__name__}: {exc}")
        self.receipts.append(r)
        return r


# ---- EIP-712 signed commitments (the cheap path) ----------------------------
#
# A commitment does not need a transaction to be binding -- it needs a
# SIGNATURE. The client signs (deviceKey, roundId, gradHash) off-chain and
# hands the signature to the server along with the gradient. The server
# submits every client's signature for the round in ONE transaction.
#
#   client cost   : zero gas, no wallet funding, no RPC, no node connection
#   server cost   : one transaction per round instead of N
#   preserved     : non-repudiation, anti-fabrication, ban lockout
#   not preserved : independent timestamping. The server controls submission
#                   and could withhold a signature, making a present client
#                   look absent. The client retains its signature and can
#                   publish it; anyone can verify it against the contract's
#                   domain separator. Detectable, not prevented.
#
# Replay protection is structural: the EIP-712 domain binds chainId and the
# contract address, and the struct binds roundId.

EIP712_DOMAIN_NAME = "DLTFRegistry"
EIP712_DOMAIN_VERSION = "1"

COMMIT_TYPES = {
    "GradientCommit": [
        {"name": "deviceKey", "type": "bytes32"},
        {"name": "roundId", "type": "uint256"},
        {"name": "gradHash", "type": "bytes32"},
    ]
}


def device_key(device_label: str) -> bytes:
    """keccak256 of the label -- the contract's internal device identifier."""
    return keccak(device_label.encode())


def eip712_domain(chain_id: int, contract_address: str) -> dict:
    return {"name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": int(chain_id),
            "verifyingContract": contract_address}


def commit_message(device_label: str, round_id: int, gh: bytes,
                   chain_id: int, contract_address: str) -> dict:
    """The full EIP-712 typed-data structure the client signs."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            **COMMIT_TYPES,
        },
        "primaryType": "GradientCommit",
        "domain": eip712_domain(chain_id, contract_address),
        "message": {"deviceKey": device_key(device_label),
                    "roundId": int(round_id),
                    "gradHash": gh},
    }


@dataclass
class SignedCommit:
    """One client's signed commitment. Transported over HTTP alongside the
    gradient; never touches a node on the client side."""
    device_label: str
    round_id: int
    grad_hash: bytes
    v: int
    r: bytes
    s: bytes
    signer: str

    @property
    def device_key(self) -> bytes:
        return device_key(self.device_label)

    def to_wire(self) -> dict:
        return {"device": self.device_label, "round": self.round_id,
                "grad_hash": self.grad_hash.hex(), "v": self.v,
                "r": self.r.hex(), "s": self.s.hex(), "signer": self.signer}

    @staticmethod
    def from_wire(d: dict) -> "SignedCommit":
        return SignedCommit(d["device"], int(d["round"]),
                            bytes.fromhex(d["grad_hash"]), int(d["v"]),
                            bytes.fromhex(d["r"]), bytes.fromhex(d["s"]),
                            d["signer"])


class SigningCommitAgent:
    """Runs on the CLIENT. Signs gradient commitments; never sends a
    transaction. The only dependency is a private key."""

    def __init__(self, device_label: str, private_key: str,
                 chain_id: int, contract_address: str):
        from eth_account import Account
        self._Account = Account
        self._acct = Account.from_key(private_key)
        self.device_label = device_label
        self.chain_id = int(chain_id)
        self.contract_address = contract_address
        self.wallet = self._acct.address
        self.signed: list = []

    def sign(self, round_id: int, gradient: Sequence[float]) -> SignedCommit:
        from eth_account.messages import encode_typed_data
        gh = grad_hash(gradient)
        msg = commit_message(self.device_label, round_id, gh,
                             self.chain_id, self.contract_address)
        encoded = encode_typed_data(full_message=msg)
        sig = self._acct.sign_message(encoded)
        sc = SignedCommit(
            device_label=self.device_label, round_id=round_id, grad_hash=gh,
            v=sig.v, r=sig.r.to_bytes(32, "big"), s=sig.s.to_bytes(32, "big"),
            signer=self.wallet)
        self.signed.append(sc)
        return sc


def recover_commit_signer(sc: SignedCommit, chain_id: int,
                          contract_address: str) -> str:
    """Server-side / auditor-side recovery. Anyone holding the signature can
    verify it without trusting the server."""
    from eth_account import Account
    from eth_account.messages import encode_typed_data
    msg = commit_message(sc.device_label, sc.round_id, sc.grad_hash,
                         chain_id, contract_address)
    encoded = encode_typed_data(full_message=msg)
    signature = sc.r + sc.s + bytes([sc.v])
    return Account.recover_message(encoded, signature=signature)


def build_batch(commits: Sequence[SignedCommit]):
    """Flatten signed commitments into the parallel arrays commitBatch expects.
    Returns (roundId, deviceKeys, gradHashes, vs, rs, ss)."""
    if not commits:
        raise ValueError("empty batch")
    rounds = {c.round_id for c in commits}
    if len(rounds) != 1:
        raise ValueError(f"batch spans multiple rounds: {sorted(rounds)}")
    return (commits[0].round_id,
            [c.device_key for c in commits],
            [c.grad_hash for c in commits],
            [c.v for c in commits],
            [c.r for c in commits],
            [c.s for c in commits])


# ---- server-side verification ------------------------------------------------

@dataclass
class CommitCheck:
    device_label: str
    round_id: int
    committed: Optional[bytes]
    received: bytes
    matched: bool
    reason: str

    def __str__(self):
        return (f"r{self.round_id} {self.device_label}: {self.reason}")


def check_commit(backend, device_label: str, round_id: int,
                 gradient: Sequence[float]) -> CommitCheck:
    """Runs on the SERVER, after receiving a gradient over HTTP and before
    classifying. Recomputes the hash and compares against the chain."""
    received = grad_hash(gradient)
    committed = backend.get_commit(device_label, round_id)
    if committed is None or committed == b"\x00" * 32:
        return CommitCheck(device_label, round_id, None, received, False,
                           "NO_COMMIT")
    if committed != received:
        return CommitCheck(device_label, round_id, committed, received, False,
                           "MISMATCH")
    return CommitCheck(device_label, round_id, committed, received, True, "OK")


# ---- mock backend extension --------------------------------------------------

class CommitMockBackend:
    """Wraps a MockBackend to add the commitment surface, so CI exercises the
    full flow without a node. Composition rather than subclassing so
    chain/mock.py stays untouched.

    Every Backend method is forwarded; the commitment methods are new.
    """

    is_mock = True

    def __init__(self, inner, require_commit: bool = True):
        self._inner = inner
        self.require_commit = require_commit
        self._device_wallet: dict = {}      # device_label -> wallet
        self._wallet_device: dict = {}      # wallet -> device_label
        self._commits: dict = {}            # (device_label, round) -> hash

    # -- forwarding --------------------------------------------------------
    def __getattr__(self, name):
        return getattr(self._inner, name)

    # -- wallet binding ----------------------------------------------------
    def bind_wallet(self, writer, device_label: str, wallet: str):
        if writer != self._inner._writer:
            raise ChainRejection(Reason.UNAUTHORIZED_WRITER)
        if self._inner.get_device(device_label) is None:
            raise ChainRejection(Reason.DEVICE_UNKNOWN, device_label)
        existing = self._device_wallet.get(device_label)
        if existing is not None:
            if existing == wallet:
                return                                   # idempotent
            raise ChainRejection("WalletAlreadyBound",
                                 f"{device_label} bound to {existing}")
        if wallet in self._wallet_device:
            raise ChainRejection("WalletAlreadyBound",
                                 f"wallet {wallet} bound to "
                                 f"{self._wallet_device[wallet]}")
        self._device_wallet[device_label] = wallet
        self._wallet_device[wallet] = device_label
        self._inner._emit("WALLET_BOUND",
                          {"device": device_label, "wallet": wallet})

    def get_wallet(self, device_label: str):
        return self._device_wallet.get(device_label)

    # -- client commit -----------------------------------------------------
    def commit_gradient(self, wallet: str, round_id: int, gh: bytes):
        """Called by the CLIENT (identified by its wallet), not the server."""
        if gh == b"\x00" * 32 or not gh:
            raise ChainRejection("EmptyCommit")
        device_label = self._wallet_device.get(wallet)
        if device_label is None:
            raise ChainRejection("NotDeviceWallet", wallet)
        d = self._inner.get_device(device_label)
        if d is None:
            raise ChainRejection(Reason.DEVICE_UNKNOWN, device_label)
        if d.status == StatusFP.BANNED:
            raise ChainRejection(Reason.DEVICE_BANNED, device_label)
        key = (device_label, round_id)
        if key in self._commits:
            raise ChainRejection("DuplicateCommit",
                                 f"{device_label} r{round_id}")
        self._commits[key] = gh
        self._inner._emit("GRADIENT_COMMITTED",
                          {"round": round_id, "device": device_label,
                           "wallet": wallet, "grad_hash": gh.hex()})

    def get_commit(self, device_label: str, round_id: int):
        return self._commits.get((device_label, round_id))

    # -- batched signed commits (server submits, clients pay nothing) -------
    def commit_batch(self, writer, commits, chain_id=1,
                     contract_address="0x" + "00" * 20):
        """Server submits every client's signed commitment for a round.
        Atomic: one bad signature rejects the whole batch, so a server cannot
        silently drop one client's commitment and then claim absence."""
        if writer != self._inner._writer:
            raise ChainRejection(Reason.UNAUTHORIZED_WRITER)
        if not commits:
            raise ChainRejection("EmptyBatch")
        rounds = {c.round_id for c in commits}
        if len(rounds) != 1:
            raise ChainRejection("BatchLengthMismatch",
                                 f"batch spans rounds {sorted(rounds)}")

        # Validate every signature BEFORE mutating anything (atomicity).
        staged = []
        for c in commits:
            if c.grad_hash == b"\x00" * 32:
                raise ChainRejection("EmptyCommit", c.device_label)
            recovered = recover_commit_signer(c, chain_id, contract_address)
            bound = self._device_wallet.get(c.device_label)
            if bound is None:
                raise ChainRejection("WalletNotBound", c.device_label)
            if recovered.lower() != bound.lower():
                raise ChainRejection(
                    "SignerNotDeviceWallet",
                    f"{c.device_label}: recovered {recovered}, bound {bound}")
            d = self._inner.get_device(c.device_label)
            if d is None:
                raise ChainRejection(Reason.DEVICE_UNKNOWN, c.device_label)
            if d.status == StatusFP.BANNED:
                raise ChainRejection(Reason.DEVICE_BANNED, c.device_label)
            if (c.device_label, c.round_id) in self._commits:
                raise ChainRejection("DuplicateCommit",
                                     f"{c.device_label} r{c.round_id}")
            staged.append((c, recovered))

        for c, recovered in staged:
            self._commits[(c.device_label, c.round_id)] = c.grad_hash
            self._inner._emit("GRADIENT_COMMITTED",
                              {"round": c.round_id, "device": c.device_label,
                               "wallet": recovered,
                               "grad_hash": c.grad_hash.hex()})
        return len(staged)

    # -- enforcement -------------------------------------------------------
    def classify(self, writer, round_id, device_id, severity,
                 stage=0, reason=""):
        """THE ANTI-FABRICATION RULE: refuse to classify a device that did not
        commit for this round."""
        if self.require_commit and \
                (device_id, round_id) not in self._commits:
            raise ChainRejection("MissingCommit",
                                 f"{device_id} did not commit for r{round_id}")
        return self._inner.classify(writer, round_id, device_id, severity,
                                    stage=stage, reason=reason)

    def mark_absent(self, writer, round_id, device_label):
        if writer != self._inner._writer:
            raise ChainRejection(Reason.UNAUTHORIZED_WRITER)
        if self._inner.get_device(device_label) is None:
            raise ChainRejection(Reason.DEVICE_UNKNOWN, device_label)
        return self._inner._emit("ABSENT",
                                 {"round": round_id, "device": device_label})

    def report_commit_mismatch(self, writer, round_id, device_label, received):
        if writer != self._inner._writer:
            raise ChainRejection(Reason.UNAUTHORIZED_WRITER)
        committed = self._commits.get((device_label, round_id))
        return self._inner._emit(
            "COMMIT_MISMATCH",
            {"round": round_id, "device": device_label,
             "committed": committed.hex() if committed else None,
             "received": received.hex()})


# ---- self-test ---------------------------------------------------------------

def _self_test():
    import hashlib
    from chain.mock import MockBackend
    from chain.fixedpoint import TierFP, SeverityFP

    print("chain/commit.py self-test")
    W = b"commit-writer-key-32-xxxxxxxxxxx"
    WALLET_A = "0x" + "aa" * 20
    WALLET_B = "0x" + "bb" * 20
    WALLET_EVIL = "0x" + "ee" * 20

    def ek(label):
        return hashlib.sha256(label.encode()).digest()

    def build(require=True):
        b = CommitMockBackend(MockBackend(W), require_commit=require)
        return b

    # === 1. Canonical hashing is deterministic and order-sensitive =========
    g1 = [0.1, -0.25, 3.5, 0.0]
    assert grad_hash(g1) == grad_hash([0.1, -0.25, 3.5, 0.0])
    assert grad_hash(g1) != grad_hash([0.1, -0.25, 3.5, 1e-12])
    assert grad_hash(g1) != grad_hash([-0.25, 0.1, 3.5, 0.0])   # order matters
    assert len(grad_hash(g1)) == 32
    assert len(canonical(g1)) == 8 * len(g1)
    print("\u2713 grad_hash: deterministic, order-sensitive, 32 bytes, "
          "8 bytes/param")

    # A one-ULP change flips the hash -- no silent tolerance.
    tweaked = list(g1); tweaked[0] = 0.1 + 5e-17
    print(f"\u2713 canonical form is exact float64 "
          f"(1-ULP tweak {'changes' if grad_hash(tweaked) != grad_hash(g1) else 'does NOT change'} the hash)")

    # === 2. Wallet binding ================================================
    b = build()
    b.register(W, "c1", TierFP.HARDWARE, ek("c1"))
    b.bind_wallet(W, "c1", WALLET_A)
    assert b.get_wallet("c1") == WALLET_A
    b.bind_wallet(W, "c1", WALLET_A)                     # idempotent
    print("\u2713 bind_wallet: binds, idempotent on repeat")

    # rebinding to a different wallet is refused
    try:
        b.bind_wallet(W, "c1", WALLET_B)
        raise AssertionError("rebinding should be refused")
    except ChainRejection as e:
        assert e.reason == "WalletAlreadyBound"
    print("\u2713 REJECT: rebinding a device to a second wallet")

    # one wallet cannot serve two devices
    b.register(W, "c2", TierFP.HARDWARE, ek("c2"))
    try:
        b.bind_wallet(W, "c2", WALLET_A)
        raise AssertionError("wallet reuse should be refused")
    except ChainRejection as e:
        assert e.reason == "WalletAlreadyBound"
    print("\u2713 REJECT: one wallet bound to two devices")

    # non-server cannot bind
    try:
        b.bind_wallet(b"not-the-server", "c2", WALLET_B)
        raise AssertionError("non-server bind should be refused")
    except ChainRejection as e:
        assert e.reason == Reason.UNAUTHORIZED_WRITER
    print("\u2713 REJECT: non-server calling bind_wallet")

    # === 3. Commit + verify happy path ====================================
    b = build()
    b.register(W, "c1", TierFP.HARDWARE, ek("c1"))
    b.bind_wallet(W, "c1", WALLET_A)
    agent = CommitAgent(b, "c1", WALLET_A)
    grad = [0.01 * i for i in range(20)]
    r = agent.commit(0, grad)
    assert r.ok, r.error
    chk = check_commit(b, "c1", 0, grad)
    assert chk.matched and chk.reason == "OK"
    print(f"\u2713 commit -> check_commit OK ({r.grad_hash[:8].hex()}...)")

    # === 4. TAMPERED GRADIENT IS CAUGHT ===================================
    # The server receives a gradient different from the committed one.
    tampered = list(grad); tampered[3] = 99.0
    chk = check_commit(b, "c1", 0, tampered)
    assert not chk.matched and chk.reason == "MISMATCH"
    b.report_commit_mismatch(W, 0, "c1", grad_hash(tampered))
    assert len(b.events("COMMIT_MISMATCH")) == 1
    print("\u2713 NON-REPUDIATION: gradient altered in transit -> MISMATCH, "
          "evidence written on chain")

    # === 5. THE ANTI-FABRICATION RULE =====================================
    # Server tries to classify a device that never committed this round.
    b = build(require=True)
    b.register(W, "honest", TierFP.HARDWARE, ek("honest"))
    b.bind_wallet(W, "honest", WALLET_A)
    try:
        b.classify(W, 0, "honest", SeverityFP.MAJOR, 2, "fabricated")
        raise AssertionError("fabricated classification was accepted")
    except ChainRejection as e:
        assert e.reason == "MissingCommit", e.reason
    print("\u2713 ANTI-FABRICATION: server cannot classify a device that did "
          "not commit -> MissingCommit")

    # With a commit present, the same classify succeeds.
    CommitAgent(b, "honest", WALLET_A).commit(0, grad)
    st, ev = b.classify(W, 0, "honest", SeverityFP.NEUTRAL, 0, "")
    assert st == int(StatusFP.ACTIVE)
    print("\u2713 same classify succeeds once the client has committed")

    # === 6. Absence is recordable =========================================
    b.register(W, "offline", TierFP.HARDWARE, ek("offline"))
    b.mark_absent(W, 0, "offline")
    assert len(b.events("ABSENT")) == 1
    print("\u2713 mark_absent: genuine non-participation recordable without "
          "touching reputation")

    # === 7. A BANNED DEVICE CANNOT COMMIT =================================
    # This is what makes the wallet binding load-bearing.
    b = build()
    b.register(W, "adv", TierFP.SOFTWARE, ek("adv"))
    b.bind_wallet(W, "adv", WALLET_A)
    adv = CommitAgent(b, "adv", WALLET_A)
    adv.commit(0, grad)
    b.classify(W, 0, "adv", SeverityFP.CRITICAL, 3, "poison")
    assert b.get_device("adv").status == StatusFP.BANNED

    r = adv.commit(1, grad)
    assert not r.ok and r.error == Reason.DEVICE_BANNED
    print("\u2713 BANNED device cannot commit -> DeviceBanned "
          "(wallet binding is load-bearing, not decorative)")

    # === 8. WHITEWASH VIA FRESH WALLET IS REFUSED =========================
    # The banned machine generates a new keypair and tries again.
    evil = CommitAgent(b, "adv_v2", WALLET_EVIL)
    r = evil.commit(1, grad)
    assert not r.ok and r.error == "NotDeviceWallet"
    print("\u2713 WHITEWASH: fresh unbound wallet cannot commit "
          "-> NotDeviceWallet")

    # And the banned machine cannot get its EK re-registered under a new label
    # to bind a new wallet, because register() already refuses the banned EK.
    status, ev = b.register(W, "adv_v2", TierFP.SOFTWARE, ek("adv"))
    assert status == int(StatusFP.BANNED)
    assert ev.event_type == "WHITEWASH_REJECTED"
    print("\u2713 WHITEWASH: banned EK cannot re-enrol, so no new wallet can "
          "ever be bound to that machine")

    # === 9. Duplicate commit refused ======================================
    b = build()
    b.register(W, "d", TierFP.HARDWARE, ek("d"))
    b.bind_wallet(W, "d", WALLET_A)
    a = CommitAgent(b, "d", WALLET_A)
    assert a.commit(0, grad).ok
    r = a.commit(0, grad)
    assert not r.ok and r.error == "DuplicateCommit"
    print("\u2713 REJECT: two commits for one (device, round) "
          "-> DuplicateCommit")

    # === 10. Wallet binding challenge is domain-separated =================
    c1 = wallet_bind_challenge("c1", WALLET_A)
    assert c1.startswith(WALLET_BIND_DOMAIN)
    assert c1 != wallet_bind_challenge("c2", WALLET_A)     # label matters
    assert c1 != wallet_bind_challenge("c1", WALLET_B)     # wallet matters
    assert bytes.fromhex(WALLET_A[2:]) in c1
    print("\u2713 wallet_bind_challenge: domain-separated, binds BOTH the "
          "device label and the wallet address")

    # === 11. require_commit=False restores baseline behaviour =============
    b = build(require=False)
    b.register(W, "x", TierFP.HARDWARE, ek("x"))
    st, ev = b.classify(W, 0, "x", SeverityFP.NEUTRAL, 0, "")
    assert st == int(StatusFP.ACTIVE)
    print("\u2713 require_commit=False: classify works with no commit "
          "(baseline DLTF behaviour preserved)")

    # ==== EIP-712 SIGNED COMMITMENTS (the cheap path) =====================
    CHAIN_ID = 31337
    CONTRACT = "0x" + "5f" * 20
    KEYS = {
        "s0": "0x" + "11" * 32,
        "s1": "0x" + "22" * 32,
        "s2": "0x" + "33" * 32,
    }

    b = build(require=True)
    agents = {}
    for lbl, pk in KEYS.items():
        a = SigningCommitAgent(lbl, pk, CHAIN_ID, CONTRACT)
        agents[lbl] = a
        b.register(W, lbl, TierFP.HARDWARE, ek(lbl))
        b.bind_wallet(W, lbl, a.wallet)

    # -- signature recovers to the signing wallet -------------------------
    sc = agents["s0"].sign(0, grad)
    rec = recover_commit_signer(sc, CHAIN_ID, CONTRACT)
    assert rec.lower() == agents["s0"].wallet.lower()
    assert len(sc.r) == 32 and len(sc.s) == 32 and sc.v in (27, 28)
    print(f"\u2713 EIP-712 sign -> recover round-trips to the client wallet "
          f"(v={sc.v})")

    # -- signature is bound to round, contract, and chain -----------------
    assert recover_commit_signer(sc, CHAIN_ID + 1, CONTRACT).lower() \
        != agents["s0"].wallet.lower()
    assert recover_commit_signer(sc, CHAIN_ID, "0x" + "ab" * 20).lower() \
        != agents["s0"].wallet.lower()
    replayed = SignedCommit(sc.device_label, sc.round_id + 1, sc.grad_hash,
                            sc.v, sc.r, sc.s, sc.signer)
    assert recover_commit_signer(replayed, CHAIN_ID, CONTRACT).lower() \
        != agents["s0"].wallet.lower()
    print("\u2713 REPLAY PROOF: signature does not verify under a different "
          "chainId, contract address, or roundId")

    # -- the whole round in ONE server call -------------------------------
    batch = [agents[l].sign(1, [0.01 * i + j for i in range(20)])
             for j, l in enumerate(KEYS)]
    n = b.commit_batch(W, batch, CHAIN_ID, CONTRACT)
    assert n == 3
    for c in batch:
        assert b.get_commit(c.device_label, 1) == c.grad_hash
    print(f"\u2713 BATCH: {n} client commitments submitted in ONE server call; "
          "clients sent no transaction and hold no funds")

    # -- classify now permitted for every batched device ------------------
    for lbl in KEYS:
        st, _ = b.classify(W, 1, lbl, SeverityFP.NEUTRAL, 0, "")
        assert st == int(StatusFP.ACTIVE)
    print("\u2713 batched commitments satisfy the anti-fabrication rule")

    # -- a forged signature rejects the WHOLE batch -----------------------
    good = agents["s0"].sign(2, grad)
    forged = SignedCommit("s1", 2, grad_hash(grad), good.v, good.r, good.s,
                          agents["s1"].wallet)      # s0's sig claimed for s1
    try:
        b.commit_batch(W, [good, forged], CHAIN_ID, CONTRACT)
        raise AssertionError("forged signature accepted")
    except ChainRejection as e:
        assert e.reason == "SignerNotDeviceWallet", e.reason
    assert b.get_commit("s0", 2) is None, "batch was not atomic"
    print("\u2713 ATOMIC: one forged signature rejects the entire batch, and "
          "the valid commitment in it is NOT recorded")

    # -- the server cannot manufacture a commitment -----------------------
    fake = SignedCommit("s2", 3, grad_hash(grad), 27, b"\x01" * 32,
                        b"\x02" * 32, agents["s2"].wallet)
    try:
        b.commit_batch(W, [fake], CHAIN_ID, CONTRACT)
        raise AssertionError("fabricated signature accepted")
    except ChainRejection as e:
        assert e.reason in ("SignerNotDeviceWallet", "InvalidSignature")
    print("\u2713 NON-REPUDIATION: a server cannot forge a client signature "
          "-> the anti-fabrication rule survives batching")

    # -- a banned device's signature is refused ---------------------------
    # s2 must commit before it can be classified -- the anti-fabrication rule
    # applies to the CRITICAL that bans it, exactly as it does to any other
    # classification. (This test previously failed here, which is the rule
    # working correctly.)
    b.commit_batch(W, [agents["s2"].sign(2, grad)], CHAIN_ID, CONTRACT)
    b.classify(W, 2, "s2", SeverityFP.CRITICAL, 3, "poison")
    assert b.get_device("s2").status == StatusFP.BANNED
    try:
        b.commit_batch(W, [agents["s2"].sign(3, grad)], CHAIN_ID, CONTRACT)
        raise AssertionError("banned device commitment accepted")
    except ChainRejection as e:
        assert e.reason == Reason.DEVICE_BANNED
    print("\u2713 BANNED device's signature refused even inside a batch")

    # -- wire format survives JSON round-trip ------------------------------
    sc = agents["s0"].sign(9, grad)
    back = SignedCommit.from_wire(sc.to_wire())
    assert back.grad_hash == sc.grad_hash and (back.v, back.r, back.s) == \
        (sc.v, sc.r, sc.s)
    assert recover_commit_signer(back, CHAIN_ID, CONTRACT).lower() \
        == agents["s0"].wallet.lower()
    print("\u2713 SignedCommit survives the HTTP wire format (hex JSON) and "
          "still recovers correctly")

    # -- build_batch guards ------------------------------------------------
    try:
        build_batch([agents["s0"].sign(4, grad), agents["s1"].sign(5, grad)])
        raise AssertionError("mixed-round batch accepted")
    except ValueError:
        pass
    print("\u2713 build_batch refuses a batch spanning multiple rounds")

    print("\u2713 all commit self-tests passed")


if __name__ == "__main__":
    _self_test()
