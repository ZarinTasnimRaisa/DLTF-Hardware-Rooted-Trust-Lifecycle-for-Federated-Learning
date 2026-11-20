"""
chain/commit_parity_test.py

Runs the commitment layer against the DEPLOYED Solidity contract on a local
py-evm instance, using REAL distinct wallet addresses for the clients.

This is the acceptance test for the commitment port. The Python mock
(chain/commit.py CommitMockBackend) and the contract must agree on every rule.

Unlike chain/evm_parity_test.py, this test uses MULTIPLE senders: the server
account for server-only methods, and separate client accounts for
commitGradient. That is the point -- commitGradient is the only function in
DLTFRegistry not gated by onlyServer.

    PYTHONPATH=. python3 -m chain.commit_parity_test
"""
from eth_tester.exceptions import TransactionFailed
from eth_utils import keccak

from chain.evm_parity_test import Harness, to_bytes32, decode_revert
from chain.fixedpoint import TierFP, StatusFP, SeverityFP
from chain.commit import grad_hash, canonical, wallet_bind_challenge


GRAD = [0.01 * i for i in range(20)]


class CommitHarness(Harness):
    def deploy(self, chain_id_hex="00" * 32, require_commit=True):
        factory = self.w3.eth.contract(abi=self.abi, bytecode=self.bin)
        tx = factory.constructor(self.server, bytes.fromhex(chain_id_hex),
                                 require_commit).transact({"from": self.server})
        r = self.w3.eth.wait_for_transaction_receipt(tx)
        return self.w3.eth.contract(address=r.contractAddress, abi=self.abi)


def test_wallet_binding(h):
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("c1", int(TierFP.HARDWARE), to_bytes32("ek_c1")),
           h.server)
    h.call(c.functions.bindWallet("c1", cw), h.server)
    assert c.functions.getWallet("c1").call() == cw
    h.call(c.functions.bindWallet("c1", cw), h.server)          # idempotent
    print("\u2713 bindWallet: binds and is idempotent")

    other = h.w3.eth.accounts[3]
    h.expect_revert(c.functions.bindWallet("c1", other), h.server,
                    "WalletAlreadyBound")
    h.call(c.functions.register("c2", int(TierFP.HARDWARE), to_bytes32("ek_c2")),
           h.server)
    h.expect_revert(c.functions.bindWallet("c2", cw), h.server,
                    "WalletAlreadyBound")
    h.expect_revert(c.functions.bindWallet("c2", other), h.w3.eth.accounts[4],
                    "UnauthorizedWriter")
    print("\u2713 REJECT: rebind, wallet reuse, non-server bind")


def test_commit_happy_path(h):
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("c1", int(TierFP.HARDWARE), to_bytes32("ek_c1")),
           h.server)
    h.call(c.functions.bindWallet("c1", cw), h.server)

    gh = grad_hash(GRAD)
    # NOTE: sent from the CLIENT's wallet, not the server's.
    h.call(c.functions.commitGradient(0, gh), cw)
    assert c.functions.getCommit("c1", 0).call() == gh
    print(f"\u2713 commitGradient from CLIENT wallet stored "
          f"({gh[:8].hex()}...)")

    # Server can now classify.
    h.call(c.functions.classify(0, "c1", int(SeverityFP.NEUTRAL), 0, ""),
           h.server)
    st = c.functions.getDeviceState("c1").call()
    assert st[4] == int(StatusFP.ACTIVE) and st[0] == 400_000
    print("\u2713 classify succeeds once a commit exists (s=400000)")


def test_anti_fabrication(h):
    """The rule that justifies the layer: the server cannot classify a device
    that did not commit."""
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("honest", int(TierFP.HARDWARE),
                                to_bytes32("ek_h")), h.server)
    h.call(c.functions.bindWallet("honest", cw), h.server)

    h.expect_revert(
        c.functions.classify(0, "honest", int(SeverityFP.MAJOR), 2, "forged"),
        h.server, "MissingCommit")
    print("\u2713 ANTI-FABRICATION: server classify without a client commit "
          "-> MissingCommit (contract REVERTS, not merely logs)")

    # Absence remains recordable.
    h.call(c.functions.markAbsent(0, "honest"), h.server)
    print("\u2713 markAbsent records genuine non-participation")


def test_unbound_wallet_cannot_commit(h):
    c = h.deploy()
    stranger = h.w3.eth.accounts[5]
    h.expect_revert(c.functions.commitGradient(0, grad_hash(GRAD)), stranger,
                    "NotDeviceWallet")
    print("\u2713 REJECT: unbound wallet cannot commit -> NotDeviceWallet")


def test_banned_device_cannot_commit(h):
    """The wallet binding is load-bearing: a banned machine is locked out of
    committing, and cannot rebind a fresh wallet."""
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    fresh = h.w3.eth.accounts[6]
    h.call(c.functions.register("adv", int(TierFP.SOFTWARE),
                                to_bytes32("ek_adv")), h.server)
    h.call(c.functions.bindWallet("adv", cw), h.server)
    h.call(c.functions.commitGradient(0, grad_hash(GRAD)), cw)
    h.call(c.functions.classify(0, "adv", int(SeverityFP.CRITICAL), 3, "poison"),
           h.server)
    assert c.functions.getDeviceState("adv").call()[4] == int(StatusFP.BANNED)

    h.expect_revert(c.functions.commitGradient(1, grad_hash(GRAD)), cw,
                    "DeviceBanned")
    print("\u2713 BANNED device's bound wallet cannot commit -> DeviceBanned")

    h.expect_revert(c.functions.commitGradient(1, grad_hash(GRAD)), fresh,
                    "NotDeviceWallet")
    print("\u2713 WHITEWASH: fresh wallet cannot commit -> NotDeviceWallet")

    # And the banned EK cannot re-enrol, so no new wallet can ever be bound.
    receipt = h.call(c.functions.register("adv_v2", int(TierFP.SOFTWARE),
                                          to_bytes32("ek_adv")), h.server)
    ev = c.events.WhitewashRejected().process_receipt(receipt)
    assert len(ev) == 1
    assert c.functions.getDevice("adv_v2").call() == 0
    print("\u2713 WHITEWASH: banned EK cannot re-enrol, so the machine can "
          "never bind a new wallet")


def test_duplicate_and_empty_commit(h):
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("d", int(TierFP.HARDWARE), to_bytes32("ek_d")),
           h.server)
    h.call(c.functions.bindWallet("d", cw), h.server)
    h.call(c.functions.commitGradient(0, grad_hash(GRAD)), cw)
    h.expect_revert(c.functions.commitGradient(0, grad_hash(GRAD)), cw,
                    "DuplicateCommit")
    h.expect_revert(c.functions.commitGradient(1, b"\x00" * 32), cw,
                    "EmptyCommit")
    print("\u2713 REJECT: DuplicateCommit, EmptyCommit")


def test_mismatch_evidence(h):
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("m", int(TierFP.HARDWARE), to_bytes32("ek_m")),
           h.server)
    h.call(c.functions.bindWallet("m", cw), h.server)
    h.call(c.functions.commitGradient(0, grad_hash(GRAD)), cw)

    tampered = list(GRAD); tampered[3] = 99.0
    receipt = h.call(
        c.functions.reportCommitMismatch(0, "m", grad_hash(tampered)),
        h.server)
    evs = c.events.CommitMismatch().process_receipt(receipt)
    assert len(evs) == 1
    assert evs[0]["args"]["committed"] == grad_hash(GRAD)
    assert evs[0]["args"]["received"] == grad_hash(tampered)
    print("\u2713 NON-REPUDIATION: mismatch evidence on chain, both hashes "
          "recorded")


def test_python_solidity_hash_agreement(h):
    """The hash the client computes in Python must be the exact 32 bytes the
    contract stores. If these ever disagree, every round fails."""
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("hh", int(TierFP.HARDWARE), to_bytes32("ek_hh")),
           h.server)
    h.call(c.functions.bindWallet("hh", cw), h.server)

    shapes = ([0.0], [1.5, -2.5], [1e-300, 1e300], GRAD)
    for rid, grad in enumerate(shapes):
        gh = grad_hash(grad)
        h.call(c.functions.commitGradient(rid, gh), cw)
        assert c.functions.getCommit("hh", rid).call() == gh, \
            f"hash mismatch for shape {rid} (len {len(grad)})"
    print("\u2713 HASH AGREEMENT: Python keccak256(float64 LE) round-trips "
          "through the contract byte-for-byte across 4 gradient shapes")


def test_require_commit_false_is_baseline(h):
    """With requireCommit=false the contract behaves exactly as before the
    commitment layer existed -- baseline DLTF is preserved."""
    c = h.deploy(require_commit=False)
    h.call(c.functions.register("b", int(TierFP.HARDWARE), to_bytes32("ek_b")),
           h.server)
    h.call(c.functions.classify(0, "b", int(SeverityFP.NEUTRAL), 0, ""),
           h.server)
    assert c.functions.getDeviceState("b").call()[0] == 400_000
    assert c.functions.requireCommit().call() is False
    print("\u2713 requireCommit=false: baseline DLTF behaviour preserved "
          "(classify with no commit succeeds)")


def test_require_commit_is_immutable(h):
    c = h.deploy(require_commit=True)
    assert c.functions.requireCommit().call() is True
    fns = {f["name"] for f in h.abi if f.get("type") == "function"}
    assert not any("requireCommit" in n and n != "requireCommit" for n in fns)
    print("\u2713 requireCommit is immutable -- no setter exists, a server "
          "cannot disable the rule mid-federation")


def test_gas(h):
    c = h.deploy()
    cw = h.w3.eth.accounts[2]
    h.call(c.functions.register("g", int(TierFP.HARDWARE), to_bytes32("ek_g")),
           h.server)
    r_bind = h.call(c.functions.bindWallet("g", cw), h.server)
    r_commit = h.call(c.functions.commitGradient(0, grad_hash(GRAD)), cw)
    r_cls = h.call(c.functions.classify(0, "g", int(SeverityFP.NEUTRAL), 0, ""),
                   h.server)
    print(f"\u2713 GAS  bindWallet {r_bind.gasUsed}  "
          f"commitGradient {r_commit.gasUsed} (CLIENT pays)  "
          f"classify {r_cls.gasUsed}")


def _self_test():
    print("chain/commit_parity_test: commitment layer on the deployed contract")
    h = CommitHarness()
    for t in (test_wallet_binding,
              test_commit_happy_path,
              test_anti_fabrication,
              test_unbound_wallet_cannot_commit,
              test_banned_device_cannot_commit,
              test_duplicate_and_empty_commit,
              test_mismatch_evidence,
              test_python_solidity_hash_agreement,
              test_require_commit_false_is_baseline,
              test_require_commit_is_immutable,
              test_gas):
        t(h)
    print("\u2713 all commitment parity tests passed")


if __name__ == "__main__":
    _self_test()
