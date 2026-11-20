"""
chain/batch_parity_test.py

Verifies the EIP-712 batched-commitment path against the DEPLOYED contract,
and MEASURES the gas saving rather than estimating it.

The critical assertion: a signature produced by eth_account in Python must
recover to the same address inside Solidity's ecrecover. If the EIP-712
encodings differ by a single byte, every round fails. There is no partial
agreement here.

    PYTHONPATH=. python3 -m chain.batch_parity_test
"""
from eth_utils import keccak

from chain.evm_parity_test import Harness, to_bytes32
from chain.fixedpoint import TierFP, StatusFP, SeverityFP
from chain.commit import (grad_hash, SigningCommitAgent, SignedCommit,
                          build_batch, device_key, recover_commit_signer)


# Deterministic test keys. Anvil-style, never used for anything real.
KEYS = ["0x" + f"{i+1:02x}" * 32 for i in range(12)]


def _grad(seed, n=20):
    return [0.01 * i + seed for i in range(n)]


class BatchHarness(Harness):
    def deploy(self, chain_id_hex="00" * 32, require_commit=True):
        factory = self.w3.eth.contract(abi=self.abi, bytecode=self.bin)
        tx = factory.constructor(self.server, bytes.fromhex(chain_id_hex),
                                 require_commit).transact({"from": self.server})
        r = self.w3.eth.wait_for_transaction_receipt(tx)
        return self.w3.eth.contract(address=r.contractAddress, abi=self.abi)

    def enrol_signers(self, c, n):
        """Register n devices and bind each to a signing agent's wallet."""
        chain_id = self.w3.eth.chain_id
        agents = []
        for i in range(n):
            lbl = f"d{i}"
            a = SigningCommitAgent(lbl, KEYS[i], chain_id, c.address)
            self.call(c.functions.register(lbl, int(TierFP.HARDWARE),
                                           to_bytes32(f"ek_{lbl}")), self.server)
            self.call(c.functions.bindWallet(lbl, a.wallet), self.server)
            agents.append(a)
        return agents


def submit_batch(h, c, commits):
    rid, keys, hashes, vs, rs, ss = build_batch(commits)
    return h.call(c.functions.commitBatch(rid, keys, hashes, vs, rs, ss),
                  h.server)


# =============================================================================

def test_domain_separator_agreement(h):
    """Python and Solidity must derive the SAME EIP-712 domain separator."""
    c = h.deploy()
    on_chain = c.functions.DOMAIN_SEPARATOR().call()

    domain_typehash = keccak(
        b"EIP712Domain(string name,string version,uint256 chainId,"
        b"address verifyingContract)")
    from eth_abi import encode
    local = keccak(encode(
        ["bytes32", "bytes32", "bytes32", "uint256", "address"],
        [domain_typehash, keccak(b"DLTFRegistry"), keccak(b"1"),
         h.w3.eth.chain_id, c.address]))
    assert on_chain == local, (on_chain.hex(), local.hex())
    print(f"\u2713 DOMAIN SEPARATOR agrees Python <-> Solidity "
          f"({on_chain[:8].hex()}...)")


def test_digest_agreement(h):
    """The EIP-712 digest the client signs must equal commitDigest() on chain."""
    c = h.deploy()
    a = h.enrol_signers(c, 1)[0]
    gh = grad_hash(_grad(0))
    on_chain = c.functions.commitDigest(device_key("d0"), 7, gh).call()

    from eth_account.messages import encode_typed_data, _hash_eip191_message
    from chain.commit import commit_message
    msg = commit_message("d0", 7, gh, h.w3.eth.chain_id, c.address)
    local = _hash_eip191_message(encode_typed_data(full_message=msg))
    assert on_chain == local, (on_chain.hex(), local.hex())
    print(f"\u2713 EIP-712 DIGEST agrees byte-for-byte "
          f"({on_chain[:8].hex()}...)")


def test_single_signed_commit(h):
    c = h.deploy()
    a = h.enrol_signers(c, 1)[0]
    sc = a.sign(0, _grad(0))
    assert recover_commit_signer(sc, h.w3.eth.chain_id, c.address).lower() \
        == a.wallet.lower()
    submit_batch(h, c, [sc])
    assert c.functions.getCommit("d0", 0).call() == sc.grad_hash
    print("\u2713 client-signed commitment accepted by the contract "
          "(ecrecover matched the bound wallet)")

    h.call(c.functions.classify(0, "d0", int(SeverityFP.NEUTRAL), 0, ""),
           h.server)
    assert c.functions.getDeviceState("d0").call()[0] == 400_000
    print("\u2713 classify permitted after a batched commitment")


def test_server_cannot_forge(h):
    """The whole point: no valid signature means the server cannot commit for
    a client, so it cannot classify one either."""
    c = h.deploy()
    agents = h.enrol_signers(c, 2)

    # d0's signature, submitted claiming to be d1's.
    good = agents[0].sign(0, _grad(0))
    forged = SignedCommit("d1", 0, good.grad_hash, good.v, good.r, good.s,
                          agents[1].wallet)
    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d1")], [forged.grad_hash],
                                [forged.v], [forged.r], [forged.s]),
        h.server, "SignerNotDeviceWallet")
    print("\u2713 REJECT: one client's signature replayed for another device "
          "-> SignerNotDeviceWallet")

    # Garbage signature.
    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d1")], [good.grad_hash],
                                [27], [b"\x01" * 32], [b"\x02" * 32]),
        h.server, "SignerNotDeviceWallet")
    print("\u2713 REJECT: fabricated signature bytes -> recovered address is "
          "not the bound wallet")

    # And so d1 still cannot be classified.
    h.expect_revert(
        c.functions.classify(0, "d1", int(SeverityFP.MAJOR), 2, "forged"),
        h.server, "MissingCommit")
    print("\u2713 ANTI-FABRICATION SURVIVES BATCHING: no signature -> no "
          "commitment -> classify reverts")


def test_batch_is_atomic(h):
    """One bad signature must reject the whole batch, so a server cannot
    silently drop a client and then claim it was absent."""
    c = h.deploy()
    agents = h.enrol_signers(c, 3)
    good0 = agents[0].sign(0, _grad(0))
    good2 = agents[2].sign(0, _grad(2))
    bad1 = SignedCommit("d1", 0, good0.grad_hash, good0.v, good0.r, good0.s,
                        agents[1].wallet)

    h.expect_revert(
        c.functions.commitBatch(
            0, [device_key("d0"), device_key("d1"), device_key("d2")],
            [good0.grad_hash, bad1.grad_hash, good2.grad_hash],
            [good0.v, bad1.v, good2.v],
            [good0.r, bad1.r, good2.r],
            [good0.s, bad1.s, good2.s]),
        h.server, "SignerNotDeviceWallet")
    assert c.functions.getCommit("d0", 0).call() == b"\x00" * 32
    assert c.functions.getCommit("d2", 0).call() == b"\x00" * 32
    print("\u2713 ATOMIC: a bad signature reverts the batch; the two VALID "
          "commitments in it were not written")


def test_replay_protection(h):
    """A signature is bound to roundId, contract address, and chainId."""
    c1 = h.deploy()
    a = h.enrol_signers(c1, 1)[0]
    sc = a.sign(0, _grad(0))
    submit_batch(h, c1, [sc])

    # Same signature, different round.
    h.expect_revert(
        c1.functions.commitBatch(1, [device_key("d0")], [sc.grad_hash],
                                 [sc.v], [sc.r], [sc.s]),
        h.server, "SignerNotDeviceWallet")
    print("\u2713 REPLAY: signature from round 0 rejected at round 1")

    # Same signature, different contract instance (different address).
    c2 = h.deploy()
    h.call(c2.functions.register("d0", int(TierFP.HARDWARE),
                                 to_bytes32("ek_d0")), h.server)
    h.call(c2.functions.bindWallet("d0", a.wallet), h.server)
    h.expect_revert(
        c2.functions.commitBatch(0, [device_key("d0")], [sc.grad_hash],
                                 [sc.v], [sc.r], [sc.s]),
        h.server, "SignerNotDeviceWallet")
    print("\u2713 REPLAY: signature rejected by a different contract instance "
          "(domain separator binds the address)")


def test_malleability_and_shape_guards(h):
    c = h.deploy()
    a = h.enrol_signers(c, 1)[0]
    sc = a.sign(0, _grad(0))

    # s flipped into the upper half of the curve order.
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    s_high = (N - int.from_bytes(sc.s, "big")).to_bytes(32, "big")
    v_flip = 27 if sc.v == 28 else 28
    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d0")], [sc.grad_hash],
                                [v_flip], [sc.r], [s_high]),
        h.server, "MalleableSignature")
    print("\u2713 REJECT: malleable (high-s) signature -> MalleableSignature")

    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d0")], [sc.grad_hash],
                                [29], [sc.r], [sc.s]),
        h.server, "MalleableSignature")
    print("\u2713 REJECT: v outside {27,28}")

    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d0")], [], [sc.v], [sc.r],
                                [sc.s]),
        h.server, "BatchLengthMismatch")
    h.expect_revert(
        c.functions.commitBatch(0, [], [], [], [], []),
        h.server, "EmptyBatch")
    print("\u2713 REJECT: mismatched array lengths, empty batch")

    h.expect_revert(
        c.functions.commitBatch(0, [device_key("d0")], [sc.grad_hash],
                                [sc.v], [sc.r], [sc.s]),
        h.w3.eth.accounts[7], "UnauthorizedWriter")
    print("\u2713 REJECT: non-server submitting a batch")


def test_banned_device_in_batch(h):
    c = h.deploy()
    agents = h.enrol_signers(c, 2)
    submit_batch(h, c, [agents[0].sign(0, _grad(0)),
                        agents[1].sign(0, _grad(1))])
    h.call(c.functions.classify(0, "d0", int(SeverityFP.CRITICAL), 3, "poison"),
           h.server)
    assert c.functions.getDeviceState("d0").call()[4] == int(StatusFP.BANNED)

    h.expect_revert(
        c.functions.commitBatch(
            1, [device_key("d0")], [grad_hash(_grad(0))],
            *[[x] for x in (agents[0].sign(1, _grad(0)).v,
                            agents[0].sign(1, _grad(0)).r,
                            agents[0].sign(1, _grad(0)).s)]),
        h.server, "DeviceBanned")
    print("\u2713 BANNED device's signature refused inside a batch "
          "-> DeviceBanned")


# =============================================================================
#                          THE GAS COMPARISON
# =============================================================================

def test_gas_comparison(h):
    """Measure, do not estimate."""
    print("\n  --- per-client transactions (the expensive path) ---")
    c = h.deploy()
    agents = h.enrol_signers(c, 6)
    wallets = [h.w3.eth.accounts[2 + i] for i in range(6)]
    # rebind to funded accounts so they can actually send transactions
    c2 = h.deploy()
    for i in range(6):
        lbl = f"d{i}"
        h.call(c2.functions.register(lbl, int(TierFP.HARDWARE),
                                     to_bytes32(f"ek_{lbl}")), h.server)
        h.call(c2.functions.bindWallet(lbl, wallets[i]), h.server)
    per_client_total = 0
    for i in range(6):
        r = h.call(c2.functions.commitGradient(0, grad_hash(_grad(i))),
                   wallets[i])
        per_client_total += r.gasUsed
    print(f"      6 separate commitGradient txs : {per_client_total:>8,} gas "
          f"({per_client_total // 6:,} each, paid by CLIENTS)")

    print("\n  --- batched signatures (the cheap path) ---")
    results = {}
    for n in (1, 2, 6, 12):
        c3 = h.deploy()
        ags = h.enrol_signers(c3, n)
        commits = [ags[i].sign(0, _grad(i)) for i in range(n)]
        r = submit_batch(h, c3, commits)
        results[n] = r.gasUsed
        per = r.gasUsed / n
        print(f"      commitBatch n={n:<3} : {r.gasUsed:>8,} gas "
              f"({per:>8,.0f}/client, paid by SERVER)")

    marginal = (results[12] - results[2]) / 10
    saving = 100 * (1 - results[6] / per_client_total)
    print(f"\n      marginal cost per additional client: ~{marginal:,.0f} gas")
    print(f"      6-client round: {per_client_total:,} -> {results[6]:,} gas "
          f"= {saving:.1f}% saving")
    print(f"      clients pay: {per_client_total // 6:,} gas each -> ZERO")

    assert results[6] < per_client_total, "batching must be cheaper"
    # 36k, not the ~4.5k a naive ecrecover-only estimate suggests: the
    # SSTORE writing each commitment dominates. See classifySigned.
    assert 20_000 < marginal < 45_000, f"unexpected marginal: {marginal}"
    print("\u2713 GAS: batching is cheaper and scales linearly with a small "
          "constant")


def _self_test():
    print("chain/batch_parity_test: EIP-712 batched commitments on the "
          "deployed contract")
    h = BatchHarness()
    for t in (test_domain_separator_agreement,
              test_digest_agreement,
              test_single_signed_commit,
              test_server_cannot_forge,
              test_batch_is_atomic,
              test_replay_protection,
              test_malleability_and_shape_guards,
              test_banned_device_in_batch,
              test_gas_comparison,
              test_classify_signed,
              test_three_way_gas):
        t(h)
    print("\u2713 all batched-commitment parity tests passed")




# =============================================================================
#         THE THIRD PATH: verify at point of use, store nothing
# =============================================================================

def test_classify_signed(h):
    """classifySigned proves the client signature inside classify() and never
    stores the commitment. Same guarantees, no SSTORE."""
    c = h.deploy()
    a = h.enrol_signers(c, 1)[0]
    sc = a.sign(0, _grad(0))

    h.call(c.functions.classifySigned(
        0, "d0", int(SeverityFP.NEUTRAL), 0, "",
        sc.grad_hash, sc.v, sc.r, sc.s), h.server)
    assert c.functions.getDeviceState("d0").call()[0] == 400_000
    print("\u2713 classifySigned: state updated, no separate commit needed")

    # No signature -> cannot classify at all.
    h.expect_revert(
        c.functions.classifySigned(
            1, "d0", int(SeverityFP.MAJOR), 2, "forged",
            grad_hash(_grad(9)), sc.v, sc.r, sc.s),
        h.server, "SignerNotDeviceWallet")
    print("\u2713 ANTI-FABRICATION: signature over a different gradient hash "
          "is refused")

    # Signature evidence is recoverable from the event log.
    logs = c.events.CommitProof().get_logs(from_block=0)
    assert len(logs) == 1
    ev = logs[0]["args"]
    rebuilt = SignedCommit("d0", 0, ev["gradHash"], ev["v"],
                           bytes(ev["r"]), bytes(ev["s"]), a.wallet)
    assert recover_commit_signer(rebuilt, h.w3.eth.chain_id,
                                 c.address).lower() == a.wallet.lower()
    print("\u2713 NON-REPUDIATION: signature recoverable from CommitProof "
          "event alone -- a third party can verify without the server")


def test_three_way_gas(h):
    """The honest comparison, measured on the deployed contract."""
    N = 6
    print("\n  --- three ways to get the same guarantee, 6 clients, 1 round ---")

    # A. per-client transactions + plain classify
    c = h.deploy()
    wallets = [h.w3.eth.accounts[2 + i] for i in range(N)]
    for i in range(N):
        h.call(c.functions.register(f"d{i}", int(TierFP.HARDWARE),
                                    to_bytes32(f"ek_d{i}")), h.server)
        h.call(c.functions.bindWallet(f"d{i}", wallets[i]), h.server)
    a_total = 0
    for i in range(N):
        a_total += h.call(c.functions.commitGradient(0, grad_hash(_grad(i))),
                          wallets[i]).gasUsed
    for i in range(N):
        a_total += h.call(c.functions.classify(
            0, f"d{i}", int(SeverityFP.NEUTRAL), 0, ""), h.server).gasUsed

    # B. batched signatures + plain classify
    c = h.deploy()
    ags = h.enrol_signers(c, N)
    b_total = submit_batch(h, c, [ags[i].sign(0, _grad(i))
                                  for i in range(N)]).gasUsed
    for i in range(N):
        b_total += h.call(c.functions.classify(
            0, f"d{i}", int(SeverityFP.NEUTRAL), 0, ""), h.server).gasUsed

    # C. classifySigned -- no commit step at all
    c = h.deploy()
    ags = h.enrol_signers(c, N)
    c_total = 0
    for i in range(N):
        sc = ags[i].sign(0, _grad(i))
        c_total += h.call(c.functions.classifySigned(
            0, f"d{i}", int(SeverityFP.NEUTRAL), 0, "",
            sc.grad_hash, sc.v, sc.r, sc.s), h.server).gasUsed

    # D. baseline, no commitment guarantee at all
    c = h.deploy(require_commit=False)
    for i in range(N):
        h.call(c.functions.register(f"d{i}", int(TierFP.HARDWARE),
                                    to_bytes32(f"ek_d{i}")), h.server)
    d_total = sum(h.call(c.functions.classify(
        0, f"d{i}", int(SeverityFP.NEUTRAL), 0, ""), h.server).gasUsed
        for i in range(N))

    print(f"      A  per-client txs + classify : {a_total:>8,} gas  "
          f"(clients pay {a_total // N:,} each)")
    print(f"      B  commitBatch  + classify   : {b_total:>8,} gas  "
          f"(clients pay 0)")
    print(f"      C  classifySigned            : {c_total:>8,} gas  "
          f"(clients pay 0)")
    print(f"      D  baseline, no commitment   : {d_total:>8,} gas  "
          f"(no guarantee)")
    print(f"\n      C vs A: {100*(1-c_total/a_total):.1f}% cheaper")
    print(f"      C vs B: {100*(1-c_total/b_total):.1f}% cheaper")
    print(f"      cost of the guarantee (C - D): {c_total-d_total:,} gas "
          f"= {100*(c_total/d_total-1):.1f}% over baseline")

    assert c_total < b_total < a_total
    print("\u2713 GAS: classifySigned is the cheapest path to the same "
          "guarantee")


if __name__ == "__main__":
    _self_test()
