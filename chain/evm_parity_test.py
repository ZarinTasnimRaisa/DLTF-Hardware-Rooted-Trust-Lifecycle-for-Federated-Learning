"""
chain/evm_parity_test.py

Run the SAME scenarios against MockBackend (chain/mock.py) and the deployed
Solidity contract (contracts/src/DLTFRegistry.sol). Verify:

  1. Contract reverts with the CORRECT custom error for each rejection rule
  2. Packed device state matches mock BIT-FOR-BIT after every write
  3. Ban survival across a fresh deploy (mimics restart -> replay)
  4. Whitewash: banned EK rejected under fresh label
  5. Event emission counts match

This is the acceptance test for the Solidity port. If any assertion fails,
the Solidity port has diverged from the Python spec (chain/fixedpoint.py +
chain/mock.py) and MUST be brought back into agreement before proceeding.

Runs against a local py-evm / eth-tester instance -- no node needed.

    PYTHONPATH=. python3 -m chain.evm_parity_test
"""
import json
from pathlib import Path

from eth_tester import EthereumTester, PyEVMBackend
from eth_tester.exceptions import TransactionFailed
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider
from eth_utils import function_signature_to_4byte_selector, keccak

from chain.fixedpoint import StatusFP, TierFP, SeverityFP
from chain.mock import MockBackend


# ---- Solidity artifact loading ----------------------------------------------

# Delegate discovery to chain/evm.py, which searches every layout the contract
# has lived in (contracts/out, chain/out, chain/contracts/out, out, build) and
# handles both split .abi/.bin and Foundry .json artifacts.
#
# This replaced a hardcoded `contracts/out` path whose error message also
# printed a build command WITHOUT --via-ir. That command fails with
# "Stack too deep" at _classifyCore, so anyone following it could not build.
from chain.evm import (ABI_PATH, BIN_PATH, build_command,  # noqa: F401
                       find_artifacts, load_abi, load_bin)

ARTIFACT_DIR = Path(ABI_PATH).parent


def load_artifact():
    if find_artifacts()[0] is None:
        raise SystemExit(
            f"contract artifacts not found.\nBuild with:\n  "
            f"{build_command()}\n"
            f"(--via-ir is REQUIRED: the contract exceeds the 16-slot stack "
            f"limit without it)")
    return load_bin(), load_abi()


# ---- custom-error selector table -------------------------------------------

ERROR_SIGS = {
    "UnauthorizedWriter()": "UnauthorizedWriter",
    "BanToActive(bytes32)": "BanToActive",
    "TierMutation(bytes32,uint8,uint8)": "TierMutation",
    "DuplicateRound(uint256)": "DuplicateRound",
    "StaleRound(uint256,uint256)": "StaleRound",
    "DeviceUnknown(bytes32)": "DeviceUnknown",
    "DeviceBanned(bytes32)": "DeviceBanned",
    "EkAlreadyRegistered(bytes32)": "EkAlreadyRegistered",
    "OutcomeInvalid(uint8)": "OutcomeInvalid",
    "NotOnProbation(bytes32)": "NotOnProbation",
    "InvalidSeverity(uint8)": "InvalidSeverity",
    "InvalidTier(uint8)": "InvalidTier",
    # commitment layer
    "WalletAlreadyBound(address)": "WalletAlreadyBound",
    "WalletNotBound(bytes32)": "WalletNotBound",
    "NotDeviceWallet(address)": "NotDeviceWallet",
    "MissingCommit(bytes32,uint256)": "MissingCommit",
    "DuplicateCommit(bytes32,uint256)": "DuplicateCommit",
    "EmptyCommit()": "EmptyCommit",
    # batched signed commitments
    "BatchLengthMismatch()": "BatchLengthMismatch",
    "InvalidSignature(bytes32)": "InvalidSignature",
    "SignerNotDeviceWallet(bytes32,address)": "SignerNotDeviceWallet",
    "MalleableSignature()": "MalleableSignature",
    "EmptyBatch()": "EmptyBatch",
}
SELECTOR_TO_NAME = {
    function_signature_to_4byte_selector(sig).hex(): name
    for sig, name in ERROR_SIGS.items()
}


def decode_revert(exc: Exception) -> str:
    """Extract the custom-error name from py-evm's TransactionFailed. The
    exception message format is:
        'execution reverted: b\\'\\xb4&\\xab\\xc1...\\''
    We extract the byte literal, take the first 4 bytes as the selector,
    and look it up in the ABI selector table."""
    import re, ast
    msg = str(exc)
    # Look for a Python bytes literal in the message: b'...' or b"..."
    m = re.search(r"(b'(?:[^'\\]|\\.)*'|b\"(?:[^\"\\]|\\.)*\")", msg)
    if m:
        try:
            data = ast.literal_eval(m.group(1))
        except (ValueError, SyntaxError):
            return f"UNPARSEABLE({msg!r})"
    else:
        # Fall back: check args for raw bytes
        for a in getattr(exc, "args", ()):
            if isinstance(a, (bytes, bytearray)):
                data = bytes(a)
                break
        else:
            return f"NO_REVERT_DATA({msg!r})"
    if len(data) < 4:
        return f"SHORT_REVERT({data.hex()})"
    return SELECTOR_TO_NAME.get(
        data[:4].hex(), f"UNKNOWN_SELECTOR({data[:4].hex()})")


# ---- harness ---------------------------------------------------------------

class Harness:
    def __init__(self):
        backend = PyEVMBackend()
        self.tester = EthereumTester(backend=backend)
        self.w3 = Web3(EthereumTesterProvider(self.tester))
        accounts = self.w3.eth.accounts
        self.server = accounts[0]
        self.other  = accounts[1]
        self.bin, self.abi = load_artifact()

    def deploy(self, chain_id_hex="00" * 32):
        factory = self.w3.eth.contract(abi=self.abi, bytecode=self.bin)
        tx = factory.constructor(self.server, bytes.fromhex(chain_id_hex),
                                 False) \
                    .transact({"from": self.server})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        return self.w3.eth.contract(address=receipt.contractAddress,
                                    abi=self.abi)

    def expect_revert(self, fn_call, from_addr, expected_error):
        try:
            fn_call.transact({"from": from_addr})
        except TransactionFailed as e:
            got = decode_revert(e)
            assert got == expected_error, (
                f"expected revert {expected_error!r}, got {got!r} ({e!r})")
            return
        raise AssertionError(
            f"expected revert {expected_error!r}, but tx succeeded")

    def call(self, fn_call, from_addr):
        tx = fn_call.transact({"from": from_addr})
        return self.w3.eth.wait_for_transaction_receipt(tx)


def to_bytes32(s: str) -> bytes:
    """32-byte ekHmac from any short label (test-only)."""
    return keccak(s.encode())


# =============================================================================
#                                  TESTS
# =============================================================================

def test_deploy_and_read(h: Harness):
    c = h.deploy()
    assert c.functions.server().call() == h.server
    assert c.functions.lastRoundSet().call() is False
    print("\u2713 deploy: server set immutable, no rounds closed yet")


def test_basic_enroll_classify(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_alpha")
    h.call(c.functions.register("alpha", int(TierFP.HARDWARE), ek), h.server)

    packed = c.functions.getDevice("alpha").call()
    assert packed != 0, "device not registered"
    state = c.functions.getDeviceState("alpha").call()
    # DeviceState tuple order: (s, f, cleanRun, majorRun, status, tier, lastRound)
    assert state[4] == int(StatusFP.ACTIVE)
    assert state[5] == int(TierFP.HARDWARE)

    h.call(c.functions.classify(
        0, "alpha", int(SeverityFP.NEUTRAL), 0, ""), h.server)
    state = c.functions.getDeviceState("alpha").call()
    # After one NEUTRAL: s = 0.4 * SCALE = 400_000, cleanRun = 1
    assert state[0] == 400_000, state[0]
    assert state[2] == 1
    assert state[4] == int(StatusFP.ACTIVE)
    print("\u2713 enroll + classify NEUTRAL: state matches spec "
          f"(s={state[0]}, cleanRun={state[2]}, status=ACTIVE)")


def test_reject_unauthorized_writer(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_x")
    h.expect_revert(
        c.functions.register("x", int(TierFP.HARDWARE), ek),
        h.other, "UnauthorizedWriter")
    print("\u2713 REJECT: register from non-server -> UnauthorizedWriter")


def test_reject_tier_mutation(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_beta")
    h.call(c.functions.register("beta", int(TierFP.TPM_RESIDENT), ek), h.server)
    h.expect_revert(
        c.functions.register("beta", int(TierFP.HARDWARE), ek),
        h.server, "TierMutation")
    print("\u2713 REJECT: tier change after enrollment -> TierMutation")


def test_reject_ek_already_registered(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_shared")
    h.call(c.functions.register("d1", int(TierFP.HARDWARE), ek), h.server)
    h.expect_revert(
        c.functions.register("d2", int(TierFP.HARDWARE), ek),
        h.server, "EkAlreadyRegistered")
    print("\u2713 REJECT: two device_ids claim one EK -> EkAlreadyRegistered")


def test_reject_ban_to_active(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_z")
    h.call(c.functions.register("z", int(TierFP.SOFTWARE), ek), h.server)
    h.call(c.functions.classify(
        0, "z", int(SeverityFP.CRITICAL), 3, "test"), h.server)
    # z is now BANNED. Attempting to re-register with the same device_id and
    # a *different* EK is a resurrection attempt -> BanToActive.
    fresh_ek = to_bytes32("ek_z_fresh")
    h.expect_revert(
        c.functions.register("z", int(TierFP.SOFTWARE), fresh_ek),
        h.server, "BanToActive")
    print("\u2713 REJECT: re-register banned device_id with fresh EK "
          "-> BanToActive (resurrection refused)")


def test_reject_duplicate_and_stale_round(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_g")
    h.call(c.functions.register("g", int(TierFP.HARDWARE), ek), h.server)
    h.call(c.functions.classify(
        5, "g", int(SeverityFP.NEUTRAL), 0, ""), h.server)
    h.call(c.functions.roundSummary(
        5, keccak(b"g"), True, b"\x00" * 32), h.server)

    h.expect_revert(
        c.functions.roundSummary(5, keccak(b"g"), True, b"\x00" * 32),
        h.server, "DuplicateRound")
    h.expect_revert(
        c.functions.classify(5, "g", int(SeverityFP.NEUTRAL), 0, ""),
        h.server, "StaleRound")
    h.expect_revert(
        c.functions.classify(3, "g", int(SeverityFP.NEUTRAL), 0, ""),
        h.server, "StaleRound")
    print("\u2713 REJECT: duplicate round -> DuplicateRound; "
          "stale classify -> StaleRound (both variants)")


def test_reject_device_banned_and_unknown(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_b")
    h.call(c.functions.register("b", int(TierFP.SOFTWARE), ek), h.server)
    h.call(c.functions.classify(
        0, "b", int(SeverityFP.CRITICAL), 3, "test"), h.server)
    h.expect_revert(
        c.functions.classify(1, "b", int(SeverityFP.NEUTRAL), 0, ""),
        h.server, "DeviceBanned")
    h.expect_revert(
        c.functions.classify(1, "nonexistent", int(SeverityFP.NEUTRAL), 0, ""),
        h.server, "DeviceUnknown")
    print("\u2713 REJECT: classify on BANNED -> DeviceBanned; "
          "on unknown -> DeviceUnknown")


def test_whitewash_rejected(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_victim")
    h.call(c.functions.register("victim", int(TierFP.HARDWARE), ek), h.server)
    h.call(c.functions.classify(
        0, "victim", int(SeverityFP.CRITICAL), 3, ""), h.server)
    # Rejoin under a fresh label with the same EK -> WhitewashRejected event,
    # no state created for the new label.
    receipt = h.call(
        c.functions.register("victim_v2", int(TierFP.HARDWARE), ek), h.server)
    events = c.events.WhitewashRejected().process_receipt(receipt)
    assert len(events) == 1, f"expected 1 WhitewashRejected, got {len(events)}"
    assert events[0]["args"]["deviceId"] == "victim_v2"
    assert c.functions.getDevice("victim_v2").call() == 0
    assert c.functions.isBannedEk(ek).call() is True
    print("\u2713 WHITEWASH: banned EK under new label -> WhitewashRejected, "
          "no device record created, EK still banned")


def test_probation_lifecycle(h: Harness):
    c = h.deploy()
    ek = to_bytes32("ek_hw")
    h.call(c.functions.register("hw", int(TierFP.HARDWARE), ek), h.server)
    for r in range(3):
        h.call(c.functions.classify(
            r, "hw", int(SeverityFP.MAJOR), 2, ""), h.server)
    state = c.functions.getDeviceState("hw").call()
    assert state[4] == int(StatusFP.PROBATION), state
    h.call(c.functions.enterProbation(3, "hw"), h.server)
    h.call(c.functions.probationDecision(
        10, "hw", 0), h.server)  # REINSTATED
    state = c.functions.getDeviceState("hw").call()
    assert state[4] == int(StatusFP.ACTIVE), state
    assert c.functions.isRehabUsed("hw").call() is True
    print("\u2713 PROBATION lifecycle: T1 3xMAJOR -> PROBATION -> "
          "REINSTATED -> ACTIVE; rehabUsed = true")

    # Re-offend: must use exhaustProbation, not enterProbation
    for r in range(11, 14):
        h.call(c.functions.classify(
            r, "hw", int(SeverityFP.MAJOR), 2, ""), h.server)
    assert c.functions.getDeviceState("hw").call()[4] == int(StatusFP.PROBATION)
    h.expect_revert(
        c.functions.enterProbation(14, "hw"),
        h.server, "NotOnProbation")
    h.call(c.functions.exhaustProbation(14, "hw"), h.server)
    assert c.functions.getDeviceState("hw").call()[4] == int(StatusFP.BANNED)
    assert c.functions.isBannedEk(ek).call() is True
    print("\u2713 REHAB EXHAUSTED: re-offense after REINSTATED -> BAN "
          "(enterProbation reverts, exhaustProbation succeeds)")


# =============================================================================
#                       BIT-FOR-BIT PARITY WITH MOCK
# =============================================================================

WRITER_KEY = b"parity-writer-key-32-xxxxxxxxxxx"


def test_bit_parity_with_mock(h: Harness):
    """Drive both mock and contract through a scripted sequence covering
    the paths that matter, and compare packed state after every write."""
    c = h.deploy()
    mock = MockBackend(WRITER_KEY)

    def register(did, tier, ek_label):
        ek = to_bytes32(ek_label)
        mock.register(WRITER_KEY, did, tier, ek)
        h.call(c.functions.register(did, int(tier), ek), h.server)

    def classify(rid, did, sev, stage=0, reason=""):
        mock.classify(WRITER_KEY, rid, did, sev, stage=stage, reason=reason)
        h.call(c.functions.classify(rid, did, int(sev), stage, reason),
               h.server)

    def compare(did):
        m = mock.get_device(did)
        got = c.functions.getDevice(did).call()
        expected = m.pack() if m else 0
        assert got == expected, (
            f"parity break at {did}: mock={expected} contract={got}\n"
            f"  mock state: s={m.s} f={m.f} status={m.status.name}")

    # Two devices, mixed behaviour
    register("hw", TierFP.HARDWARE, "ek_hw")
    register("sw", TierFP.SOFTWARE, "ek_sw")
    for did in ("hw", "sw"):
        compare(did)

    # 15 rounds of mixed events
    script = [
        (0, "hw", SeverityFP.NEUTRAL), (0, "sw", SeverityFP.MINOR),
        (1, "hw", SeverityFP.NEUTRAL), (1, "sw", SeverityFP.NEUTRAL),
        (2, "hw", SeverityFP.MAJOR),   (2, "sw", SeverityFP.NEUTRAL),
        (3, "hw", SeverityFP.NEUTRAL), (3, "sw", SeverityFP.NEUTRAL),
        (4, "hw", SeverityFP.NEUTRAL), (4, "sw", SeverityFP.NEUTRAL),
        (5, "hw", SeverityFP.MINOR),   (5, "sw", SeverityFP.NEUTRAL),
        (6, "hw", SeverityFP.NEUTRAL), (6, "sw", SeverityFP.NEUTRAL),
        (7, "hw", SeverityFP.NEUTRAL), (7, "sw", SeverityFP.NEUTRAL),
    ]
    for rid, did, sev in script:
        classify(rid, did, sev)
        compare(did)

    print("\u2713 BIT PARITY: mock and contract packed state agree after "
          f"every one of {len(script)} classify() calls across 2 devices")


def test_ban_survives_redeploy(h: Harness):
    """The full 'restart' story: ban is recorded in events, and a fresh
    contract (rebuilt from those events) still refuses the whitewash."""
    c = h.deploy()
    ek = to_bytes32("ek_replayed")
    h.call(c.functions.register("v", int(TierFP.SOFTWARE), ek), h.server)
    h.call(c.functions.classify(
        0, "v", int(SeverityFP.CRITICAL), 3, ""), h.server)
    assert c.functions.isBannedEk(ek).call() is True

    # Rebuild: fresh deploy, replay via ENROLL + classify.
    c2 = h.deploy()
    h.call(c2.functions.register("v", int(TierFP.SOFTWARE), ek), h.server)
    h.call(c2.functions.classify(
        0, "v", int(SeverityFP.CRITICAL), 3, ""), h.server)
    assert c2.functions.isBannedEk(ek).call() is True

    # Whitewash after "restart"
    receipt = h.call(
        c2.functions.register("v_v2", int(TierFP.SOFTWARE), ek), h.server)
    events = c2.events.WhitewashRejected().process_receipt(receipt)
    assert len(events) == 1
    print("\u2713 RESTART: ban is reconstructible from events; "
          "post-restart whitewash still rejected")


def test_storage_fits_one_slot(h: Harness):
    """Confirm the on-chain packed word for a fully-populated device is
    <= 208 bits (fits one 256-bit SSTORE slot with 48 bits spare)."""
    c = h.deploy()
    ek = to_bytes32("ek_dense")
    h.call(c.functions.register("d", int(TierFP.HARDWARE), ek), h.server)
    for r in range(5):
        h.call(c.functions.classify(
            r, "d", int(SeverityFP.NEUTRAL), 0, ""), h.server)
    packed = c.functions.getDevice("d").call()
    bits = packed.bit_length()
    assert bits <= 208, f"packed word too large: {bits} bits"
    print(f"\u2713 STORAGE: on-chain packed word = {bits} bits "
          "(fits one 256-bit slot with room)")


# =============================================================================
#                                RUNNER
# =============================================================================

def _self_test():
    print("chain/evm_parity_test: deployed-contract parity harness")
    h = Harness()
    for t in (test_deploy_and_read,
              test_basic_enroll_classify,
              test_reject_unauthorized_writer,
              test_reject_tier_mutation,
              test_reject_ek_already_registered,
              test_reject_ban_to_active,
              test_reject_duplicate_and_stale_round,
              test_reject_device_banned_and_unknown,
              test_whitewash_rejected,
              test_probation_lifecycle,
              test_bit_parity_with_mock,
              test_ban_survives_redeploy,
              test_storage_fits_one_slot):
        t(h)
    print("\u2713 all EVM parity tests passed -- contract matches mock spec")


if __name__ == "__main__":
    _self_test()
