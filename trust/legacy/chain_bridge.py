"""
trust/legacy/chain_bridge.py

ChainReputationEngine: drop-in replacement for trust.reputation.ReputationEngine.
Same public API (register, record_event, reinstate, get_status, get_weight,
get_all_weights, get_opinion, rank, banned_ek_hashes), so fl/server.py and
trust/probation.py work UNCHANGED with reputation_engine=ChainReputationEngine(...).

v3 architecture (see ReputationRegistry.sol docstring): the chain stores,
it does not compute. This class embeds a private ReputationEngine (the
computer); after every register/record_event/reinstate call it pushes the
resulting state to the deployed contract, THEN reads back from the chain
for anything a decision depends on (status, weight). The chain, not this
process's memory, is authoritative.

O2 anti-whitewash, concretely: the contract's bannedEk[] mapping lives on
the chain, keyed by EK hash, independent of device_id and independent of
any single Python process. Three consequences this file exists to prove:
  1. a banned device re-enrolling under a NEW device_label but the SAME EK
     comes back Status.BANNED at register() time, before it ever submits
     a gradient (R2 in the contract).
  2. a server restart (fresh FederatedServer, fresh in-memory engine) does
     NOT reset any ban: reconnecting to the SAME deployed contract address
     inherits every EK ban ever recorded. This closes the "in-memory
     engine state (restart = re-enroll)" gap named in the project's own
     honest-scope section.
  3. isEkBanned() lets ANYONE with the contract address (not just the FL
     server) verify a ban independently, without trusting the server's
     word for it.

The opinion (b, d, u, a) and rank() stay off-chain-derived: the contract
stores s/f only in the ReputationPushed event log, not as queryable
state, so a fully independent recompute means replaying that event log,
exactly as trust/legacy/test_parity.py already does for the golden scenarios.
"""
from web3 import Web3

from trust.reputation import ReputationEngine, Status, Tier

SCALE = 10 ** 6

SEV = {"POSITIVE": 0, "NEUTRAL": 1, "MINOR": 2, "MAJOR": 3, "CRITICAL": 4}
STATUS_IDX = {Status.ACTIVE: 0, Status.PROBATION: 1, Status.BANNED: 2}
STATUS = {0: Status.ACTIVE, 1: Status.PROBATION, 2: Status.BANNED}
TIER_IDX = {Tier.HARDWARE: 0, Tier.TPM_RESIDENT: 1, Tier.SOFTWARE: 2}


def _severity_value(severity):
    return severity.value if hasattr(severity, "value") else severity


class ChainReputationEngine:
    def __init__(self, w3, contract, sender, params=None):
        self.w3 = w3
        self.c = contract
        self.sender = sender
        self.engine = ReputationEngine(params)   # the off-chain computer

    @staticmethod
    def _id(device_id):
        return Web3.keccak(text=device_id)

    @staticmethod
    def _ek(ek_hash):
        return Web3.keccak(text=ek_hash) if ek_hash else b"\x00" * 32

    def _send(self, fn):
        tx = fn.transact({"from": self.sender})
        return self.w3.eth.wait_for_transaction_receipt(tx)

    def _snapshot(self, device_id):
        d = self.engine._dev[device_id]
        weight = self.engine.get_weight(device_id)
        return (int(d.trust * SCALE), int(weight * SCALE),
                STATUS_IDX[d.status], int(d.s * SCALE), int(d.f * SCALE))

    # ---- O1/O2: enrollment ---------------------------------------------------
    def register(self, device_id, tier, ek_hash=None):
        self.engine.register(device_id, tier, ek_hash)
        _, weight_s, _, _, _ = self._snapshot(device_id)
        self._send(self.c.functions.register(
            self._id(device_id), TIER_IDX[Tier(tier)],
            self._ek(ek_hash), weight_s))
        return self._sync_status(device_id)

    # ---- O3: judged events ----------------------------------------------------
    def record_event(self, device_id, severity):
        self.engine.record_event(device_id, severity)
        trust_s, weight_s, status_idx, s_s, f_s = self._snapshot(device_id)
        sev = SEV[_severity_value(severity)]
        self._send(self.c.functions.pushReputation(
            self._id(device_id), sev, trust_s, weight_s, status_idx, s_s, f_s))
        return self._sync_status(device_id)

    def reinstate(self, device_id, trial_rounds=0):
        ok = self.engine.reinstate(device_id, trial_rounds)
        if ok:
            trust_s, weight_s, _, _, _ = self._snapshot(device_id)
            self._send(self.c.functions.reinstate(
                self._id(device_id), int(trial_rounds), trust_s, weight_s))
            self._sync_status(device_id)
        return ok

    def _sync_status(self, device_id):
        """Chain is the source of truth. If the contract already knows this
        EK is banned (an earlier identity, or an earlier server process),
        but this in-memory Device copy does not, pull the ban down so the
        rest of the server acts on the chain's verdict, not stale memory."""
        chain_status = STATUS[self.c.functions.getStatus(self._id(device_id)).call()]
        d = self.engine._dev[device_id]
        if chain_status == Status.BANNED and d.status != Status.BANNED:
            d.status = Status.BANNED
            if d.ek_hash is not None:
                self.engine._banned_ek.add(d.ek_hash)
        return chain_status

    # ---- reads: chain is authoritative for anything a decision depends on ----
    def get_status(self, device_id):
        return STATUS[self.c.functions.getStatus(self._id(device_id)).call()]

    def get_weight(self, device_id):
        return self.c.functions.getWeight(self._id(device_id)).call() / SCALE

    def get_all_weights(self):
        return {i: self.get_weight(i) for i in self.engine._dev
                if self.get_status(i) != Status.BANNED}

    def is_ek_banned_onchain(self, ek_hash):
        """The concrete O2 check: query the contract directly, independent
        of any Python process's memory. Use this for the whitewash proof,
        not banned_ek_hashes() below (that one is a local cache)."""
        return self.c.functions.isEkBanned(self._ek(ek_hash)).call()

    def get_device_onchain(self, device_id):
        """Full on-chain record for one device: (tier, ekHash, trust,
        weight, status, seq). Useful for a transparency panel / dashboard
        that reads the chain directly instead of trusting this class."""
        tier, ek, trust, weight, status, seq = \
            self.c.functions.getDevice(self._id(device_id)).call()
        return {"tier": tier, "ek_hash": ek.hex(), "trust": trust / SCALE,
                "weight": weight / SCALE, "status": STATUS[status], "seq": seq}

    # ---- opinion/rank stay off-chain-derived (see module docstring) ----------
    def get_opinion(self, device_id):
        return self.engine.get_opinion(device_id)

    def rank(self, device_ids=None):
        return self.engine.rank(device_ids)

    def banned_ek_hashes(self):
        return self.engine.banned_ek_hashes()


def load_registry(w3, path):
    """Reconnect to an already-deployed contract from the JSON deploy_chain.py
    wrote (address + abi + sender). Used by a fresh server process to prove
    restart-survival, and by any independent verifier reading the chain."""
    import json
    with open(path) as f:
        info = json.load(f)
    contract = w3.eth.contract(address=info["address"], abi=info["abi"])
    return contract, info["sender"]


def _self_test():
    """Requires solc network access (binaries.soliditylang.org) to compile
    ReputationRegistry.sol via py-solc-x, then deploys to an in-process EVM.
    Run: PYTHONPATH=. python3 -m trust.legacy.chain_bridge"""
    from web3 import EthereumTesterProvider
    from trust.legacy.deploy_chain import compile_contract

    print("trust/legacy/chain_bridge.py self-test")
    abi, bytecode = compile_contract()
    w3 = Web3(EthereumTesterProvider())
    sender = w3.eth.accounts[0]
    Registry = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Registry.constructor().transact({"from": sender})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)

    eng = ChainReputationEngine(w3, contract, sender)
    eng.register("atk1", Tier.SOFTWARE, ek_hash="EK_BAD")
    assert eng.get_status("atk1") == Status.ACTIVE
    status = eng.record_event("atk1", "CRITICAL")
    assert status == Status.BANNED
    assert eng.is_ek_banned_onchain("EK_BAD") is True
    print("\u2713 attacker banned, EK banned on-chain")

    status2 = eng.register("atk1_reborn", Tier.SOFTWARE, ek_hash="EK_BAD")
    assert status2 == Status.BANNED
    assert eng.get_weight("atk1_reborn") == 0.0
    print("\u2713 whitewash attempt (same EK, new device_id) rejected at register()")

    status3 = eng.register("honest1", Tier.HARDWARE, ek_hash="EK_GOOD")
    assert status3 == Status.ACTIVE
    print("\u2713 genuinely new EK admitted normally (no false ban)")

    eng2 = ChainReputationEngine(w3, contract, sender)   # simulates process restart
    assert eng2.is_ek_banned_onchain("EK_BAD") is True
    status4 = eng2.register("atk1_after_restart", Tier.SOFTWARE, ek_hash="EK_BAD")
    assert status4 == Status.BANNED
    print("\u2713 EK ban survives a fresh in-memory engine (server-restart proof)")

    print("\u2713 all chain_bridge self-tests passed")


if __name__ == "__main__":
    _self_test()
