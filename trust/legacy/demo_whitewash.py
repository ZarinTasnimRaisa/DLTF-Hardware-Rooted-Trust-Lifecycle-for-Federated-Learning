"""
trust/legacy/demo_whitewash.py

End-to-end demo, real objectives O1/O2/O3, chain-backed:
  1. Deploy ReputationRegistry.sol to an in-process EVM (dev mode).
  2. Run a real DLTF round loop (fl/server.py, trust/filter.py, the actual
     detection and reputation logic) with a "poison" attacker, using
     eval/scenarios.py's own SyntheticWorld and attacker behaviors, but
     with reputation_engine=ChainReputationEngine instead of the default
     in-memory one. Every judged event is a chain transaction.
  3. Once the attacker is banned, attempt the WHITEWASH: the SAME
     hardware EK (same TPM signer/cert) re-enrolls under a brand new
     device_label. Assert the chain rejects it at register() time.
  4. Simulate a server restart (fresh FederatedServer + fresh
     ChainReputationEngine, SAME deployed contract address) and show the
     ban still holds.

Run: PYTHONPATH=. python3 -m trust.legacy.demo_whitewash
"""
from web3 import Web3, EthereumTesterProvider

from tpm.common import generate_test_ca, issue_ek_cert, ca_bundle_pem
from tpm.client import make_signer
from fl.client import FLClient
from fl.server import FederatedServer
from net.handles import LocalClientHandle
from trust.reputation import Status
from trust.legacy.chain_bridge import ChainReputationEngine
from trust.legacy.deploy_chain import compile_contract
from eval.scenarios import SyntheticWorld, behavior, make_handle


def deploy_dev_contract():
    abi, bytecode = compile_contract()
    w3 = Web3(EthereumTesterProvider())
    sender = w3.eth.accounts[0]
    Registry = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Registry.constructor().transact({"from": sender})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    contract = w3.eth.contract(address=receipt.contractAddress, abi=abi)
    return w3, contract, sender


def build_server(w3, contract, sender, ca_cert):
    engine = ChainReputationEngine(w3, contract, sender)
    return FederatedServer(initial_params=[0.0] * SyntheticWorld().dim,
                           ca_bundle_pem=ca_bundle_pem(ca_cert),
                           reputation_engine=engine), engine


def main():
    print("trust/legacy/demo_whitewash.py")
    w3, contract, sender = deploy_dev_contract()
    print(f"\u2713 ReputationRegistry deployed at {contract.address} (dev EVM)")

    world = SyntheticWorld(seed=0)
    ca_key, ca_cert = generate_test_ca()

    server, engine = build_server(w3, contract, sender, ca_cert)

    honest = [make_handle(f"h{k}", behavior(world, "honest", seed=100 + k))
              for k in range(5)]

    # attacker enrolls Tier 1 HARDWARE (a real EK cert), poisons from round 5
    atk_cert, atk_ek_hash = issue_ek_cert(ca_key, ca_cert, "atk_hw")
    atk_signer = make_signer("mock", "atk1", ek_cert_der=atk_cert)
    atk_trainer = behavior(world, "poisoner", seed=999, attack_start=5)
    atk_handle = LocalClientHandle("atk1", atk_signer, FLClient("atk1", atk_trainer))

    handles = honest + [atk_handle]
    for h in handles:
        r = server.enroll(h)
        print(f"  enroll {r['device_id']}: tier {r['tier']} status {r['status']}")

    banned_round = None
    for rnd in range(15):
        rep = server.run_round(rnd, handles)
        flags = {d: e["severity"] for d, e in rep["events"].items() if e["severity"] != "NEUTRAL"}
        if flags:
            print(f"  round {rnd}: flags {flags} weights {rep['weights']}")
        if engine.get_status("atk1") == Status.BANNED and banned_round is None:
            banned_round = rnd
    assert banned_round is not None, "attacker was never banned, check attack_start/thresholds"
    print(f"\u2713 attacker banned at round {banned_round} (verified via chain read, not local memory)")
    assert engine.is_ek_banned_onchain(atk_ek_hash)
    print(f"\u2713 attacker's EK hash confirmed banned on-chain: {atk_ek_hash[:16]}...")

    # ---- WHITEWASH ATTEMPT: same signer/cert, brand new device_label --------
    reborn_trainer = behavior(world, "honest", seed=1)   # tries to look clean this time
    reborn_handle = LocalClientHandle("atk1_reborn", atk_signer, FLClient("atk1_reborn", reborn_trainer))
    r = server.enroll(reborn_handle)
    assert r["status"] == Status.BANNED.value, r
    assert engine.get_weight("atk1_reborn") == 0.0
    print(f"\u2713 whitewash rejected: 'atk1_reborn' (same EK) enrolled as {r['status']}, weight 0")

    # ---- RESTART SIMULATION: fresh server, fresh in-memory engine ------------
    server2, engine2 = build_server(w3, contract, sender, ca_cert)
    fresh_handle = LocalClientHandle("atk1_after_restart", atk_signer,
                                     FLClient("atk1_after_restart", behavior(world, "honest", seed=2)))
    r2 = server2.enroll(fresh_handle)
    assert r2["status"] == Status.BANNED.value, r2
    print("\u2713 ban survives a full server restart (new process, same deployed contract)")

    print("\nALL WHITEWASH-PREVENTION CHECKS PASSED")


if __name__ == "__main__":
    main()
