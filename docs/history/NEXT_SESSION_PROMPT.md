> **RETIRED (2026-11-17) - TASK FULLY EXECUTED.** Every item in "WHAT IS LEFT TO BUILD" now exists and is tested. Unique reference content (module manifest, 8 design decisions, audit event surface, serialization, BRACU constraints) was carried into root MASTER_CONTEXT.md section 16.

# DLTF Chain Layer — Continuation Prompt

Upload this file along with the MASTER_CONTEXT.md (already rewritten) and every
file in the `chain/` and `contracts/` folders into the next chat's project
knowledge. Then paste the TASK section at the bottom as your first message.

---

## ROLE

Senior engineer, distributed systems + Solidity. You are continuing work on an
optional on-chain trust registry for DLTF, an existing federated-learning system
with TPM-rooted identity. The PREVIOUS session built the core modules and the
contract. This session wires them into the running system and completes the
remaining deliverables.

## READ FIRST

Read MASTER_CONTEXT.md (the rewritten one — it describes the system accurately).
Then read all files in `chain/` and `contracts/src/DLTFRegistry.sol`. Then read
`fl/server.py`, `run_local.py`, `run_server.py`, `config.py`, `net/agent.py`,
`net/handles.py`, `audit/hashchain.py`, `tpm/client.py`.

Report back with a status check before writing code:
- confirm all self-tests pass (expect 150 checks green)
- confirm you understand the wiring plan below
- flag any conflict between the plan and what you see in the code

---

## WHAT WAS BUILT (complete, tested, do not rebuild)

### File manifest (all in the project)

```
chain/
  __init__.py          empty
  fixedpoint.py        518 loc, 14 checks — integer mirror of reputation.py
  backend.py           241 loc,  5 checks — abstract Backend ABC + Reason codes
  mock.py              574 loc, 20 checks — deterministic in-memory backend
  keys.py              193 loc, 11 checks — FederationKey (ek_hmac privacy)
  registry.py          627 loc, 14 checks — HashChain-compatible adapter
  verifier.py          392 loc, 11 checks — third-party recomputation
  commit.py            785 loc, 27 checks — client-side gradient commitment
                                            + EIP-712 batch signing
                                            + CommitMockBackend wrapper
  evm_parity_test.py   448 loc, 15 checks — deployed-contract parity (base)
  commit_parity_test.py 250 loc, 17 checks — deployed-contract parity (commit)
  README.md            mode-selection table, guarantees, gas, commands

contracts/
  src/DLTFRegistry.sol  881 loc — compiles 8.9 KB, solc 0.8.24
  test/DLTFRegistry.t.sol 208 loc — Foundry tests (not run, provided for forge)
  foundry.toml

trust/
  reputation.py        711 loc, 16 checks — patched (FORGET=0.90, self-test green)
```

Total: **150 self-test checks green** (141 + 9 from batch signing additions).

### Architecture summary

Three independent axes, never coupled:
- TPM: mock signer / real TPM via tpm2-tools
- Transport: in-process (LocalClientHandle) / HTTP (RemoteClientHandle)
- Chain: off / mock in-memory / Hardhat or Anvil node

The chain layer sits behind `ChainRegistry`, which implements the HashChain
interface (`append`, `entries`, `verify`, `head_hash`, `__len__`). It drops into
`FederatedServer(audit=registry)` with ZERO changes to `fl/server.py`.

When `append("EVENT", {...})` is called, the registry:
1. Forwards to the inner HashChain (local audit log unchanged)
2. Buffers the event by round
3. At `ROUND`, infers NEUTRAL for participants with no EVENT (the NEUTRAL
   inference — server.py line 113 skips NEUTRAL, but NEUTRAL decays s/f)
4. Dispatches to the chain backend (mock or EVM)
5. On ChainRejection: records it, marks round UNANCHORED, does NOT propagate

### Constants (from live code, authoritative)

```
SCALE = 1_000_000
THETA_FP = 400_000    TAU_FP = 600_000    DECAY = 9/10 (floor)
BAN_T = 300_000       PROBATION_T = 500_000    REINSTATE_T = 750_000
FORGIVE_AFTER = 2     MAJOR_RUN_TO_ESCALATE = 2
REINSTATE_RATIO = 3   (exact at r=0.75)
GAMMA = FORGET = 0.90 (one decay primitive, [DERIVED])
Status: ACTIVE=0, PROBATION=1, BANNED=2
Tier: HARDWARE=1, TPM_RESIDENT=2, SOFTWARE=3
Severity: POSITIVE=0, NEUTRAL=1, MINOR=2, MAJOR=3, CRITICAL=4
REHAB: HARDWARE only
```

### Contract storage (one packed 256-bit slot per device)

```
s(64) + f(64) + cleanRun(16) + majorRun(16) + status(8) + tier(8) + lastRound(32) = 208 bits
```

Plus: `deviceEk`, `bannedEk`, `ekToDevice`, `rehabUsed`, `roundClosed`,
`lastRound`, `deviceWallet`, `walletDevice`, `commitments`.

### Six rejection rules (all tested on deployed contract)

| Rule | Custom error |
|---|---|
| BANNED → ACTIVE | BanToActive |
| tier change | TierMutation |
| delta outside rule | structural (no delta API) |
| duplicate/stale round | DuplicateRound / StaleRound |
| duplicate EK | EkAlreadyRegistered |
| non-server write | UnauthorizedWriter |

### Commitment layer (also tested on deployed contract)

- Clients commit `keccak256(canonical(gradient))` before sending
- Canonical = little-endian IEEE-754 float64, `struct.pack("<Nd", *G)`
- Wallet bound to TPM identity at enrollment (one wallet, one device, immutable)
- `requireCommit` is `immutable` — cannot be disabled mid-federation
- `classify` reverts with `MissingCommit` if no commit exists for that round
- EIP-712 batch signing available: clients sign off-chain, server batches

### Gas (measured on py-evm, Cancun, optimizer=200)

| Operation | Gas |
|---|---:|
| deploy | 1,397,314 |
| register (fresh) | 95,047 |
| classify NEUTRAL (warm) | 36,593 |
| classify (with commit check) | 38,618 |
| commitGradient | 51,440 |
| roundSummary | 91,277 |
| bindWallet | 71,712 |

### Key design decisions (do not revisit)

1. **Semantic API, not state-driven.** Backend has no `submitState()`. Callers
   submit severity; backend recomputes. N20 is structural.
2. **BANNED is absorbing.** No exception. `register()` in `reputation.py` has a
   latent hole (ek_hash=None resurrects); the chain layer catches it.
3. **Mock chain is deterministic.** No timestamps in hashed bodies (unlike
   audit/hashchain.py which hashes `time.time()`). Same sequence → same head.
4. **NEUTRAL inference.** The adapter infers NEUTRAL from the complement of
   logged EVENTs vs the ROUND participant list. Exact, not heuristic.
5. **Consequence events ignored.** BAN and WHITEWASH_REJECTED are cascaded by
   the backend; the adapter does not re-dispatch them.
6. **Never on the critical path.** Rejection/timeout → UNANCHORED, never halt.
7. **EK privacy.** `ek_hmac = HMAC-SHA256(federation_key, "DLTF-EKv1|" + ek_hash)`.
   Raw EK hashes never go on chain. Federation key separate from audit key.
8. **FORGET = GAMMA = 0.90.** One decay primitive. [DERIVED], not [CALIBRATED].
   Self-test bands re-derived and green.

---

## WHAT IS LEFT TO BUILD

### Priority 1: SIM mode wiring (makes the acceptance test runnable)

#### 1a. `chain/reconcile.py`

Rebuild a `ReputationEngine`'s state from chain events at startup. The logic
already exists in `chain/verifier.py::replay_events()` — that returns a
`FixedEngine`. This module needs to:

- Take a `FixedEngine` from `replay_events`
- Inject the state into a FRESH `ReputationEngine` by calling
  `register()` and then patching `_dev[id].s`, `_dev[id].f`, etc.
  from the fixed-point values (divide by SCALE)
- Mark `_banned_ek` from the chain's banned set
- Return the populated engine

This is the feature that makes N23 real: bans survive restart.

IMPORTANT: `reputation.py` is a strict BLACK BOX. Do not edit it. Interact only
via public APIs. If you need to set internal state, use `setattr` on the module
globals or patch `_dev` entries, exactly as `run_local.py::_self_test` does.

#### 1b. `config.py` additions

```python
CHAIN = {
    "mode": "off",                          # off | mock | node
    "rpc_url": "http://127.0.0.1:8545",
    "contract_address": None,               # filled by deploy.py
    "federation_key_path": "results/federation.key",
    "require_commit": False,                # commitment layer off by default
}
```

All defaulting to disabled. With `CHAIN["mode"] = "off"`, everything behaves
exactly as before.

#### 1c. `run_local.py` — three new flags

```
--chain off|mock|node    (default: off)
--restart-at N           tear down server at round N, rebuild from chain, continue
--rejoin-as LABEL        a banned client re-enrolls under a fresh label with same EK
```

Also fix two existing bugs:
- Wire `audit=` into `FederatedServer()` — currently it's constructed without it,
  so SIM mode records nothing.
- Add `--tier1 N` flag using the `generate_test_ca` / `issue_ek_cert` pattern from
  `fl/server.py::_self_test`, so Tier-1 (HARDWARE) clients are reachable in SIM.
  Without this, every SIM client is Tier-2, REHAB=False, and probation never fires.
- Delete the dead `--engine beta` flag (lines 34, 52).

Target acceptance test:

```bash
PYTHONPATH=. python3 run_local.py \
    --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient
```

Expected: attackers flagged → banned → server restarts at round 12 → state
rebuilt from chain → `newclient` enrolls with a banned EK → WHITEWASH_REJECTED.

#### 1d. `run_server.py` — chain flag for REAL mode

```
--chain off|mock|node    (default: off)
```

At enrollment: if chain is enabled, check `registry.is_banned_on_chain(ek_hash)`
before proceeding. If banned: refuse enrollment, log WHITEWASH_REJECTED, continue
with remaining clients.

When node is stopped mid-run: rounds continue, no crash.

### Priority 2: `chain/evm.py` (live-node backend)

web3.py adapter that implements `chain.backend.Backend`. Talks to a Hardhat or
Anvil node via JSON-RPC. Must:

- Wrap every call in retry + timeout
- On timeout/revert: set `is_available() = False`, let the registry degrade
- On success: set `is_available() = True`
- Match MockBackend's event emission by reading transaction receipts
- `get_device()` calls `contract.functions.getDeviceState(deviceId).call()`
- `is_banned_ek()` calls `contract.functions.isBannedEk(ekHmac).call()`
- Events come from `contract.events.ClassifyEvent.get_logs()`

Constructor takes `(web3_instance, contract_address, abi, server_account)`.

### Priority 3: `chain/deploy.py`

```bash
PYTHONPATH=. python3 -m chain.deploy --network localhost
```

Deploys `DLTFRegistry.sol` to the specified node. Prints the contract address.
Writes it to `config.py`'s `CHAIN["contract_address"]` or to a separate
`chain/deployed.json`.

### Priority 4: Wire commitment into the training loop

#### 4a. `net/agent.py` — commit before returning

In the `/train` handler, after computing the update and BEFORE returning it:

```python
if self.commit_agent:
    receipt = self.commit_agent.commit(body["round"], update)
    # include receipt in response so server knows the commit exists
```

#### 4b. `fl/server.py` or `chain/registry.py` — verify after receiving

After `handle.train(round_id, params)` returns:

```python
if chain_enabled and require_commit:
    chk = check_commit(backend, device_label, round_id, gradient)
    if not chk.matched:
        backend.report_commit_mismatch(...)
        # drop this client's update for this round
```

#### 4c. `tpm/client.py` — wallet-binding signature

For real TPM:
```python
def sign_challenge(self, message: bytes) -> bytes:
    """Sign with the attestation key. For wallet binding."""
    # tpm2_sign -c ak.ctx -g sha256 -o sig.bin msg.bin
```

For mock TPM: already has a compatible `verify`, just needs `sign`.

### Priority 5: Evaluation harness

Per the spec:
- Gas per operation and per round (DONE in the previous session)
- Wall-clock latency per round, scaling 2–50 clients (SIM, chain mock and node)
- Contract storage growth over 30 rounds
- Reconciliation time vs number of historical rounds
- With/without comparison on identical seeds: accuracy and reputation trajectories
  must be UNCHANGED
- REAL mode: one table of per-round latency with 2 physical clients (feasibility)

### Priority 6: `tests/test_pipeline.py` integration

Wire all chain module `_self_test()` functions into the pipeline test so
`PYTHONPATH=. python3 tests/test_pipeline.py` runs them when chain is importable.

### Priority 7: Foundry tests update

`contracts/test/DLTFRegistry.t.sol` needs updating for the commitment layer
additions (bindWallet, commitGradient, the anti-fabrication rule). The Python
parity test already covers these; the Foundry file is an independent check.

---

## DESIGN CONSTRAINTS (non-negotiable, from the original spec)

1. **Off by default.** With `--chain off`, these must work EXACTLY as today:
   - `python3 tests/test_pipeline.py` → PIPELINE GREEN
   - `python3 -m eval.run_experiments --exp all --seeds 5 --rounds 30 --out results --check`
   - `python3 run_local.py`
   - `python3 run_server.py --rounds 10`

2. **Never on the critical path.** Node down → degrade, not halt.

3. **Mock chain backend mandatory.** CI must never need a node.

4. **No gradients on chain.** Hashes and scalars only.

5. **No raw EK hashes on chain.** Write ek_hmac with domain separation.

6. **Touch nothing outside `chain/` plus minimal seams** in `fl/server.py`,
   `run_local.py`, `run_server.py`, `config.py`, `net/agent.py`.

7. **reputation.py is a strict black box.** No edits. `setattr` for patching.

8. **House style:** `_self_test()` per module, `__main__` runnable, ✓ lines,
   assertions, maps features to O1–O4.

9. **BRACU LaTeX template constraints:** no `booktabs`, `longtable`, `amssymb`,
   `tikz`, `listings`, `float`, `subcaption`. Tables use `\hline` only. Figures
   are external PNGs. biblatex biber IEEE style.

10. **Truffle and Ganache are dead.** ConsenSys archived both Dec 2023.
    Foundry or Hardhat only.

---

## BUILD ORDER

```
1. chain/reconcile.py        (needed by run_local.py --restart-at)
2. config.py additions       (CHAIN block, defaults to disabled)
3. run_local.py wiring       (--chain, --restart-at, --rejoin-as, --tier1, audit=)
4. run_server.py wiring      (--chain, whitewash check at enrollment)
5. chain/evm.py              (live-node backend)
6. chain/deploy.py           (deploy script)
7. net/agent.py hook         (commit before returning)
8. tpm/client.py             (sign_challenge for wallet binding)
9. tests/test_pipeline.py    (wire chain self-tests)
10. evaluation harness        (gas, latency, storage, reconciliation time)
11. contracts/test update     (Foundry tests for commitment)
```

Do not attempt steps 5-6 until steps 1-4 are green. Do not attempt step 7 until
step 5 works. Run the full self-test suite after every step.

---

## EXISTING CODE CONTEXT

### `fl/server.py` — the seam

`FederatedServer.__init__` takes `audit=None`. When set, it calls:
- `audit.append("ENROLL", {...})` at enrollment
- `audit.append("EVENT", {...})` for non-NEUTRAL classifications
- `audit.append("BAN", {...})` on ban
- `audit.append("WHITEWASH_REJECTED", {...})` on whitewash
- `audit.append("PROBATION_ENTER", {...})` on probation entry
- `audit.append("PROBATION_DECISION", {...})` on probation outcome
- `audit.append("REHAB_EXHAUSTED", {...})` on rehab failure
- `audit.append("ROUND", {"round": rid, "participants": sorted(labels), "aggregated": bool})` at round close

`ChainRegistry` implements exactly this surface.

Line 113: `if self.audit and cls.severity != "NEUTRAL"` — NEUTRALs are NEVER
logged. The adapter infers them from the ROUND participant list.

### `run_local.py` — current state

Constructs `FederatedServer(initial_params=...)` WITHOUT `audit=`. Uses
`LocalClientHandle`. `make_signer("mock", label)` for TPM. No `ca_bundle_pem`,
so all clients are Tier 2. Has a dead `--engine beta` flag.

### `audit/hashchain.py` — the interface to match

```python
HashChain(path=None, key=None)
.append(event_type, payload) -> entry dict
.entries(event_type=None) -> list[dict]
.verify() -> (bool, err|None)
.head_hash() -> hex string
.__len__() -> int
```

Entry: `{seq, ts, type, payload, prev, hash, sig}`.
GENESIS auto-appended at construction.

### `net/handles.py` — the transport seam

```python
LocalClientHandle(device_label, signer, fl_client, tpm_backend="mock")
RemoteClientHandle(device_label, endpoint, tpm_backend="real", timeout=30, train_timeout=600)
```

Both expose: `.device_label`, `.tpm_backend`, `.enroll_payload()`,
`.activate_credential(blob)`, `.train(round_id, params)`.

### Live deployment (REAL mode)

- Server: 100.95.144.127
- client1: 100.70.28.2 (s4zz4d HP)
- client2: 100.64.57.82 (tafsir HP)
- Both AMD fTPM, Tier 1 (HARDWARE), real MNIST 409k params
- Tailscale mesh, port 8470
- Node (Anvil) runs on server machine, localhost only

---

## LATEX STATUS

### Already written (in LATEX_CHANGES.md + LATEX_CHANGES_COMMITMENT.md)

Paste-ready snippets for:
- Ch. 3 §3.1.1: T21–T30 threat IDs (server-operator + commitment)
- Ch. 3 §3.1.2: N18–N27 requirements with traceability table
- Ch. 3 §3.2: chain layer architecture (8 paragraphs: architecture, fixed-point,
  storage, integration seam, degradation, EK privacy, verification, mode table,
  commitment subsection)
- Ch. 5: gas table, SIM lifecycle table, commitment attacks table, central claim
- Ch. 6: 12 limitation items
- Ch. 2: ZTA-FL hedging, Slovic reframing

### What the next session needs to produce

- Chapter 5 evaluation results after the harness runs (step 10 above)
- Any updates to MASTER_CONTEXT.md after wiring is complete
- The final chain/README.md with all commands verified end-to-end

### Stale items that block Chapter 5

**Chapter 4 CSVs MUST be re-run.** They were generated at FORGET=0.95 under v2.1.
Under v3 + 0.90 every trust trajectory shifts. Command:

```bash
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```

Chain OFF for sweeps. This is not optional.

---

## CONFLICTS AND KNOWN ISSUES

1. `run_local.py` produces ONLY Tier-2 clients. No `ca_bundle_pem` → `cert_ok=False`
   → `TPM_RESIDENT` → `REHAB=False`. Probation unreachable. Fix with test-CA.

2. `run_local.py` constructs FederatedServer without `audit=`. SIM records nothing.

3. `run_local.py` has dead `--engine beta` flag at lines 34, 52. Delete.

4. `check_tiers.py` — referenced but existence unconfirmed. Verify.

5. Wang 2022 in MASTER_CONTEXT.md but missing from REFERENCES.md.

6. Reference [24] Domingo-Ferrer marked VERIFY.

7. Live poison-injection command undocumented.

8. `reputation.py` latent hole: `register(id, tier)` with `ek_hash=None`
   resurrects BANNED as ACTIVE. Unreachable from server.py. The chain layer
   catches it — that's the demo. Do not fix in reputation.py (black box).

---

## TASK

Build steps 1–4 of the build order (reconcile.py, config additions,
run_local.py wiring, run_server.py wiring). Then run the acceptance test:

```bash
PYTHONPATH=. python3 run_local.py \
    --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient
```

Expected output:
- Rounds 0–11 run normally, attackers get banned
- Server tears down at round 12
- State rebuilt from chain events (print device count, ban count)
- Rounds 12–19 resume with rebuilt state
- `newclient` enrolls with a banned EK → WHITEWASH_REJECTED
- Final verification: `chain/verifier.py` confirms 0 discrepancies

Then confirm the baseline is untouched:
```bash
PYTHONPATH=. python3 run_local.py --clients 6 --rounds 10
```
Must behave identically to before — no chain, no audit, no new output.

Report back with the full test output before proceeding to steps 5–8.
