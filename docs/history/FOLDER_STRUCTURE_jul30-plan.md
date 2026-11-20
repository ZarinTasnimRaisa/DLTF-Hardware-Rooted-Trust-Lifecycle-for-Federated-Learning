> **RETIRED (2026-11-17) - PLAN EXECUTED / SUPERSEDED.** The July 30 target-layout plan with nine decisions. The layout it describes no longer matches the tree (qbft/, figs/, signer/async_writer/preflight, exp_* harnesses all missing from it); its install commands are long done; its housekeeping decisions were executed on 2026-11-17 (v1 to trust/legacy/, dsadas/ deleted, duplicates removed). Current layout: root README.md and docs/INDEX.md. Evergreen residue: the never-commit/secret-handling rationale (also in SETUP_GUIDE section 12).

# Folder Structure — Where Every File Goes

Target layout after installing everything, reconciled against the tree in your
screenshots.

Legend: **NEW** = add it · **REPLACE** = back yours up first · *(yours)* = leave
alone · ⚠ = needs a decision

---

## Target tree

```
DLTF-main/
│
├── audit/
│   ├── __init__.py                        (yours)
│   └── hashchain.py                       REPLACE ⚠  check first, see §3
│
├── chain/                                 the v2 chain layer
│   ├── __init__.py                        (yours, may be absent — fine)
│   ├── backend.py                         (yours)   Backend ABC + Reason codes
│   ├── fixedpoint.py                      (yours)   integer mirror, SCALE=1e6
│   ├── keys.py                            (yours)   FederationKey, ek_hmac
│   ├── mock.py                            (yours)   in-memory backend
│   ├── registry.py                        (yours)   HashChain-shaped adapter
│   ├── verifier.py                        (yours)   third-party replay
│   ├── commit.py                          (yours)   commitment + EIP-712
│   ├── reconcile.py                       NEW       rebuild engine (N23)
│   ├── wiring.py                          NEW       --chain -> audit object
│   ├── verifier.py                        REPLACE   knows non-state events
│   ├── evm_parity_test.py                 REPLACE   layout-agnostic artifacts
│   ├── evm.py                             NEW       live-node backend
│   ├── deploy.py                          NEW       deploy + deployed.json
│   ├── evm_parity_test.py                 (yours)
│   ├── commit_parity_test.py              (yours)
│   ├── batch_parity_test.py               (yours)
│   ├── DLTFRegistry.sol                   (yours)   the contract
│   ├── DLTFRegistry.t.sol                 ⚠ old Foundry test, see §4
│   ├── foundry.toml                       (yours)
│   ├── deployed.json                      auto-written by chain/deploy.py
│   ├── README.md                          (yours)
│   ├── reputation.py                      ⚠ DUPLICATE, see §5
│   ├── MASTER_CONTEXT.md                  ⚠ DUPLICATE of root
│   ├── LATEX_CHANGES.md                   (yours)
│   ├── LATEX_CHANGES_COMMITMENT (1).md    (yours)
│   ├── NEXT_SESSION_PROMPT.md             (yours)
│   ├── contracts/                         ⚠ check contents
│   └── files/                             ⚠ check contents
│
├── contracts/                             NEW dir — Foundry project
│   ├── foundry.toml                       NEW
│   ├── src/
│   │   └── DLTFRegistry.sol               NEW  copy of chain/DLTFRegistry.sol
│   ├── test/
│   │   └── DLTFRegistryCommit.t.sol       NEW  34 tests, all passing
│   ├── lib/
│   │   └── forge-std/                     `forge install foundry-rs/forge-std`
│   └── out/
│       ├── DLTFRegistry.abi               NEW  prebuilt, skip solc if you like
│       └── DLTFRegistry.bin               NEW
│
├── eval/
│   ├── __init__.py                        (yours)
│   ├── scenarios.py                       (yours)
│   ├── run_experiments.py                 (yours)  ⚠ MUST RE-RUN, see §6
│   ├── plot_results.py                    (yours)
│   ├── make_figures.py                    (yours)
│   └── chain_eval.py                      NEW      Chapter 5 harness
│
├── fl/
│   ├── __init__.py                        (yours)
│   ├── aggregator.py                      (yours)
│   ├── client.py                          (yours)  ⚠ DO NOT overwrite, see §2
│   ├── dataset.py                         (yours)
│   ├── model.py                           (yours)
│   └── server.py                          (yours)  untouched — the seam works
│
├── net/
│   ├── __init__.py                        (yours)
│   ├── agent.py                           REPLACE  + --attack, /bind-wallet
│   └── handles.py                         REPLACE  band fix + commit_agent hook
│
├── tpm/
│   ├── __init__.py                        (yours)
│   ├── check_ek_cert.py                   (yours)
│   ├── client.py                          REPLACE  + sign_message/verify
│   ├── common.py                          (yours)
│   ├── ca/
│   │   └── amd_ftpm_ca.pem                (yours)  BOTH AMD intermediates
│   └── cert/                              per-machine, CLIENTS ONLY
│       └── ek.crt                              never shared between machines
│
├── trust/
│   ├── __init__.py                        (yours)
│   ├── reputation.py                      (yours)  BLACK BOX — never edit
│   ├── probation.py                       (yours)
│   ├── filter.py                          (yours)
│   ├── CHANGES_v3.md                      (yours)
│   ├── parameter_justification_report.md  (yours)
│   ├── dashboard_1_reputation.html        (yours)
│   ├── dashboard_2_parameters.html        (yours)
│   ├── dashboard_3_attacks.html           (yours)
│   ├── chain_bridge.py                    ⚠ v1 LEGACY, see §1
│   ├── ReputationRegistry.sol             ⚠ v1 LEGACY
│   ├── deploy_chain.py                    ⚠ v1 LEGACY
│   ├── test_parity.py                     ⚠ v1 LEGACY
│   └── demo_whitewash.py                  ⚠ v1 LEGACY
│
├── tests/
│   ├── test_pipeline.py                   REPLACE  + 4 chain groups
│   └── test_chain_integration.py          NEW      9 groups
│
├── tools/                                 NEW dir
│   └── prove_it_works.py                  NEW  41 checks w/ negative controls
│
├── results/                               generated, gitignore it
│   ├── audit.jsonl                        REAL-mode audit log
│   ├── sim_audit.jsonl                    SIM audit log
│   ├── federation.key                     ⚠ SECRET — never commit
│   ├── *.csv                              ⚠ Ch.4, STALE, see §6
│   └── chain/                             NEW  Ch.5 results, supplied
│       ├── TABLES.md                           paste-ready LaTeX
│       ├── parity.csv  gas_ops.csv  gas_fit.csv  gas_rounds.csv
│       ├── latency.csv  latency_raw.csv  reconcile.csv
│       ├── storage_rounds.csv  storage_summary.csv
│       └── fig_gas_clients.png  fig_storage.png  fig_latency.png
│           fig_latency_mock.png  fig_reconcile.png
│
├── legacy/                                ⚠ CREATE, see §1
│
├── docs/                                  optional, keeps root tidy
│   ├── MASTER_CONTEXT.md                  REPLACE ⚠ v2.1 -> v3, see §8
│   ├── THESIS_CONTEXT.md                  NEW
│   ├── HOW_THE_BLOCKCHAIN_WORKS.md        NEW
│   ├── SIM_WALKTHROUGH.md                 NEW
│   ├── REAL_MODE_RUNBOOK.md               NEW
│   ├── PLACEMENT_AND_USAGE.md             NEW
│   ├── CHAIN_INTEGRATION.md               (yours)
│   ├── SETUP_GUIDE.md                     (yours)
│   ├── FETCH_EK_CERT.md                   (yours)
│   ├── REFERENCES.md                      (yours)  ⚠ add Wang 2022
│   └── contributions_and_prior_work.md    (yours)
│
├── config.py                              REPLACE  + CHAIN block
├── run_local.py                           REPLACE  see §9
├── run_server.py                          REPLACE  + --chain, whitewash gate
├── dashboard.py                           (yours)
├── requirements.txt                       (yours)
├── requirements-chain.txt                 (yours)  add web3, eth-tester, py-evm
├── README.md                              (yours)
├── .gitignore                             (yours)  add results/, venv/, out/
├── venv/                                  (yours)
│
├── build/registry_dev.json                ⚠ v1 LEGACY
└── dsadas/                                ⚠ DELETE — stray
```

---

## Install commands

```bash
cd DLTF-main

# 1. back up what gets replaced
mkdir -p .backup
cp run_local.py run_server.py config.py net/agent.py tpm/client.py \
   tests/test_pipeline.py audit/hashchain.py .backup/

# 2. new chain modules
cp chain/reconcile.py chain/wiring.py chain/evm.py chain/deploy.py  chain/

# 3. replacements
cp run_local.py run_server.py config.py  ./
cp net/agent.py        net/
cp tpm/client.py       tpm/
cp tests/test_pipeline.py tests/test_chain_integration.py  tests/

# 4. eval harness
cp eval/chain_eval.py  eval/

# 5. Foundry project + prebuilt artifacts
mkdir -p contracts/src contracts/test contracts/out
cp DLTFRegistry.sol            contracts/src/     # or: cp chain/DLTFRegistry.sol
cp DLTFRegistryCommit.t.sol    contracts/test/
cp foundry.toml                contracts/
cp DLTFRegistry.abi DLTFRegistry.bin  contracts/out/

# 6. results
mkdir -p results/chain && cp -r results/chain/* results/chain/

# 7. docs
mkdir -p docs && cp *.md docs/

# 8. deps
pip install web3 eth-tester py-evm eth-utils eth-account
echo -e "web3\neth-tester\npy-evm\neth-utils\neth-account" >> requirements-chain.txt

# 9. verify
PYTHONPATH=. python3 tests/test_pipeline.py
PYTHONPATH=. python3 tests/test_chain_integration.py
```

**You do not have to move `chain/DLTFRegistry.sol`.** `chain/evm.py` searches
`contracts/src/`, `chain/`, and `chain/contracts/` and prints the correct build
command for whichever it finds.

---

## The nine decisions

### §1 — Two chain implementations coexist ⚠ **highest priority**

`trust/` still holds the v1 Polygon attempt, superseded by `chain/`:

```bash
mkdir -p legacy
git mv trust/chain_bridge.py trust/ReputationRegistry.sol \
       trust/deploy_chain.py trust/test_parity.py trust/demo_whitewash.py \
       build/registry_dev.json  legacy/
```

Move, don't delete — it's evidence of iteration, and `demo_whitewash.py` may
still be useful. But it must leave the import path. Two implementations invites
"which one is the contribution?", and that is a bad question to face live.

Note `audit/hashchain.py`'s docstring still points at `trust/chain_bridge.py`.
Update that line.

### §2 — `fl/client.py`: KEEP YOURS

`fl/client.py` was missing from every drop you sent (the file you uploaded as
`client.py` was `tpm/client.py`). I reconstructed a minimal `FLClient` for my
sandbox. **Yours has `TorchTrainer`, which mine lacks and which `net/agent.py`
imports for REAL mode.** The file marked `.SANDBOX-ONLY-DO-NOT-COPY` is reference
only.

### §3 — `audit/hashchain.py`: check before replacing

```bash
grep -n "def verify\|self.entries\|def head_hash" audit/hashchain.py
```

The copy in your tree is the self-labelled *"minimal, compatible stand-in"*. Its
interface breaks the chain layer:

| Callers expect | Placeholder has |
|---|---|
| `entries(event_type=None)` method | `entries` list attribute |
| `verify()` → `(ok, err)` | `verify()` → `bool` |
| `entry["payload"]` | `entry["data"]` |
| `head_hash()`, `__len__()`, `seq` | absent |

Your own `test_pipeline.py` calls `entries()`, unpacks `ok, err = verify()`, and
calls `head_hash()` — so the placeholder was never what your pipeline ran
against. **If `verify` returns a bare bool, replace it. If yours already has the
full surface, keep yours** — mine is a reconstruction.

### §4 — `chain/DLTFRegistry.t.sol` vs the new suite

Your existing Foundry file predates the commitment layer. Mine
(`DLTFRegistryCommit.t.sol`, 34 tests, all passing under forge 1.7.1) covers
`bindWallet`, `commitGradient`, the anti-fabrication rule, EIP-712, and batching.
Keep both — different contracts, no conflict — and run them from `contracts/`.

### §5 — `chain/reputation.py` duplicates `trust/reputation.py`

```bash
diff chain/reputation.py trust/reputation.py
```

All my code imports `from trust.reputation import ...`. If they've drifted you
have two engines and no way to know which produced a result. Delete the loser.
Same for `chain/MASTER_CONTEXT.md` vs root.

### §6 — Chapter 4 CSVs are stale ⚠ **the real blocker**

Every file in `results/` was generated under v2.1: per-tier priors, FORGET=0.95,
`w(MAJOR)=3`. v3 uses uniform Beta(1,1), FORGET=0.90, MINOR==MAJOR. Every trust
trajectory has shifted.

```bash
grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/     # will KeyError if found
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
```

Chain off. Nothing in Chapter 5 finalises until Chapter 4's numbers are stable.

### §7 — `net/handles.py:99` stale assertion

Asserts `0.3 <= w <= 0.5`. Under v3, a fresh Tier-2 device after one NEUTRAL round
is `s=0.4, f=0 → T=0.5833 → w=0.2917`. Fails.

```python
assert all(0.25 <= w <= 0.35 for w in report["weights"].values())
```

```bash
grep -rn "0\.3 <=\|<= 0\.5" --include=*.py .        # find siblings
```

This is the same v2.1→v3 staleness as §6, surfacing in a self-test — decent
evidence the CSVs really are stale rather than close enough.

### §8 — `MASTER_CONTEXT.md` describes the old engine

Your copy documents v2.1 constants that are not in the code: priors
(8,2)/(4,2)/(2,2), start trust 0.80/0.667/0.50, per-tier γ, `w(MINOR)=1
w(MAJOR)=3`, θ_r=0.55, FORGIVE_AFTER=5, FORGET=0.95. It also says *"no smart
contracts in the current codebase… do not reintroduce blockchain"*. Use the
rewritten one — every constant read back from live code.

### §9 — `run_local.py`: use mine, settled empirically

I ran both on identical arguments and diffed:

```
1d0
< engine: additive
```

**Every weight, every ban, every number byte-identical.** The only difference is
the dead `--engine` flag your prompt (#3) told me to delete. Mine adds `audit=`
wiring (#2), `--tier1` (#1), `--chain`, `--restart-at`, `--rejoin-as`.

---

## Never commit these

```gitignore
venv/
results/
contracts/out/
contracts/lib/
chain/deployed.json
tpm/cert/
__pycache__/
*.pyc
```

`results/federation.key` is the HMAC key for EK privacy. **If it leaks, anyone can
test whether a given EK is in your banned set** — the privacy property in N22 is
gone. Treat it like a private key.

`tpm/cert/ek.crt` is per-machine hardware identity. Not secret, but it is
machine-specific and committing it invites someone to copy it to the wrong box
and spend a day debugging a Tier-2 enrollment.

---

## Post-install verification

```bash
PYTHONPATH=. python3 tests/test_pipeline.py           # whole stack + chain
PYTHONPATH=. python3 tests/test_chain_integration.py  # 9 groups
PYTHONPATH=. python3 run_local.py --clients 6 --rounds 5          # baseline
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient            # the demo
cd contracts && forge test -vv                        # 34 Solidity tests
```

Expected: **274 ✓ Python checks** across 22 modules, 9 integration groups, 34
Foundry tests.

Then read `SIM_WALKTHROUGH.md` for the nine-step demo and
`REAL_MODE_RUNBOOK.md` for the Tailscale deployment — starting with §0 of the
runbook, which explains why two physical clients cannot demonstrate detection.
