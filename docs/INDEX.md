# DLTF Documentation Index

Consolidated 2026-11-17. One canonical version of each document; superseded
versions are preserved, labeled, in `docs/history/`. Start with §1 if you are
setting up, §2 if you are writing, §3 if you are running or verifying.

**Root-level canonical docs**

| Document | Read it when |
|---|---|
| `README.md` (root) | first contact — what DLTF is, current state, quick start |
| `MASTER_CONTEXT.md` (root) | **the authoritative system state** — engine constants, chain layer, Sept-2026 deployment phase (§15), merged appendix (§16) |
| `RUNBOOK.md` (root) | the newest engineering record: local signing, correctness fixes, liveness/economics, QBFT runs (§11) |
| `CLAUDE.md` (root) | session handoff + ordered next steps (Anvil → testnet → QBFT → paper) |
| `SETUP_GUIDE.md` (root) | first install, or something broke (13 sections, in break-order) |
| `FETCH_EK_CERT.md` (root) | provisioning a new AMD client's EK certificate (evergreen) |
| `REFERENCES.md` (root) | annotated bibliography + novelty vs prior work |

---

## 1. Getting the system running

| Document | Read it when |
|---|---|
| `SETUP_GUIDE.md` (root) | install, venv ABI trap, solc pin, TPM certs, Tailscale, real chain (§13) |
| `SIM_WALKTHROUGH.md` | demoing on one PC — nine steps, each with its proof line |
| `REAL_MODE_RUNBOOK.md` | the three-machine deployment; **read §0 first** (two physical clients cannot demonstrate detection) |
| `qbft/README.md` | the 4-validator Besu stage: what it proves, what already ran, the open POA bug |

## 2. Writing the thesis / paper

| Document | Read it when |
|---|---|
| `ARCHITECTURE.md` | **you want the full picture** — every layer, the exact round lifecycle, data flows, end-to-end walkthroughs (code-grounded, 2026-11-18) |
| `THESIS_CONTEXT.md` | **start here — writing any chapter/section.** §0: eight claims you must not make |
| `HOW_THE_BLOCKCHAIN_WORKS.md` | the chain design explainer (no-txid argument, semantic-vs-state API, EK privacy); see its 2026 addendum for async/QBFT corrections |
| `MASTER_CONTEXT.md` (root) | you need the authoritative system state and constants |
| `RESULTS_EXPLAINED.md` | what each measured number licenses you to claim |
| `FORGE_LINT_WARNINGS.md` | `forge build` printed unsafe-typecast notes (justified suppression) |
| `eval/RUNBOOK.md` | the paper-evidence completion plan (28-requirement coverage) |

Two writing tracks exist and their instruction sets must stay separate:
the **BRACU thesis** (`\hline`-only tables, biblatex-biber; constraints in
MASTER_CONTEXT §16.11 and `docs/history/LATEX_CHANGES*.md`) and the
**ACM NSysS paper** (acmart sigconf v2.19, 6–8 pages, booktabs allowed;
CLAUDE.md §2, `eval/RUNBOOK.md`).

## 3. Running and verifying

| Document | Read it when |
|---|---|
| `TEST_COMMANDS.md` | **the master catalogue — 8 tiers**, plus the September suites (preflight, liveness, economics) |
| `RESULTS_EXPLAINED.md` | interpreting output, negative controls, the three defensible sentences |
| `FORGE_LINT_WARNINGS.md` | lint output during `forge build` |

---

## Current evidence base (September 2026)

| Artifact | Count |
|---|---|
| module self-tests | 274 ✓ across 22 modules (July baseline) |
| contract tests through the signed path | 55/55 (September) |
| pipeline groups | 8/8 |
| chain integration groups | 9/9 |
| falsification checks (with controls) | 41/41 |
| Python contract parity checks | 53 (15 + 17 + 21) |
| Solidity tests | Rules + Commit suites (`contracts/test/`) |
| Chapter 4 CSVs + figures | 6 + 8 (regenerated under v3) |
| Chapter 5 CSVs + figures | 9 + 5 |
| QBFT preflight (2026-09-11) | 18/19 — **open POA `head_hash` bug**, fix before faucet spend |

Canonical result tables: `results/chain/TABLES.md` (generated, regenerable;
the old `docs/TABLES.md` snapshot was a stale duplicate and was deleted).

## Numbers to quote carefully

| Quote | Not |
|---|---|
| `round_gas ≈ 58,281 + 38,818 × clients` (slope exact, intercept ±5 from calldata) | a single precise intercept |
| packed word **208 bits declared** | 179 or 181 (varies with `lastRound`) |
| deploy **2,085,425** at solc 0.8.24 | any figure from another compiler |
| flag-level FPR 0.6%, **sanction-level 0%** | "zero false positives" |
| latency from `--exp real` only (or the QBFT runs, labeled) | SIM py-evm absolutes |
| 50-client projection 1,999,181 from the printed fit | 1,999,175 (unrounded coefficients — say which you used) |
| gas figures labeled with label-length / client-count / path | mixing pre-commitment, 6-client and 4-client signed-path numbers |
| async liveness numbers **with** backlog collateral | async numbers alone |

## Open items (see MASTER_CONTEXT §14 for the full list)

1. Fix the QBFT POA bug (`geth_poa_middleware` in `chain/evm.py`), re-run preflight.
2. Anvil with real block time (pending-transaction path never exercised).
3. Public testnet (Sepolia recommended over Amoy — CLAUDE.md §6 Step 2).
4. QBFT 2a/2d; REAL-mode detection demo needs a third agent (n ≥ 3).
5. REFERENCES.md: add Wang 2022, ZTA-FL, Douceur, Theil/Sen, TrustFed; verify
   [24]; resolve the Kang venue conflict.

## History

`docs/history/README.md` explains every retired document and why it was
retired. Nothing was deleted without a backup: the full pre-cleanup tree is
at `D:\DLTF-backup-2026-11-17`, and git history preserves all committed files.
