# Documentation History

Retired documents, preserved with provenance banners (added 2026-11-17 during
the directory consolidation). **Nothing here is current.** Each banner says
why the file was retired and where its living content went. The full
pre-cleanup tree is backed up at `D:\DLTF-backup-2026-11-17`; git history
preserves everything that was ever committed.

## The document lineage (why there were so many versions)

| Era | System state | Documents from that era |
|---|---|---|
| E1 — thesis v2.1, no chain | tier-priors engine, additive+beta ablation, "do not reintroduce blockchain" | `MASTER_CONTEXT_v2.1.md`, `SETUP_GUIDE_jul19.md`, `contributions_and_prior_work.md` |
| E2 — divergent v3 push-model branch | Beta(1,1) but FORGET=0.95/FORGIVE_AFTER=5; storage-only ReputationRegistry + Tron bridge; dashboards | `CHANGES_v3_push-model-variant.md`, `parameter_justification_report_v3-variant.md`, `CHAIN_INTEGRATION_v1.md` |
| E3a — chain enforcement core | DLTFRegistry.sol (enforcement, fixed-point), mock/keys/registry/verifier | `MASTER_CONTEXT_chain-era.md`, `LATEX_CHANGES.md` |
| E3b — commitment layer | commit.py, EIP-712 batch signing, classifySigned | `NEXT_SESSION_PROMPT.md`, `LATEX_CHANGES_COMMITMENT.md` |
| E4 — July 30 doc set | v3.1: commitment wired, solc pin, full test catalogue | `FOLDER_STRUCTURE_jul30-plan.md`, `TIER_0_6_VERIFICATION.md`, `GRAPHS_AND_VERIFICATION.md` (the rest of that set was promoted to canonical docs) |
| E5 — September 2026 | local signing, async writer, preflight, liveness/economics, QBFT | root `RUNBOOK.md`, `CLAUDE.md` (kept living) |

**File mtimes lie:** several root docs carried September timestamps but E1/E2
content (bulk-copied from older archives). Content vintage, verified against
live code, decided what was canonical — not timestamps.

## Where each retired file's content went

| Retired file | Living destination |
|---|---|
| `MASTER_CONTEXT_v2.1.md` | nothing operational (retired math); repudiation recorded in root `MASTER_CONTEXT.md` §4 |
| `MASTER_CONTEXT_chain-era.md` | root `MASTER_CONTEXT.md` §16 appendix (state machine, design decisions, audit seam, fixed-point, storage, privacy, verification) |
| `NEXT_SESSION_PROMPT.md` | root `MASTER_CONTEXT.md` §16 (design decisions, event surface, serialization, BRACU constraints) |
| `LATEX_CHANGES.md` / `LATEX_CHANGES_COMMITMENT.md` | kept as applied thesis-edit records; design rationale in root `MASTER_CONTEXT.md` §11/§15/§16 and `chain/README.md` |
| `CHAIN_INTEGRATION_v1.md` | one-paragraph legacy note in root `MASTER_CONTEXT.md` §11; v1 code in `trust/legacy/` |
| `CHANGES_v3_push-model-variant.md` | dashboard-pipeline description preserved here; engine authority is root `MASTER_CONTEXT.md` §4 |
| `parameter_justification_report_v3-variant.md` | preserved here (variant-specific; regenerate or annotate before quoting) |
| `FOLDER_STRUCTURE_jul30-plan.md` | current layout: root `README.md`, `docs/INDEX.md`; secret-handling: `SETUP_GUIDE.md` §12 |
| `TIER_0_6_VERIFICATION.md` | `docs/RESULTS_EXPLAINED.md` §7–8 |
| `GRAPHS_AND_VERIFICATION.md` | `docs/RESULTS_EXPLAINED.md` §2, §5–6 |
| `SETUP_GUIDE_jul19.md` | root `SETUP_GUIDE.md` §12–13 |
| `contributions_and_prior_work.md` | root `REFERENCES.md` §H (v3-corrected) |

## Known cross-document conflicts, resolved

1. **FORGET / FORGIVE_AFTER:** 0.90 / 2 (live code) wins over 0.95 / 5 (E1/E2 docs).
2. **Contract philosophy:** enforcement/recompute (DLTFRegistry) wins over
   storage-only push (ReputationRegistry). Legacy path marked do-not-use.
3. **client2 IP:** `100.64.57.82` (config.py) wins over `100.73.178.45`.
4. **Testnet:** Sepolia recommended over Amoy (CLAUDE.md §6 Step 2); RUNBOOK
   commands show Amoy as originally run, with a note.
5. **Gas figures:** three measurement contexts (pre-commitment; 6-client
   commitment; 4-client signed path) — each labeled, never mixed.
6. **Kang 2019 venue:** IoT-J vs TVT — flagged in REFERENCES.md §G, unresolved.
7. **Two paper tracks:** BRACU thesis (\hline-only) vs ACM NSysS (acmart,
   booktabs allowed) — instruction sets kept separate and labeled.
