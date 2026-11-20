# DLTF — runbook to a submission-grade paper

> **STATUS NOTE (2026-11-17).** This plan predates the September 2026
> deployment session. Since it was written: all six "NEW" eval files exist
> (`exp_aggregator`, `exp_tiers`, `exp_window`, `exp_engine_sweep`,
> `verify_numbers`, plus `exp_liveness`/`exp_economics`/`exp_commit_gas`);
> the Foundry rejection-rule suite exists
> (`contracts/test/DLTFRegistryRules.t.sol` + `DLTFRegistryCommit.t.sol`);
> local signing, async writes and the QBFT stage ran (root `RUNBOOK.md`,
> `CLAUDE.md`, `MASTER_CONTEXT.md` §15 — including one open POA-middleware
> bug). Re-check each phase below against the current tree before ticking;
> the requirement→test-name table and the falsification methodology remain
> the authoritative plan for the paper's evidence section.

Everything needed, in dependency order. Tick as you go.

Current state: **17 of 28 requirements** established by measurement; O1 and O4
have essentially no supporting evidence; the contract's rejection rules — the
basis of the paper's central claim — are untested.

Target state: **28 of 28**, all four objectives evidenced, results section
mirroring the design.

---

## 0. File placement

```
your-repo/
├── src/
│   └── DLTFRegistry.sol
├── test/
│   ├── DLTFRegistryCommit.t.sol      yours    — N24–N28, commitment layer
│   └── DLTFRegistryRules.t.sol       NEW      — N18–N22, rejection rules
├── fl/       server.py  client.py  aggregator.py
├── trust/    reputation.py  probation.py  filter.py
├── tpm/      common.py  client.py
├── net/      handles.py
├── chain/    registry.py  mock.py  reconcile.py  keys.py
├── audit/    hashchain.py
├── eval/
│   ├── scenarios.py  run_experiments.py  chain_eval.py
│   ├── exp_aggregator.py             NEW      — O4 + robust baselines
│   ├── exp_tiers.py                  NEW      — O1 tier matrix
│   ├── exp_window.py                 NEW      — N8 trial window
│   ├── exp_engine_sweep.py           NEW      — Class 2 + mechanism ablation
│   └── verify_numbers.py             NEW      — artifact integrity
└── paper/
    ├── dltf_nsyss.tex
    ├── dltf.bib
    └── figs/
```

Six new files. None modifies existing code — each builds what it needs
directly, so any can be deleted without side effects.

---

## Phase 1 — Contract enforcement (do this first)

**Why first.** Your distinguishing claim is that the ban ledger constrains a
dishonest *server operator*. That claim lives entirely in contract reverts, and
not one is currently exercised. The Python parity suite shows two backends
*agree* — agreement against a shared specification is not correctness. This is
ten of the eleven open requirements.

```bash
forge test -vv                                        # both suites
forge test --match-contract DLTFRegistryRulesTest -vv # new one alone
```

**What `DLTFRegistryRules.t.sol` proves**

| Test | Requirement | What fails if it fails |
|---|---|---|
| `test_BannedDeviceCannotBeClassifiedAgain` | N18 | O2 is false; ledger is a log |
| `test_BanSurvivesManyCleanRounds` | N18 | Ban is a score, not a status |
| `test_BanLocksTheEndorsementKey` | N18 | Whitewash claim has no mechanism |
| `test_BannedEkCannotReRegisterUnderNewLabel` | N18 | Whitewashing works |
| `test_BannedDeviceCannotBeResurrectedWithNewEk` | N18 | Server can swap keys to revive |
| `test_TierCannotBeChanged` | N19 | Server grants itself influence |
| `test_EkCannotBeClaimedByASecondDevice` | N19 | One chip → two Sybil slots |
| `test_DeviceCannotSwapItsEk` | N19 | Identity migrates to uncertified silicon |
| `test_ContractRecomputesEvidence...` | N20 | Contract stores what it's handed |
| `test_PositiveEvidenceSaturatesAtCeiling` | N20 | Sleeper argument false on-chain |
| `test_MinorAndMajorCarryIdenticalEvidenceWeight` | N20 | Sanctions offsettable by accumulation |
| `test_RoundCannotBeClosedTwice` | N21 | Two rosters per round |
| `test_RoundSummaryCannotGoBackwards` | N21 | Fabricated history beneath anchors |
| `test_ClassifyRejectedForClosedRound` | N21 | Closed rounds aren't final |
| `test_OutsiderCannot{Classify,Register,CloseARound}` | N22 | Anyone can write |
| `test_UnknownDeviceCannotBeClassified` | N22 | History for phantom devices |
| `test_RefusalIsCheaperThanAdmission` | cost | Enforcement is a DoS surface |

**Watch two of these.** `test_MinorAndMajorCarryIdenticalEvidenceWeight` — I
checked `_applyRule` and both add `TAU_FP`, so it should pass; if it ever
doesn't, "severity selects a rule, not a magnitude" is false in the
implementation. And `test_PositiveEvidenceSaturatesAtCeiling` — 100 neutrals
must converge `s` to exactly 4,000,000 under `floor(9s/10) + 400000`. That is
the sleeper argument tested on-chain rather than only in Python.

**Record for the paper:** total tests, pass count, and gas from
`test_RefusalIsCheaperThanAdmission` (compare to your 27,358 / 95,344).

---

## Phase 2 — O4 and the robust baselines

**Why.** The paper spends a page and a half critiquing Krum, trimmed mean,
FoolsGold and FLTrust, then compares only against equal-weight averaging. A
reviewer will notice. Separately, O4 is an objective with zero evidence.

```bash
python -m eval.exp_aggregator --seeds 5 --rounds 30 --out results/
# if your ATTACKS keys differ from the defaults:
python -m eval.exp_aggregator --attacks poison sybil --out results/
```

**What it does.** Splits O4 into the two questions it contains:

1. **Interface check** — captures a real weight dictionary from a live DLTF
   round, hands the *same* dict to `fedavg`, `trimmed_mean` and `krum`, and
   verifies each accepts it and none mutates it. That is the literal N5/O4
   claim.
2. **Composition grid** — 3 rules × attacks × {no layer, DLTF} × 5 seeds.

**Outputs:** `aggregator_iface.csv`, `aggregator_grid.csv`, plus a printed
summary table with the layer-on/layer-off delta per rule.

**Read the Krum + Sybil row first.** Krum bounds the malicious *fraction*; your
layer bounds the identity *supply* that fraction is drawn from. If the layer
lifts Krum there, you have demonstrated composition rather than competition —
a stronger result than beating FedAvg, and the one your thesis actually argues.

---

## Phase 3 — O1, identity and tiering

**Why.** O1 is the foundation the other three objectives rest on and the paper
supports it with one clause and no table.

```bash
python -m eval.exp_tiers --repeats 5 --out results/
```

**What it does.** Enrols identities under all four gate combinations and
records the tier reached, with enrolment timing and a fingerprint-stability
check.

The load-bearing row is **cert present, activation failed → SOFTWARE**. A
`max()` rule would wrongly grant Hardware there; the conjunction gives Software.
That single row demonstrates the design decision the section argues for.

**Output:** `tier_matrix.csv`. Any row printing `MISMATCH` means the
implementation disagrees with the paper — investigate before reporting.

---

## Phase 4 — Two cheap closers

```bash
python -m eval.exp_window       --devices 200 --rounds 20 --out results/
python -m eval.exp_engine_sweep --seeds 5 --rounds 30     --out results/
```

**`exp_window.py` (N8).** Every probation run you report drew *k* = 5, because
they all used the same device label and entry round, so the keyed hash had
identical input. This samples 200 devices × 20 entry rounds to show [4, 9] is
genuinely exercised. Finish the requirement by re-running with a different
`HMAC_SALT` in `trust/probation.py` and confirming the assignments reshuffle —
salt-dependence is what makes the window unrecoverable by the device.

**`exp_engine_sweep.py` (Class 2).** You sweep detector thresholds but never the
engine's own seven calibrated constants, so every trajectory and sanction path
rests on Class 1 evidence.

The **ablation table matters more than the sweep**. With `m3_enabled=False` the
sleeper *should survive* — that is precisely the case the paper says a
score-only design fails. If the sleeper is still caught, M3 is not doing the
work the paper attributes to it, and you want to find that out yourself.

---

## Phase 5 — One real-MNIST scenario

**Why.** Every headline accuracy number comes from a 20-dimensional synthetic
generator. Your isolation argument is legitimate, but a reviewer reads
"0.685 vs 0.520" as a model result.

You do not need the whole evaluation on MNIST. Run **one poisoning scenario**,
layer on and off, on the three-machine deployment you already have
(`model.py`, `dataset.py`, `run_local.py`, `agent.py`). Report it as a
validation row beside the synthetic table.

---

## Phase 6 — Reconcile the numbers

```bash
python -m eval.verify_numbers --results results/
```

**Why.** `metrics_summary.csv` says sleeper latency 0.00 and whitewash 90/90;
your thesis tables say 0.4 and 25/25. Both cannot be the artifact. A reviewer
who runs your code and gets different numbers will not assume versioning.

Pick the authoritative run, regenerate every table from it, edit the `CLAIMS`
list in `verify_numbers.py` to match the paper, and make it exit 0.

Note `metrics_summary.csv` also has detection latency for all seven attack
behaviours, not the three the paper reports — so it may be the newer run, and
using it would let you delete a stated limitation.

---

## Phase 7 — Rewrite the paper

### 7a. Restructure Evaluation so it mirrors the design

```
6    Evaluation
6.1  Setup and evidence classes
6.2  O1: identity binding and tier assignment      ← Phase 3, new
6.3  O2: sanction durability and attacker cost     ← existing + Phase 1
6.4  O3: trust dynamics, detection, rehabilitation ← existing + Phase 4
6.5  O4: aggregator independence                   ← Phase 2, new
6.6  Cost: gas, storage, latency, reconciliation   ← existing
6.7  Requirements coverage                         ← new table
```

Right now Design has five components and Evaluation has five subsections and
**they don't line up** — which is why the paper reads as smaller than the
system. This fixes that.

### 7b. Add the coverage table

This single table is what makes the results reflect the whole work. Condense
your thesis Table 5.9 to 28 rows: requirement, result establishing it, evidence
class, adequate y/n. After Phases 1–4 it reads 28/28.

```latex
\begin{table}[t]
\caption{Requirements N1--N28 against the result establishing each.}
\label{tab:coverage}
\footnotesize
\setlength{\tabcolsep}{3pt}
\begin{tabular}{@{}>{\raggedright\arraybackslash}p{0.9cm}
                  >{\raggedright\arraybackslash}p{4.3cm}
                  >{\centering\arraybackslash}p{0.7cm}
                  >{\centering\arraybackslash}p{0.8cm}@{}}
\toprule
\textbf{Req.} & \textbf{Result establishing it} & \textbf{Cls} & \textbf{Adq.} \\
\midrule
N1  & Tier matrix, all four gate combinations (\S6.2) & 3 & yes \\
N2  & Fingerprint-keyed refusal, 25/25 (\S6.3)        & 3 & yes \\
% ... N3 through N17 ...
N18 & \texttt{BanToActive} / \texttt{DeviceBanned} exercised (\S6.3) & 4 & yes \\
N19 & \texttt{TierMutation}, \texttt{EkAlreadyRegistered} (\S6.3)    & 4 & yes \\
N20 & Contract recomputes evidence; no interface (\S6.3)             & 4 & yes \\
N21 & \texttt{DuplicateRound}, \texttt{StaleRound} (\S6.3)           & 4 & yes \\
N22 & \texttt{UnauthorizedWriter} on all writers (\S6.3)             & 4 & yes \\
% ... N23 through N28 ...
\bottomrule
\end{tabular}
\end{table}
```

### 7c. Delete from Limitations

- The entire **Baselines** paragraph (Phase 2 answers it).
- The entire **Coverage** paragraph (Phases 1 and 4 answer it).
- **Requirement coverage** → change 17/28 to 28/28.
- In *Substrate and scale*, drop "the physical deployment demonstrates ... but
  not detection" only if Phase 5 changes it.

### 7d. What honestly stays in Limitations

Synthetic substrate for most results; simulated TPMs beyond three clients;
scale (6 clients is not a systems result); the shared-lineage caveat on parity;
and the four properties of hardware binding (migration, linkability,
manufacturer trust, no formal verification). Disclosing these is what makes
everything else credible.

### 7e. Update the abstract

It is currently heavy on O3 and silent on O1 and O4. Carry one headline number
per objective.

---

## Phase 8 — Before you submit

- [ ] `forge test` — all green, count recorded in the paper
- [ ] `python -m eval.verify_numbers` — exits 0
- [ ] Coverage table reads 28/28
- [ ] Every claim in the abstract traceable to a table
- [ ] `\documentclass[sigconf,anonymous]{acmart}` — **double-blind required**
- [ ] No author-identifying strings in figures, filenames or the bib
- [ ] Page count within limit (confirm 8 vs 9 with the publication chair —
      the CFP and the author instructions disagree)
- [ ] Artifact matches the paper number for number
- [ ] Re-read for the em dashes you asked me to remove; new prose reintroduces them

---

## Effort and honest ceiling

| Phase | Effort | Buys |
|---|---|---|
| 1 — forge | 0.5 d | 10 requirements, the central claim |
| 2 — aggregator | 2 h | O4 + kills the baseline objection |
| 3 — tiers | 2 h | O1, currently absent |
| 4 — closers | 2 h | N8 + Class 2 evidence |
| 5 — MNIST | 1 d | Removes "synthetic only" |
| 6 — reconcile | 1 h | Artifact credibility |
| 7 — rewrite | 1 d | Results reflect the work |

**Phases 1, 2, 3 and 6 are about two days and take the paper from 7 to 9.**
They are also the four that convert "argued" into "demonstrated".

The tenth point needs deployment-scale evaluation and a multi-validator chain,
and your own gap list correctly identifies that stealthy directed-deviation
attacks from legitimately enrolled devices defeat the design. That last one is
an architectural boundary, not an evaluation gap — no experiment closes it. A
paper that is excellent *and* precise about that boundary is the realistic
ceiling, and it is worth hitting.
