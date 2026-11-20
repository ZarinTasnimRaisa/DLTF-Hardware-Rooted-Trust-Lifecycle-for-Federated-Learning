> **HISTORICAL CHANGELOG - APPLIED.** Paste-ready BRACU-thesis edit instructions (Parts A-I), executed. Retains unique reference value: the derived 5e-6 fixed-point bound (F.2), the v2.1-to-v3 changed/unchanged numbers table (C.2), full T21-T26/N18-N23 LaTeX text. For current system state see root MASTER_CONTEXT.md. Thesis track only - the NSysS paper has different template rules.

# LATEX_CHANGES.md — DLTF Thesis, All Required Edits

**Consolidated.** Supersedes `LATEX_CHANGES_FORGET_0_90.md`,
`LATEX_CHANGES_MOCK_BACKEND.md`, `LATEX_CHANGES_SOLIDITY_CONTRACT.md`, and
`LATEX_CHANGES_REGISTRY_VERIFIER.md`. Delete those four; use only this file.

**Two drivers for these edits:**
1. `FORGET` is pinned at **0.90** (= `GAMMA`), not 0.95. Rate change, not a typo.
2. The optional on-chain trust registry (`chain/`, `contracts/`) is built and
   needs documenting.

**Verification status: 122 checks green.**

| Module | Checks |
|---|---:|
| `trust.reputation` | 16 |
| `chain.fixedpoint` | 14 |
| `chain.keys` | 11 |
| `chain.backend` | 5 |
| `chain.mock` | 20 |
| `chain.registry` | 14 |
| `chain.verifier` | 11 |
| `chain.evm_parity_test` (live EVM) | 15 |

Every claim in this document is backed by a runnable self-test. Nothing is
speculative.

---

## HOW TO USE THIS DOCUMENT

Work top to bottom. Parts A–C are **required** — they fix factual errors
currently in the thesis. Parts D–H are **additive** — they document the chain
layer. Part I is the checklist.

| Part | Chapter | Priority |
|---|---|---|
| A | Ch. 3 — `FORGET` provenance | REQUIRED (currently wrong) |
| B | Ch. 3 — NEUTRAL sparsity finding | REQUIRED (undocumented code property) |
| C | Ch. 4 / 5 — stale numbers | REQUIRED (blocks Ch. 5) |
| D | Ch. 3 §3.1.1 — threat model T21–T26 | additive |
| E | Ch. 3 §3.1.2 — requirements N18–N23 | additive |
| F | Ch. 3 §3.2 — chain layer architecture | additive |
| G | Ch. 5 — results, gas table, SIM lifecycle | additive |
| H | Ch. 2 / Ch. 6 — related work, limitations | additive |
| I | Pre-defense checklist | — |

---

# PART A — `FORGET` provenance (REQUIRED)

## A.1 The problem

Whatever the thesis currently says about asymmetric decay is **false at
`FORGET = 0.90`**. `GAMMA = 0.90` and `FORGET = 0.90` are the same number, so
trust and distrust decay at the SAME rate, not half.

Search Chapter 3 for any of:

- "distrust fades slower than trust"
- "asymmetric decay"
- "half the rate" / "half-rate"
- "Slovic 1993" used to justify a rate RATIO
- the closed form `1 - (1 - GAMMA)/2` or the value `0.95`

## A.2 Parameter table row

If Chapter 3 has a parameter table with `FORGET`, replace the row:

```latex
% OLD -- delete
FORGET & 0.95 & CALIBRATED & Slovic 1993 (direction); half-rate decay \\

% NEW
FORGET & 0.90 & [DERIVED] & $= \gamma$; single decay primitive.
  Asymmetry carried by \texttt{FORGIVE\_AFTER}, not by a rate ratio
  (Sun 2008; Labraoui 2015 for penalty stickiness) \\
```

## A.3 Replacement prose

```latex
\paragraph{Forgetting.}
Positive and negative evidence decay at the same rate,
$\gamma = \textsc{forget} = 0.90$. \textsc{forget} is therefore not a free
parameter: it is [DERIVED], forced by the decision to use a single decay
primitive, and no separate constant is introduced.

Asymmetry between how trust and distrust are treated is carried by the
\emph{gate}, not by the rate. \texttt{FORGIVE\_AFTER} $= 2$ means positive
evidence decays every round unconditionally, whereas negative evidence decays
only from the second consecutive clean round onward. A single clean round
launders nothing. The asymmetry direction reported by Slovic (1993) --- that
adverse information persists --- is preserved through this gate mechanism
rather than through a slower fade rate.
```

Measured trajectory, safe to quote:

```
after 1 MAJOR:  s=0.000  f=0.600  T=0.385
  clean 1:      s=0.400  f=0.600  T=0.467   <- f untouched
  clean 2:      s=0.760  f=0.540  T=0.533   <- f decays first time
  clean 3:      s=1.084  f=0.486  T=0.584
  clean 4:      s=1.376  f=0.437  T=0.623
```

## A.4 Code edits (already applied in the patched `reputation.py`)

| Line | Change |
|---|---|
| 35 | docstring cold-start band `~0.69-0.73` → `~0.72-0.76` |
| 132–142 | `FORGET` provenance block → symmetric-decay + gate framing |
| 234 | comment `# 0.90 CALIBRATED` → `# [DERIVED] = GAMMA` |
| 446 | `assert abs(FORGET - 0.95)` → `abs(FORGET - 0.90)` |
| 453 | print `FORGET = 0.95 uniform` → `FORGET = 0.90 = GAMMA uniform` |
| 481 | band `0.68 < t12 < 0.74` → `0.71 < t12 < 0.76` |

Result: self-test 16/16 green. **The arithmetic is unchanged** — 0.90 was
already the runtime value; only comments, docstrings and test bands moved.

## A.5 `theta_r` correction

If Chapter 3 anywhere says `θ_r = 0.55`, that is the retired v2.1 value.
**The v3 value is 0.75**, closed form `0.5·(1 + 1/W) = 0.75`.

This matters beyond documentation: `0.75/(1−0.75) = 3` exactly, so the
reinstatement floor `need_s = 3f + 2` is exact in integer arithmetic. At 0.55
the ratio 11/9 would not be exact and the on-chain port would need a stated
rounding direction. Worth one sentence in the text — it is a genuine design
advantage that fell out of a [DERIVED] constant.

---

# PART B — Audit-log sparsity (REQUIRED)

## B.1 The finding

`fl/server.py` line 113:

```python
if self.audit and cls.severity != "NEUTRAL":
    self.audit.append("EVENT", {...})
```

**NEUTRAL classifications are never written to the audit log.** Sound space
optimisation, harmless for tamper-evidence. But NEUTRAL is what decays `s`,
increments `clean_run`, and (at `clean_run ≥ FORGIVE_AFTER`) decays `f`.

**Consequence: the audit log alone cannot reconstruct reputation state.**

This must be in the thesis. A committee member reading `server.py` alongside the
chain design will notice, and the answer should be prepared.

## B.2 Suggested text

```latex
\paragraph{Audit-log sparsity and the NEUTRAL inference.}
For space efficiency, \texttt{FederatedServer} writes an \texttt{EVENT} record
only for non-NEUTRAL classifications; in a healthy federation the overwhelming
majority of rounds are entirely NEUTRAL. This is sound for the hash chain, whose
guarantee is tamper-evidence over the records it holds, but it means the audit
log alone does not determine reputation state: a NEUTRAL classification decays
$s$, increments the clean-run counter, and once that counter reaches
\texttt{FORGIVE\_AFTER} also decays $f$.

The chain adapter recovers the missing information by inference rather than by
modifying the server. Each \texttt{ROUND} record carries the participant set;
since the server classifies every participant and logs every non-NEUTRAL
outcome, the participants without an \texttt{EVENT} in a given round are exactly
those classified NEUTRAL. The inference is exact.

Its safety rests on a property of the transition rule: NEUTRAL raises $s$,
lowers $f$, and resets the consecutive-MAJOR counter, so it cannot trigger the
backstop, the M3 escalation, or the probation threshold. No device can therefore
receive both an inferred NEUTRAL and an explicit transition event within one
round, and per-device event ordering is preserved.
```

Verification: `chain/registry.py::_self_test` drives a six-round, three-device
script through both the float engine and the adapter, asserting trust agreement
within $5\times10^{-6}$ and identical statuses.

---

# PART C — Stale numbers (REQUIRED, blocks Chapter 5)

## C.1 Re-run the evaluation

Every CSV under `results/` was generated at `FORGET = 0.95` under the **v2.1**
engine. Under v3 + 0.90 every trust trajectory shifts.

```bash
PYTHONPATH=. python3 -m eval.run_experiments --exp all --seeds 5 \
    --rounds 30 --out results --check
PYTHONPATH=. python3 make_figures.py
```

Chain OFF for all sweeps — chain writes introduce nondeterministic block
numbers and gas that break `--check` reproducibility, and thousands of
transactions turn a two-minute sweep into an hour.

## C.2 What moves and what survives

| Quantity | v2.1 @ 0.95 | v3 @ 0.90 | Status |
|---|---|---|---|
| Noise MINOR r1, trust at r12 | ~0.734 | **0.7559** | CHANGED |
| Noise MINOR r3, trust at r12 | ~0.727 | **0.7470** | CHANGED |
| Noise MINOR r5, trust at r12 | ~0.719 | **0.7361** | CHANGED |
| Noise MINOR r8, trust at r12 | ~0.704 | **0.7151** | CHANGED |
| Clean device gate-exit round | 7 | 7 | unchanged |
| Clean device `s` at gate exit | 2.087 | 2.087 | unchanged |
| All-MINOR attacker gate-exit trust | 0.227 | 0.227 | unchanged |
| Fresh T3 first MINOR trust | 0.385 | 0.385 | unchanged |
| Reinstatement floor | 0.75 | 0.75 | unchanged |
| Trust ceiling (M1 saturation) | 0.833 | 0.833 | unchanged |

Most survive because they depend on `THETA`, `TAU`, `W_PRIOR`, `REINSTATE_T` —
not on `FORGET`. Only trajectories where `f` decays under a sustained clean
streak change.

## C.3 Worked example — regenerate

If Chapter 4 has a worked example, the v2.1 one (`enroll 0.80`, two MAJORs
`0.80 → 0.615 → 0.500`) is retired. Live v3 output:

```
Honest T1, 12 clean rounds : 0.500 -> 0.795  (ceiling 0.833)
T1 two MAJORs              : 0.500 -> 0.385 (ACTIVE) -> 0.312 (PROBATION via M3)
T2 MINOR, MAJOR, MAJOR     : 0.500 -> 0.385 -> 0.312 (ACTIVE) -> 0.263 (BANNED)
T3 first MINOR             : 0.500 -> 0.385, ACTIVE (u-gate still closed)
Sleeper, 30 clean + attack : banks 0.828, MAJOR#1 -> 0.735 (ACTIVE),
                             MAJOR#2 -> 0.651 (PROBATION: score > 0.5, M3 fires)
On-off (MAJOR then clean)  : f = 0.600 held through clean round 1,
                             then 0.540 / 0.486 / 0.437
```

Cite the exact command used to generate whatever you print.

## C.4 Claim to delete

Remove any phrasing like "the asymmetric fade protects honest noisy clients" or
"distrust fades slower than trust builds". Replace:

```latex
Trust and distrust decay at the same rate ($0.90$ per round). Asymmetry is
provided by the \texttt{FORGIVE\_AFTER} $=2$ gate: negative evidence is
protected from decay for the first clean round following a violation, which
prevents an on-off attacker from laundering $f$ with a single clean round.
```

---

# PART D — Chapter 3 §3.1.1, threat model (append-only)

The chain layer is only defensible if the threat model extends to a
partially-adversarial server OPERATOR. Append to the locked registry —
numbering continues from T20, no renumbering.

```latex
% --- Server-operator threats (introduced with the on-chain trust registry) ---
T21 & A compromised server operator attempts to silently un-ban a device
      (BANNED $\rightarrow$ ACTIVE). Rejected by the DLTFRegistry contract with
      the \texttt{BanToActive(bytes32)} custom error; the transaction reverts
      and no state changes. Demonstrated in
      \texttt{chain/evm\_parity\_test.py::test\_reject\_ban\_to\_active}. \\
T22 & A server operator attempts to change a device's tier after enrollment.
      Rejected with \texttt{TierMutation(bytes32,uint8,uint8)}. \\
T23 & A server operator attempts to write a reputation delta outside the
      published rule. Structurally impossible: the registry API accepts a
      severity and recomputes the transition; no delta parameter exists. \\
T24 & A server operator replays or reorders a round to conceal an event.
      Rejected with \texttt{DuplicateRound(uint256)} or
      \texttt{StaleRound(uint256,uint256)}. \\
T25 & A server operator enrols a duplicate endorsement key to grant a banned
      device a second identity. Rejected with
      \texttt{EkAlreadyRegistered(bytes32)}. \\
T26 & A holder of the server key writes FALSE classifications (for example
      labelling an honest client MAJOR). \textbf{NOT MITIGATED.} The contract
      constrains the rule of transition given a classification, not the
      truthfulness of the classification. Detection provenance (which stage of
      \texttt{trust/filter.py} fired, with what reason string) is recorded in
      the event payload for later audit, but the contract does not verify it.
      Mitigation requires either multi-party classification consensus or
      client-side proofs of update validity; both are future work. \\
```

**T26 is the one to prepare for.** "Can the server just lie?" will be asked. The
answer must be ready, not improvised.

---

# PART E — Chapter 3 §3.1.2, requirements (append-only)

```latex
N18 & The trust registry SHALL reject any transition BANNED $\rightarrow$
      ACTIVE unconditionally, at the contract level. \\
N19 & The trust registry SHALL reject any tier change for a registered device,
      at the contract level. \\
N20 & The trust registry SHALL reject any reputation delta that does not match
      the published integer rule (\texttt{chain/fixedpoint.py}), at the
      contract level. \\
N21 & The trust registry SHALL reject any duplicate or out-of-order round
      identifier, at the contract level. \\
N22 & The trust registry SHALL reject any write originating from an address
      other than the designated server address, at the contract level. \\
N23 & The trust registry SHALL survive server restart with no loss of ban or
      probation state, by reconciliation from the on-chain event history. \\
```

Note the explicit "at the contract level" scope in N18–N22. The contract
constrains transitions, not input truthfulness (T26).

## E.1 Traceability

```latex
\begin{table}[h]
\centering
\caption{Verification of the chain-layer requirements.}
\begin{tabular}{|l|l|l|}
\hline
Req & Enforcement & Verified by \\
\hline
N18 & \texttt{BanToActive} & mock + deployed contract \\
N19 & \texttt{TierMutation} & mock + deployed contract \\
N20 & no delta API surface & structural (both) \\
N21 & \texttt{DuplicateRound}, \texttt{StaleRound} & mock + deployed contract \\
N22 & \texttt{UnauthorizedWriter} & mock + deployed contract \\
N23 & event replay & \texttt{test\_ban\_survives\_redeploy} \\
\hline
\end{tabular}
\end{table}
```

## E.2 N20's stronger form — say this explicitly

```latex
N20 is enforced structurally rather than behaviourally. The registry API accepts
a severity value and recomputes the resulting $(s, f, \text{status})$ transition
using the published integer rule; it exposes no parameter through which an
off-rule state could be submitted. A caller cannot write a delta outside the
rule because no such parameter exists. The Solidity port preserves this
property: a \texttt{submitState()}-style function is explicitly forbidden.
```

---

# PART F — Chapter 3 §3.2, chain layer architecture

## F.1 Main subsection

```latex
\subsection{Chain Layer (chain/)}

DLTF's chain layer places a subset of trust-lifecycle state behind an
append-only ledger that enforces published transition rules independently of
the federated-learning server. The layer is designed around three axes that
vary orthogonally: TPM identity (mock versus real TPM), transport (in-process
versus HTTP), and chain (off, mock in-memory, or EVM node). All combinations are
valid; the chain axis defaults to \texttt{off}, in which case the system behaves
identically to the pre-registry baseline.

The layer is structured as an abstract backend interface
(\texttt{chain/backend.py}) with two implementations: \texttt{chain/mock.py}, a
deterministic in-memory backend used for continuous integration, rule
development and reconciliation testing, whose head hash is a pure function of
the event sequence; and an EVM adapter speaking JSON-RPC to a local Hardhat or
Anvil node running a Solidity contract that reproduces the mock backend's rules
bit-for-bit.

The API is severity-driven rather than state-driven: the backend recomputes
trust transitions using an integer mirror of the reputation rule
(\texttt{chain/fixedpoint.py}) shared verbatim with the contract. There is
therefore no reputation-delta surface for a compromised server to exploit; the
backend is authoritative for status.

Rule enforcement is by revert. Each rejection rule corresponds to a stable
reason code --- \texttt{UnauthorizedWriter}, \texttt{BanToActive},
\texttt{TierMutation}, \texttt{DuplicateRound}, \texttt{StaleRound},
\texttt{EkAlreadyRegistered} --- and these map one-to-one to Solidity custom
errors in the port.
```

## F.2 Fixed-point arithmetic

```latex
\paragraph{Fixed-point arithmetic.}
The reputation rule operates on floating-point numbers; Solidity does not
support floats. The chain layer resolves this with a single-scale integer mirror
at $\text{SCALE} = 10^6$, chosen so that every constant in the model is exactly
representable and contributes zero quantisation error
($\theta \rightarrow 400000$, $\tau \rightarrow 600000$, thresholds
$300000/500000/750000$).

Only one operation truncates:
$\mathrm{decay}(x) = \lfloor 9x/10 \rfloor$, implemented identically by
Solidity's \texttt{/} on \texttt{uint256} and Python's \texttt{//} on
non-negative \texttt{int}; the two agree bit-for-bit by construction rather than
approximately. Threshold checks avoid division entirely by cross-multiplication,
comparing $(1+s)\cdot\text{SCALE}$ against $t\cdot(2+s+f)$, and are exact. The
reinstatement floor $\text{need}_S = 3F + 2\cdot\text{SCALE}$ is likewise exact
because $\theta_r = 0.75$ yields the integer ratio $3$.

Because $\gamma = \textsc{forget}$, a single decay primitive serves both
positive and negative evidence, so the contract implements one decay operation
rather than two.

The divergence between the float and integer representations of trust is bounded
by $|T_\text{float} - T_\text{fixed}| \leq 5 \times 10^{-6}$. The bound is
derived rather than measured: each truncation loses less than one unit, giving
the error recurrence $e' \leq 0.9e + 1$ with fixed point $10$ units on each of
$s$ and $f$, and $|\partial T/\partial s|, |\partial T/\partial f| \leq 1/4$.
Measured across $80{,}000$ random events spanning all three tiers, \emph{zero}
status decisions differed between the float engine and the integer path. The
fixed-point path is authoritative for status; the float engine remains the
research artefact.
```

## F.3 Storage and cost

```latex
\paragraph{Storage layout.}
Each device's full state --- $s$, $f$, the clean-run and consecutive-MAJOR
counters, status, tier, and last-round --- packs into 208 bits held in a single
256-bit slot with 48 bits reserved, requiring one warm \texttt{SSTORE} per
device per round. Contract bytecode is 6.5\,KB, well under the EIP-170 limit of
24\,KB.
```

## F.4 Integration seam — the zero-change property

```latex
\paragraph{Integration seam.}
The chain layer attaches to DLTF through a single object,
\texttt{chain.registry.ChainRegistry}, which presents exactly the
\texttt{audit.hashchain.HashChain} interface (\texttt{append},
\texttt{entries}, \texttt{verify}, \texttt{head\_hash}, \texttt{\_\_len\_\_})
and is passed to \texttt{FederatedServer} through the existing \texttt{audit=}
parameter. No change to \texttt{fl/server.py} is required. Every call is
forwarded to the inner hash chain first, so with the chain layer enabled the
local audit log is byte-identical to what it would have been with the layer
disabled; the adapter then mirrors the semantic content of each record onto the
chain backend.

Records are partitioned into \emph{drivers}, dispatched as chain writes
(\texttt{ENROLL}, \texttt{EVENT}, the inferred NEUTRALs,
\texttt{PROBATION\_ENTER}, \texttt{REHAB\_EXHAUSTED},
\texttt{PROBATION\_DECISION}, \texttt{ROUND}), and \emph{consequences}, which
the backend already emits as a cascade and which are therefore ignored to avoid
double-counting (\texttt{BAN}, \texttt{WHITEWASH\_REJECTED}).
```

## F.5 Degradation

```latex
\paragraph{Degradation.}
Chain writes are never on the critical path of a training round. Every mirror
call is wrapped: a rule rejection, an RPC timeout, or any other exception is
recorded with its reason and detail, marks the affected round
\texttt{UNANCHORED} for later reconciliation, and does not propagate.
Rejections are counted and inspectable, so enforcement remains observable, but a
node outage or an unexpected revert cannot stall aggregation.

At enrollment the adapter fails \emph{open}: if the node is unreachable, the
ban-list check returns negative rather than refusing the enrollment. Failing
closed would allow any adversary capable of disrupting the node to deny
enrollment to the entire federation. The resulting staleness window is stated as
a limitation.
```

## F.6 EK privacy

```latex
\paragraph{Endorsement-key privacy on chain.}
Real EK hashes are permanent physical-machine fingerprints. Writing them to any
immutable ledger --- even a local node used only for evaluation --- creates a
durable de-anonymisation surface. DLTF therefore never writes an EK hash to the
chain directly; the chain stores
\[
  \text{ek\_hmac} = \text{HMAC-SHA256}\bigl(\text{federation\_key},\;
  \text{DOMAIN} \,\|\, \text{ek\_hash}\bigr),
\]
where $\text{DOMAIN} = $ \texttt{"DLTF-EKv1|"} is a domain-separation tag and
the federation key is a 32-byte value held only by the federation server,
distinct from the audit log's HMAC key and stored at a separate location
(\texttt{results/federation.key}, mode 0600).

Three properties follow. The mapping is deterministic, so the contract's ban
list is stable across restarts. It is federation-scoped: two federations with
distinct keys produce different values for the same EK, so a device banned in
one federation is not identifiable as such by another sharing the registry
contract. The domain tag prevents chosen-message attacks reusing values derived
under the same key for a different purpose.

Loss of the federation key does not affect existing ban enforcement, since the
committed values remain, but prevents future enrollments from being checked
against the ban list until the key is recovered or the federation rotates.
Rotation invalidates the ban list, and is the closest approximation to
erasure-on-request that an immutable ledger supports.
```

## F.7 Third-party verification — the strongest single argument

```latex
\paragraph{Third-party verification.}
Because the reputation rule is deterministic and the contract emits an event for
every classification, the stored state is a computable function of the event
stream. \texttt{chain/verifier.py} exploits this: it replays the emitted events
through the integer engine and compares the recomputed state, field by field,
against the state the backend holds. It uses only the public read surface
(\texttt{events()}, \texttt{get\_device()}, \texttt{is\_banned\_ek()}), so the
same code runs unmodified against a live node's event log; a read-only view is
sufficient.

This is a materially stronger property than the hash chain provides. The hash
chain establishes that nobody edited the log. Verification establishes that the
log's \emph{contents imply} the recorded state. A server that wrote a plausible
event stream while storing inconsistent state --- for example inflating a
device's accumulated positive evidence, or silently returning a banned device to
\texttt{ACTIVE} --- produces a log that passes hash-chain verification and fails
recomputation. Both cases are demonstrated in the module's self-test.

The limitation is equally clear and must be stated: verification establishes
internal consistency, not ground truth. A server that labels an honest client
MAJOR produces a log that verifies perfectly.
```

## F.8 Mode-selection table

```latex
\begin{table}[h]
\centering
\caption{The three independent axes of the evaluation setup. All combinations
are valid; the four rows below are those used in this work.}
\begin{tabular}{|l|l|l|l|}
\hline
TPM & Transport & Chain & Purpose \\
\hline
mock & in-process & off  & Sweeps, CI, fast iteration \\
mock & in-process & mock & Rejection tests, restart demo, reconciliation \\
mock & in-process & node & Gas and latency measurement, scale tests \\
real & HTTP       & node & Hardware identity binding; the thesis demo \\
\hline
\end{tabular}
\end{table}
```

Accompanying sentence, needed pre-emptively:

```latex
The chain layer is identical code in both simulated and hardware modes; it
observes only an event type and payload. The sole legitimate difference is that
simulated mode supplies mock endorsement-key hashes and hardware mode supplies
TPM-derived ones; both are opaque bytes to the contract.
```

---

# PART G — Chapter 5, results

## G.1 Gas table

```latex
\begin{table}[h]
\centering
\caption{Gas cost per operation on the DLTFRegistry contract, measured on
py-evm (Cancun, optimizer runs $=200$).}
\label{tab:gas}
\begin{tabular}{|l|r|r|}
\hline
Operation & Gas & USD @ 20 gwei / \$2000 ETH \\
\hline
Deploy (one-time) & 1{,}397{,}314 & \$0.056 \\
\hline
register (fresh device) & 95{,}047 & \$0.004 \\
register (banned EK $\to$ whitewash) & 27{,}153 & \$0.001 \\
\hline
classify NEUTRAL (cold slot) & 36{,}332 & \$0.001 \\
classify NEUTRAL (warm slot) & 36{,}593 & \$0.001 \\
classify MAJOR (warm slot) & 36{,}380 & \$0.001 \\
classify CRITICAL $\to$ BAN & 64{,}346 & \$0.003 \\
\hline
roundSummary & 91{,}277 & \$0.004 \\
\hline
\end{tabular}
\end{table}
```

Narrative points:
- Per-round marginal cost, six clients: 6 classify + 1 roundSummary
  $\approx 309{,}000$ gas $\approx$ \$0.012.
- Cost is $O(n)$ in active clients; the contract never iterates unbounded arrays.
- Deployment is one-time and comparable to a simple ERC-20.

## G.2 SIM lifecycle table

```latex
\begin{table}[h]
\centering
\caption{End-to-end simulated lifecycle: six clients (four honest, two
colluding), SOFTWARE tier, five rounds.}
\label{tab:sim-lifecycle}
\begin{tabular}{|l|l|}
\hline
Stage & Outcome \\
\hline
Enrollment & 6 devices registered on chain \\
Rounds 0--1 & attackers classified MAJOR; both banned at round 1 via M3 \\
Rounds 2--4 & proceed with 4 participants; 5/5 rounds anchored, 0 failures \\
Restart & 6 devices, 30 events replayed, 0 discrepancies \\
Whitewash & banned EK under fresh label $\to$ \texttt{WHITEWASH\_REJECTED} \\
Forged resurrection & hash chain ACCEPTS; contract REJECTS, status unchanged \\
\hline
\end{tabular}
\end{table}
```

Recomputed attacker state after restart, from events alone:
`status=BANNED  s=0  f=1200000  major_run=2`.

## G.3 The central claim — the delta over the hash chain

```latex
\paragraph{Delta over the local hash chain.}
The hash chain in \texttt{audit/hashchain.py} records every write it receives.
If a compromised server submitted a BANNED $\rightarrow$ ACTIVE transition, a
delta outside the reputation rule, or a duplicate round, the hash chain would
record the event faithfully and would not refuse it. The chain layer does refuse
it.

The final row of Table~\ref{tab:sim-lifecycle} is the demonstration that
justifies the layer. A server attempting to return a banned device to
\texttt{ACTIVE} by re-enrolling it under a fresh endorsement key produces a
write that the local hash chain accepts without complaint --- the log still
verifies, because nothing was edited. The chain layer refuses the same write and
the device's status is unchanged. This is the concrete capability difference
between recording and enforcing.

A latent instance of exactly this transition exists in the codebase: the
reputation engine's \texttt{register} method overwrites its device record
unconditionally, so re-registering a banned device without an endorsement-key
argument resurrects it as ACTIVE with zeroed evidence. The path is unreachable
from the server, which always supplies the key, but it is precisely the class of
write the contract exists to refuse, and the integer engine treats BANNED as
absorbing per device identifier and per endorsement key alike.
```

## G.4 Decentralisation disclaimer — state before anyone asks

```latex
\paragraph{Scope of the deployment.}
The evaluation runs against a local development node. Such a node has no
consensus or decentralisation properties whatsoever. This work evaluates the
enforcement \emph{mechanism} --- that illegal transitions are refused, that
state survives restart, and that the cost of doing so is small --- and not the
trust properties that would follow from deployment across independent
validators. Those properties are contingent on a deployment this thesis does not
claim to have performed.
```

---

# PART H — Chapter 2 and Chapter 6

## H.1 Chapter 2 — related work

Check for and fix:
- any statement that DLTF uses "asymmetric fade rates" — reframe per Part A
- any citation of Slovic 1993 supporting a rate RATIO rather than a direction
- **ZTA-FL (arXiv:2512.23809, Dec 2025)** must be named as the closest
  competing work, with an explicit statement of what it does and what precise
  gap remains. All novelty claims hedged with "to our knowledge".
- **Wang 2022** appears in `MASTER_CONTEXT.md` but is MISSING from
  `REFERENCES.md` — add it.
- **Reference [24] Domingo-Ferrer** is marked VERIFY — resolve before submission.

## H.2 Chapter 6 — limitations

Add the chain-layer limitations:

```latex
\item A local development node has no decentralisation properties; trust
      properties are contingent on multi-validator deployment.
\item A compromised server key can still write false classifications; the
      contract constrains transitions, not input truthfulness (T26).
\item An immutable ledger conflicts with erasure-on-request. Federation-key
      rotation invalidates the ban list and is the only approximation
      available.
\item The trust model is fixed-point on chain and floating-point in the
      reference engine. Divergence is bounded at $5\times10^{-6}$ with zero
      measured status divergence over $80{,}000$ events, but is non-zero in
      principle.
\item Enrollment fails open against a cached ban-list snapshot when the node is
      unreachable, introducing a staleness window.
\item Evaluation covers a single federation.
\item Hardware mode is limited to two physical clients. This supports a
      feasibility claim, not a scaling claim.
```

**Also amend the existing limitation** that reads "in-memory engine state
(restart = re-enroll)":

```latex
In-memory engine state means a server restart requires re-enrollment
\emph{when the chain layer is disabled}. With the chain layer enabled this
limitation is removed by reconciliation from the on-chain event history (N23).
```

---

# PART I — Pre-defense checklist

## Code green

- [ ] `PYTHONPATH=. python3 -m trust.reputation` → 16 ticks
- [ ] `PYTHONPATH=. python3 -m trust.probation` → green
- [ ] `PYTHONPATH=. python3 -m chain.fixedpoint` → 14 ticks
- [ ] `PYTHONPATH=. python3 -m chain.backend` → 5 ticks
- [ ] `PYTHONPATH=. python3 -m chain.mock` → 20 ticks
- [ ] `PYTHONPATH=. python3 -m chain.keys` → 11 ticks
- [ ] `PYTHONPATH=. python3 -m chain.registry` → 14 ticks
- [ ] `PYTHONPATH=. python3 -m chain.verifier` → 11 ticks
- [ ] `PYTHONPATH=. python3 -m chain.evm_parity_test` → 15 ticks (needs solc)
- [ ] `PYTHONPATH=. python3 tests/test_pipeline.py` → PIPELINE GREEN
- [ ] baseline unchanged with chain off: `run_local.py`, `run_server.py --rounds 10`

## Required LaTeX edits

- [ ] Part A — `FORGET = 0.90` [DERIVED], gate-based asymmetry, no "half-rate"
- [ ] Part A.5 — `θ_r = 0.75` everywhere (not 0.55)
- [ ] Part B — NEUTRAL sparsity finding documented
- [ ] Part C — Chapter 4 CSVs re-run; every quoted trust value re-verified
- [ ] Part C.3 — worked example regenerated from live code
- [ ] Part C.4 — "distrust fades slower" claim removed

## Additive LaTeX edits

- [ ] Part D — T21–T26 appended to §3.1.1, ID registry file updated
- [ ] Part E — N18–N23 appended to §3.1.2, traceability table added
- [ ] Part F — §3.2 chain layer: architecture, fixed-point, storage, seam,
      degradation, EK privacy, verification, mode table
- [ ] Part G — Chapter 5: gas table, SIM lifecycle table, delta paragraph,
      decentralisation disclaimer
- [ ] Part H — Chapter 2 ZTA-FL hedging, Wang 2022 added to REFERENCES.md,
      ref [24] verified; Chapter 6 limitations extended

## Repo hygiene

- [ ] `MASTER_CONTEXT.md` replaced with the rewritten version
- [ ] `run_local.py` — delete dead `--engine beta` flag (lines 34, 52)
- [ ] confirm `check_tiers.py` exists
- [ ] `grep -rn "BAD_EVIDENCE\[.CRITICAL" eval/ trust/` → no hits
- [ ] `grep -rn reputation_beta .` → no hits
- [ ] live poison-injection command written into the runbook

## Template constraints (BRACU) — verify on every table above

- [ ] no `booktabs`, `longtable`, `amssymb`, `tikz`, `listings`, `float`,
      `subcaption`
- [ ] tables use `\hline` only
- [ ] figures are external PNGs
- [ ] biblatex/biber IEEE style

All tables in this document are written with `\hline` only and no forbidden
packages. The `\texttildelow` macro used in some prose is plain LaTeX; if your
preamble lacks it, substitute `$\sim$`.
