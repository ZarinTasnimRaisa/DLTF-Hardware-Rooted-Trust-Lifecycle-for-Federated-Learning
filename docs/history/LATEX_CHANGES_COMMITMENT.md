> **HISTORICAL CHANGELOG - APPLIED.** Part J append: the commitment layer (three designs, gas comparison, wallet binding, T27-T31/N24-N28). Renamed from "LATEX_CHANGES_COMMITMENT (1).md" (browser-download artifact). Its 6-client gas numbers are a different measurement context from the September 4-client signed-path numbers - do not mix. Design rationale lives in root MASTER_CONTEXT.md sections 11/15 and chain/README.md.

# LATEX_CHANGES_COMMITMENT.md — Client-Side Gradient Commitment

**Append to `LATEX_CHANGES.md` as Part J.** Supersedes the earlier version of
this file, which documented only the per-client-transaction design and quoted
an incorrect gas estimate.

**Verification: 171 checks green** (was 141).

    chain.commit               27   (was 18)
    chain.commit_parity_test   17   live EVM, per-client path
    chain.batch_parity_test    21   live EVM, signed + batched + classifySigned

---

## J.0 — A correction worth recording

An earlier analysis in this project estimated the marginal on-chain cost of a
batched signed commitment at roughly 4,500 gas per client, reasoning from the
`ecrecover` precompile (3,000 gas) plus calldata. **The measured figure is
35,951 gas** — eight times higher.

The estimate omitted the dominant term: storing each commitment is a cold
zero-to-nonzero `SSTORE` at 22,100 gas, which alone is roughly 60% of the
per-client cost. `ecrecover` is nearly free by comparison.

That correction is what motivated the third design below, and it is worth
stating in the thesis: it is a concrete instance of the general point that on
the EVM, **storage dominates computation**, and a design that reasons only
about computation will mis-predict cost by an order of magnitude.

---

## J.1 — Three designs, one guarantee

All three deliver the same property: the server cannot classify a device
unless that device provably signed the gradient being classified.

| | Design | 6 clients, 1 round | Client pays |
|---|---|---:|---:|
| A | Each client sends its own `commitGradient` transaction | 539,406 | 89,901 each |
| B | Clients sign off-chain; server submits one `commitBatch` | 469,532 | 0 |
| C | Signature verified inside `classifySigned`; nothing stored | **279,662** | **0** |
| D | Baseline — no commitment guarantee at all | 216,036 | — |

Measured on the deployed contract (py-evm, Cancun, optimizer runs = 200,
`via_ir` enabled).

**C is 48.2% cheaper than A and 40.4% cheaper than B.** The entire
non-repudiation guarantee costs **63,626 gas per round — 29.5% over
baseline** — and clients pay nothing, hold no funds, and need no node
connection.

### Why C wins

A commitment does not have to be *stored* to be binding. It has to be *proven
at the point where it matters*, which is the moment the server classifies the
update. `classifySigned` recovers the signer, checks the recovered address
against the wallet bound to that device, applies the reputation rule, and
discards the signature — which remains permanently in the transaction's
calldata and is re-emitted in a `CommitProof` event, so any third party can
still recover and verify it. The contract simply declines to pay for a copy it
will never read.

---

## J.2 — Chapter 3 §3.2, new subsection

```latex
\subsection{Client-Side Gradient Commitment}

The registry described so far constrains the server's lifecycle writes but
takes its account of each round at face value: a classification names a device
and a severity, and the contract checks only that the implied transition is
legal. Nothing establishes that the named device participated, or that the
gradient classified is the gradient the client sent.

The commitment layer closes both gaps. Before transmitting its update, a client
computes $H = \mathrm{keccak256}(\mathrm{canon}(G))$ over the canonical
serialisation of its gradient and signs the tuple
$(\textit{deviceKey}, \textit{roundId}, H)$ as EIP-712 typed data. It sends the
gradient and the signature to the server over HTTP. The server recomputes the
hash from what it received, and submits the signature to the registry as part
of the classification call. The contract recovers the signing address and
requires it to equal the wallet bound to that device.

The canonical serialisation is little-endian IEEE-754 binary64, one value per
parameter, with no length prefix or padding. Both sides must hash identical
bytes, so representations that vary across language versions or platforms
(\texttt{repr}, JSON, pickling) are unsuitable.

\paragraph{Wallet binding.}
A signature from an arbitrary key establishes nothing about identity: a banned
machine would generate a fresh keypair and continue signing. The binding is
therefore load-bearing. At enrolment the client signs its wallet address with
the attestation key of its enrolled TPM, over a domain-separated challenge
\texttt{"DLTF-WALLETv1|"} $\|$ \textit{label} $\|$ \textit{address}; the server
verifies that signature against the TPM identity it has already validated and
records the binding on chain. The mapping is one-to-one and immutable
thereafter, in the same manner as tier.

The binding is performed by the server because the server is the party that
verified the attestation-key signature. A malicious server could bind a wallet
under its own control; the binding is public, so the affected client detects
the substitution by reading its own entry. As with the truthfulness of
classifications, this is detectable rather than preventable.

\paragraph{The anti-fabrication rule.}
\texttt{classifySigned} cannot be called without a signature that recovers to
the device's bound wallet. A server therefore cannot record a classification
against a client that did not participate. Genuine non-participation is
recorded separately through \texttt{markAbsent}, which emits an event and
alters no reputation state; a server that falsely marks a present client absent
is contradicted by the signature that client holds, which anyone can verify
against the contract's domain separator.

\paragraph{Replay protection.}
The EIP-712 domain separator binds the chain identifier and this contract's
address, and the signed struct binds the round identifier. A signature
therefore cannot be replayed into a different round, a different deployment of
the same contract, or a different chain. All three cases are covered by
failing tests.

\paragraph{Signature malleability.}
For every valid ECDSA signature $(r, s)$ there exists a second valid signature
$(r,\, n - s)$ with the recovery identifier flipped. The contract rejects
signatures whose $s$ lies in the upper half of the curve order and requires
$v \in \{27, 28\}$, so each commitment has exactly one accepted encoding.
```

## J.3 — Chapter 3 §3.2, the cost argument

```latex
\paragraph{Where the cost actually lies.}
Three implementations of this guarantee were built and measured. In the first,
each client submits its own commitment transaction; in the second, clients sign
off-chain and the server submits all signatures for a round in a single batched
transaction; in the third, the signature is verified inside the classification
call and never stored.

The measured costs for a six-client round were 539{,}406, 469{,}532 and
279{,}662 gas respectively, against a baseline of 216{,}036 gas with no
commitment guarantee. The third design is 48.2\% cheaper than the first.

The reason is instructive. An analysis reasoning only from computation would
attribute the marginal per-client cost to the \texttt{ecrecover} precompile at
3{,}000 gas and conclude that batching is nearly free. The measured marginal
cost of a batched commitment is 35{,}951 gas, eight times such an estimate. The
dominant term is not the signature recovery but the cold zero-to-nonzero
\texttt{SSTORE} that persists each commitment, at 22{,}100 gas. Once that
observation is made the third design follows directly: a commitment must be
\emph{proven} where it is used, but it need not be \emph{persisted}, because
the signature survives in transaction calldata and in the emitted event, from
which any third party can recover it independently.

The residual cost of the guarantee is 63{,}626 gas per six-client round,
29.5\% above baseline, borne entirely by the server. Clients hold no funds,
submit no transactions, and require no node connectivity; a client's entire
obligation is one local signing operation.
```

## J.4 — Chapter 3 §3.1.1, additional threats

```latex
T27 & An adversary alters a client's gradient in transit. Detected by
      comparing the received gradient's hash against the client's signature;
      the signature does not verify and \texttt{classifySigned} reverts with
      \texttt{SignerNotDeviceWallet}. \\
T28 & A compromised server fabricates a classification against a client that
      did not participate. Rejected: the server cannot produce a valid client
      signature, and \texttt{classifySigned} cannot be called without one. \\
T29 & A banned machine attempts to continue participating by signing from a
      newly generated key. Rejected with \texttt{SignerNotDeviceWallet}: only
      the wallet bound to an enrolled, non-banned device is accepted, and the
      banned machine's endorsement key cannot be re-enrolled to bind a new
      one. \\
T30 & A client denies having sent the gradient attributed to it, or claims to
      have sent a different one. Refuted by its own EIP-712 signature, which is
      recorded in calldata and re-emitted in a \texttt{CommitProof} event. \\
T31 & A signature is replayed into a later round, another deployment, or
      another chain. Prevented structurally by the EIP-712 domain separator
      and the round identifier inside the signed struct. \\
```

## J.5 — Chapter 3 §3.1.2, additional requirements

```latex
N24 & Each enrolled device SHALL be bound to exactly one wallet address,
      established by attestation-key signature at enrolment and immutable
      thereafter. \\
N25 & A client SHALL sign the tuple (device key, round identifier, gradient
      hash) as EIP-712 typed data before transmitting the corresponding
      gradient. \\
N26 & The registry SHALL reject any classification not accompanied by a
      signature recovering to the device's bound wallet, when deployed with
      commitment enforcement enabled. \\
N27 & A device in the BANNED state SHALL be unable to obtain a valid
      classification, and its wallet SHALL NOT be rebindable to any other
      device. \\
N28 & The registry SHALL reject malleable signatures, accepting exactly one
      encoding per commitment. \\
```

## J.6 — Chapter 5, tables

```latex
\begin{table}[h]
\centering
\caption{Three implementations of the commitment guarantee, measured on the
deployed contract for a six-client round.}
\label{tab:commit-gas}
\begin{tabular}{|l|r|r|}
\hline
Design & Total gas & Gas per client \\
\hline
Per-client commitment transactions & 539{,}406 & 89{,}901 (client-paid) \\
Batched signatures, stored & 469{,}532 & 0 \\
Signature verified in classify, not stored & 279{,}662 & 0 \\
\hline
Baseline, no commitment guarantee & 216{,}036 & --- \\
\hline
\end{tabular}
\end{table}

\begin{table}[h]
\centering
\caption{Scaling of the batched-commitment path.}
\label{tab:batch-scaling}
\begin{tabular}{|r|r|r|}
\hline
Clients & Gas & Gas per client \\
\hline
1  &  60{,}246 & 60{,}246 \\
2  &  96{,}186 & 48{,}093 \\
6  & 240{,}012 & 40{,}002 \\
12 & 455{,}697 & 37{,}975 \\
\hline
\end{tabular}
\end{table}
```

Marginal cost per additional client: 35,951 gas. Cost is $O(n)$ with a small
constant; no unbounded iteration occurs.

```latex
\begin{table}[h]
\centering
\caption{Attacks blocked by the commitment layer.}
\label{tab:commit-attacks}
\begin{tabular}{|l|l|l|}
\hline
Attack & Baseline & With commitment \\
\hline
Gradient altered in transit & undetected & signature fails, revert \\
Server fabricates a classification & recorded & cannot produce signature \\
Signature replayed to another round & n/a & domain/round mismatch, revert \\
Banned device signs & n/a & \texttt{DeviceBanned}, revert \\
Banned device signs from fresh key & n/a & \texttt{SignerNotDeviceWallet} \\
Banned device re-enrols same TPM & rejected & rejected (unchanged) \\
\hline
\end{tabular}
\end{table}
```

## J.7 — Chapter 6, limitations (append)

```latex
\item The commitment establishes what a client transmitted, not whether the
      server's classification of it was correct. A server receiving an honest
      gradient with a valid signature may still label it MAJOR. The client
      holds evidence sufficient to dispute the classification, but the
      framework provides no on-chain arbitration; resolution requires an
      external party to re-run the detector, which is a governance mechanism
      this work does not specify.
\item Wallet binding is performed by the server on the basis of an
      attestation-key signature it verifies off-chain. A compromised server
      could bind a wallet under its own control. The binding is public and the
      substitution is therefore detectable by the affected client, but not
      prevented.
\item Under the batched and in-classify designs the server controls
      submission. A server that simply withholds a client's signature makes a
      present client appear absent. The client retains its signature and can
      publish it for independent verification, so the omission is detectable
      after the fact, but it is not prevented.
\item Commitment must precede transmission for the binding property to hold. A
      client that transmits first and signs afterwards obtains no guarantee.
      The ordering is enforced by convention in the client agent, not by the
      contract.
\item Signatures are verified but not stored, so the contract cannot answer
      ``did this device commit in round $r$?'' from state. The answer is
      available from the event log and from transaction calldata.
```

---

## J.8 — What was built

* **`contracts/src/DLTFRegistry.sol`**, now 881 lines. Adds the EIP-712 domain
  separator, `commitDigest`, `commitBatch` (atomic, all-or-nothing),
  `classifySigned`, malleability guards, and eleven new custom errors. The
  reputation rule was factored into `_applyRule` so `classify` and
  `classifySigned` cannot drift apart. Compiles to 9,941 bytes, 40% of the
  EIP-170 limit.

  **Requires `--via-ir`.** `classifySigned` exceeds the EVM's 16-slot stack
  limit under the legacy pipeline. `contracts/foundry.toml` sets
  `via_ir = true`; the equivalent solc flag is `--via-ir`. The IR pipeline also
  produces *smaller* bytecode here (9,941 versus 10,878).

* **`chain/commit.py`**, 785 lines, 27 checks. Adds `SigningCommitAgent`
  (client-side, signs only), `SignedCommit` with an HTTP wire format,
  `recover_commit_signer` for independent verification, `build_batch`, and
  `commit_batch` on the mock backend with staged all-or-nothing validation.

* **`chain/batch_parity_test.py`**, 430 lines, 21 checks. Verifies against the
  deployed contract that Python's EIP-712 domain separator and digest match
  Solidity byte-for-byte, that replay and malleability are rejected, that
  batches are atomic, and measures the three-way gas comparison.

---

## J.9 — Which design to use

**Use `classifySigned`.** It is the cheapest, the simplest to reason about, and
requires nothing of clients beyond a local signing operation.

`commitBatch` is retained because it is useful when commitments must be
timestamped independently of classification — for instance if a federation
wants commitments visible before the server has finished evaluating the round.
It costs 40% more.

The per-client transaction path (`commitGradient`) is retained for the thesis
comparison and should not be used in deployment: it is the most expensive
option, and it is the only one that requires every client to hold funds.
