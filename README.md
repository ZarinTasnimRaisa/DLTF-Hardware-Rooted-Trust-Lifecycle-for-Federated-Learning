# DLTF: Hardware-Rooted Trust Lifecycle for Federated Learning

The contribution is not detection. It is the response after detection: a sanction
and rehabilitation lifecycle bound to an unforgeable TPM hardware identity, with
the response policy and reversibility made a function of the hardware-trust tier —
and a Solidity registry that **enforces** the trust lifecycle on chain, so the ban
ledger is verifiable by a party that does not trust the server operator.

## Objectives
- **O1 Sybil resistance**: one TPM EK equals one identity, proven by credential activation.
- **O2 Anti-whitewashing**: a ban binds to the EK hash, so it cannot be shed by
  re-registering — and it survives server restart (reconciliation from chain events).
- **O3 Quantified trust**: reputation is deterministic; attacker cost per tier is measured.
- **O4 Aggregator-agnostic**: trust outputs `dict[str, float]` weights for FedAvg,
  Krum, TrimmedMean from one unmodified weight dictionary.

## Trust model (v3 engine)

Trust is **identity-blind**: every tier starts at 0.5 under the same uniform
Beta(1,1) prior and the same dynamics (θ=0.4, τ=0.6, γ=FORGET=0.90, ceiling
0.8333). Behaviour determines trust; hardware determines consequences. Tier is
set at enrollment and enters at exactly three places, none of them the score:

| Tier | Meaning | Weight cap | Rehabilitation |
|---|---|---|---|
| 1 HARDWARE | EK cert chains to a manufacturer CA AND credential activation passes | 1.0 | probation allowed |
| 2 TPM_RESIDENT | activation passes, no verifiable cert | 0.5 | ban only |
| 3 SOFTWARE / TOFU | no hardware proof | 0.1 | ban only |

Core idea: identity replacement cost drives policy. Expensive identities (Tier 1)
get patience and a path back; free identities get low caps and instant bans.
Hardening: bounded recency (M1), earned forgetting (M2), sustained-MAJOR
escalation (M3), a cold-start evidence gate, and due-process probation (D5).

## On-chain layer (optional, off by default)

`contracts/src/DLTFRegistry.sol` (Foundry project in `contracts/`) recomputes
reputation from submitted severities — there is no state-submission API — and
rejects illegal transitions by EVM revert: `BanToActive`, `TierMutation`,
`DuplicateRound`/`StaleRound`, `EkAlreadyRegistered`, `UnauthorizedWriter`.
Only `ek_hmac = HMAC(federation_key, "DLTF-EKv1|" + ek_hash)` goes on chain;
raw EK hashes never leave the host. A client-side **commitment layer**
(`keccak256` of the canonical gradient, EIP-712 batch signing, TPM-bound
wallets) prevents the server from fabricating an update and attributing it.
September 2026 added local transaction signing, an async write queue, a
19-check testnet preflight, liveness/economics experiments, and a 4-validator
Besu QBFT stage (`qbft/`, partially executed — see MASTER_CONTEXT §15).

## Real-hardware status (AMD fTPM, verified June 2026)

The dev laptop (Ryzen 5 5600X, AMD fTPM) DOES expose a fetchable EK certificate
(issuer "Advanced Micro Devices, CN = PRG-RN") that chain-verifies through PRG-RN
to the self-signed AMDTPM root. So this machine reaches a REAL Tier 1, not a
simulated one. Two findings came out of bringing this up:
- Not all AMD fTPMs expose a cert; it depends on board/BIOS provisioning. The tier
  model degrades correctly to Tier 2 when absent.
- AMD EK certs are technically malformed (a non-spec DEFAULT encoding on an extension
  `critical` field). Python's strict parser rejects them; openssl accepts them.
  `verify_ek_certificate` falls back to `openssl verify -partial_chain`, so both
  paths work. The CA bundle must contain BOTH intermediates (PRG-RN and PRG-SSP).

Two physical clients plus a server run over a Tailscale mesh; both enroll as
real Tier 1 with distinct EK hashes. Detection demos need a third agent
(n ≥ 3 for median-based stages — measured, see docs/REAL_MODE_RUNBOOK.md §0).

## Layout

```
config.py        topology + CHAIN block (env-overridable). The local-to-real switch.
run_local.py     SIM runner: one PC, in-process federation (--chain, --restart-at,
                 --rejoin-as, --tier1, --require-commit, --attack profiles)
run_server.py    REAL runner: enrolls remote agents, runs rounds, writes audit
tpm/             Layer 1. EK + AK, EK-cert verification, MakeCredential/ActivateCredential,
                 wallet-binding signatures
trust/           reputation.py (v3 engine, black box), probation.py, filter.py
                 legacy/ — v1 push-model chain attempt (superseded, kept as history)
fl/              CNN (409k params), non-IID MNIST, client, server, aggregators
net/             transport seam (handles.py) + per-client HTTP agent (agent.py)
audit/           local append-only HMAC-signed hash chain
chain/           on-chain layer: enforcement adapter, mock/evm backends, commitment,
                 signing, async writer, deploy, reconcile, verifier, preflight
contracts/       Foundry project: src/DLTFRegistry.sol + Rules/Commit test suites
qbft/            4-validator Besu QBFT setup + experiments 2a–2d
eval/            scenarios, run_experiments (Ch.4), chain_eval (Ch.5), make_figures,
                 exp_* harnesses (liveness, economics, gas, aggregator, tiers, ...)
tests/           test_pipeline.py, test_chain_integration.py
tools/           prove_it_works.py — 41 falsification checks with negative controls
docs/            consolidated documentation (start at docs/INDEX.md)
results/         generated outputs (gitignored); data/ datasets (gitignored)
```

Run everything from the project root: `PYTHONPATH=. python3 <module>`.

## Quick start (one PC, no hardware)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-chain.txt

PYTHONPATH=. python3 tests/test_pipeline.py            # ✓ PIPELINE GREEN
PYTHONPATH=. python3 tools/prove_it_works.py           # 41 checks + controls
PYTHONPATH=. python3 run_local.py --clients 6 --attackers 2 --rounds 20 \
    --chain mock --restart-at 12 --rejoin-as newclient # ban → restart → rebuild → whitewash
cd contracts && forge test -vv                         # Solidity suites
```

Full setup (venv ABI trap, solc 0.8.24 pin, TPM certs, Tailscale, real chain):
**SETUP_GUIDE.md**.

## Documentation map

| Doc | What it is |
|---|---|
| **MASTER_CONTEXT.md** | authoritative system state: engine constants, chain layer, Sept-2026 deployment phase |
| **RUNBOOK.md** | newest engineering record: local signing, correctness fixes, liveness/economics results |
| **CLAUDE.md** | session handoff + ordered next steps (Anvil → testnet → QBFT → paper) |
| **SETUP_GUIDE.md** | install and run, in the order things break |
| **FETCH_EK_CERT.md** | per-machine AMD EK certificate fetch + chain verification |
| **REFERENCES.md** | annotated bibliography + novelty vs prior work |
| **docs/INDEX.md** | index of the consolidated docs (thesis context, testing, results, demos) |
| **docs/ARCHITECTURE.md** | full in-depth architecture breakdown: every layer, data flows, end-to-end walkthroughs |
| **qbft/README.md** | what the 4-validator stage proves and how to run it |
| **eval/RUNBOOK.md** | paper-evidence completion plan |
| **docs/history/** | retired documents, labeled (v2.1 context, executed prompts, LaTeX changelogs, v1 guide) |

## Honest scope

The hardware-rooted guarantee holds only where a verifiable EK certificate exists
(Tier 1). Without it, whitewashing is hardware-cost-bound, not impossible. Tier 1
soundness depends on the CA allow-list: trusting a cloud vTPM CA admits
real-but-rented hardware identities, bounded by rental cost. Six to fifty clients
is not deployment scale; two physical TPMs is not a hardware study; a stealthy
directed-deviation attack from a legitimately enrolled device still defeats the
design; and four Docker validators on one host are consensus in mechanism, not
in threat model. Stated as results and limitations, not hidden.
