# How the Blockchain Layer Actually Works

Every trace in this document was captured from live code, not described from
memory.

---

## Your question answered directly

> *Does the client send their gradient hash to the blockchain, and the txid with
> the gradient to the server?*

**Half right, and the half that differs is the important design choice.**

✅ **Yes:** the client writes `keccak256(gradient)` to the contract itself, before
transmitting the gradient.

❌ **No txid is ever sent to the server.** The reply carries no transaction id.

**Why no txid.** A txid would be a *pointer the server has to trust and follow*.
The server would have to accept the client's claim about which transaction to
look at, fetch it, and parse it. That adds a trust step and a failure mode for no
benefit — because both parties already share a **queryable database**. The
contract exposes `getCommit(deviceId, roundId)`, so the server looks the
commitment up by (device, round) directly.

```
WITH a txid                          WHAT DLTF ACTUALLY DOES
client -> "look at tx 0xabc..."      client -> (nothing about the chain)
server -> fetch tx, parse, trust     server -> getCommit(device, round)
                                               ^ keyed lookup, no client input
```

The client cannot mislead the server about *where* to look, because the client
does not get to say. `(deviceId, roundId)` is the address, and the server already
knows both.

The `/train` reply *does* include a convenience receipt:

```json
{
  "update": [0.25, -0.5, 0.125, 2.0],
  "num_samples": 64,
  "commit": {"round": 0, "grad_hash": "c105bebd...", "ok": true, "error": null}
}
```

**The server does not trust this receipt.** It is diagnostics — it lets the
client report "my commit failed, the node was down" so the server can log why.
Verification always re-reads from the chain. If you deleted the `commit` key
entirely, security would be unchanged.

---

## The commitment flow, traced live

### Step 1 — bind a wallet to the TPM, once, at enrollment

An Ethereum wallet is just a keypair; anyone can make one. So a wallet only means
something if it is provably tied to a *specific chip*. The client signs a
domain-separated challenge with its TPM attestation key:

```
challenge = "DLTF-WALLETv1|" + device_label + "|" + wallet_bytes     (42 bytes)
signature = AK_sign(challenge)                       # tpm2_sign, RSASSA/SHA-256
```

Verified output:

```
AK signature verifies: True
on-chain: getWallet(client1) -> 0x1111111111111111111111111111111111111111
```

Three properties, all enforced by the contract:

- **one wallet, one device** — `WalletAlreadyBound` if a wallet is reused
- **immutable** — rebinding reverts, so a server cannot rotate a client's wallet
  to one it controls and then forge that client's commitments
- **domain-separated** — the `DLTF-WALLETv1|` prefix means a signature harvested
  for the liveness check cannot be replayed as a wallet binding

That last point is why `sign_message()` is a **separate method** from
`sign_challenge()`. On real hardware `sign_challenge` emits a `tpm2_quote` over
PCRs — that is not a signature over caller-supplied bytes and cannot be verified
as one. Overloading it would have silently produced unverifiable bindings.

### Step 2 — client trains, hashes, commits, *then* sends

```
update sent     : [0.25, -0.5, 0.125, 2.0]
canonical bytes : 000000000000d03f 000000000000e0bf 000000000000c03f 0000000000000040
keccak256       : c105bebdcea44c4acd0243fe51417b231c0f09b2735ecf81c59f6400af960393
```

**Canonical form is load-bearing.** Little-endian IEEE-754 float64, one per
parameter: `struct.pack("<Nd", *gradient)`. Both sides must produce byte-identical
input or every honest client looks like an attacker. This form is stable across
Python versions, platforms, numpy vs torch, and CPU architectures, and it matches
Solidity's `keccak256(abi.encodePacked(...))` over the same byte string.

**The ordering is the entire security property.** Commit → then send. A commitment
made *after* transmission proves nothing, because the server would already have
had the opportunity to substitute. This is why the hook sits inside `/train`
before the return, not in the server's receive path.

### Step 3 — server verifies against the chain

```
getCommit(client1, 0) -> c105bebdcea44c4acd02...
check_commit          -> matched=True  reason=OK
```

The server recomputes `keccak256(canonical(received_update))` and compares
against what the chain holds. Note it never sees the client's receipt in this
path.

### Step 4 — the attack this defeats

```
check_commit([99, 99, 99, 99]) -> matched=False  reason=MISMATCH
committed c105bebdcea44c4a... != received 4a4860e81a4086b4...
```

A malicious *server* invents an update and attributes it to `client1`. The hash
does not match the client's on-chain commitment, so `reportCommitMismatch` writes
**both** hashes on chain and the update is dropped. Neither party can later
rewrite what was claimed.

This is the threat class most FL security work ignores: **the server as
adversary**. Not "does the server compute correctly" but "can the server
fabricate participation".

### Two submission paths, and a real asymmetry

| | `commitGradient` | `classifySigned` (EIP-712) |
|---|---|---|
| who pays | **client**, ~51,653 gas | client pays **zero**; server batches |
| client needs | funded wallet + RPC access | nothing but a signing key |
| transactions | one per client per round | one per **round** |
| evidence lives in | contract **storage** | `CommitProof` **event** |
| duplicate protection | ✅ `DuplicateCommit` | ❌ none |
| independent timestamping | ✅ | ❌ server controls submission |

The signed path exists because requiring every client to fund an Ethereum wallet
is a deployment blocker. A commitment does not need a *transaction* to be
binding — it needs a *signature*. The client signs
`(deviceKey, roundId, gradHash)` under an EIP-712 domain that binds chainId and
contract address, and the server submits everyone's signatures in one
transaction.

**My Foundry tests surfaced two consequences worth stating in the thesis:**

1. `classifySigned` deliberately does **not** write `commitments[]` — a cold
   SSTORE is ~22,100 gas per client, exactly the cost this path exists to avoid.
   So **`getCommit()` returns zero for a valid signed commitment.** Anything
   checking commitment presence must also scan `CommitProof` events.
2. The signed path has no `DuplicateCommit` guard, so a server can emit two
   `CommitProof` events for one round with different gradient hashes. It cannot
   *forge* either — both carry the client's signature — but an observer sees
   conflicting commitments with no on-chain tiebreak.

Neither is a vulnerability. Both are honest costs of the cheap path, and the
signed path additionally gives up independent timestamping: the server could
withhold a signature, making a present client look absent. The client keeps its
signature and can publish it, so this is **detectable, not prevented**.

---

## The reputation ledger — separate from commitments

The commitment layer is optional and off by default (`require_commit: False`).
The **main** job of the chain layer is the ban ledger. Different data, different
purpose.

### What a real run writes — full trace, 5 clients, 3 rounds

```
  0 GENESIS   {'chain_id': 'mock', 'version': 1}
  1 ENROLL    {'device': 'h0', 'tier': 2, 'ek_hmac': '98f2ed0d0ac0db...', 'status': 0}
  2 ENROLL    {'device': 'h1', 'tier': 2, 'ek_hmac': 'fd36bcaa0006ca...', 'status': 0}
  3 ENROLL    {'device': 'h2', 'tier': 2, 'ek_hmac': 'f42ee617b4d7b9...', 'status': 0}
  4 ENROLL    {'device': 's0', 'tier': 2, 'ek_hmac': '8fcf4a44724b1f...', 'status': 0}
  5 ENROLL    {'device': 's1', 'tier': 2, 'ek_hmac': '12d7cb604eb680...', 'status': 0}
  6 EVENT     {'round': 0, 'device': 'h0', 'severity': 1, 'stage': 0, 'reason': 'inferred', 'status': 0}
  7 EVENT     {'round': 0, 'device': 'h1', 'severity': 1, ...}
  8 EVENT     {'round': 0, 'device': 'h2', 'severity': 1, ...}
  9 EVENT     {'round': 0, 'device': 's0', 'severity': 1, ...}
 10 EVENT     {'round': 0, 'device': 's1', 'severity': 1, ...}
 11 ROUND     {'round': 0, 'participants_hash': 'a54093e7a99429...', 'aggregated': True,
              'local_head': '842deff49c0c5c...'}
 12 EVENT     {'round': 1, 'device': 'h0', 'severity': 1, ...}
 13 EVENT     {'round': 1, 'device': 'h1', 'severity': 1, ...}
 14 EVENT     {'round': 1, 'device': 'h2', 'severity': 1, ...}
 15 EVENT     {'round': 1, 'device': 's0', 'severity': 4, 'stage': 3,
              'reason': 'sybil similari...', 'status': 2}      <- CRITICAL, BANNED
 16 BAN       {'round': 1, 'device': 's0', 'ek_hmac': '8fcf4a44724b1f...'}
 17 EVENT     {'round': 1, 'device': 's1', 'severity': 4, 'stage': 3, ..., 'status': 2}
 18 BAN       {'round': 1, 'device': 's1', 'ek_hmac': '12d7cb604eb680...'}
 19 ROUND     {'round': 1, 'participants_hash': 'a54093e7a99429...', ...}
 20 EVENT     {'round': 2, 'device': 'h0', 'severity': 1, ...}
 21 EVENT     {'round': 2, 'device': 'h1', 'severity': 1, ...}
 22 EVENT     {'round': 2, 'device': 'h2', 'severity': 1, ...}
 23 ROUND     {'round': 2, 'participants_hash': '7143c4c7a1c34b...', ...}
```

Read six things off this trace:

1. **No gradients.** Severity codes (integers 0–4), stage numbers, 32-byte
   hashes, scalars. Nothing reconstructable into a model update.
2. **`ek_hmac`, never `ek_hash`.** Raw EK hashes never leave the host.
3. **NEUTRALs are inferred.** `fl/server.py` never logs NEUTRAL, so the adapter
   derives them from *participants minus devices-with-an-EVENT*. Note
   `reason: 'inferred'`. This is exact, not heuristic — NEUTRAL still decays `s`
   and `f`, so omitting it would corrupt any replay.
4. **BAN cascades from the contract.** Seq 15 sets `status: 2` and the contract
   emits BAN at 16 by itself. The server never *asks* for a ban; it submits
   CRITICAL and the contract decides. That is N20.
5. **Round 2 has only 3 devices.** Banned identities are structurally absent, not
   down-weighted.
6. **`participants_hash` is identical for rounds 0 and 1** (`a54093e7…`, same 5
   participants) and differs at round 2 (`7143c4c7…`, only 3). It commits to
   *who was in the round* without publishing the roster.

### The two fields that link the two ledgers

`ROUND` carries `local_head` — the local hash chain's head at that moment. So:

- the **local log** proves internal integrity (each entry commits to the previous)
- the **chain** proves the local log was not rewritten *after the fact*, because
  an immutable ledger records what its head was at round N

A server that rewrites history must produce a local log whose head at round N
matches what the chain already recorded. It cannot.

---

## Why the API takes severity, not state

The single most important contract-design decision. Compare:

```solidity
// NOT what DLTF does -- the contract is a notary for whatever the server claims
function submitState(string deviceId, uint64 trust, uint8 status) external;

// What DLTF does -- the contract is an ENFORCER
function classify(uint256 roundId, string deviceId, uint8 severity,
                  uint8 stage, string reason) external;
```

With `submitState`, a server could write `trust = 0.99` for a known attacker and
the chain would faithfully record the lie. Putting that on a blockchain adds
immutability to a falsehood.

With `classify`, the server submits only the **observation** (severity 4, stage
3). The contract holds its own copy of the trust arithmetic — `chain/fixedpoint.py`
mirrored in Solidity at `SCALE = 1e6` — recomputes `s`, `f`, `status`, and
**reverts if the result would violate the lifecycle**.

This is why there is no `submitState()` in the ABI at all. Its absence is the
guarantee.

### The six rules, enforced by EVM revert

| Attempt | Revert |
|---|---|
| resurrect a BANNED device as ACTIVE | `BanToActive` |
| change a device's tier after enrollment | `TierMutation` |
| replay or backdate a round | `DuplicateRound` / `StaleRound` |
| register two device ids under one EK | `EkAlreadyRegistered` |
| write from any address but the server | `UnauthorizedWriter` |
| classify an unknown or banned device | `DeviceUnknown` / `DeviceBanned` |

`reputation.py` has a latent hole: `register(id, tier)` with `ek_hash=None`
resurrects a BANNED device as ACTIVE. It is unreachable from `server.py`, and it
is deliberately **not fixed** — it is the demo. The chain layer catches it with
`BanToActive`, and the integration test asserts the revert:

```
✓ ENFORCEMENT: the contract reverted the resurrection write (BanToActive)
               -- not a Python check, an EVM revert
```

That distinction is the whole argument. A Python check is enforced by code the
server operator controls. An EVM revert is not.

---

## EK privacy: how a ban binds to a chip without publishing the chip

The tension: O2 needs bans to bind to `SHA256(EK_pub)`, but publishing raw EK
hashes on a public chain would let anyone track a specific machine across
federations forever.

```
ek_hmac = HMAC-SHA256(federation_key, "DLTF-EKv1|" + ek_hash)
```

- **one-way** — the chain cannot recover `ek_hash`
- **federation-scoped** — the same chip in two federations has unlinkable HMACs
- **key-separated** — the federation key is distinct from the audit HMAC key, so
  compromising one does not reveal the other
- **domain-separated** — `"DLTF-EKv1|"` prevents cross-protocol reuse

Anyone with the federation key can *check* whether a given EK is banned; nobody
without it can *enumerate* the banned set.

### This creates the two-ledger requirement

`ReputationEngine.register()` decides O2 with `ek_hash in self._banned_ek`, where
`ek_hash` is the **raw hex the handle presents at enrollment**. The chain only
holds the HMAC. So reconciliation after a restart must read *both*:

| What | Source | Why |
|---|---|---|
| `s`, `f`, `clean_run`, `major_run`, `status`, `tier` | **chain** | authoritative: the contract rejected any illegal write |
| raw `ek_hash` | **local audit log** | the chain holds only the one-way HMAC |

**If you seeded `_banned_ek` with HMAC digests instead**, the set would be
non-empty, every raw lookup would miss, and **every banned device would silently
re-enroll as ACTIVE**. O2 would fail with no error anywhere — no exception, no
log line, just an attacker back in the federation. There is a permanent
regression test for exactly this.

The privacy requirement and the O2 requirement pull in opposite directions, and
the resolution is to split *authority* between the two ledgers rather than
compromise either. That is worth a paragraph in Chapter 3.

---

## Restart and reconciliation (N23)

```
--- server torn down at round 12 ---
rebuilt from chain: 6 devices (4 active, 0 probation, 2 banned),
                    58 events replayed, 2 banned EKs
--- resumed at round 12 (6 devices re-enrolled) ---
round 12: weights {'client0': 0.4, ...}
```

`chain/verifier.py::replay_events()` re-runs the entire event log through an
independent fixed-point engine and produces every device's state from scratch.
`chain/reconcile.py` then injects that into a fresh `ReputationEngine` and seeds
the ban set from the local log's raw hashes.

**Round 11 ended at 0.397. Round 12 continues at 0.400.** A wiped engine restarts
at 0.292 — a fresh Tier-2 device's first round. That continuity is the proof.

Measured cost: **2.3 ms to rebuild 200 rounds** of history, 2.2 ms to
independently re-verify. ~1.6 µs/event, linear. The guarantee is effectively
free.

---

## Never on the critical path (N24)

Two failure classes, which must never be conflated:

| Class | Cause | Retried | Lands in | Round marked |
|---|---|---|---|---|
| `ChainRejection` | contract reverted | **never** (deterministic) | `.rejections` | UNANCHORED |
| `TransportError` | node timeout / refused | yes, linear backoff | `.failures` | UNANCHORED |

Training **never stops**. A node outage degrades auditability, not availability.

The design requirement that follows: **`EvmBackend` must RAISE on timeout**, not
merely set an `is_available()` flag. `ChainRegistry._guard()` degrades on a
*raised* exception and never consults the flag. A backend that swallowed timeouts
would let rounds be marked ANCHORED while nothing reached the node — an outage
that lies, which is worse than an outage. A test pins this permanently.

The on-chain ban check **fails OPEN**: node unreachable → `is_banned_on_chain()`
returns False → enrollment proceeds. Failing closed would hand anyone who can DoS
the node a federation-wide enrollment DoS. The staleness window is a deliberate
trade; state it in Chapter 6.

---

## Storage: one word per device

```
s(64) | f(64) | cleanRun(16) | majorRun(16) | status(8) | tier(8) | lastRound(32)
= 208 bits declared, 181 measured in use, of a 256-bit slot
```

One SSTORE slot per device is why per-round gas is flat in round count. Measured
drift over 30 rounds: **0.15%**.

**Why gas proves the storage claim.** Under EIP-2929/3529 a cold SSTORE to a zero
slot costs 22,100; a warm non-zero update costs 5,000 or 2,900. Per-round gas is
therefore dominated by how many *new* slots that round touched. Flat gas across
30 rounds ⇒ no new per-device slots ⇒ the word is being overwritten in place.
That is O(devices), measured rather than asserted.

The one genuinely O(rounds) term is `roundClosed[roundId]` — one fresh slot per
round. Report it rather than hiding it.

**Cost model:** `round_gas = 58,282 + 38,818 × clients`, R² = 1.000000.
Affine, not proportional: `roundSummary` is a fixed per-round cost regardless of
size.

---

## End-to-end sequence

```
ENROLLMENT (once per device)
  client   provision: EK cert + AK name + ek_hash
  server   verify EK cert -> assess_tier -> Tier 1/2/3
  server   MakeCredential challenge -> client ActivateCredential  (O1: chip proof)
  server   rep.register(label, tier, ek_hash)
             |-> if ek_hash in _banned_ek: BANNED, refuse            (O2)
  server   audit.append("ENROLL", {device, tier, ek_hash, status})
  chain      \-> register(label, tier, HMAC(fed_key, ek_hash))
             \-> contract: TierMutation? EkAlreadyRegistered? BanToActive?
  [if commitment enabled]
  client   AK-sign "DLTF-WALLETv1|label|wallet"
  server   verify, then bindWallet(label, wallet)                    (immutable)

EACH ROUND
  server   POST /train {round, params} -> every enrolled client
  client   train -> update
  client   [if enabled] commit keccak256(canonical(update))  BEFORE returning
  client   reply {update, num_samples, commit?}
  server   [if enabled] check_commit: read chain, recompute, compare
             |-> mismatch -> reportCommitMismatch, DROP this update
  server   filter.classify() -> severity per client (4 stages, max-severity)
  server   rep.record_event(label, severity) -> status + weight
  server   probation shadow-model step for probated Tier-1 devices
  server   aggregator(updates, weights) -> new global params
  server   audit.append("EVENT", ...) for non-NEUTRAL only
  chain      \-> BUFFERED until the round closes
  server   audit.append("ROUND", {round, participants, aggregated})
  chain      \-> infer NEUTRAL for participants with no EVENT
             \-> flush buffered EVENTs in arrival order
             \-> roundSummary(round, participants_hash, aggregated, local_head)
             \-> contract: DuplicateRound? StaleRound?
             \-> success: ANCHORED | failure: UNANCHORED, training continues

ON RESTART
  replay_events(backend.events()) -> FixedEngine with every device's state
  seed _banned_ek from the LOCAL log's raw ek_hash values
  inject scalars into a fresh ReputationEngine, divide by SCALE
  restore server.enrolled so run_round's participant filter works
  resume
```

---

## What is NOT on the chain

Worth an explicit list, because "blockchain" invites the wrong assumptions.

| Not on chain | Why |
|---|---|
| gradients | privacy and cost; only 32-byte hashes |
| model parameters | 409k floats; the chain stores trust state, not the model |
| raw EK hashes | privacy (N22); only the federation-scoped HMAC |
| training data | never leaves the client, as in any FL system |
| the aggregation itself | training is centralized; only the *ledger* is decentralized |
| accuracy metrics | off-chain evaluation |

"Decentralized" in DLTF means **the ban ledger is independently verifiable**. It
does not mean training is decentralized. Say that plainly — an examiner will ask.

---

## Is this "really" a blockchain?

Answer it head-on rather than waiting to be asked.

**What it is:** a Solidity smart contract on an EVM chain, holding append-only
state, enforcing a state machine by revert, emitting a verifiable event log.
Deployed and tested on Anvil/Hardhat. Anyone with the federation key and RPC
access can recompute every device's state from events and confirm the server
applied its own rules — that is a real decentralized-verifiability property.

**What it is not:** deployed to a public chain. Anvil has no consensus, no
finality, no gas market. The server is the only authorised writer, so this is a
*permissioned* ledger with one writer and many verifiers.

**Why that is still meaningful, and how to phrase it:** the property being
bought is not Byzantine fault tolerance among writers — it is that **the writer
cannot rewrite history and cannot violate the rules it published**. One writer
plus many verifiers is sufficient for that, and it is exactly the trust gap in
centralized FL. Moving to a public chain changes cost and latency, not
correctness.

**The honest residual:** the contract prevents *illegal* writes, not *withheld*
ones. A server can decline to report a classification. A third party comparing
rounds-anchored against rounds-run detects it, but nothing prevents it. Put that
in Chapter 6.

---

## Addendum (2026-11-17): what the September phase changed

Two framing claims in this document are now superseded; the design reasoning
above remains valid.

1. **"Not deployed to a public chain / one writer, many verifiers."** A
   4-validator Besu QBFT network (`qbft/`) ran on 2026-09-11: enforcement by
   consensus was demonstrated (`UnauthorizedWriter` refused by 2f+1
   agreement, not by one operator's node). Public-testnet deployment is the
   next pending step (Sepolia recommended). The ceiling still holds: four
   Docker validators on one host are consensus in mechanism, not in threat
   model.
2. **The unqualified N24 "never on the critical path."** Measured: synchronous
   writes ARE on the wall-clock critical path (injected stall: ~5× slower
   rounds; real QBFT: first stalled round ~189 s). `chain/async_writer.py`
   removes ledger work from the round (~115–136 ms healthy rounds on QBFT)
   but carries a backlog INTO an outage — writes issued while healthy can be
   destroyed (an ENROLL was lost at queue depth 17). Structural survival
   holds; quote the split verdict with the collateral.

Also new since this document: local transaction signing (`chain/signer.py` —
public RPCs do not implement `eth_sendTransaction`), the resend/double-apply
fix (same-nonce replacement), revert-name recovery from status-0 receipts,
chunked `eth_getLogs`, and `chain/testnet_preflight.py` (19 checks; one open
POA `head_hash` bug on Besu). Full record: root `RUNBOOK.md`,
`MASTER_CONTEXT.md` §15.
