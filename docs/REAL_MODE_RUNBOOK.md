# REAL Mode Runbook — Three Machines Over Tailscale

Read the finding in §0 first. It changes what your live demo can claim, and it
is better to know now than during the defense.

---

## 0. READ THIS FIRST: two physical clients cannot demonstrate detection

I tested every attack profile against the real detector at different federation
sizes. With **exactly 2 clients, three of the four stages cannot fire at all**:

| Attack | 2 clients | 3 clients |
|---|---|---|
| `scale` | **NEUTRAL** (undetected) | MINOR, stage 1 ✓ |
| `flip` | **NEUTRAL** (undetected) | MAJOR, stage 2 ✓ |
| `sleeper` | **NEUTRAL** (undetected) | MAJOR, stage 2 ✓ |
| `sybil` ×2 | CRITICAL ✓ | CRITICAL ✓ |

### Why — this is arithmetic, not a bug

**Stage 1** compares a norm against `2.5 ×` the median of **all** norms, the
attacker included. With n=2 the median lands *between* the two values:

```
norms [1, 10]  ->  median 5.50  ->  ratio 1.82  ->  below 2.5, no fire
norms [1, 1, 10] -> median 1.00 ->  ratio 10.00 ->  fires
```

A median needs **≥3 samples** to be robust. With two, the outlier drags the
median halfway to itself.

**Stage 2** compares against the leave-one-out median of the *others*. With n=2,
"the others" is a single client, so the "robust reference" is one noisy honest
update. At σ=0.3 honest noise, a flipped attacker still scores above −0.45.

**Stage 4** needs the attacker's own history to be honest first, so only
`sleeper` can trip it, and only after `MIN_HISTORY = 3` clean rounds.

### What to do

**Run a third agent on the server machine.** It costs nothing and restores every
stage. Add to `config.CLIENTS`:

```python
{
    "device_label": "client3",
    "tpm_backend":  "mock",          # no second TPM on that box
    "endpoint":     "http://127.0.0.1:8471",
},
```

The mixed-tier federation is a *feature* for the thesis: `client1`/`client2`
enroll Tier 1 (HARDWARE, cap 1.0, rehab-eligible), `client3` enrolls Tier 2
(TPM_RESIDENT, cap 0.5, no rehab). One run then demonstrates tier-differentiated
consequences on real hardware.

**State this in Chapter 6 either way.** "Detection requires n ≥ 3 for
median-based stages" is an honest, quantified limitation with a clean
explanation. Far better than a reader discovering your 2-client demo silently
detects nothing.

---

## 1. Tailscale

On all three machines:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up          # log in to the SAME account: tpm97510@
tailscale status           # must list ALL machines
```

If a machine is missing, it is on a different account. Bangladeshi CGNAT blocks
direct inbound, so Tailscale is not optional.

Confirm the mesh from the server:

```bash
ping -c2 100.70.28.2
ping -c2 100.64.57.82
```

> ⚠ **Resolve the client2 IP conflict.** MASTER_CONTEXT says `100.73.178.45`;
> `config.py` says `100.64.57.82`. `config.py` is what runs. Check
> `tailscale status` and make them agree — a stale IP looks exactly like a dead
> agent, and you do not want to debug that live.

---

## 2. Per-machine prerequisites

### All three machines

```bash
cd DLTF-main
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-chain.txt     # or: pip install web3 eth-tester py-evm eth-utils eth-account
python3 -c "import torch, torchvision; print('torch', torch.__version__)"
```

The server imports `MNISTModel` too, so it needs torch as well.

### Clients only — TPM tooling

```bash
sudo apt install -y tpm2-tools
ls -l /dev/tpmrm0
sudo usermod -aG tss $USER        # then log out and back in
tpm2_getcap properties-fixed | head        # must not error
```

### Clients only — EK certificate

Tier 1 requires a verifiable EK cert **on that machine**. Each chip has its own;
they are not shareable.

```bash
mkdir -p cert
tpm2_createek -c ek.ctx -G rsa -u ek.pub
tpm2_getekcertificate -u ek.pub -o cert/ek.crt -X
PYTHONPATH=. python3 tpm/check_ek_cert.py        # expect: verifies
```

`tpm/client.py` reads `cert/ek.crt` from disk **first** and only live-fetches as
a fallback — AMD's PKI is flaky and has returned a different, failing 1262-byte
cert. If the fetch fails, see `FETCH_EK_CERT.md`.

### Server only — CA bundle

```bash
ls -l tpm/ca/amd_ftpm_ca.pem
```

Must contain **both** AMD intermediates (CN=PRG-RN *and* CN=PRG-SSP) plus the
AMDTPM root. Client certs chain through PRG-RN; a bundle with only PRG-SSP
silently yields `cert_ok=False` → every client Tier 2.

### Server only — `config.py`

```python
CLIENTS = [
    {"device_label": "client1", "tpm_backend": "real",
     "tcti": "device:/dev/tpmrm0", "endpoint": "http://100.70.28.2:8470"},
    {"device_label": "client2", "tpm_backend": "real",
     "tcti": "device:/dev/tpmrm0", "endpoint": "http://100.64.57.82:8470"},
    {"device_label": "client3", "tpm_backend": "mock",
     "endpoint": "http://127.0.0.1:8471"},          # the 3rd agent, see §0
]
```

The server dials **out** to clients; clients never dial the server, so the
server's own IP is not in this list.

---

## 3. Smoke test before anything real

### On each client

```bash
cd DLTF-main && source venv/bin/activate
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --stub
```

`--stub` sends a zero vector, so no MNIST download and no training. Leave it
running.

Third agent, on the server box:

```bash
PYTHONPATH=. python3 -m net.agent --label client3 --port 8471 --stub
```

### On the server

```bash
curl http://100.70.28.2:8470/health      # {"ok": true, "device": "client1"}
curl http://100.64.57.82:8470/health
curl http://127.0.0.1:8471/health

PYTHONPATH=. python3 run_server.py --rounds 3 --stub --dim 6
```

**Proof:** three `enrolled ...` lines with `tier HARDWARE` for client1/client2
and `TPM_RESIDENT` for client3, then three rounds of weights.

If a client shows `TPM_RESIDENT` when you expect `HARDWARE`, the cert chain
failed — check the CA bundle and `tpm_backend: "real"` in config.

---

## 4. Real MNIST, no chain

Restart the agents without `--stub` (first run downloads MNIST, ~10 MB):

```bash
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470
```

Server:

```bash
PYTHONPATH=. python3 run_server.py --rounds 10
```

**Proof:** `real MNIST model: 409034 parameters`, then per-round weights. This is
your current thesis configuration, chain off, behaviour unchanged.

---

## 5. Add the chain layer

### Mock backend (no node)

```bash
PYTHONPATH=. python3 run_server.py --rounds 10 --chain mock
```

**Proof — the last three lines:**

```
chain: N mirrored writes, 0 rejections, 0 failures
chain: 10 rounds anchored, 0 unanchored
VERIFIED: 3 devices, M events replayed, 0 discrepancies
```

Weights identical to §4. The chain observes; it never feeds back.

### Real node

```bash
# server machine, separate terminal
anvil                                       # localhost only, do not expose

# server machine
PYTHONPATH=. python3 -m chain.deploy --network localhost
PYTHONPATH=. python3 run_server.py --rounds 10 --chain node
```

`deploy.py` writes the address to `chain/deployed.json`. Every write is now a
real transaction and every rejection a real EVM revert.

---

## 6. The live attack demo

`net/agent.py` now takes `--attack`. Each profile corrupts a **real** training
update rather than emitting a synthetic vector.

### 6a. Poisoning → MAJOR → probation (Tier 1)

Needs 3 clients (§0). `client2` attacks; `client1` and `client3` stay honest.

```bash
# client1
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470
# client3 (on the server box)
PYTHONPATH=. python3 -m net.agent --label client3 --port 8471
# client2  -- THE ATTACKER
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470 --attack flip
```

It announces itself:

```
⚠ ATTACK MODE: client2 running profile 'flip'
```

Server:

```bash
PYTHONPATH=. python3 run_server.py --rounds 12 --chain mock
```

**Expected:** `client2` flagged MAJOR (stage 2, cosine below −0.45). Two
consecutive MAJORs trip **M3 escalation**, and because client2 is Tier 1
(`REHAB=True`) it goes to **PROBATION**, not banned. Its weight drops to the
0.1 probation cap while a shadow model evaluates recovery.

This is the flagship result: **tier-differentiated consequences on real
hardware.** Same offence on `client3` (Tier 2, `REHAB=False`) → immediate ban.

### 6b. Sybil collusion → CRITICAL → ban → whitewash rejected

Both TPM machines collude with the **same seed**:

```bash
PYTHONPATH=. python3 -m net.agent --label client1 --port 8470 --attack sybil --attack-seed 1337
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470 --attack sybil --attack-seed 1337
```

Keep `client3` honest so an honest baseline survives.

```bash
PYTHONPATH=. python3 run_server.py --rounds 10 --chain mock
```

**Expected:** both flagged CRITICAL (stage 3, similarity 1.00 sustained ≥2
rounds). CRITICAL is ungated and non-compensable, so **both ban immediately
regardless of tier** — banked history cannot offset identity abuse.

> **Verified:** two colluding peers → CRITICAL. A **lone** sybil → NEUTRAL.
> Collusion is what stage 3 detects, so a single colluder is undetectable *by
> definition*, not by defect. Say it that way if asked.

### 6c. Whitewash rejection — the O2 demo

With `client1` banned, restart its agent under a new label. Add to
`config.CLIENTS`:

```python
{"device_label": "client1_reborn", "tpm_backend": "real",
 "tcti": "device:/dev/tpmrm0", "endpoint": "http://100.70.28.2:8470"},
```

Same machine, same chip, **same EK hash**, new name.

```bash
PYTHONPATH=. python3 -m net.agent --label client1_reborn --port 8470
PYTHONPATH=. python3 run_server.py --rounds 5 --chain mock
```

**Expected:**

```
WHITEWASH_REJECTED: client1_reborn presents an EK banned on chain; refusing enrollment
```

The other clients keep enrolling — one whitewashing attacker does not take the
federation down.

### 6d. Sleeper — banked trust does not buy immunity

```bash
PYTHONPATH=. python3 -m net.agent --label client2 --port 8470 \
    --attack sleeper --attack-after 5
PYTHONPATH=. python3 run_server.py --rounds 14 --chain mock
```

Honest for 5 rounds (banking trust up to the M1 saturation ceiling `s → 4`),
then flips. **Expected:** sanctioned on the second consecutive MAJOR via M3,
*even though its score is still above the probation threshold.* That is the case
a score-only defence misses, and it is why M3 is a rule rather than a weight.

### Attack profile reference

| Profile | Mechanism | Stage | Severity | Notes |
|---|---|---|---|---|
| `scale` | update × 10 | 1 | MINOR | needs n ≥ 3 |
| `flip` | update × −1.5 | 2 | MAJOR | needs n ≥ 3 |
| `sybil` | identical vectors from shared seed | 3 | CRITICAL | needs ≥2 colluders |
| `sleeper` | honest, then flips | 2 | MAJOR | tests M1 + M3 |

`--attack-magnitude`, `--attack-after`, `--attack-seed` tune them.

> **Honest note on `sleeper`:** it surfaces as MAJOR via **stage 2**, not stage
> 4. Both stages return MAJOR and the max-severity compose reports the first
> match. The point of the profile is not which stage fires but that the device
> banks trust first.

---

## 7. REAL-mode latency measurement

```bash
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain off  --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain mock --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain node --real-rounds 10
PYTHONPATH=. python3 -m eval.chain_eval --exp real --chain node --full-model
```

Writes `results/chain/real_{rounds,enroll,summary}_<mode>.csv`.

**This is the only latency measurement you may quote as an absolute figure.**
Everything in Chapter 5's SIM tables runs on in-process py-evm, which
over-states EVM execution (pure-Python interpreter) while under-stating
transport (no socket, no block time). It is a different regime, not a bound.

---

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| client missing from `tailscale status` | different Tailscale account |
| `/health` times out | agent not running, or wrong IP (see §1) |
| `TPM_RESIDENT` when you expect `HARDWARE` | cert missing, wrong CA bundle, or `tpm_backend` not `"real"` |
| `tpm2_createek: permission denied` | not in `tss` group, or no re-login |
| `getekcertificate` fails | AMD PKI flaky; see `FETCH_EK_CERT.md`, use on-disk cert |
| attack runs but nothing flagged | only 2 clients — **see §0** |
| lone sybil not flagged | correct; collusion needs ≥2 peers |
| `ModuleNotFoundError` | missing `PYTHONPATH=.` |
| `--chain node` cannot connect | `anvil` not running, or no `chain/deployed.json` |
| node dies mid-run | expected: round marked UNANCHORED, training continues |

### Pre-demo checklist

```bash
tailscale status                                    # all machines
curl http://<each-client>:8470/health               # all {"ok":true}
PYTHONPATH=. python3 run_server.py --rounds 1 --stub --dim 6   # tiers correct
PYTHONPATH=. python3 tests/test_pipeline.py         # stack green
```

Capture terminal output to files — the audit log and chain state are your
evidence, but a reader wants the console narrative too.

```bash
PYTHONPATH=. python3 run_server.py --rounds 12 --chain mock 2>&1 | tee results/demo_$(date +%s).log
```

---

> **STATUS NOTE (2026-11-17).** The client2 IP conflict is resolved:
> `100.64.57.82` (matches `config.py`). The n ≥ 3 finding in §0 stands —
> a third agent is still required for any detection demo. Chain mode now
> also supports real endpoints with local signing (`DLTF_CHAIN_PRIVKEY`,
> `--rpc`/`--network`); see SETUP_GUIDE §13 and MASTER_CONTEXT §15 before
> pointing a REAL run at a public node.
