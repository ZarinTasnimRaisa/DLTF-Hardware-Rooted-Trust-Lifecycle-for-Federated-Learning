"""
chain/evm.py

Live-node Backend: talks to DLTFRegistry.sol on a Hardhat or Anvil node over
JSON-RPC via web3.py. Drop-in replacement for chain/mock.py -- ChainRegistry,
chain/verifier.py and chain/reconcile.py all work against it unchanged,
because it implements the same chain.backend.Backend surface and emits the
same event_type / payload shapes.

    from chain.evm import EvmBackend
    backend = EvmBackend.connect("http://127.0.0.1:8545", addr, writer)

FAILURE SEMANTICS -- THE LOAD-BEARING PART
-----------------------------------------------------------------------------
Two failure classes, and conflating them would be a silent integrity bug:

  ChainRejection   the contract REVERTED with a custom error. The server
                   tried something the trust lifecycle forbids. This is the
                   enforcement signal and the entire justification for the
                   layer. Decoded from the revert selector, mapped to the
                   same Reason codes MockBackend raises.

  TransportError   the node did not answer: timeout, connection refused,
                   RPC error. Nothing is known about whether the write
                   landed.

Both propagate as exceptions, and ChainRegistry._guard() sorts them:
Rejections into .rejections, everything else into .failures, both marking the
round UNANCHORED. Neither halts training.

WHY WE RAISE ON TIMEOUT RATHER THAN JUST FLIPPING is_available()
-----------------------------------------------------------------------------
ChainRegistry._guard() degrades on a RAISED exception; it never consults
is_available(). A backend that swallowed timeouts and only set the flag would
let _guard() return success, and rounds would be marked ANCHORED while
nothing reached the node. That is worse than an outage: it is an outage that
lies. So every write raises on failure, and is_available() is a secondary
signal used only by the fail-OPEN enrollment check.

RETRY POLICY
-----------------------------------------------------------------------------
Reads and writes retry with linear backoff on TRANSPORT errors only. A revert
is deterministic -- retrying it would just waste time and produce the same
error -- so reverts are never retried.

  python3 -m chain.evm            (self-test, runs on eth-tester, no node)
"""
import json
import time
from pathlib import Path
from typing import Optional

from chain.backend import Backend, ChainRejection, Event, Reason
from chain.fixedpoint import DeviceFP, StatusFP, TierFP


ROOT = Path(__file__).resolve().parent.parent

# Artifact and source discovery. The contract has lived in two layouts during
# development -- contracts/src/DLTFRegistry.sol (Foundry convention) and
# chain/DLTFRegistry.sol (flat) -- so search both rather than hard-coding one
# and failing with a confusing "not found" on a tree that is perfectly fine.
_ARTIFACT_CANDIDATES = [
    ROOT / "contracts" / "out",
    ROOT / "chain" / "out",
    ROOT / "chain" / "contracts" / "out",
    ROOT / "out",
    ROOT / "build",
]

_SOURCE_CANDIDATES = [
    ROOT / "contracts" / "src" / "DLTFRegistry.sol",
    ROOT / "chain" / "DLTFRegistry.sol",
    ROOT / "chain" / "contracts" / "DLTFRegistry.sol",
    ROOT / "chain" / "contracts" / "src" / "DLTFRegistry.sol",
]


def find_source():
    """Locate DLTFRegistry.sol. Returns Path or None."""
    for p in _SOURCE_CANDIDATES:
        if p.exists():
            return p
    hits = sorted(ROOT.rglob("DLTFRegistry.sol"))
    hits = [h for h in hits if "node_modules" not in h.parts
            and "venv" not in h.parts]
    return hits[0] if hits else None


def find_artifacts():
    """Locate (abi_path, bin_path). Either may be None."""
    for d in _ARTIFACT_CANDIDATES:
        abi, bin_ = d / "DLTFRegistry.abi", d / "DLTFRegistry.bin"
        if abi.exists() and bin_.exists():
            return abi, bin_
    # Foundry writes JSON instead of split .abi/.bin
    for d in _ARTIFACT_CANDIDATES:
        j = d / "DLTFRegistry.sol" / "DLTFRegistry.json"
        if j.exists():
            return j, j
    return None, None


def build_command():
    """The exact solc invocation for THIS tree, --via-ir included."""
    src = find_source()
    src_rel = src.relative_to(ROOT) if src else Path(
        "chain/DLTFRegistry.sol")
    return ("solc --optimize --optimize-runs 200 --via-ir --bin --abi "
            f"--overwrite -o contracts/out {src_rel}")


ABI_PATH, BIN_PATH = find_artifacts()
if ABI_PATH is None:
    # Keep the attribute present so callers can report a clean error.
    ABI_PATH = _ARTIFACT_CANDIDATES[0] / "DLTFRegistry.abi"
    BIN_PATH = _ARTIFACT_CANDIDATES[0] / "DLTFRegistry.bin"
ARTIFACT_DIR = Path(ABI_PATH).parent


class TransportError(Exception):
    """The node did not answer. Distinct from ChainRejection: a rejection is
    the contract working as designed, a transport error is infrastructure."""


# Solidity custom errors -> the Reason codes MockBackend already raises.
# Errors with no MockBackend equivalent keep their Solidity name, so they are
# still legible in ChainRegistry.rejections rather than collapsing to a
# generic bucket.
ERROR_TO_REASON = {
    "UnauthorizedWriter":    Reason.UNAUTHORIZED_WRITER,
    "BanToActive":           Reason.BAN_TO_ACTIVE,
    "TierMutation":          Reason.TIER_MUTATION,
    "DuplicateRound":        Reason.DUPLICATE_ROUND,
    "StaleRound":            Reason.STALE_ROUND,
    "DeviceUnknown":         Reason.DEVICE_UNKNOWN,
    "DeviceBanned":          Reason.DEVICE_BANNED,
    "EkAlreadyRegistered":   Reason.EK_REGISTERED,
    "OutcomeInvalid":        Reason.OUTCOME_INVALID,
    "NotOnProbation":        Reason.NOT_ON_PROBATION,
    "RoundUnknown":          Reason.ROUND_UNKNOWN,
}

# Contract event names -> the event_type strings chain/verifier.py replays.
# This mapping is what lets replay_events() and verify_backend() run against
# a live node with no changes.
EVENT_NAME_MAP = {
    "Genesis":            "GENESIS",
    "Enroll":             "ENROLL",
    "ClassifyEvent":      "EVENT",
    "Ban":                "BAN",
    "WhitewashRejected":  "WHITEWASH_REJECTED",
    "ProbationEnter":     "PROBATION_ENTER",
    "ProbationDecision":  "PROBATION_DECISION",
    "RehabExhausted":     "REHAB_EXHAUSTED",
    "Round":              "ROUND",
    "Absent":             "ABSENT",
    "GradientCommitted":  "GRADIENT_COMMITTED",
    "CommitMismatch":     "COMMIT_MISMATCH",
    "CommitProof":        "COMMIT_PROOF",
    "WalletBound":        "WALLET_BOUND",
}

OUTCOME_TO_INT = {"PENDING": 0, "EXTENDED": 1, "REINSTATED": 2,
                  "PERMANENT_BAN": 3}
INT_TO_OUTCOME = {v: k for k, v in OUTCOME_TO_INT.items()}

VALID_OUTCOMES = set(OUTCOME_TO_INT) - {"PENDING"}


def load_abi():
    """ABI from split .abi or a Foundry .json artifact.

    Honours the module-level ABI_PATH if it has been overridden, then falls
    back to discovery. It previously called find_artifacts() unconditionally,
    which meant the module global was decorative and the "missing artifacts"
    error below was unreachable -- chain/deploy.py's self-test asserted on it
    and had been failing.
    """
    abi_path = ABI_PATH if (ABI_PATH and Path(ABI_PATH).exists()) else None
    if abi_path is None:
        abi_path, _ = find_artifacts()
    if abi_path is None:
        raise SystemExit(
            f"DLTFRegistry artifacts not found. Searched:\n  "
            + "\n  ".join(str(d) for d in _ARTIFACT_CANDIDATES)
            + f"\n\nBuild with:\n  {build_command()}\n"
              f"(--via-ir is REQUIRED: the contract exceeds the 16-slot "
              f"stack limit without it)")
    txt = Path(abi_path).read_text()
    obj = json.loads(txt)
    if isinstance(obj, dict) and "abi" in obj:      # Foundry JSON
        return obj["abi"]
    return obj


def load_bin():
    bin_path = BIN_PATH if (BIN_PATH and Path(BIN_PATH).exists()) else None
    if bin_path is None:
        _, bin_path = find_artifacts()
    if bin_path is None:
        raise SystemExit(f"contract bytecode not found.\n"
                         f"Build with:\n  {build_command()}")
    txt = Path(bin_path).read_text().strip()
    if txt.startswith("{"):                          # Foundry JSON
        obj = json.loads(txt)
        bc = obj.get("bytecode", {})
        txt = (bc.get("object") if isinstance(bc, dict) else bc) or ""
        txt = txt.strip()
    return txt[2:] if txt.startswith("0x") else txt


def _selector_table(abi):
    """4-byte selector -> custom error name, built from the ABI so it can
    never drift from the deployed contract.

    The two standard selectors are added by hand because Solidity does NOT
    emit them as ABI error entries. Without them a plain `require(cond, "..")`
    or an arithmetic overflow decoded to None, was misfiled as a transport
    failure, and was RETRIED three times before being reported as a node
    outage -- a deterministic contract refusal presented as infrastructure.
    """
    from eth_utils import function_signature_to_4byte_selector
    out = {}
    for entry in abi:
        if entry.get("type") != "error":
            continue
        sig = f"{entry['name']}({','.join(i['type'] for i in entry['inputs'])})"
        out[function_signature_to_4byte_selector(sig).hex()] = entry["name"]
    out.setdefault("08c379a0", "Error")        # Error(string)
    out.setdefault("4e487b71", "Panic")        # Panic(uint256)
    return out


def _extract_revert_data(exc) -> Optional[bytes]:
    """Pull ABI-encoded revert data out of whatever the provider raised.

    Providers disagree wildly here: eth-tester raises TransactionFailed with
    a bytes literal in the message, Hardhat returns a `data` field on the RPC
    error, Anvil embeds a hex string. Try all three rather than assuming.
    """
    import re
    import ast

    # 1. structured .data on the exception or its args
    for holder in (exc,) + tuple(getattr(exc, "args", ()) or ()):
        data = getattr(holder, "data", None)
        if isinstance(data, dict):
            data = data.get("data")
        if isinstance(data, str) and data.startswith("0x") and len(data) >= 10:
            try:
                return bytes.fromhex(data[2:])
            except ValueError:
                pass
        if isinstance(data, (bytes, bytearray)) and len(data) >= 4:
            return bytes(data)

    # 2. raw bytes in args (eth-tester)
    for a in getattr(exc, "args", ()) or ():
        if isinstance(a, (bytes, bytearray)) and len(a) >= 4:
            return bytes(a)

    msg = str(exc)

    # 3. python bytes literal inside the message (eth-tester)
    m = re.search(r"(b'(?:[^'\\]|\\.)*'|b\"(?:[^\"\\]|\\.)*\")", msg)
    if m:
        try:
            v = ast.literal_eval(m.group(1))
            if isinstance(v, (bytes, bytearray)) and len(v) >= 4:
                return bytes(v)
        except (ValueError, SyntaxError):
            pass

    # 4. bare hex string in the message (Anvil / Hardhat).
    #    GATED on the message actually describing a revert. Un-gated, this
    #    matched the transaction hash that public providers embed in ordinary
    #    error text ("transaction 0xabc... not found"), and fed 32 random
    #    bytes to the selector table on every timeout.
    if "revert" in msg.lower() or "custom error" in msg.lower():
        m = re.search(r"0x[0-9a-fA-F]{8,}", msg)
        if m:
            try:
                return bytes.fromhex(m.group(0)[2:])
            except ValueError:
                pass
    return None


class EvmBackend(Backend):
    """web3.py adapter for DLTFRegistry.sol."""

    def __init__(self, w3, contract, server_account, writer=None,
                 retries=3, retry_backoff=0.25, poll_timeout=120,
                 signer=None, deploy_block=0, log_chunk=2000,
                 replace_after=1, replace_bump=1.25):
        self.w3 = w3
        self.contract = contract
        self.server_account = server_account
        # signer is None  -> eth_sendTransaction, i.e. the node holds the key.
        #                    Works on Anvil, Hardhat and eth-tester ONLY.
        # signer is set    -> local signing. The only path a public RPC or a
        #                    Besu consortium node will accept.
        self.signer = signer
        if signer is not None:
            self.server_account = signer.address
        # eth_getLogs from block 0 is refused or truncated by every public
        # provider (Alchemy and Infura cap the span; several public endpoints
        # reject genesis-to-latest outright). Knowing where the contract was
        # deployed turns a full-chain scan into a bounded one.
        self.deploy_block = int(deploy_block or 0)
        self.log_chunk = int(log_chunk)
        # How many poll timeouts to absorb before replacing the transaction at
        # the same nonce with a higher fee.
        self.replace_after = replace_after
        self.replace_bump = replace_bump
        # The registry passes `writer` through to every call so MockBackend
        # can authenticate it. On chain the authorised writer is an ADDRESS,
        # fixed immutably at deploy. We accept any writer token and use the
        # server account for the actual transaction; the contract enforces
        # UnauthorizedWriter itself, which is the real check.
        self._writer = writer if writer is not None else b"evm"
        self.retries = retries
        self.retry_backoff = retry_backoff
        self.poll_timeout = poll_timeout
        self._abi = contract.abi
        self._selectors = _selector_table(self._abi)
        self._available = True
        self._seq = 0
        # Gas accounting for eval/chain_eval.py. Off the hot path: appending
        # to a list per write is negligible next to a JSON-RPC round trip.
        self.gas_log = []
        self._track_gas = True
        # Kept SEPARATE from gas_log rather than widening its tuples, because
        # gas_total/gas_by_op and eval/chain_eval.py all unpack exactly two
        # elements. (op, gas_used, effective_gas_price_wei, block).
        self.fee_log = []

    def gas_total(self):
        return sum(g for _, g in self.gas_log)

    def wei_total(self):
        """Actual fee paid, in wei. Zero on a chain with no fee market."""
        return sum(g * p for _, g, p, _ in self.fee_log)

    def fee_reset(self):
        self.fee_log = []

    def gas_by_op(self):
        out = {}
        for op, g in self.gas_log:
            out.setdefault(op, []).append(g)
        return out

    def gas_reset(self):
        self.gas_log = []

    # ---- construction --------------------------------------------------------

    @classmethod
    def connect(cls, rpc_url, contract_address, writer=None,
                server_account=None, abi=None, timeout=30,
                private_key=None, signer=None, deploy_block=None, **kw):
        """Attach to an already-deployed contract on a live node.

        private_key (or DLTF_CHAIN_PRIVKEY) switches on local signing. Without
        it every write goes out as eth_sendTransaction, which only Anvil,
        Hardhat and eth-tester implement -- so on any real endpoint the reads
        will succeed and every write will fail.
        """
        import os
        from web3 import Web3
        from web3.middleware import ExtraDataToPOAMiddleware

        w3 = Web3(Web3.HTTPProvider(
            rpc_url,
            request_kwargs={"timeout": timeout}
        ))

        # Besu QBFT blocks contain consensus data in extraData that is
        # longer than the standard 32-byte Ethereum extraData field.
        # Web3.py otherwise raises ExtraDataLengthError while decoding
        # the block header.
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

        if not w3.is_connected():
            raise TransportError(f"cannot reach node at {rpc_url}")
        abi = abi or load_abi()
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(contract_address), abi=abi)

        if signer is None:
            key = private_key or os.environ.get("DLTF_CHAIN_PRIVKEY")
            if key:
                from chain.signer import TxSigner
                signer = TxSigner(w3, key)

        on_chain_server = contract.functions.server().call()
        acct = server_account or (signer.address if signer
                                  else on_chain_server)

        if signer is not None and signer.address.lower() != \
                on_chain_server.lower():
            # Say it now rather than letting every write come back as
            # UnauthorizedWriter. This is a legitimate configuration for the
            # non-writer half of the enforcement experiment, so it warns
            # rather than raising.
            print(f"\u26a0 signer {signer.address} is NOT the contract's "
                  f"authorised writer ({on_chain_server}); every write will "
                  f"revert with UnauthorizedWriter")

        if deploy_block is None:
            deploy_block = int(os.environ.get("DLTF_DEPLOY_BLOCK", 0) or 0)
        return cls(w3, contract, acct, writer=writer, signer=signer,
                   deploy_block=deploy_block, **kw)

    @classmethod
    def attach(cls, w3, contract_address, writer=None, server_account=None,
               abi=None, **kw):
        """Attach using a caller-supplied Web3 (eth-tester, IPC, WS)."""
        abi = abi or load_abi()
        contract = w3.eth.contract(address=contract_address, abi=abi)
        acct = server_account or contract.functions.server().call()
        return cls(w3, contract, acct, writer=writer, **kw)

    # ---- transport -----------------------------------------------------------

    def _decode_revert(self, exc) -> Optional[str]:
        """Return the custom-error NAME if this exception is a contract
        revert, else None (meaning: treat as transport)."""
        data = _extract_revert_data(exc)
        if data is None or len(data) < 4:
            # Some providers report a revert with no data. Fall back to the
            # message so a genuine revert is not misfiled as an outage.
            msg = str(exc).lower()
            if "revert" in msg or "execution reverted" in msg:
                return "UnknownRevert"
            return None
        return self._selectors.get(data[:4].hex())

    def _revert_name_from_receipt(self, receipt, fn_call):
        """A mined transaction with status 0 carries no reason in the receipt.
        Re-run the same call as eth_call AT THE BLOCK IT FAILED IN, which
        replays it against the state it actually saw and returns the revert
        data.

        This used to raise ChainRejection("UnknownRevert") and throw the name
        away. That name is the whole enforcement result: 'the contract
        refused' is a much weaker claim than 'the contract refused with
        BanToActive'.
        """
        try:
            fn_call.call({"from": self.server_account},
                         block_identifier=receipt["blockNumber"])
        except Exception as exc:
            name = self._decode_revert(exc)
            if name:
                return name, str(exc)[:200]
        return "UnknownRevert", (
            f"status 0 in block {receipt.get('blockNumber')}, gas used "
            f"{receipt.get('gasUsed')} of {receipt.get('cumulativeGasUsed')} "
            f"-- re-simulation produced no revert data (out of gas?)")

    def _record(self, receipt, fn_call, op):
        if receipt.get("status", 1) == 0:
            name, detail = self._revert_name_from_receipt(receipt, fn_call)
            raise ChainRejection(ERROR_TO_REASON.get(name, name), detail)
        self._available = True
        label = op or getattr(fn_call, "fn_name", "unknown")
        if self._track_gas:
            self.gas_log.append((label, receipt["gasUsed"]))
            self.fee_log.append((label, receipt["gasUsed"],
                                 int(receipt.get("effectiveGasPrice", 0) or 0),
                                 receipt.get("blockNumber")))
        return receipt

    def _send(self, fn_call, gas=None, op=None):
        """Transact and wait for the receipt.

        Raises ChainRejection on revert (never retried -- deterministic) and
        TransportError on node failure.

        THE RULE THIS ENFORCES: a transaction is BUILT at most once. The
        previous version retried the whole operation on any non-revert
        exception, and the commonest such exception on a public chain is a
        poll timeout on a transaction that was broadcast and simply is not
        mined yet. Retrying rebuilt it at a fresh nonce, so both copies could
        land and `classify` would apply the reputation rule twice -- silently,
        because nothing raises. Here a timeout either keeps waiting or
        REPLACES the transaction at the same nonce, which the chain can
        include at most once.
        """
        if self.signer is not None:
            return self._send_signed(fn_call, gas=gas, op=op)
        return self._send_unlocked(fn_call, gas=gas, op=op)

    def _send_signed(self, fn_call, gas=None, op=None):
        from chain.signer import BroadcastError, PendingTimeout
        try:
            tx_hash, tx = self.signer.send(fn_call, gas=gas)
        except BroadcastError as exc:
            # Nothing reached the chain, so nothing is ambiguous.
            self._available = False
            raise TransportError(f"broadcast refused: {exc}") from exc
        except Exception as exc:
            # Estimation reverts land here, with their data intact -- which is
            # why signer.build() estimates explicitly instead of letting
            # build_transaction do it silently.
            name = self._decode_revert(exc)
            if name is not None:
                raise ChainRejection(ERROR_TO_REASON.get(name, name),
                                     str(exc)[:200]) from exc
            self._available = False
            raise TransportError(
                f"{type(exc).__name__}: {exc}") from exc

        nonce = tx["nonce"]
        for attempt in range(self.replace_after + 1):
            try:
                receipt = self.signer.wait(tx_hash, timeout=self.poll_timeout,
                                           nonce=nonce)
                return self._record(receipt, fn_call, op)
            except PendingTimeout:
                if attempt >= self.replace_after:
                    self._available = False
                    raise TransportError(
                        f"tx {tx_hash.hex()} (nonce {nonce}) still not mined "
                        f"after {(attempt + 1) * self.poll_timeout:.0f}s and "
                        f"{self.replaced_note()}; it is BROADCAST, so the "
                        f"round is unanchored but the write may still land "
                        f"later -- reconcile rather than resend")
                try:
                    tx_hash = self.signer.replace(
                        fn_call, nonce=nonce, bump=self.replace_bump ** (
                            attempt + 1), gas=gas)
                except BroadcastError:
                    # Usually "nonce too low": the original just got mined.
                    continue

    def replaced_note(self):
        return f"{self.signer.replaced} fee replacement(s)" if self.signer \
            else "no signer"

    def _send_unlocked(self, fn_call, gas=None, op=None):
        """eth_sendTransaction path: Anvil, Hardhat, eth-tester.

        Also fixed to broadcast once. The node holds the nonce here, so there
        is no replacement to make -- but rebuilding on a timeout would produce
        the same double-write, so we poll the original hash instead.
        """
        tx_params = {"from": self.server_account}
        if gas:
            tx_params["gas"] = gas
        last = None
        tx_hash = None
        for attempt in range(self.retries):
            try:
                tx_hash = fn_call.transact(tx_params)
                break
            except Exception as exc:
                name = self._decode_revert(exc)
                if name is not None:
                    raise ChainRejection(ERROR_TO_REASON.get(name, name),
                                         str(exc)[:200]) from exc
                last = exc
                if attempt < self.retries - 1:
                    time.sleep(self.retry_backoff * (attempt + 1))
        if tx_hash is None:
            self._available = False
            raise TransportError(f"node unreachable after {self.retries} "
                                 f"attempts: {type(last).__name__}: {last}")
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self.poll_timeout)
        except Exception as exc:
            self._available = False
            raise TransportError(
                f"tx {tx_hash.hex()} broadcast but not mined within "
                f"{self.poll_timeout}s: {type(exc).__name__}: {exc}") from exc
        return self._record(receipt, fn_call, op)

    def _call(self, fn_call):
        """Read-only call with the same retry policy."""
        last = None
        for attempt in range(self.retries):
            try:
                out = fn_call.call()
                self._available = True
                return out
            except Exception as exc:
                name = self._decode_revert(exc)
                if name is not None:
                    raise ChainRejection(
                        ERROR_TO_REASON.get(name, name), str(exc)[:200]
                    ) from exc
                last = exc
                if attempt < self.retries - 1:
                    time.sleep(self.retry_backoff * (attempt + 1))
        self._available = False
        raise TransportError(f"node unreachable after {self.retries} "
                             f"attempts: {type(last).__name__}: {last}")

    # ---- receipt -> Event ----------------------------------------------------

    def _events_from_receipt(self, receipt, want=None):
        """Decode the contract events a transaction emitted, in log order,
        into chain.backend.Event objects with mock-compatible payloads."""
        out = []
        for name, mapped in EVENT_NAME_MAP.items():
            if want is not None and mapped not in want:
                continue
            try:
                logs = getattr(self.contract.events, name)().process_receipt(
                    receipt, errors=_DISCARD)
            except Exception:
                continue
            for log in logs:
                out.append((log["logIndex"], mapped,
                            self._payload(mapped, dict(log["args"]))))
        out.sort(key=lambda t: t[0])
        evs = []
        for _, etype, payload in out:
            self._seq += 1
            evs.append(Event(seq=self._seq, event_type=etype, payload=payload,
                             prev_hash=b"\x00" * 32,
                             hash=bytes(receipt["transactionHash"])))
        return evs

    @staticmethod
    def _payload(event_type, args):
        """Normalise contract event args into the payload shape MockBackend
        emits, so chain/verifier.py replays identically against both."""
        def h(v):
            return v.hex() if isinstance(v, (bytes, bytearray)) else v

        if event_type == "ENROLL":
            return {"device": args["deviceId"], "tier": int(args["tier"]),
                    "ek_hmac": h(args["ekHmac"]), "status": int(args["status"])}
        if event_type == "EVENT":
            return {"round": int(args["roundId"]), "device": args["deviceId"],
                    "severity": int(args["severity"]),
                    "stage": int(args["stage"]),
                    "reason": args["reason"], "status": int(args["status"])}
        if event_type == "BAN":
            return {"round": int(args["roundId"]), "device": args["deviceId"],
                    "ek_hmac": h(args["ekHmac"])}
        if event_type == "WHITEWASH_REJECTED":
            return {"device": args["deviceId"], "ek_hmac": h(args["ekHmac"])}
        if event_type == "PROBATION_ENTER":
            return {"round": int(args["roundId"]), "device": args["deviceId"]}
        if event_type == "PROBATION_DECISION":
            return {"round": int(args["roundId"]), "device": args["deviceId"],
                    "outcome": INT_TO_OUTCOME.get(int(args["outcome"]),
                                                  str(args["outcome"]))}
        if event_type == "REHAB_EXHAUSTED":
            return {"round": int(args["roundId"]), "device": args["deviceId"],
                    "ek_hmac": h(args["ekHmac"])}
        if event_type == "ROUND":
            return {"round": int(args["roundId"]),
                    "participants_hash": h(args["participantsHash"]),
                    "aggregated": bool(args["aggregated"]),
                    "local_head": h(args["localHead"])}
        if event_type == "GENESIS":
            return {"chain_id": h(args.get("chainId", b"")),
                    "version": int(args.get("version", 1))}
        # ---- commitment layer ------------------------------------------
        # One asymmetry against MockBackend that cannot be closed: the
        # contract indexes on keccak(deviceId), so these events carry
        # `deviceKey`, not the label. The label is not recoverable from a
        # hash. We expose it as `device_key` and leave `device` absent rather
        # than inventing a value, because a payload that pretends to hold a
        # label the chain never stored is worse than one that admits the gap.
        if event_type == "GRADIENT_COMMITTED":
            return {"round": int(args["roundId"]),
                    "device_key": h(args["deviceKey"]),
                    "wallet": args["wallet"],
                    "grad_hash": h(args["gradHash"])}
        if event_type == "WALLET_BOUND":
            return {"device": args["deviceId"], "wallet": args["wallet"]}
        if event_type == "ABSENT":
            return {"round": int(args["roundId"]), "device": args["deviceId"]}
        if event_type == "COMMIT_MISMATCH":
            return {"round": int(args["roundId"]), "device": args["deviceId"],
                    "committed": h(args.get("committed", b"")),
                    "received": h(args.get("received", b""))}
        if event_type == "COMMIT_PROOF":
            return {"round": int(args["roundId"]),
                    "device_key": h(args["deviceKey"]),
                    "grad_hash": h(args["gradHash"])}
        return {k: h(v) for k, v in args.items()}

    # ---- writes --------------------------------------------------------------

    def register(self, writer, device_id, tier, ek_hmac):
        receipt = self._send(
            self.contract.functions.register(device_id, int(tier), ek_hmac),
            op="register")
        evs = self._events_from_receipt(receipt)
        ww = [e for e in evs if e.event_type == "WHITEWASH_REJECTED"]
        if ww:
            return (int(StatusFP.BANNED), ww[0])
        enroll = [e for e in evs if e.event_type == "ENROLL"]
        status = enroll[0].payload["status"] if enroll else int(StatusFP.ACTIVE)
        return (int(status), enroll[0] if enroll else None)

    def classify(self, writer, round_id, device_id, severity, stage=0,
                 reason=""):
        receipt = self._send(self.contract.functions.classify(
            int(round_id), device_id, int(severity), int(stage), str(reason)),
            op="classify")
        evs = self._events_from_receipt(receipt)
        ev = next((e for e in evs if e.event_type == "EVENT"), None)
        status = ev.payload["status"] if ev else int(
            self.get_device(device_id).status)
        return (int(status), ev)

    def enter_probation(self, writer, round_id, device_id):
        receipt = self._send(
            self.contract.functions.enterProbation(int(round_id), device_id),
            op="enterProbation")
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs if e.event_type == "PROBATION_ENTER"), None)

    def exhaust_probation(self, writer, round_id, device_id):
        receipt = self._send(
            self.contract.functions.exhaustProbation(int(round_id), device_id),
            op="exhaustProbation")
        evs = self._events_from_receipt(receipt)
        return (int(StatusFP.BANNED),
                [e for e in evs
                 if e.event_type in ("REHAB_EXHAUSTED", "BAN")])

    def probation_decision(self, writer, round_id, device_id, outcome):
        if outcome not in VALID_OUTCOMES:
            raise ChainRejection(Reason.OUTCOME_INVALID, str(outcome))
        receipt = self._send(self.contract.functions.probationDecision(
            int(round_id), device_id, OUTCOME_TO_INT[outcome]),
            op="probationDecision")
        evs = self._events_from_receipt(receipt)
        dev = self.get_device(device_id)
        return (int(dev.status) if dev else int(StatusFP.ACTIVE),
                [e for e in evs
                 if e.event_type in ("PROBATION_DECISION", "BAN")])

    def round_summary(self, writer, round_id, participants_hash, aggregated,
                      local_head):
        receipt = self._send(self.contract.functions.roundSummary(
            int(round_id), participants_hash, bool(aggregated), local_head),
            op="roundSummary")
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs if e.event_type == "ROUND"), None)

    # ---- commitment layer ----------------------------------------------------
    # Mirrors chain/commit.py's CommitMockBackend method-for-method, so the
    # same federation code drives either one and commit_parity_test.py can
    # compare them. The contract side and its 34 tests already existed; this
    # is the Python side that never got written, which is why the paper says
    # the per-round cost is "unmeasured rather than zero".

    def bind_wallet(self, writer, device_label: str, wallet: str):
        """Server-submitted, and idempotent in the contract: re-binding the
        SAME wallet returns quietly, a different one reverts
        WalletAlreadyBound."""
        from web3 import Web3
        receipt = self._send(self.contract.functions.bindWallet(
            device_label, Web3.to_checksum_address(wallet)),
            op="bindWallet")
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs if e.event_type == "WALLET_BOUND"), None)

    def get_wallet(self, device_label: str):
        w = self._call(self.contract.functions.getWallet(device_label))
        return None if int(w, 16) == 0 else w

    def commit_gradient(self, wallet, round_id: int, gh: bytes,
                        signer=None):
        """Called by the CLIENT, not the server: the contract keys the
        commitment on msg.sender via walletDevice[]. So this needs the
        client's own key, which is the one asymmetry against the mock -- the
        mock takes a wallet STRING because it has no notion of who is
        sending.

        Pass `signer` (a chain.signer.TxSigner for that wallet). Passing only
        a wallet string is accepted when that wallet is this backend's own
        signer, which is the single-process test configuration.
        """
        sgn = signer
        if sgn is None:
            if self.signer is None or (
                    isinstance(wallet, str)
                    and wallet.lower() != self.signer.address.lower()):
                raise ValueError(
                    "commit_gradient is sent BY the client wallet: pass "
                    "signer=TxSigner(w3, <that wallet's key>). The server "
                    "cannot fabricate it, which is the anti-fabrication "
                    "property the commitment layer exists for.")
            sgn = self.signer
        saved, self.signer = self.signer, sgn
        try:
            receipt = self._send(self.contract.functions.commitGradient(
                int(round_id), gh), op="commitGradient")
        finally:
            self.signer = saved
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs
                     if e.event_type == "GRADIENT_COMMITTED"), None)

    def commit_batch(self, writer, commits, chain_id=None,
                     contract_address=None):
        """The path a federation actually uses: the server submits every
        client's SIGNED commitment for one round in one transaction, so
        clients pay no gas and hold no funded wallet.

        Atomic in the contract: one bad signature reverts the whole batch.
        """
        from chain.commit import build_batch
        if not commits:
            raise ChainRejection("EmptyBatch", "no commitments")
        round_id, keys, hashes, vs, rs, ss = build_batch(commits)
        receipt = self._send(self.contract.functions.commitBatch(
            int(round_id), keys, hashes, vs, rs, ss), op="commitBatch")
        evs = self._events_from_receipt(receipt)
        return len([e for e in evs if e.event_type == "GRADIENT_COMMITTED"])

    def classify_signed(self, writer, round_id, device_id, severity,
                        stage=0, reason="", grad_hash=None, v=None,
                        r=None, s=None, signed_commit=None):
        """The cheap path: classify and prove the client signed the gradient
        in ONE transaction, so no separate commitment SSTORE is paid.

        Either pass the four signature pieces or a SignedCommit.
        """
        if signed_commit is not None:
            grad_hash = signed_commit.grad_hash
            v, r, s = signed_commit.v, signed_commit.r, signed_commit.s
        if grad_hash is None or v is None:
            raise ValueError("classify_signed needs grad_hash and a signature")
        receipt = self._send(self.contract.functions.classifySigned(
            int(round_id), device_id, int(severity), int(stage), str(reason),
            grad_hash, int(v), r, s), op="classifySigned")
        evs = self._events_from_receipt(receipt)
        ev = next((e for e in evs if e.event_type == "EVENT"), None)
        status = ev.payload["status"] if ev else int(
            self.get_device(device_id).status)
        return (int(status), ev)

    def get_commit(self, device_label: str, round_id: int):
        """None rather than 32 zero bytes when absent, matching the mock, so
        chain/commit.py's check_commit() reads NO_COMMIT identically against
        either backend."""
        got = bytes(self._call(self.contract.functions.getCommit(
            device_label, int(round_id))))
        return None if got == b"\x00" * 32 else got

    def mark_absent(self, writer, round_id, device_id):
        receipt = self._send(self.contract.functions.markAbsent(
            int(round_id), device_id), op="markAbsent")
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs if e.event_type == "ABSENT"), None)

    def report_commit_mismatch(self, writer, round_id, device_id, received):
        receipt = self._send(self.contract.functions.reportCommitMismatch(
            int(round_id), device_id, received), op="reportCommitMismatch")
        evs = self._events_from_receipt(receipt)
        return next((e for e in evs
                     if e.event_type == "COMMIT_MISMATCH"), None)

    @property
    def require_commit(self) -> bool:
        return bool(self._call(self.contract.functions.requireCommit()))

    # ---- reads ---------------------------------------------------------------

    def get_device(self, device_id):
        packed = self._call(self.contract.functions.getDevice(device_id))
        if not packed:
            return None
        ek = self._call(self.contract.functions.deviceEk(
            _device_key(device_id)))
        return DeviceFP.unpack(int(packed), device_id=device_id,
                               ek_hmac=bytes(ek) if ek else None)

    def is_banned_ek(self, ek_hmac) -> bool:
        return bool(self._call(self.contract.functions.isBannedEk(ek_hmac)))

    def last_round(self) -> int:
        if not bool(self._call(self.contract.functions.lastRoundSet())):
            return -1
        return int(self._call(self.contract.functions.lastRound()))

    def events(self, event_type=None, since_seq=0):
        """Rebuild the full event log from chain logs.

        This is the read surface chain/verifier.py and chain/reconcile.py use,
        so its ORDER must be the emission order: sorted by block, then by log
        index within the block.
        """
        want = None if event_type is None else {event_type}
        collected = []
        for name, mapped in EVENT_NAME_MAP.items():
            if want is not None and mapped not in want:
                continue
            try:
                logs = self._get_logs(name)
            except Exception:
                continue
            for log in logs:
                collected.append((log["blockNumber"], log["logIndex"],
                                  mapped, dict(log["args"]),
                                  bytes(log["transactionHash"])))
        collected.sort(key=lambda t: (t[0], t[1]))

        out, prev = [], b"\x00" * 32
        for seq, (_, _, etype, args, txh) in enumerate(collected):
            if seq < since_seq:
                continue
            out.append(Event(seq=seq, event_type=etype,
                             payload=self._payload(etype, args),
                             prev_hash=prev, hash=txh))
            prev = txh
        return out

    def _get_logs(self, event_name):
        """Fetch one event type over the contract's lifetime, in bounded
        chunks.

        `get_logs(from_block=0)` worked on Anvil and is refused by essentially
        every public provider: Alchemy and Infura cap the span at 10k blocks,
        and several public endpoints reject genesis-to-latest outright. On a
        chain whose genesis predates the contract by millions of blocks it is
        also pure waste. Starting at deploy_block and walking in chunks makes
        the same query answerable everywhere.
        """
        ev = getattr(self.contract.events, event_name)
        try:
            head = self.w3.eth.block_number
        except Exception as exc:
            self._available = False
            raise TransportError(f"cannot read head block: {exc}") from exc

        out, start = [], self.deploy_block
        chunk = self.log_chunk
        while start <= head:
            end = min(start + chunk - 1, head)
            got, last = None, None
            for attempt in range(self.retries):
                try:
                    got = ev().get_logs(from_block=start, to_block=end)
                    break
                except TypeError:
                    got = ev().get_logs(fromBlock=start, toBlock=end)
                    break
                except Exception as exc:
                    last = exc
                    msg = str(exc).lower()
                    # Providers signal an over-wide range in a dozen dialects.
                    # Halving and retrying is cheaper than parsing any of them.
                    if any(s in msg for s in ("range", "too many", "limit",
                                              "exceed", "query returned more",
                                              "block range")) and chunk > 32:
                        chunk = max(32, chunk // 4)
                        end = min(start + chunk - 1, head)
                        continue
                    if attempt < self.retries - 1:
                        time.sleep(self.retry_backoff * (attempt + 1))
            if got is None:
                self._available = False
                raise TransportError(
                    f"get_logs({event_name}) failed over blocks "
                    f"{start}-{end}: {last}")
            out.extend(got)
            start = end + 1
        self._available = True
        self.log_chunk = chunk           # remember what this provider tolerates
        return out

    def head_hash(self, block="latest") -> bytes:
        """The chain's own head. On an EVM this is the latest block hash:
        every mirrored write is committed under it.

        RAISES on failure. It used to swallow every exception and return 32
        zero bytes, which is the one place this module violated its own stated
        rule that a write path must never report success when nothing reached
        the node: a throttled provider would produce a round anchored under a
        null head, indistinguishable from a real one. Callers that genuinely
        want the degraded value now have to ask for it by name.

        block="finalized" is the right choice on a probabilistic-finality
        chain (Sepolia). Under QBFT finality is immediate and the two agree.
        """
        try:
            return bytes(self.w3.eth.get_block(block)["hash"])
        except Exception as exc:
            self._available = False
            raise TransportError(f"cannot read {block} block: "
                                 f"{type(exc).__name__}: {exc}") from exc

    def head_hash_or_null(self, block="latest") -> bytes:
        """head_hash() for reporting paths that must not raise. Returns 32
        zero bytes on failure, which callers MUST treat as 'unknown', never
        as a head."""
        try:
            return self.head_hash(block)
        except TransportError:
            return b"\x00" * 32

    def snapshot(self) -> dict:
        # One log pass, not three. The old version called events("ENROLL"),
        # then two eth_calls per device, then events() again for seq -- which
        # on a rate-limited endpoint is the fastest way to get throttled.
        all_events = self.events()
        devices, banned = {}, set()
        for e in all_events:
            if e.event_type != "ENROLL":
                continue
            d = self.get_device(e.payload["device"])
            if d is not None:
                devices[e.payload["device"]] = d.pack()
                if d.status == StatusFP.BANNED and d.ek_hmac:
                    banned.add(d.ek_hmac.hex())
        return {"devices": devices, "banned_eks": banned,
                "last_round": self.last_round(),
                "head": self.head_hash_or_null().hex(),
                "seq": len(all_events)}

    def is_available(self) -> bool:
        return self._available

    def ping(self) -> bool:
        """Actively probe the node and refresh is_available()."""
        try:
            self.w3.eth.block_number
            self._available = True
        except Exception:
            self._available = False
        return self._available


class _Discard:
    """web3 log-processing 'discard' sentinel, defined locally so this module
    does not depend on a specific web3 internal import path."""
    pass


try:                                   # pragma: no cover
    from web3.logs import DISCARD as _DISCARD
except Exception:                      # pragma: no cover
    _DISCARD = _Discard


def _device_key(device_id: str) -> bytes:
    from eth_utils import keccak
    return keccak(text=device_id)


# ---- self-test ---------------------------------------------------------------

def _self_test():
    """Runs against eth-tester / py-evm. No node required."""
    import hashlib
    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    from chain.fixedpoint import SeverityFP
    from chain.mock import MockBackend
    from chain.verifier import verify_backend

    print("chain/evm.py self-test (eth-tester, no node needed)")

    abi, binary = load_abi(), load_bin()
    tester = EthereumTester(backend=PyEVMBackend())
    w3 = Web3(EthereumTesterProvider(tester))
    server = w3.eth.accounts[0]
    W = b"evm-writer"

    def deploy():
        factory = w3.eth.contract(abi=abi, bytecode=binary)
        tx = factory.constructor(server, b"\x00" * 32, False).transact(
            {"from": server})
        rc = w3.eth.wait_for_transaction_receipt(tx)
        return EvmBackend.attach(w3, rc.contractAddress, writer=W,
                                 server_account=server, abi=abi)

    def ek(label):
        return hashlib.sha256(label.encode()).digest()

    # === 1. Implements the Backend ABC ====================================
    b = deploy()
    assert isinstance(b, Backend)
    assert b.last_round() == -1
    assert b.is_available() is True
    print("\u2713 EvmBackend is a concrete chain.backend.Backend; fresh "
          "contract reports last_round = -1")

    # === 2. register / classify round-trip ================================
    st, ev = b.register(W, "alpha", TierFP.HARDWARE, ek("alpha"))
    assert st == int(StatusFP.ACTIVE)
    assert ev.event_type == "ENROLL"
    assert ev.payload["device"] == "alpha"
    assert ev.payload["tier"] == int(TierFP.HARDWARE)
    d = b.get_device("alpha")
    assert d.status == StatusFP.ACTIVE and d.tier == TierFP.HARDWARE
    st, ev = b.classify(W, 0, "alpha", SeverityFP.NEUTRAL)
    assert ev.event_type == "EVENT" and ev.payload["severity"] == 1
    d = b.get_device("alpha")
    assert d.s == 400_000 and d.clean_run == 1, (d.s, d.clean_run)
    print(f"\u2713 register + classify NEUTRAL: s={d.s}, clean_run="
          f"{d.clean_run}, decoded events match mock payload shape")

    # === 3. BIT PARITY with MockBackend ===================================
    b = deploy()
    m = MockBackend(W)
    for lbl, tier in (("p", TierFP.HARDWARE), ("q", TierFP.SOFTWARE)):
        b.register(W, lbl, tier, ek(lbl))
        m.register(W, lbl, tier, ek(lbl))
    script = [SeverityFP.NEUTRAL, SeverityFP.MINOR, SeverityFP.NEUTRAL,
              SeverityFP.NEUTRAL, SeverityFP.MAJOR, SeverityFP.NEUTRAL]
    for rid, sev in enumerate(script):
        for lbl in ("p", "q"):
            if b.get_device(lbl).status == StatusFP.BANNED:
                continue
            b.classify(W, rid, lbl, sev)
            m.classify(W, rid, lbl, sev)
            assert b.get_device(lbl).pack() == m.get_device(lbl).pack(), (
                rid, lbl, b.get_device(lbl).pack(), m.get_device(lbl).pack())
        ph = hashlib.sha256(b"p\nq").digest()
        b.round_summary(W, rid, ph, True, b"\x11" * 32)
        m.round_summary(W, rid, ph, True, b"\x11" * 32)
    print(f"\u2713 BIT PARITY: packed word identical to MockBackend after "
          f"every write across {len(script)} rounds x 2 devices")

    # === 4. last_round tracks roundSummary ================================
    assert b.last_round() == len(script) - 1 == m.last_round()
    print(f"\u2713 last_round() = {b.last_round()}, matches mock")

    # === 5. Reverts become ChainRejection with the RIGHT Reason ===========
    b = deploy()
    b.register(W, "x", TierFP.HARDWARE, ek("x"))
    cases = []

    try:
        b.register(W, "x", TierFP.SOFTWARE, ek("x"))
        cases.append(("tier mutation", "NO REVERT"))
    except ChainRejection as e:
        cases.append(("tier mutation", e.reason))

    try:
        b.register(W, "y", TierFP.HARDWARE, ek("x"))
        cases.append(("duplicate EK", "NO REVERT"))
    except ChainRejection as e:
        cases.append(("duplicate EK", e.reason))

    try:
        b.classify(W, 0, "ghost", SeverityFP.NEUTRAL)
        cases.append(("unknown device", "NO REVERT"))
    except ChainRejection as e:
        cases.append(("unknown device", e.reason))

    assert dict(cases)["tier mutation"] == Reason.TIER_MUTATION, cases
    assert dict(cases)["duplicate EK"] == Reason.EK_REGISTERED, cases
    assert dict(cases)["unknown device"] == Reason.DEVICE_UNKNOWN, cases
    print(f"\u2713 REVERT DECODING: {cases}")

    # === 6. Stale / duplicate round =======================================
    b = deploy()
    b.register(W, "r", TierFP.HARDWARE, ek("r"))
    b.classify(W, 5, "r", SeverityFP.NEUTRAL)
    b.round_summary(W, 5, hashlib.sha256(b"r").digest(), True, b"\x00" * 32)
    try:
        b.classify(W, 3, "r", SeverityFP.NEUTRAL)
        raise AssertionError("stale classify should revert")
    except ChainRejection as e:
        assert e.reason == Reason.STALE_ROUND, e.reason
    try:
        b.round_summary(W, 5, hashlib.sha256(b"r").digest(), True,
                        b"\x00" * 32)
        raise AssertionError("duplicate round should revert")
    except ChainRejection as e:
        assert e.reason == Reason.DUPLICATE_ROUND, e.reason
    print("\u2713 StaleRound and DuplicateRound decode to the same Reason "
          "codes MockBackend raises")

    # === 7. Unauthorized writer ===========================================
    b2 = EvmBackend.attach(w3, b.contract.address, writer=W,
                           server_account=w3.eth.accounts[1], abi=abi)
    try:
        b2.register(W, "intruder", TierFP.HARDWARE, ek("intruder"))
        raise AssertionError("non-server write should revert")
    except ChainRejection as e:
        assert e.reason == Reason.UNAUTHORIZED_WRITER, e.reason
    print("\u2713 write from a non-server address -> UnauthorizedWriter")

    # === 8. Reverts are NOT retried =======================================
    # A revert is deterministic; retrying wastes time and changes nothing.
    b3 = deploy()
    b3.retries = 3
    b3.retry_backoff = 0.5
    b3.register(W, "z", TierFP.HARDWARE, ek("z"))
    t0 = time.time()
    try:
        b3.register(W, "z2", TierFP.HARDWARE, ek("z"))
    except ChainRejection:
        pass
    elapsed = time.time() - t0
    assert elapsed < 0.5, f"revert appears to have been retried ({elapsed:.2f}s)"
    print(f"\u2713 reverts are not retried ({elapsed*1000:.0f} ms, no backoff "
          f"incurred)")

    # === 9. WHITEWASH is expected flow, not a rejection ====================
    b = deploy()
    b.register(W, "atk", TierFP.SOFTWARE, ek("atk"))
    b.classify(W, 0, "atk", SeverityFP.CRITICAL)
    assert b.get_device("atk").status == StatusFP.BANNED
    assert b.is_banned_ek(ek("atk")) is True
    st, ev = b.register(W, "atk_v2", TierFP.SOFTWARE, ek("atk"))
    assert st == int(StatusFP.BANNED)
    assert ev.event_type == "WHITEWASH_REJECTED"
    assert b.get_device("atk_v2") is None
    print("\u2713 WHITEWASH: returns (BANNED, WHITEWASH_REJECTED) without "
          "raising, and creates no device record")

    # === 10. events() replays through the UNMODIFIED verifier =============
    b = deploy()
    for lbl in ("v1", "v2"):
        b.register(W, lbl, TierFP.HARDWARE, ek(lbl))
    for rid in range(4):
        for lbl in ("v1", "v2"):
            b.classify(W, rid, lbl,
                       SeverityFP.MINOR if (rid == 1 and lbl == "v2")
                       else SeverityFP.NEUTRAL)
        b.round_summary(W, rid, hashlib.sha256(b"v1\nv2").digest(), True,
                        b"\x00" * 32)
    res = verify_backend(b)
    assert res.ok, res.summary()
    assert res.devices_checked == 2
    print(f"\u2713 THIRD-PARTY VERIFICATION against a deployed contract: "
          f"{res.summary()}")

    # === 11. Event ordering is emission order =============================
    evs = b.events()
    assert [e.seq for e in evs] == list(range(len(evs)))
    types = [e.event_type for e in evs]
    assert types.index("ENROLL") < types.index("EVENT") < types.index("ROUND")
    assert len(b.events("ROUND")) == 4
    print(f"\u2713 events() returns {len(evs)} events in emission order "
          f"(block, logIndex), filterable by type")

    # === 12. reconcile.py rebuilds a REAL engine from the contract ========
    from audit.hashchain import HashChain
    from chain.reconcile import rebuild_engine
    from trust.reputation import Status as FStatus
    inner = HashChain()
    for lbl in ("v1", "v2"):
        inner.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                                "ek_hash": f"raw_{lbl}", "status": "ACTIVE"})
    engine, rep = rebuild_engine(b, inner)
    assert rep.ok, rep.summary()
    assert rep.devices == 2
    assert engine.get_status("v1") == FStatus.ACTIVE
    print(f"\u2713 chain/reconcile.py rebuilds a ReputationEngine straight "
          f"from the deployed contract ({rep.summary()})")

    # === 13. snapshot() shape =============================================
    snap = b.snapshot()
    for k in ("devices", "banned_eks", "last_round", "head", "seq"):
        assert k in snap, k
    assert set(snap["devices"]) == {"v1", "v2"}
    assert snap["last_round"] == 3
    print(f"\u2713 snapshot(): {len(snap['devices'])} devices, "
          f"last_round {snap['last_round']}, seq {snap['seq']}")

    # === 14. Transport failure RAISES (never silently 'succeeds') =========
    # The critical property. If a dead node returned success, rounds would be
    # marked ANCHORED while nothing reached the chain.
    class DeadW3:
        class eth:
            accounts = []
            @staticmethod
            def wait_for_transaction_receipt(*a, **k):
                raise ConnectionError("node down")
            @staticmethod
            def get_block(*a, **k):
                raise ConnectionError("node down")
    dead = deploy()
    dead.retries = 2
    dead.retry_backoff = 0.01

    class BoomFn:
        def transact(self, *a, **k):
            raise ConnectionError("connection refused")
        def call(self, *a, **k):
            raise ConnectionError("connection refused")

    try:
        dead._send(BoomFn())
        raise AssertionError("dead node must raise")
    except TransportError as e:
        assert "unreachable" in str(e)
    assert dead.is_available() is False
    try:
        dead._call(BoomFn())
        raise AssertionError("dead node must raise on read too")
    except TransportError:
        pass
    print("\u2713 NEVER LIES: transport failure raises TransportError and "
          "flips is_available() False -- rounds cannot be falsely ANCHORED")

    # === 15. Recovery ======================================================
    assert dead.ping() is True
    assert dead.is_available() is True
    print("\u2713 ping() re-probes the node and restores availability")

    # === 16. ChainRegistry drives the deployed contract end to end ========
    from chain.registry import ChainRegistry
    from chain.keys import FederationKey
    b = deploy()
    reg = ChainRegistry(HashChain(), b, FederationKey(key=b"\x55" * 32),
                        writer=W)
    for lbl in ("c1", "c2"):
        reg.append("ENROLL", {"device": lbl, "tier": "HARDWARE",
                              "ek_hash": hashlib.sha256(lbl.encode()).hexdigest(),
                              "status": "ACTIVE"})
    for rid in range(3):
        if rid == 1:
            reg.append("EVENT", {"round": rid, "device": "c2",
                                 "severity": "MINOR", "stage": 1,
                                 "reason": "t", "status": "ACTIVE"})
        reg.append("ROUND", {"round": rid, "participants": ["c1", "c2"],
                             "aggregated": True})
    assert not reg.rejections, [str(x) for x in reg.rejections]
    assert not reg.failures, [f.error for f in reg.failures]
    assert reg.anchored_rounds == {0, 1, 2}
    assert verify_backend(b).ok
    # the NEUTRAL inference reached the contract
    assert b.get_device("c1").clean_run == 3, b.get_device("c1").clean_run
    print("\u2713 END-TO-END: ChainRegistry mirrors onto the DEPLOYED contract "
          "(3 rounds anchored, NEUTRAL inference applied, 0 rejections)")

    print("\u2713 all evm backend self-tests passed")


if __name__ == "__main__":
    _self_test()
