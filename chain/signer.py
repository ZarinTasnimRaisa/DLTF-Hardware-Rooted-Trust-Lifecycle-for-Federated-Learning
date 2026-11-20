"""
chain/signer.py

Local transaction signing for chain/evm.py.

WHY THIS MODULE EXISTS
-----------------------------------------------------------------------------
chain/evm.py was written against Anvil and used `fn.transact({"from": addr})`,
which is `eth_sendTransaction`: the NODE holds the key and signs. Anvil and
eth-tester do that. No public RPC does -- Alchemy, Infura, the Polygon Amoy
and Sepolia public endpoints all omit the method entirely. So every write
failed, and failed misleadingly: evm.py could not find revert data in
"the method eth_sendTransaction does not exist", classified it as transport,
retried three times, and reported `node unreachable` about a node that was
answering every read perfectly.

This module signs locally and submits raw. It also owns the three things the
node used to own and nobody replaced:

  NONCE      A node assigns nonces. Signing locally means we assign them, and
             `get_transaction_count(addr, "pending")` is NOT sufficient on
             its own: load-balanced public RPCs answer from different nodes
             with different mempool views, so two consecutive calls can
             return the same number. We keep a local monotonic counter and
             resync it only when the chain tells us it is wrong.

  FEES       No public chain accepts a transaction with no fee fields. Polygon
             enforces a 25 gwei minimum priority fee that web3's default
             estimation underprices, producing a transaction that is accepted
             into the mempool and never mined -- which is the worst outcome,
             because it looks like success followed by an outage.

  RESEND     THE LOAD-BEARING RULE. A transaction that has been broadcast must
             never be broadcast again as a NEW transaction. The old _send()
             retried on any non-revert exception, and the commonest such
             exception on a public chain is TimeExhausted -- the transaction
             was broadcast, it just is not mined yet. Retrying rebuilt it with
             a fresh nonce, so both could land, and `classify` would apply the
             reputation rule twice. Nothing would raise; the on-chain packed
             word would silently diverge from the local engine and the paper's
             parity result ("every deviation is exactly zero") would be false.

             So: broadcast is attempted at most once per nonce. If it times
             out we either keep waiting or REPLACE it at the same nonce with a
             higher fee. Replacement at the same nonce is safe by construction
             -- the chain can include one of them, never both.

  python3 -m chain.signer          (self-test, eth-tester, no node)
"""
import time
from typing import Optional

# Minimum priority fee by chain id. Polygon rejects anything under 25 gwei at
# the node level; the others are sane defaults rather than protocol rules.
GWEI = 10 ** 9
PRIORITY_FLOOR = {
    137:   30 * GWEI,      # Polygon PoS mainnet
    80002: 30 * GWEI,      # Polygon Amoy testnet
    80001: 30 * GWEI,      # Polygon Mumbai (retired, kept for old configs)
}
DEFAULT_PRIORITY = 2 * GWEI

# How much headroom over the estimate. Estimation runs against the CURRENT
# state; by the time the transaction is included the state has moved, and a
# classify that crosses a status boundary can touch a different branch.
GAS_MULTIPLIER = 1.30


class PendingTimeout(Exception):
    """The transaction was broadcast and is not mined yet.

    Carries the hash, which is the entire point: the caller must poll THIS
    hash or replace it at the same nonce. It must not build a new one.
    """

    def __init__(self, tx_hash, nonce, waited):
        self.tx_hash = tx_hash
        self.nonce = nonce
        self.waited = waited
        super().__init__(
            f"tx {tx_hash.hex() if hasattr(tx_hash, 'hex') else tx_hash} "
            f"(nonce {nonce}) not mined after {waited:.0f}s -- it is "
            f"broadcast; poll or replace it, do NOT resend")


class BroadcastError(Exception):
    """The transaction was NOT accepted by the node. Nothing is on chain, so
    rebuilding it is safe."""


# Substrings that prove the node rejected the transaction outright, meaning
# nothing was broadcast and our nonce counter is wrong.
_NONCE_ERRORS = ("nonce too low", "nonce too high", "invalid nonce",
                 "nonce is too low", "oldnonce",
                 "replacement transaction underpriced")

# Substrings meaning "this exact transaction is ALREADY in the mempool".
# That is success, not failure: the hash we computed locally is live. Treating
# it as an error is how a correct rebroadcast turns into a spurious retry.
_ALREADY_SENT = ("already known", "known transaction", "already imported",
                 "transaction already in the pool", "duplicate transaction")


class TxSigner:
    """Signs and broadcasts from one private key. One per account.

    Not thread-safe by design: the nonce counter is the shared state, and
    serialising writes is what keeps it correct. chain/async_writer.py owns
    exactly one writer thread for this reason.
    """

    def __init__(self, w3, private_key, chain_id=None, priority_floor=None,
                 gas_multiplier=GAS_MULTIPLIER):
        from eth_account import Account

        if isinstance(private_key, str) and not private_key.startswith("0x"):
            private_key = "0x" + private_key
        self.account = Account.from_key(private_key)
        self.address = self.account.address
        self.w3 = w3
        self.chain_id = chain_id if chain_id is not None else w3.eth.chain_id
        self.gas_multiplier = gas_multiplier
        self.priority_floor = (
            priority_floor if priority_floor is not None
            else PRIORITY_FLOOR.get(self.chain_id, DEFAULT_PRIORITY))
        self._nonce = None                 # lazily synced
        self._inflight = {}                # nonce -> tx_hash
        self.sent = 0
        self.replaced = 0
        self.resyncs = 0

    # ---- nonce ---------------------------------------------------------------

    def sync_nonce(self):
        """Re-read the nonce from the chain. Called on first use and whenever
        the chain says our counter is wrong -- never speculatively, because a
        pending-tag read from a load-balanced RPC can move backwards."""
        n = self.w3.eth.get_transaction_count(self.address, "pending")
        if self._nonce is None or n > self._nonce:
            self._nonce = n
        else:
            # The RPC's mempool view is behind ours. Trust the local counter:
            # going backwards would reuse a nonce we already broadcast.
            self.resyncs += 1
        return self._nonce

    @property
    def nonce(self):
        if self._nonce is None:
            self.sync_nonce()
        return self._nonce

    # ---- fees ----------------------------------------------------------------

    def fee_fields(self, bump=1.0):
        """EIP-1559 fields, falling back to legacy gasPrice on chains with no
        base fee (some consortium Besu configurations, older devnets)."""
        try:
            base = self.w3.eth.get_block("latest").get("baseFeePerGas")
        except Exception:
            base = None

        if base is None:
            price = int(self.w3.eth.gas_price * max(bump, 1.0))
            return {"gasPrice": max(price, 1)}

        try:
            tip = int(self.w3.eth.max_priority_fee)
        except Exception:
            tip = DEFAULT_PRIORITY
        tip = int(max(tip, self.priority_floor) * bump)
        # 2x base gives room for a few blocks of base-fee growth; the sender
        # only ever pays base + tip, so headroom is free.
        max_fee = int(base * 2) + tip
        return {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip}

    # ---- build / send --------------------------------------------------------

    def build(self, fn_call, gas=None, value=0, nonce=None, bump=1.0):
        """Build a signed-ready transaction dict from a web3 contract call."""
        params = {
            "from": self.address,
            "nonce": self.nonce if nonce is None else nonce,
            "chainId": self.chain_id,
            "value": value,
        }
        params.update(self.fee_fields(bump=bump))
        if gas is not None:
            params["gas"] = int(gas)
        else:
            # Estimate explicitly rather than letting build_transaction do it,
            # so an estimation revert surfaces here with its data intact.
            est = fn_call.estimate_gas({"from": self.address, "value": value})
            params["gas"] = int(est * self.gas_multiplier)
        return fn_call.build_transaction(params)

    def sign(self, tx):
        """Sign and return (raw_bytes, tx_hash).

        The hash is derived from the signed payload BEFORE the transaction is
        broadcast, which is what makes a lost RPC response recoverable: if the
        connection drops mid-`eth_sendRawTransaction` we still know the hash,
        so we can look it up rather than guessing whether it landed. Guessing
        is how a resend bug starts.
        """
        from eth_utils import keccak
        signed = self.account.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None)
        if raw is None:                                  # web3 < 7
            raw = signed.rawTransaction
        return bytes(raw), keccak(bytes(raw))

    def broadcast(self, raw, tx_hash, attempts=3, backoff=0.5):
        """Push the SAME signed bytes until the node has them.

        Rebroadcasting identical bytes is idempotent: the hash does not
        change, so the chain can include it at most once however many times we
        send it. That is why this may retry where `_send` may not.
        """
        last = None
        for attempt in range(attempts):
            try:
                self.w3.eth.send_raw_transaction(raw)
                return tx_hash
            except Exception as exc:
                msg = str(exc).lower()
                if any(s in msg for s in _ALREADY_SENT):
                    return tx_hash                      # it is in the pool
                if any(s in msg for s in _NONCE_ERRORS):
                    self._nonce = None
                    self.sync_nonce()
                    raise BroadcastError(
                        f"nonce rejected, resynced to {self._nonce}: "
                        f"{exc}") from exc
                # Ambiguous (timeout, connection reset): the node may have it.
                # Ask before deciding.
                if self._known_to_chain(tx_hash):
                    return tx_hash
                last = exc
                if attempt < attempts - 1:
                    time.sleep(backoff * (attempt + 1))
        raise BroadcastError(f"could not broadcast after {attempts} "
                             f"attempts: {last}")

    def _known_to_chain(self, tx_hash):
        """Does the node know this hash, mined or pending?"""
        for getter in (self.w3.eth.get_transaction_receipt,
                       self.w3.eth.get_transaction):
            try:
                if getter(tx_hash) is not None:
                    return True
            except Exception:
                continue
        return False

    def send_tx(self, tx):
        """Sign, broadcast, and return the hash. Advances the nonce only on
        an accepted broadcast."""
        raw, tx_hash = self.sign(tx)
        h = self.broadcast(raw, tx_hash)
        self._nonce = max(self._nonce or 0, tx["nonce"] + 1)
        self._inflight[tx["nonce"]] = h
        self.sent += 1
        return h

    def send(self, fn_call, gas=None, value=0):
        """build + send_tx. Returns (tx_hash, tx)."""
        tx = self.build(fn_call, gas=gas, value=value)
        return self.send_tx(tx), tx

    # ---- polling -------------------------------------------------------------

    def wait(self, tx_hash, timeout=180, poll=2.0, nonce=None):
        """Poll ONE hash. Raises PendingTimeout carrying the hash -- it does
        not swallow it, and it never rebuilds the transaction."""
        deadline = time.time() + timeout
        last_err = None
        while time.time() < deadline:
            try:
                rc = self.w3.eth.get_transaction_receipt(tx_hash)
                if rc is not None:
                    self._inflight.pop(rc.get("nonce", nonce), None)
                    return rc
            except Exception as exc:
                # "not found" is the normal answer for a pending transaction
                # on most providers, so it is not an error condition.
                last_err = exc
            time.sleep(poll)
        raise PendingTimeout(tx_hash, nonce, timeout) from last_err

    def replace(self, fn_call, nonce, bump=1.25, gas=None):
        """Rebuild at the SAME nonce with higher fees.

        This is the only safe response to a stuck transaction: the chain
        accepts at most one transaction per nonce, so the original and the
        replacement cannot both be included. Rebuilding at a NEW nonce is the
        bug this module exists to prevent.
        """
        tx = self.build(fn_call, gas=gas, nonce=nonce, bump=bump)
        h = self.send_tx(tx)
        self._nonce = max(self._nonce, nonce + 1)
        self.replaced += 1
        return h

    def balance(self):
        return self.w3.eth.get_balance(self.address)

    def __repr__(self):
        return (f"<TxSigner {self.address[:10]}... chain {self.chain_id} "
                f"nonce {self._nonce} sent {self.sent}>")


# ---- self-test ---------------------------------------------------------------

def _self_test():
    """Runs against eth-tester with a funded external key: the same code path
    a public testnet takes, minus the network."""
    from eth_account import Account
    from eth_tester import EthereumTester, PyEVMBackend
    from web3 import Web3
    from web3.providers.eth_tester import EthereumTesterProvider

    print("chain/signer.py self-test (eth-tester, no node needed)")

    tester = EthereumTester(backend=PyEVMBackend())
    w3 = Web3(EthereumTesterProvider(tester))
    faucet = w3.eth.accounts[0]

    key = "0x" + "11" * 32
    acct = Account.from_key(key)
    w3.eth.send_transaction({"from": faucet, "to": acct.address,
                             "value": w3.to_wei(10, "ether")})

    signer = TxSigner(w3, key)
    assert signer.address == acct.address
    print(f"\u2713 signer holds {signer.address[:12]}..., balance "
          f"{w3.from_wei(signer.balance(), 'ether')} ETH, chain "
          f"{signer.chain_id}")

    # === 1. A plain value transfer signs and lands ========================
    n0 = signer.nonce
    tx = {"from": signer.address, "to": faucet, "value": 1,
          "nonce": n0, "chainId": signer.chain_id, "gas": 21000}
    tx.update(signer.fee_fields())
    h = signer.send_tx(tx)
    rc = signer.wait(h, timeout=10, poll=0.01)
    assert rc["status"] == 1
    assert signer.nonce == n0 + 1, (signer.nonce, n0)
    print(f"\u2713 raw signed transaction accepted (no eth_sendTransaction), "
          f"nonce advanced {n0} -> {signer.nonce}")

    # === 2. Nonce is LOCAL and monotonic across rapid sends ===============
    # The bug this prevents: two sends in the same block both reading the same
    # transaction count and colliding.
    hashes = []
    for _ in range(5):
        tx = {"from": signer.address, "to": faucet, "value": 1,
              "nonce": signer.nonce, "chainId": signer.chain_id, "gas": 21000}
        tx.update(signer.fee_fields())
        hashes.append(signer.send_tx(tx))
    assert len(set(hashes)) == 5
    for h in hashes:
        assert signer.wait(h, timeout=10, poll=0.01)["status"] == 1
    assert signer.nonce == n0 + 6
    print(f"\u2713 five back-to-back sends get five distinct nonces "
          f"({n0 + 1}..{n0 + 5}); none collided")

    # === 3. A rejected broadcast does NOT advance the nonce ===============
    before = signer.nonce
    bad = {"from": signer.address, "to": faucet, "value": 1,
           "nonce": before - 3,                       # already used
           "chainId": signer.chain_id, "gas": 21000}
    bad.update(signer.fee_fields())
    try:
        signer.send_tx(bad)
        raise AssertionError("a reused nonce must be refused")
    except BroadcastError as e:
        assert "nonce" in str(e).lower(), str(e)
    assert signer.nonce >= before, (signer.nonce, before)
    print(f"\u2713 reused nonce -> BroadcastError (nothing broadcast) and the "
          f"counter resynced to {signer.nonce} rather than corrupting")

    # === 4. PendingTimeout CARRIES the hash ===============================
    # The whole resend bug turns on this: a timeout must hand back the hash so
    # the caller polls it again instead of building a second transaction.
    fake = bytes.fromhex("ab" * 32)
    try:
        signer.wait(fake, timeout=0.05, poll=0.01)
        raise AssertionError("unmined hash must time out")
    except PendingTimeout as e:
        assert e.tx_hash == fake
        assert "do NOT resend" in str(e)
    print("\u2713 PendingTimeout carries the tx hash and says not to resend")

    # === 5. Fee fields are present and respect the Polygon floor ==========
    f = signer.fee_fields()
    assert ("maxFeePerGas" in f) or ("gasPrice" in f), f
    amoy = TxSigner(w3, key, chain_id=80002)
    fa = amoy.fee_fields()
    if "maxPriorityFeePerGas" in fa:
        assert fa["maxPriorityFeePerGas"] >= 25 * GWEI, fa
        assert fa["maxFeePerGas"] > fa["maxPriorityFeePerGas"]
        print(f"\u2713 chain 80002 (Amoy) priority fee floored at "
              f"{fa['maxPriorityFeePerGas'] / GWEI:.0f} gwei, above the "
              f"25 gwei the node enforces")
    else:
        print("\u2713 legacy gasPrice path used (no baseFeePerGas on this "
              "chain)")

    # === 6. Replacement reuses the nonce ==================================
    # Cannot be double-included by construction.
    class FakeCall:
        def estimate_gas(self, p):
            return 21000

        def build_transaction(self, p):
            out = dict(p)
            out["to"] = faucet
            out["data"] = b""
            return out

    n = signer.nonce
    h1 = signer.replace(FakeCall(), nonce=n, bump=1.0)
    rc = signer.wait(h1, timeout=10, poll=0.01)
    assert rc["status"] == 1
    assert signer.replaced == 1
    print(f"\u2713 replace() rebuilds at the SAME nonce ({n}), so the original "
          f"and the replacement cannot both be included")

    print("\u2713 all signer self-tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
