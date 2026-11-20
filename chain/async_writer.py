"""
chain/async_writer.py

Moves ledger writes off the training thread.

WHY THIS EXISTS -- AND WHY THE PAPER'S CLAIM NEEDED IT
-----------------------------------------------------------------------------
Section 4 argues the server-ledger boundary is "optional and crossed by
semantic events after the fact, never before a round may proceed", and that
an unreachable ledger "degrades what can later be verified but not training
itself".

Structurally that was already true: ChainRegistry._guard() swallows both
rejections and transport failures, so nothing halts. In WALL-CLOCK terms it
was false, and measurably so. Writes were synchronous and inline. A round
with n clients issues n classify transactions plus one roundSummary, one
after another, each blocking until its receipt arrives:

    healthy Sepolia, 12 s blocks, 6 clients -> ~90 s of blocking per round
    stalled chain (QBFT below quorum)       -> the node ACCEPTS the
                                               transaction into its pool and
                                               never mines it, so each write
                                               blocks the full poll timeout
                                               before failing

The stalled case is the one that matters, because it is exactly the condition
the liveness experiment creates by killing two of four validators. Under the
original settings (poll_timeout 120 s, 3 retries) a single write took about
six minutes to fail, and a 6-client round about forty minutes. Training does
continue -- but a round that takes forty minutes because the ledger is down
is not a ledger that is off the critical path.

So there are two honest options, and this module is the second:

  1. Measure it as-is and report that the DESIGN keeps the ledger off the
     critical path while the IMPLEMENTATION does not.
  2. Make the implementation match the design, and measure that.

Do both. exp_liveness.py runs the experiment in both configurations, because
the comparison is the result: the same architecture, one line of
configuration apart, with and without the ledger on the critical path.

WHAT THIS DOES NOT CHANGE
-----------------------------------------------------------------------------
Ordering. The contract enforces StaleRound and DuplicateRound, so writes must
reach it in emission order. One worker thread, one queue, strictly FIFO. Going
wider would trade a correctness property for throughput we do not need.

Failure visibility. Results are drained back into the same ChainRegistry
bookkeeping, so a round whose write failed is still marked UNANCHORED and
still appears in .failures. An asynchronous write that failed silently would
be the ANCHORED-but-absent bug that chain/evm.py's docstring is about, one
level up.
"""
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class _Job:
    seq: int
    round_id: Optional[int]
    event_type: str
    fn: Callable
    enqueued: float = field(default_factory=time.time)


@dataclass
class WriteResult:
    seq: int
    round_id: Optional[int]
    event_type: str
    ok: bool
    error: Optional[BaseException] = None
    queued_ms: float = 0.0
    exec_ms: float = 0.0
    # Wall-clock time the write was SUBMITTED, not executed. The two differ by
    # the backlog, and that difference is the async writer's real cost: a
    # write submitted while the chain was healthy can be executed after it has
    # failed, so an outage destroys more history than it overlaps.
    enqueued_at: float = 0.0


class AsyncWriter:
    """One worker thread draining a FIFO of ledger writes.

    Usage mirrors a synchronous call closely enough that ChainRegistry can
    switch on a flag:

        w = AsyncWriter(max_queue=4096)
        w.start()
        w.submit(seq, rid, "EVENT", lambda: backend.classify(...))
        ...
        w.drain(timeout=60)      # at the end of a run, before reporting
        w.stop()
    """

    def __init__(self, max_queue=4096, on_result=None, name="dltf-chain"):
        self.q: "queue.Queue[Optional[_Job]]" = queue.Queue(maxsize=max_queue)
        self.on_result = on_result
        self.results = []
        self._thread = None
        self._stop = threading.Event()
        self._name = name
        self.submitted = 0
        self.completed = 0
        self.failed = 0
        self.dropped = 0
        self.max_depth = 0
        self._lock = threading.Lock()

    # ---- lifecycle -----------------------------------------------------------

    def start(self):
        if self._thread is not None:
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=self._name,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout=5.0):
        if self._thread is None:
            return
        self._stop.set()
        try:
            self.q.put_nowait(None)                 # wake the worker
        except queue.Full:
            pass
        self._thread.join(timeout=timeout)
        self._thread = None

    # ---- submission ----------------------------------------------------------

    def submit(self, seq, round_id, event_type, fn) -> bool:
        """Enqueue a write. Returns False if the queue is full.

        A full queue is a real condition, not a theoretical one: if the chain
        stalls for long enough the backlog grows without bound. Bounding it
        and reporting the drop is the honest behaviour -- an unbounded queue
        would trade a visible failure for an invisible memory leak, and the
        dropped rounds would still be unanchored either way.
        """
        job = _Job(seq=seq, round_id=round_id, event_type=event_type, fn=fn)
        try:
            self.q.put_nowait(job)
        except queue.Full:
            self.dropped += 1
            if self.on_result:
                self.on_result(WriteResult(
                    seq, round_id, event_type, ok=False,
                    error=RuntimeError(
                        f"chain write queue full ({self.q.maxsize}); write "
                        f"dropped and round left unanchored")))
            return False
        with self._lock:
            self.submitted += 1
            self.max_depth = max(self.max_depth, self.q.qsize())
        return True

    def drain(self, timeout=None) -> bool:
        """Block until the backlog clears. Returns False on timeout.

        Called once at the end of a run, which is the ONLY place blocking is
        acceptable: the training is finished, and what is being waited on is
        the auditability the ledger provides.
        """
        deadline = None if timeout is None else time.time() + timeout
        while not self.q.empty():
            if deadline is not None and time.time() > deadline:
                return False
            time.sleep(0.05)
        # The queue can be empty while the worker is still inside a call.
        while self._busy:
            if deadline is not None and time.time() > deadline:
                return False
            time.sleep(0.05)
        return True

    _busy = False

    # ---- worker --------------------------------------------------------------

    def _run(self):
        while not self._stop.is_set():
            try:
                job = self.q.get(timeout=0.1)
            except queue.Empty:
                continue
            if job is None:
                self.q.task_done()
                break
            self._busy = True
            queued_ms = (time.time() - job.enqueued) * 1000.0
            t0 = time.perf_counter()
            try:
                job.fn()
                res = WriteResult(job.seq, job.round_id, job.event_type,
                                  ok=True, queued_ms=queued_ms,
                                  exec_ms=(time.perf_counter() - t0) * 1000.0,
                                  enqueued_at=job.enqueued)
                self.completed += 1
            except BaseException as exc:          # noqa: BLE001 - reported, not swallowed
                res = WriteResult(job.seq, job.round_id, job.event_type,
                                  ok=False, error=exc, queued_ms=queued_ms,
                                  exec_ms=(time.perf_counter() - t0) * 1000.0,
                                  enqueued_at=job.enqueued)
                self.failed += 1
            finally:
                self._busy = False
                self.q.task_done()
            self.results.append(res)
            if self.on_result:
                try:
                    self.on_result(res)
                except Exception:
                    pass                          # reporting must not kill the worker

    # ---- reporting -----------------------------------------------------------

    def report(self) -> dict:
        return {"submitted": self.submitted, "completed": self.completed,
                "failed": self.failed, "dropped": self.dropped,
                "pending": self.q.qsize(), "max_queue_depth": self.max_depth}

    def __repr__(self):
        return f"<AsyncWriter {self.report()}>"


# ---- self-test ---------------------------------------------------------------

def _self_test():
    print("chain/async_writer.py self-test")

    # === 1. FIFO order is preserved =======================================
    # Non-negotiable: the contract reverts StaleRound and DuplicateRound, so
    # out-of-order arrival would turn correct writes into rejections.
    seen = []
    w = AsyncWriter().start()
    for i in range(200):
        w.submit(i, i, "EVENT", lambda i=i: seen.append(i))
    assert w.drain(timeout=10)
    w.stop()
    assert seen == list(range(200)), seen[:10]
    print(f"\u2713 {len(seen)} writes executed in strict submission order "
          f"(StaleRound/DuplicateRound need this)")

    # === 2. A SLOW chain does not block the caller ========================
    # The measurement that matters for the liveness claim.
    def slow():
        time.sleep(0.20)

    w = AsyncWriter().start()
    t0 = time.perf_counter()
    for i in range(10):
        w.submit(i, i, "EVENT", slow)
    caller_ms = (time.perf_counter() - t0) * 1000.0
    assert caller_ms < 50, caller_ms
    assert w.drain(timeout=30)
    total_ms = (time.perf_counter() - t0) * 1000.0
    w.stop()
    print(f"\u2713 10 writes of 200 ms each: caller blocked {caller_ms:.1f} ms, "
          f"the work still took {total_ms:.0f} ms in the background "
          f"({total_ms / max(caller_ms, 0.001):.0f}x off the critical path)")

    # === 3. Failures are REPORTED, never swallowed ========================
    # An async write that failed quietly would be exactly the
    # ANCHORED-but-absent bug chain/evm.py exists to prevent.
    got = []
    w = AsyncWriter(on_result=got.append).start()

    def boom():
        raise RuntimeError("node down")

    w.submit(1, 1, "ROUND", boom)
    w.submit(2, 2, "ROUND", lambda: None)
    assert w.drain(timeout=10)
    w.stop()
    assert len(got) == 2
    assert got[0].ok is False and isinstance(got[0].error, RuntimeError)
    assert got[1].ok is True
    assert w.failed == 1 and w.completed == 1
    print("\u2713 a failing write surfaces as WriteResult(ok=False) with the "
          "exception attached; the worker survives it")

    # === 4. The queue is BOUNDED and a drop is visible ====================
    dropped = []
    w = AsyncWriter(max_queue=4, on_result=lambda r: dropped.append(r)
                    if not r.ok else None)
    # deliberately not started: nothing drains it
    accepted = sum(w.submit(i, i, "EVENT", lambda: None) for i in range(10))
    assert accepted == 4, accepted
    assert w.dropped == 6, w.dropped
    assert all("queue full" in str(r.error) for r in dropped)
    print(f"\u2713 bounded queue: {accepted} accepted, {w.dropped} dropped, and "
          f"every drop reported (unbounded growth would hide the outage)")

    # === 5. drain() waits for a write already in flight ===================
    w = AsyncWriter().start()
    done = []
    w.submit(0, 0, "ROUND", lambda: (time.sleep(0.3), done.append(1)))
    time.sleep(0.05)                         # queue now empty, worker busy
    assert w.q.empty()
    assert w.drain(timeout=5)
    w.stop()
    assert done == [1], "drain returned while a write was still running"
    print("\u2713 drain() waits for the in-flight write, not just the queue")

    print("\u2713 all async_writer self-tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
