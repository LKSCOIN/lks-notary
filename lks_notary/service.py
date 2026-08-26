"""Background worker: batches pending leaves, then follows them to finality.

One process, two timers. Kept separate from the API process so a slow node or a
stuck OpenTimestamps calendar can never make the HTTP service unresponsive.
"""
from __future__ import annotations

import logging
import signal
import time

from . import repository
from .batcher import publish_batch
from .config import settings
from .db import session_scope
from .rpc import LksRpc
from .watcher import poll_once

log = logging.getLogger("lks_notary.worker")

WATCH_INTERVAL = 60


class Worker:
    def __init__(self) -> None:
        self.rpc = LksRpc()
        self.running = True
        self._last_batch = 0.0
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)

    def _stop(self, *_: object) -> None:
        log.info("shutdown requested; finishing the current cycle")
        self.running = False

    def batch_cycle(self) -> None:
        with session_scope() as session:
            leaves = repository.pending_leaves(session, settings.batch_max_leaves)
            if not leaves:
                return
            result = publish_batch(leaves, self.rpc)
            if result is not None:
                repository.record_batch(session, result.merkle_root, result.txid, result.ordered_ids)
                log.info("batch published: %d leaves, txid %s", len(leaves), result.txid)

    def watch_cycle(self) -> None:
        with session_scope() as session:
            updated = poll_once(session, self.rpc)
            if updated:
                log.info("refreshed %d open batches", updated)

    def housekeeping(self) -> None:
        """Drop anonymous quota counters that can no longer be reached."""
        with session_scope() as session:
            removed = repository.purge_anon_quota(session)
            if removed:
                log.info("purged %d expired quota counters", removed)

    def run(self) -> None:
        log.info("worker started: batch every %ds, watch every %ds",
                 settings.batch_interval_seconds, WATCH_INTERVAL)
        while self.running:
            now = time.monotonic()
            try:
                if now - self._last_batch >= settings.batch_interval_seconds:
                    self.batch_cycle()
                    self.housekeeping()
                    self._last_batch = now
                self.watch_cycle()
            except Exception:
                # A failed cycle must never stop the worker: the next one picks
                # up exactly the same pending rows.
                log.exception("cycle failed; retrying at the next tick")
            for _ in range(WATCH_INTERVAL):
                if not self.running:
                    break
                time.sleep(1)
        log.info("worker stopped")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    # httpx logs every single RPC call at INFO, which drowns the two lines that
    # actually matter (batch published, batch confirmed) in the journal.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    Worker().run()


if __name__ == "__main__":
    main()
