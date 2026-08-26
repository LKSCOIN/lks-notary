"""Watcher: follows published batches until they are final.

Three states matter and they are not the same guarantee:

* **confirmed** -- the transaction is in a block. Reorg-reversible.
* **chainlocked** -- an LLMQ quorum signed the block, so it can no longer be
  reorganised. Not available on LKSCOIN today: no quorum has formed since 2021
  and the field stays false until the network revival fork restores them.
* **anchored** -- the batch root is attested in the Bitcoin chain via
  OpenTimestamps. This is the guarantee that does not depend on LKSCOIN's
  hashrate, which is why the MVP does not postpone it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from . import ots, repository
from .rpc import LksRpc

log = logging.getLogger(__name__)


def poll_once(session: Session, rpc: LksRpc) -> int:
    """Refresh every open batch. Returns how many were updated."""
    updated = 0
    for batch in repository.open_batches(session):
        try:
            status = rpc.tx_status(batch.txid.hex())
        except Exception as exc:  # a node hiccup must not kill the loop
            log.warning("batch %s: cannot read tx status: %s", batch.id, exc)
            continue
        repository.update_batch_status(session, batch, status)
        updated += 1

        if batch.block_hash and ots.available():
            _advance_ots(session, batch)
    return updated


def _advance_ots(session: Session, batch) -> None:
    """Stamp a freshly confirmed batch, or try to complete a pending stamp."""
    try:
        if batch.ots_proof is None:
            batch.ots_proof = ots.stamp(batch.merkle_root)
            repository.append_audit(
                session, "watcher", "ots.stamp", {"batch_id": batch.id}
            )
            return
        if batch.ots_upgraded_at is None:
            proof, upgraded = ots.upgrade(batch.merkle_root, batch.ots_proof)
            if upgraded:
                batch.ots_proof = proof
                batch.ots_upgraded_at = datetime.now(timezone.utc)
                session.execute(
                    repository.Notarization.__table__.update()
                    .where(repository.Notarization.batch_id == batch.id)
                    .values(status="anchored")
                )
                repository.append_audit(
                    session, "watcher", "ots.upgrade", {"batch_id": batch.id}
                )
    except Exception as exc:
        log.warning("batch %s: OpenTimestamps step failed: %s", batch.id, exc)
