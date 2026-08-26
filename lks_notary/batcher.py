"""Batcher: turns pending leaves into one on-chain transaction.

Runs on a timer. Every cycle it takes the pending notarizations in a
deterministic order, builds the Merkle tree, publishes the root in a 38-byte
OP_RETURN and records the txid.

Ordering is (received_at, leaf_hash) and is part of the public specification:
an independent verifier given the same set of records must rebuild exactly the
same tree.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .merkle import root
from .payload import batch_root

log = logging.getLogger(__name__)


class Publisher(Protocol):
    """Anything that can put 38 bytes on the chain. Keeping the batcher behind
    this protocol means its tests need no node and no HTTP client."""

    def send_op_return(self, payload_hex: str, fee_rate: float | None = None) -> str: ...


@dataclass(frozen=True)
class PendingLeaf:
    notarization_id: str
    leaf_hash: bytes
    received_at: datetime


def order_leaves(leaves: list[PendingLeaf]) -> list[PendingLeaf]:
    return sorted(leaves, key=lambda leaf: (leaf.received_at, leaf.leaf_hash))


@dataclass(frozen=True)
class BatchResult:
    merkle_root: bytes
    txid: str
    ordered_ids: list[str]


def publish_batch(leaves: list[PendingLeaf], rpc: Publisher) -> BatchResult | None:
    """Build and publish one batch. Returns None when there is nothing pending.

    The transaction is sent *after* the root is computed and before the rows are
    marked as batched: if the process dies in between, the batch is republished
    with the same leaves and therefore the same root, so a duplicate costs one
    fee and proves the same thing.
    """
    if not leaves:
        return None
    ordered = order_leaves(leaves)
    merkle_root = root([leaf.leaf_hash for leaf in ordered])
    txid = rpc.send_op_return(batch_root(merkle_root).hex())
    log.info("published batch of %d leaves, root=%s, txid=%s",
             len(ordered), merkle_root.hex(), txid)
    return BatchResult(merkle_root, txid, [leaf.notarization_id for leaf in ordered])
