"""Leaf construction: the record a third party must be able to rebuild."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from .jcs import canonicalize

LEAF_VERSION = 1


def as_utc(value: datetime) -> datetime:
    """Re-attach UTC to a datetime read back from the database.

    MariaDB DATETIME columns carry no timezone, so SQLAlchemy returns naive
    values even though everything written is UTC. The leaf hash depends on the
    exact timestamp string, so a naive value read back would either raise or --
    worse -- silently produce a different leaf than the one published on chain.

    Lives here, next to the leaf construction it protects, so it stays usable
    without importing the database layer.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def canonical_record(
    document_hash: str,
    received_at: datetime,
    requester_id: str,
    metadata: dict[str, Any] | None = None,
) -> bytes:
    """Build the canonical JSON record for one notarization.

    ``received_at`` is normalised to UTC and serialised with second precision:
    the certificate must state exactly the instant that was hashed, and a
    verifier reading the certificate has to reproduce the same string.
    """
    if received_at.tzinfo is None:
        raise ValueError("received_at must be timezone-aware")
    record: dict[str, Any] = {
        "v": LEAF_VERSION,
        "hash": document_hash.lower(),
        "algo": "sha256",
        "received_at": received_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "requester": requester_id,
    }
    if metadata:
        record["metadata"] = metadata
    return canonicalize(record)


def leaf_hash(
    document_hash: str,
    received_at: datetime,
    requester_id: str,
    metadata: dict[str, Any] | None = None,
) -> bytes:
    return hashlib.sha256(
        canonical_record(document_hash, received_at, requester_id, metadata)
    ).digest()
