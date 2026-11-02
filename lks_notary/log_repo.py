"""Data access for LKS Log.

A seal is written together with the notarisation that proves it, in one
transaction, for the same reason as a Trace event: a stream can never show a seal
with no proof queued.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import log, repository
from .models import ApiKey, Batch, LogSeal, LogStream, Notarization


class SealConflict(Exception):
    """The seal does not continue the stream. Carries what would have."""

    def __init__(self, detail: str, stream: LogStream) -> None:
        super().__init__(detail)
        self.detail = detail
        self.expected_sequence = stream.last_sequence + 1
        self.expected_previous = stream.last_seal_hash.hex() if stream.last_seal_hash else None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def create_stream(
    session: Session, name: str, interval_seconds: int, requester: ApiKey
) -> LogStream:
    now = _now()
    stream = LogStream(
        id=str(uuid.uuid4()), name=name, requester_id=requester.id,
        interval_seconds=interval_seconds, last_sequence=0, created_at=now, updated_at=now,
    )
    session.add(stream)
    repository.append_audit(session, requester.id, "log.stream.create", {"stream_id": stream.id})
    return stream


def get_stream(session: Session, stream_id: str, lock: bool = False) -> LogStream | None:
    query = select(LogStream).where(LogStream.id == stream_id)
    if lock:
        query = query.with_for_update()
    return session.execute(query).scalar_one_or_none()


def record_seal(
    session: Session,
    stream: LogStream,
    requester: ApiKey,
    *,
    sequence: int,
    entry_count: int,
    window_start: datetime,
    window_end: datetime,
    entries_root: str | None = None,
    previous_seal: str | None = None,
) -> tuple[LogSeal, Notarization, bool]:
    """Append one seal. Returns (seal, proof, created).

    ``stream`` must be locked by the caller: this check and the insert have to be
    one step, or two agents racing on one stream could both pass it.

    Resending an accepted seal returns the original, so an agent that lost the
    response can simply retry. Anything else that reuses a sequence number is
    refused: rewriting history through this endpoint is precisely what the service
    exists to prevent.
    """
    record = log.canonical_seal(
        stream_id=stream.id, sequence=sequence, interval_seconds=stream.interval_seconds,
        entry_count=entry_count, window_start=window_start, window_end=window_end,
        entries_root=entries_root, previous_seal=previous_seal,
    )
    digest = log.seal_hash(record)

    if sequence <= stream.last_sequence:
        existing = session.execute(
            select(LogSeal).where(LogSeal.stream_id == stream.id, LogSeal.sequence == sequence)
        ).scalar_one()
        if existing.seal_hash != digest:
            raise SealConflict(f"seal {sequence} already exists with different content", stream)
        return existing, session.get(Notarization, existing.notarization_id), False

    if sequence != stream.last_sequence + 1:
        raise SealConflict(f"expected seal {stream.last_sequence + 1}, got {sequence}", stream)
    expected = stream.last_seal_hash.hex() if stream.last_seal_hash else None
    if previous_seal != expected:
        raise SealConflict("previous_seal does not match the last seal of the stream", stream)

    notarization, _ = repository.create_notarization(
        session,
        digest.hex(),
        requester,
        {"kind": "log_seal", "stream": stream.id, "sequence": sequence},
        f"log:{digest.hex()}",
    )
    seal = LogSeal(
        id=str(uuid.uuid4()), stream_id=stream.id, sequence=sequence,
        entries_root=bytes.fromhex(entries_root) if entries_root else None,
        entry_count=entry_count, window_start=window_start, window_end=window_end,
        canonical_record=record.decode(), seal_hash=digest,
        previous_hash=bytes.fromhex(previous_seal) if previous_seal else None,
        notarization_id=notarization.id, recorded_at=_now(),
    )
    session.add(seal)
    session.flush()
    stream.last_sequence = sequence
    stream.last_seal_hash = digest
    stream.updated_at = _now()
    return seal, notarization, True


def list_seals(
    session: Session, stream_id: str, after: int = 0, limit: int = 200, newest: bool = False
) -> list[tuple[LogSeal, Notarization, Batch | None]]:
    """A page of seals with their proofs, always returned oldest first.

    ``newest`` takes the last ``limit`` instead of the ones following ``after``.
    Paged because a stream sealing every five minutes passes 100,000 seals in a
    year, and walking them all belongs to a verifier, not to a page load.
    """
    query = (
        select(LogSeal, Notarization, Batch)
        .join(Notarization, LogSeal.notarization_id == Notarization.id)
        .outerjoin(Batch, Notarization.batch_id == Batch.id)
        .where(LogSeal.stream_id == stream_id)
    )
    if newest:
        query = query.order_by(LogSeal.sequence.desc())
    else:
        query = query.where(LogSeal.sequence > after).order_by(LogSeal.sequence)
    rows = [tuple(row) for row in session.execute(query.limit(min(limit, 1000))).all()]
    return list(reversed(rows)) if newest else rows


def seal_to_json(
    seal: LogSeal, proof: Notarization, batch: Batch | None, base_url: str
) -> dict[str, Any]:
    return {
        "sequence": seal.sequence,
        "entry_count": seal.entry_count,
        "entries_root": seal.entries_root.hex() if seal.entries_root else None,
        "window_start": log.format_time(repository.as_utc(seal.window_start)),
        "window_end": log.format_time(repository.as_utc(seal.window_end)),
        "canonical_record": seal.canonical_record,
        "seal_hash": seal.seal_hash.hex(),
        "previous_seal": seal.previous_hash.hex() if seal.previous_hash else None,
        "received_at": log.format_time(repository.as_utc(proof.received_at)),
        "proof": {
            "certificate_id": proof.id,
            "status": proof.status,
            "anchored": batch is not None and batch.ots_upgraded_at is not None,
            "verify_url": f"{base_url}/v/{proof.id}",
        },
    }
