"""Data access. Everything that touches the database lives here, so the core
crypto stays a pure library and the API stays thin."""
from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .batcher import PendingLeaf
from .jcs import canonicalize
from .leaf import as_utc, leaf_hash
from .config import settings
from .models import AnonQuota, ApiKey, AuditEntry, Batch, KeyRequest, Notarization

__all__ = ["as_utc"]  # re-exported for callers that already import the repository


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# --- audit ---------------------------------------------------------------

def append_audit(session: Session, actor: str | None, action: str, payload: dict[str, Any]) -> None:
    """Append one hash-chained audit entry.

    entry_hash = SHA-256(prev_hash || canonical(entry)). Anyone holding a copy
    of the table can replay the chain and detect a retroactive edit; the
    database triggers stop the easy case, this catches the rest.
    """
    prev = session.execute(
        select(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).limit(1)
    ).scalar_one_or_none()
    ts = _now()
    body = canonicalize(
        {"ts": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "actor": actor or "", "action": action,
         "payload": payload}
    )
    session.add(
        AuditEntry(
            ts=ts,
            actor=actor,
            action=action,
            payload=json.dumps(payload, separators=(",", ":")),
            prev_hash=prev,
            entry_hash=hashlib.sha256((prev or b"") + body).digest(),
        )
    )


def verify_audit_chain(session: Session) -> tuple[bool, int | None]:
    """Replay the audit chain. Returns (ok, first_broken_id)."""
    prev: bytes | None = None
    for entry in session.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars():
        body = canonicalize(
            {"ts": entry.ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "actor": entry.actor or "",
             "action": entry.action, "payload": json.loads(entry.payload or "null")}
        )
        if entry.prev_hash != prev or entry.entry_hash != hashlib.sha256((prev or b"") + body).digest():
            return False, entry.id
        prev = entry.entry_hash
    return True, None


# --- anonymous quota -----------------------------------------------------

def hash_client(ip: str) -> bytes:
    """Salted digest of a client address.

    Storing raw IPs would turn a quota counter into an access log, with the
    retention and disclosure duties that follow. The salt makes the table
    useless to anyone who obtains it, and rotating the salt resets every
    counter -- the cheapest possible purge.
    """
    return hashlib.sha256((settings.anon_ip_salt + "|" + ip).encode()).digest()


def consume_anon_quota(session: Session, ip: str, limit: int) -> bool:
    """Count one anonymous submission. False when the daily limit is reached.

    Counted before the write, so a submission that fails later still consumes
    one slot: the alternative lets a broken client retry without bound.
    """
    today = _now().date()
    digest = hash_client(ip)
    row = session.execute(
        select(AnonQuota).where(AnonQuota.ip_hash == digest, AnonQuota.day == today)
    ).scalar_one_or_none()
    if row is None:
        session.add(AnonQuota(ip_hash=digest, day=today, count=1))
        return True
    if row.count >= limit:
        return False
    row.count += 1
    return True


def purge_anon_quota(session: Session, keep_days: int = 3) -> int:
    """Drop counters that can no longer be reached. Returns rows removed."""
    cutoff = _now().date() - timedelta(days=keep_days)
    result = session.execute(AnonQuota.__table__.delete().where(AnonQuota.day < cutoff))
    return result.rowcount or 0


# --- api keys ------------------------------------------------------------

def api_key_by_secret(session: Session, secret: str) -> ApiKey | None:
    digest = hashlib.sha256(secret.encode()).digest()
    return session.execute(
        select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.active.is_(True))
    ).scalar_one_or_none()


def create_api_key(session: Session, name: str) -> tuple[str, str]:
    """Create a key and return (id, secret). The secret is shown once."""
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    key = ApiKey(
        id=str(uuid.uuid4()),
        name=name,
        key_hash=hashlib.sha256(secret.encode()).digest(),
        created_at=_now(),
    )
    session.add(key)
    append_audit(session, name, "api_key.create", {"api_key_id": key.id})
    return key.id, secret


# --- self-service keys ---------------------------------------------------

def recent_key_requests(session: Session, ip: str, within_hours: int = 24) -> int:
    """How many key requests came from this address recently."""
    since = _now() - timedelta(hours=within_hours)
    return session.execute(
        select(func.count())
        .select_from(KeyRequest)
        .where(KeyRequest.ip_hash == hash_client(ip), KeyRequest.requested_at >= since)
    ).scalar_one()


def create_key_request(
    session: Session, email: str, organisation: str | None, ip: str
) -> tuple[KeyRequest, str]:
    """Create a pending request and return it with its one-time token.

    The token is returned to the caller (to build the confirmation link) but
    stored hashed, so a copy of the database cannot be used to claim a pending
    request.
    """
    token = secrets.token_urlsafe(32)
    now = _now()
    row = KeyRequest(
        id=str(uuid.uuid4()),
        email=email.strip().lower(),
        organisation=(organisation or "").strip() or None,
        token_hash=hashlib.sha256(token.encode()).digest(),
        ip_hash=hash_client(ip),
        requested_at=now,
        expires_at=now + timedelta(hours=settings.key_request_ttl_hours),
    )
    session.add(row)
    append_audit(session, row.email, "key_request.create", {"request_id": row.id})
    return row, token


def confirm_key_request(session: Session, token: str) -> tuple[str, str] | None:
    """Turn a valid token into a real API key. Returns (key_id, secret).

    None when the token is unknown, already used or expired — the caller must
    not distinguish between those cases to a stranger.
    """
    row = session.execute(
        select(KeyRequest).where(KeyRequest.token_hash == hashlib.sha256(token.encode()).digest())
    ).scalar_one_or_none()
    if row is None or row.confirmed_at is not None or as_utc(row.expires_at) < _now():
        return None

    label = row.organisation or row.email
    key_id, secret = create_api_key(session, label)
    row.confirmed_at = _now()
    row.api_key_id = key_id
    append_audit(session, row.email, "key_request.confirm",
                 {"request_id": row.id, "api_key_id": key_id})
    return key_id, secret


# --- notarizations -------------------------------------------------------

def create_notarization(
    session: Session,
    document_hash: str,
    requester: ApiKey | None,
    metadata: dict[str, Any] | None,
    idempotency_key: str | None,
) -> tuple[Notarization, bool]:
    """Insert a notarization. Returns (row, created).

    An idempotency key that has been seen before returns the original row
    untouched: retrying a request must never produce a second certificate for
    the same submission.
    """
    if idempotency_key:
        existing = session.execute(
            select(Notarization).where(Notarization.idempotency_key == idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            return existing, False

    received_at = _now()
    requester_id = requester.id if requester else "anonymous"
    row = Notarization(
        id=str(uuid.uuid4()),
        document_hash=bytes.fromhex(document_hash),
        hash_algo="sha256",
        idempotency_key=idempotency_key,
        requester_id=requester.id if requester else None,
        metadata_json=json.dumps(metadata, separators=(",", ":")) if metadata else None,
        leaf_hash=leaf_hash(document_hash, received_at, requester_id, metadata),
        received_at=received_at,
        status="pending",
    )
    session.add(row)
    append_audit(session, requester_id, "notarize", {"id": row.id, "hash": document_hash})
    return row, True


def get_notarization(session: Session, certificate_id: str) -> Notarization | None:
    return session.get(Notarization, certificate_id)


def find_by_document_hash(session: Session, document_hash: str) -> list[Notarization]:
    return list(
        session.execute(
            select(Notarization)
            .where(Notarization.document_hash == bytes.fromhex(document_hash))
            .order_by(Notarization.received_at)
        ).scalars()
    )


def pending_leaves(session: Session, limit: int) -> list[PendingLeaf]:
    rows = session.execute(
        select(Notarization)
        .where(Notarization.status == "pending")
        .order_by(Notarization.received_at, Notarization.leaf_hash)
        .limit(limit)
    ).scalars()
    return [PendingLeaf(r.id, r.leaf_hash, r.received_at) for r in rows]


def batch_leaves(session: Session, batch_id: str) -> list[bytes]:
    """Every leaf of a batch, in tree order. This is what lets the service
    rebuild any inclusion proof on demand instead of storing it."""
    return list(
        session.execute(
            select(Notarization.leaf_hash)
            .where(Notarization.batch_id == batch_id)
            .order_by(Notarization.leaf_index)
        ).scalars()
    )


def recent_notarizations(session: Session, limit: int = 50) -> list[tuple]:
    """The public feed: fingerprint, time and chain reference, nothing else.

    Requester and metadata are deliberately left out. A fingerprint reveals
    nothing about a document, but a chronological list of who submitted what,
    how often and with which internal reference is commercial intelligence
    about our own customers -- and once published it cannot be unpublished.
    Anyone holding the fingerprint or the certificate still sees everything.
    """
    rows = session.execute(
        select(
            Notarization.id,
            Notarization.document_hash,
            Notarization.received_at,
            Notarization.status,
            Batch.txid,
            Batch.block_height,
            Batch.confirmations,
            Batch.chainlocked,
            Batch.ots_upgraded_at,
        )
        .outerjoin(Batch, Notarization.batch_id == Batch.id)
        .order_by(Notarization.received_at.desc())
        .limit(min(limit, 200))
    ).all()
    return list(rows)


def totals(session: Session) -> dict[str, int]:
    """Headline counters for the public page."""
    notarizations = session.execute(
        select(func.count()).select_from(Notarization)
    ).scalar_one()
    batches = session.execute(select(func.count()).select_from(Batch)).scalar_one()
    anchored = session.execute(
        select(func.count()).select_from(Batch).where(Batch.ots_upgraded_at.is_not(None))
    ).scalar_one()
    return {"notarizations": notarizations, "batches": batches, "anchored_batches": anchored}


# --- batches -------------------------------------------------------------

def record_batch(
    session: Session, merkle_root: bytes, txid: str, ordered_ids: list[str]
) -> Batch:
    batch = Batch(
        id=str(uuid.uuid4()),
        merkle_root=merkle_root,
        leaf_count=len(ordered_ids),
        txid=bytes.fromhex(txid),
        created_at=_now(),
    )
    session.add(batch)
    session.flush()
    for index, notarization_id in enumerate(ordered_ids):
        row = session.get(Notarization, notarization_id)
        row.batch_id = batch.id
        row.leaf_index = index
        row.status = "batched"
    append_audit(
        session, "batcher", "batch.publish",
        {"batch_id": batch.id, "root": merkle_root.hex(), "txid": txid, "leaves": len(ordered_ids)},
    )
    return batch


def open_batches(session: Session) -> list[Batch]:
    """Batches published but not yet ChainLocked -- the watcher's work list."""
    return list(
        session.execute(
            select(Batch).where(Batch.txid.is_not(None), Batch.chainlocked.is_(False))
            .order_by(Batch.created_at)
        ).scalars()
    )


def update_batch_status(session: Session, batch: Batch, status: dict[str, Any]) -> None:
    batch.confirmations = status.get("confirmations", 0)
    if status.get("block_hash"):
        batch.block_hash = bytes.fromhex(status["block_hash"])
        batch.block_height = status.get("block_height")
    batch.chainlocked = bool(status.get("chainlocked"))
    if batch.block_hash is not None:
        session.execute(
            Notarization.__table__.update()
            .where(Notarization.batch_id == batch.id, Notarization.status == "batched")
            .values(status="confirmed")
        )
