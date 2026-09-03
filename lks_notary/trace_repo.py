"""Data access for LKS Trace.

Every event is written together with the notarisation that proves it: the two
inserts share one transaction, so a lot can never show an event that has no
proof queued, nor a proof that refers to an event nobody can read.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import repository, trace
from .trace import DEMO_STEPS
from .models import ApiKey, Notarization, TraceEvent, TraceLink, TraceLot


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _precise_now() -> datetime:
    """Timestamps used for ordering keep their microseconds.

    ``occurred_at`` is declared by the caller and rounded to the second, because
    that is what goes into the canonical record and must be reproducible. But
    two events declared in the same second still have an order, and losing it
    turns a chain of custody into a bag of events — so ``recorded_at`` keeps
    full precision and breaks the tie.
    """
    return datetime.now(timezone.utc)


def get_lot(session: Session, lot_id: str) -> TraceLot | None:
    return session.get(TraceLot, lot_id)


def lot_events(session: Session, lot_id: str) -> list[TraceEvent]:
    return list(
        session.execute(
            select(TraceEvent)
            .where(TraceEvent.lot_id == lot_id)
            .order_by(TraceEvent.occurred_at, TraceEvent.recorded_at)
        ).scalars()
    )


def last_event_hash(session: Session, lot_id: str) -> bytes | None:
    return session.execute(
        select(TraceEvent.event_hash)
        .where(TraceEvent.lot_id == lot_id)
        .order_by(TraceEvent.recorded_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def all_edges(session: Session) -> list[tuple[str, str]]:
    return [tuple(row) for row in session.execute(
        select(TraceLink.parent_lot, TraceLink.child_lot)
    ).all()]


def record_event(
    session: Session,
    *,
    lot_id: str,
    event_type: str,
    organization: str,
    occurred_at: datetime | None = None,
    product_code: str | None = None,
    quantity: str | None = None,
    unit: str | None = None,
    facility: str | None = None,
    parent_lots: list[str] | None = None,
    metadata_hash: str | None = None,
    requester: ApiKey | None = None,
) -> tuple[TraceEvent, Notarization]:
    """Record one event and queue its proof.

    Creates the lot on first sight. ``parent_lots`` are the lots this event
    consumes; the edges are written from them to this lot, which is what makes
    a targeted recall a graph walk rather than a guess.
    """
    parsed = trace.parse_lot_id(lot_id)
    occurred = occurred_at or _now()
    if occurred.tzinfo is None:
        raise trace.TraceError("occurred_at must be timezone-aware")

    lot = get_lot(session, parsed.raw)
    if lot is None:
        lot = TraceLot(
            lot_id=parsed.raw, gtin=parsed.gtin, batch=parsed.batch, serial=parsed.serial,
            product_code=product_code, organization=organization,
            requester_id=requester.id if requester else None,
            status="active", created_at=_now(), updated_at=_now(),
        )
        session.add(lot)
        session.flush()
    else:
        lot.updated_at = _now()
        if product_code and not lot.product_code:
            lot.product_code = product_code
    if event_type == "RECALL":
        lot.status = "recalled"

    previous = last_event_hash(session, parsed.raw)
    record = trace.canonical_event(
        lot_id=parsed.raw, event_type=event_type, occurred_at=occurred,
        organization=organization, product_code=product_code, quantity=quantity,
        unit=unit, facility=facility, parent_lots=parent_lots,
        metadata_hash=metadata_hash,
        previous_event_hash=previous.hex() if previous else None,
    )
    digest = trace.event_hash(record)

    # The proof: the event digest is notarised exactly like a document hash, so
    # it rides in the same Merkle batch and gets the same Bitcoin anchor.
    notarization, _ = repository.create_notarization(
        session,
        digest.hex(),
        requester,
        {"kind": "trace_event", "lot_id": parsed.raw, "event": event_type},
        f"trace:{digest.hex()}",          # idempotency: the same event twice is one proof
    )

    event = TraceEvent(
        id=str(uuid.uuid4()), lot_id=parsed.raw, event_type=event_type,
        occurred_at=occurred, recorded_at=_precise_now(), organization=organization,
        facility=facility, quantity=quantity, unit=unit,
        metadata_hash=bytes.fromhex(metadata_hash) if metadata_hash else None,
        canonical_record=record.decode(), event_hash=digest,
        previous_hash=previous, notarization_id=notarization.id,
    )
    session.add(event)
    session.flush()

    for parent in parent_lots or []:
        parent_parsed = trace.parse_lot_id(parent)
        if get_lot(session, parent_parsed.raw) is None:
            session.add(TraceLot(
                lot_id=parent_parsed.raw, gtin=parent_parsed.gtin, batch=parent_parsed.batch,
                serial=parent_parsed.serial, organization=organization,
                requester_id=requester.id if requester else None,
                status="active", created_at=_now(), updated_at=_now()))
            session.flush()
        session.add(TraceLink(parent_lot=parent_parsed.raw, child_lot=parsed.raw,
                              event_id=event.id))

    repository.append_audit(
        session, organization, "trace.event",
        {"lot_id": parsed.raw, "event": event_type, "event_hash": digest.hex()},
    )
    return event, notarization


def event_to_json(session: Session, event: TraceEvent, base_url: str) -> dict[str, Any]:
    """One event with its proof status, as a third party would need it."""
    proof: dict[str, Any] = {"certificate_id": event.notarization_id}
    if event.notarization_id:
        n = session.get(Notarization, event.notarization_id)
        if n is not None:
            proof["status"] = n.status
            proof["verify_url"] = f"{base_url}/v/{n.id}"
    return {
        "event_id": event.id,
        "type": event.event_type,
        "occurred_at": repository.as_utc(event.occurred_at).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization": event.organization,
        "facility": event.facility,
        "quantity": event.quantity,
        "unit": event.unit,
        "metadata_hash": event.metadata_hash.hex() if event.metadata_hash else None,
        "canonical_record": event.canonical_record,
        "event_hash": event.event_hash.hex(),
        "previous_hash": event.previous_hash.hex() if event.previous_hash else None,
        "proof": proof,
    }




def create_demo(session: Session, requester: ApiKey | None = None) -> dict[str, Any]:
    """Build a small but realistic supply chain in one call.

    Six events, a split and a quality check, so a visitor immediately sees the
    thing that matters — the genealogy — instead of having to type five forms
    before the product makes any sense. Identifiers carry a timestamp so two
    people trying the demo at the same moment do not collide.
    """
    stamp = _now().strftime("%Y%m%d%H%M%S")
    lots = {k: f"DEMO-{stamp}-{k}" for k in ("RAW", "A", "B1", "B2")}
    parents = {"A": ["RAW"], "B1": ["A"], "B2": ["A"]}
    created: list[dict[str, Any]] = []

    for key, event_type, note, qty, unit, hours_ago in DEMO_STEPS:
        event, notarization = record_event(
            session,
            occurred_at=_now() - timedelta(hours=hours_ago),
            lot_id=lots[key], event_type=event_type,
            organization="Demo Manufacturing Ltd",
            product_code="DEMO-PRESSED-PART",
            quantity=qty, unit=unit, facility="Plant 1 — Demo",
            parent_lots=[lots[p] for p in parents.get(key, [])] if event_type != "CREATE" else None,
            requester=requester,
        )
        created.append({"lot_id": lots[key], "event": event_type, "note": note,
                        "event_id": event.id, "certificate_id": notarization.id})

    return {"lots": lots, "events": created, "entry_point": lots["RAW"]}
