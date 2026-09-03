"""LKS Trace — lot identity, events and genealogy.

A traceability event is notarised exactly like a document: its canonical record
is hashed, the digest becomes a Merkle leaf, and the leaf travels in the same
batch as everything else. Trace is therefore a domain layer over the notary
primitive, not a second system — one batcher, one watcher, one Bitcoin anchor.

What is recorded is the *proof of the event*, not the industrial data. The
company publishes the few fields it wants visible; anything confidential stays
in its own systems and is committed to only as `metadata_hash`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .jcs import canonicalize

EVENT_TYPES = (
    "CREATE", "UPDATE", "TRANSFORM", "SPLIT", "MERGE", "QUALITY_CHECK",
    "CERTIFY", "SHIP", "RECEIVE", "RECALL", "VERIFY",
)

# Events that may name source lots, and events that may create new ones.
CONSUMES_PARENTS = {"TRANSFORM", "SPLIT", "MERGE"}
CREATES_CHILDREN = {"TRANSFORM", "SPLIT", "MERGE"}

RECORD_VERSION = 1

# GS1 element strings we understand: (01) GTIN-14, (10) batch, (21) serial.
GS1_DIGITAL_LINK = re.compile(r"^01/(\d{14})/(?:10/([^/]{1,20})|21/([^/]{1,20}))$")
GS1_BRACKETS = re.compile(r"^\((01)\)(\d{14})\((?:(10)|(21))\)([^()]{1,20})$")


class TraceError(ValueError):
    pass


@dataclass(frozen=True)
class LotId:
    """A lot identifier, GS1-aware but not GS1-only.

    Refusing anything that is not a valid GTIN would keep the standard pure and
    the service empty: almost nobody evaluating it has a GTIN to hand. So any
    identifier is accepted, GS1 ones are recognised, and only the recognised
    ones get a Digital Link URI and a resolvable QR code.
    """

    raw: str
    gtin: str | None = None
    batch: str | None = None
    serial: str | None = None

    @property
    def is_gs1(self) -> bool:
        return self.gtin is not None

    def digital_link(self, base: str) -> str | None:
        """Canonical GS1 Digital Link URI, when the identifier is GS1."""
        if not self.is_gs1:
            return None
        tail = f"10/{self.batch}" if self.batch else f"21/{self.serial}"
        return f"{base.rstrip('/')}/01/{self.gtin}/{tail}"

    def to_json(self) -> dict[str, Any]:
        return {"lot_id": self.raw, "gs1": self.is_gs1, "gtin": self.gtin,
                "batch": self.batch, "serial": self.serial}


def gtin_check_digit_ok(gtin: str) -> bool:
    """GS1 modulo-10 check digit.

    Verified rather than assumed: a mistyped GTIN that still looks like one is
    worse than an obviously free-form identifier, because it will fail to
    resolve in somebody else's system months later.
    """
    if len(gtin) != 14 or not gtin.isdigit():
        return False
    digits = [int(c) for c in gtin]
    total = sum(d * (3 if i % 2 == 0 else 1) for i, d in enumerate(digits[:13]))
    return (10 - total % 10) % 10 == digits[13]


def parse_lot_id(raw: str) -> LotId:
    raw = raw.strip()
    if not raw or len(raw) > 120:
        raise TraceError("lot_id must be between 1 and 120 characters")

    m = GS1_DIGITAL_LINK.match(raw.replace("https://id.gs1.org/", "").lstrip("/"))
    if m and gtin_check_digit_ok(m.group(1)):
        return LotId(raw, gtin=m.group(1), batch=m.group(2), serial=m.group(3))

    m = GS1_BRACKETS.match(raw)
    if m and gtin_check_digit_ok(m.group(2)):
        is_batch = m.group(3) == "10"
        return LotId(raw, gtin=m.group(2),
                     batch=m.group(5) if is_batch else None,
                     serial=None if is_batch else m.group(5))

    return LotId(raw)


def canonical_event(
    *,
    lot_id: str,
    event_type: str,
    occurred_at: datetime,
    organization: str,
    product_code: str | None = None,
    quantity: str | None = None,
    unit: str | None = None,
    facility: str | None = None,
    parent_lots: list[str] | None = None,
    child_lots: list[str] | None = None,
    metadata_hash: str | None = None,
    previous_event_hash: str | None = None,
) -> bytes:
    """The canonical JSON of one event — what actually gets hashed.

    ``previous_event_hash`` chains each event to the one before it on the same
    lot. The Merkle proof shows *when* an event was recorded; the chain shows
    that the history was not reordered or silently pruned afterwards.

    Quantities are strings on purpose: JCS refuses floats, and a quantity that
    a verifier cannot reproduce byte for byte is a quantity that cannot be
    proved.
    """
    if event_type not in EVENT_TYPES:
        raise TraceError(f"unknown event type {event_type!r}")
    if occurred_at.tzinfo is None:
        raise TraceError("occurred_at must be timezone-aware")

    record: dict[str, Any] = {
        "v": RECORD_VERSION,
        "lot_id": lot_id,
        "event": event_type,
        "occurred_at": occurred_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "organization": organization,
    }
    optional = {
        "product_code": product_code, "quantity": quantity, "unit": unit,
        "facility": facility, "metadata_hash": metadata_hash,
        "previous_event_hash": previous_event_hash,
    }
    record.update({k: v for k, v in optional.items() if v})
    if parent_lots:
        record["parent_lots"] = sorted(parent_lots)
    if child_lots:
        record["child_lots"] = sorted(child_lots)
    return canonicalize(record)


def event_hash(record: bytes) -> bytes:
    return hashlib.sha256(record).digest()


def genealogy(edges: list[tuple[str, str]], start: str, downstream: bool = True) -> list[str]:
    """Walk the lot graph from ``start``.

    ``edges`` are (parent, child) pairs. Downstream answers "which lots came
    out of this one", which is the targeted-recall question; upstream answers
    "what went into this one", which is the origin question.

    Cycles cannot occur in a correct dataset but are guarded against anyway: a
    recall that loops forever is worse than one that stops early.
    """
    graph: dict[str, list[str]] = {}
    for parent, child in edges:
        a, b = (parent, child) if downstream else (child, parent)
        graph.setdefault(a, []).append(b)

    seen: set[str] = set()
    order: list[str] = []
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in graph.get(node, []):
            if nxt not in seen:
                seen.add(nxt)
                order.append(nxt)
                stack.append(nxt)
    return order


# The one-click demo scenario: (lot key, event, note, quantity, unit).
# Domain data, not database code, so it stays testable without a database —
# and its shape is asserted in the test suite, because this is the first thing
# a visitor sees and a broken demo is worse than no demo.
DEMO_STEPS = [
    ("RAW",  "CREATE",        "Steel coil received from the mill",        "2400", "kg"),
    ("A",    "TRANSFORM",     "Coil cut and pressed into blanks",         "2350", "kg"),
    ("B1",   "SPLIT",         "Blanks split for two customer orders",     "1200", "kg"),
    ("B2",   "SPLIT",         "Second half of the same production run",   "1150", "kg"),
    ("B1",   "QUALITY_CHECK", "Dimensional check passed on order batch",  None,   None),
    ("B1",   "SHIP",          "Shipped to the customer",                  "1200", "kg"),
]
