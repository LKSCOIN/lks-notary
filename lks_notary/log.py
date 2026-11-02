"""LKS Log — seals over system and activity logs.

Like Trace, a domain layer over the notary primitive: a seal's canonical record
is hashed and the digest becomes an ordinary notarisation, so it rides in the
same Merkle batch and gets the same Bitcoin anchor.

Two trees are involved and they should not be confused. The agent builds the
*entries* tree on the customer's machine, over salted fingerprints of the log
lines; only its root ever reaches us. That root goes into the seal, and the seal
digest becomes one leaf of the notary's *batch* tree.

Lines are salted because a log line has little entropy: without a salt, a sibling
hash in a single-entry proof could be matched by guessing likely lines, and the
proof would disclose the entries around the one being shown.

``lks_log.py`` reimplements the functions below on purpose, because it has to
work copied alone onto any machine. tests/test_log.py holds the two to the same
bytes.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any

from .jcs import canonicalize

RECORD_VERSION = 1
ENTRY_TAG = b"LKSLOG1\0"
HEX64_LEN = 64

# How late a seal may be before the pause counts as a gap. One interval of slack
# absorbs a restart or a slow cycle without reporting every hiccup as an event.
GAP_TOLERANCE = 2


class LogError(ValueError):
    pass


def format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise LogError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_salt(batch_secret: bytes, index: int) -> bytes:
    """Per-entry salt, derived so that disclosing one reveals nothing of the rest."""
    return hmac.new(batch_secret, index.to_bytes(8, "big"), hashlib.sha256).digest()


def entry_leaf(salt: bytes, line: bytes) -> bytes:
    """Leaf of the entries tree. ``line`` excludes its line terminator."""
    return hashlib.sha256(ENTRY_TAG + salt + line).digest()


def canonical_seal(
    *,
    stream_id: str,
    sequence: int,
    interval_seconds: int,
    entry_count: int,
    window_start: datetime,
    window_end: datetime,
    entries_root: str | None = None,
    previous_seal: str | None = None,
) -> bytes:
    """The canonical JSON of one seal — what actually gets hashed.

    An empty batch is still a seal: without it, an agent that was stopped and a
    system that logged nothing would look exactly the same.
    """
    if sequence < 1:
        raise LogError("sequence starts at 1")
    if entry_count < 0:
        raise LogError("entry_count cannot be negative")
    if (entry_count > 0) != bool(entries_root):
        raise LogError("entries_root is required with entries and refused without them")
    if sequence == 1 and previous_seal:
        raise LogError("the first seal has no predecessor")
    if sequence > 1 and not previous_seal:
        raise LogError("every seal after the first must name its predecessor")
    if window_start > window_end:
        raise LogError("window_start is after window_end")

    record: dict[str, Any] = {
        "v": RECORD_VERSION,
        "stream": stream_id,
        "sequence": sequence,
        "interval": interval_seconds,
        "entry_count": entry_count,
        "window_start": format_time(window_start),
        "window_end": format_time(window_end),
    }
    if entries_root:
        record["entries_root"] = entries_root
    if previous_seal:
        record["previous_seal"] = previous_seal
    return canonicalize(record)


def seal_hash(record: bytes) -> bytes:
    return hashlib.sha256(record).digest()


def check_chain(seals: list[dict[str, Any]], expected_previous: str | None = None) -> list[str]:
    """Replay a run of consecutive seals. Returns the problems found.

    Each item needs ``sequence``, ``canonical_record``, ``seal_hash`` and
    ``previous_seal``. ``expected_previous`` is the hash the run must continue
    from, when it does not start at sequence 1.
    """
    problems: list[str] = []
    previous = expected_previous
    expected_sequence = seals[0]["sequence"] if seals else 1
    for seal in seals:
        number = seal["sequence"]
        if number != expected_sequence:
            problems.append(f"expected seal {expected_sequence}, found {number}")
        if seal_hash(seal["canonical_record"].encode()).hex() != seal["seal_hash"]:
            problems.append(f"seal {number}: the hash does not match its record")
        if seal.get("previous_seal") != previous and (number > 1 or previous):
            problems.append(f"seal {number}: does not link to the previous seal")
        previous = seal["seal_hash"]
        expected_sequence = number + 1
    return problems


def find_gaps(
    times: list[tuple[int, datetime]],
    interval_seconds: int,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Pauses in sealing, from (sequence, received_at) pairs in order.

    ``received_at`` is part of the notarised record, so these gaps rest on the
    proofs rather than on what the agent declared. When ``now`` is given, a stream
    that has gone quiet is reported too: its last gap has no end yet.
    """
    limit = interval_seconds * GAP_TOLERANCE
    gaps: list[dict[str, Any]] = []
    for (before, start), (_, end) in zip(times, times[1:]):
        seconds = int((end - start).total_seconds())
        if seconds > limit:
            gaps.append({"after_sequence": before, "from": format_time(start),
                         "to": format_time(end), "seconds": seconds})
    if now is not None and times:
        before, start = times[-1]
        seconds = int((now - start).total_seconds())
        if seconds > limit:
            gaps.append({"after_sequence": before, "from": format_time(start),
                         "to": None, "seconds": seconds})
    return gaps
