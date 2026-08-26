from datetime import datetime, timedelta, timezone

import pytest

from lks_notary.leaf import canonical_record, leaf_hash
from lks_notary.payload import PayloadError, batch_root, decode, single

DOC = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
WHEN = datetime(2026, 8, 25, 15, 23, 0, tzinfo=timezone.utc)


def test_record_is_stable_and_readable():
    assert canonical_record(DOC, WHEN, "req-1") == (
        b'{"algo":"sha256","hash":"' + DOC.encode() +
        b'","received_at":"2026-08-25T15:23:00Z","requester":"req-1","v":1}'
    )


def test_timezone_is_normalised_to_utc():
    other = WHEN.astimezone(timezone(timedelta(hours=2)))
    assert leaf_hash(DOC, WHEN, "req-1") == leaf_hash(DOC, other, "req-1")


def test_naive_timestamp_is_refused():
    with pytest.raises(ValueError):
        leaf_hash(DOC, WHEN.replace(tzinfo=None), "req-1")


def test_hash_case_does_not_change_the_leaf():
    assert leaf_hash(DOC.upper(), WHEN, "req-1") == leaf_hash(DOC, WHEN, "req-1")


def test_metadata_changes_the_leaf():
    assert leaf_hash(DOC, WHEN, "req-1", {"title": "x"}) != leaf_hash(DOC, WHEN, "req-1")


def test_payload_round_trip():
    root = bytes.fromhex(DOC)
    encoded = batch_root(root).encode()
    assert len(encoded) == 38
    assert encoded.startswith(b"LKSN")
    assert decode(encoded).digest == root


def test_single_and_batch_are_distinguishable():
    root = bytes.fromhex(DOC)
    assert decode(single(root).encode()).type != decode(batch_root(root).encode()).type


def test_foreign_nulldata_output_is_rejected():
    with pytest.raises(PayloadError):
        decode(b"OTHR" + bytes([1, 1]) + bytes(32))
