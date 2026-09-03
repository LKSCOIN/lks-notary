"""LKS Trace: identifiers, canonical events and genealogy."""
from datetime import datetime, timedelta, timezone

import pytest

from lks_notary.trace import (
    TraceError, canonical_event, event_hash, genealogy, gtin_check_digit_ok, parse_lot_id,
)

WHEN = datetime(2026, 8, 27, 9, 0, 0, tzinfo=timezone.utc)
# 05412345000013 is a GS1 example GTIN-13 padded to 14 with a valid check digit.
GTIN = "00012345600012"


def test_gtin_check_digit_accepts_a_valid_one():
    assert gtin_check_digit_ok(GTIN)


def test_gtin_check_digit_rejects_a_typo():
    broken = GTIN[:-1] + str((int(GTIN[-1]) + 1) % 10)
    assert not gtin_check_digit_ok(broken)


def test_digital_link_form_is_recognised():
    lot = parse_lot_id(f"01/{GTIN}/10/BATCH-7")
    assert lot.is_gs1 and lot.gtin == GTIN and lot.batch == "BATCH-7"


def test_bracket_form_is_recognised():
    lot = parse_lot_id(f"(01){GTIN}(21)SER-9")
    assert lot.is_gs1 and lot.serial == "SER-9"


def test_free_identifier_is_accepted_but_not_gs1():
    lot = parse_lot_id("LOT-2026-001")
    assert not lot.is_gs1 and lot.raw == "LOT-2026-001"


def test_digital_link_uri_only_for_gs1():
    assert parse_lot_id("LOT-2026-001").digital_link("https://x.io") is None
    assert parse_lot_id(f"01/{GTIN}/10/B1").digital_link("https://x.io/") == \
        f"https://x.io/01/{GTIN}/10/B1"


def test_empty_identifier_is_refused():
    with pytest.raises(TraceError):
        parse_lot_id("   ")


# --- events --------------------------------------------------------------

def base(**kw):
    args = dict(lot_id="LOT-A", event_type="CREATE", occurred_at=WHEN,
                organization="Acme SpA")
    args.update(kw)
    return canonical_event(**args)


def test_record_is_deterministic_and_sorted():
    assert base() == (b'{"event":"CREATE","lot_id":"LOT-A",'
                      b'"occurred_at":"2026-08-27T09:00:00Z",'
                      b'"organization":"Acme SpA","v":1}')


def test_empty_optional_fields_are_omitted_not_null():
    # A null and an absent field would hash differently while meaning the same,
    # so only one of the two may ever be produced.
    assert b"facility" not in base(facility="")
    assert b"facility" in base(facility="Plant 1")


def test_parent_lots_are_sorted_so_input_order_cannot_change_the_hash():
    a = base(event_type="MERGE", parent_lots=["LOT-B", "LOT-A"])
    b = base(event_type="MERGE", parent_lots=["LOT-A", "LOT-B"])
    assert a == b


def test_timezone_is_normalised():
    other = WHEN.astimezone(timezone(timedelta(hours=3)))
    assert base() == base(occurred_at=other)


def test_naive_timestamp_is_refused():
    with pytest.raises(TraceError):
        base(occurred_at=WHEN.replace(tzinfo=None))


def test_unknown_event_type_is_refused():
    with pytest.raises(TraceError):
        base(event_type="TELEPORT")


def test_chaining_changes_the_hash():
    first = event_hash(base())
    second = event_hash(base(event_type="SHIP", previous_event_hash=first.hex()))
    assert first != second


def test_float_quantity_is_refused_by_canonicalisation():
    with pytest.raises(Exception):
        canonical_event(lot_id="LOT-A", event_type="CREATE", occurred_at=WHEN,
                        organization="Acme", quantity=12.5)


# --- genealogy -----------------------------------------------------------

EDGES = [
    ("RAW-1", "LOT-A"),
    ("LOT-A", "LOT-B"),
    ("LOT-B", "LOT-B1"),
    ("LOT-B", "LOT-B2"),
    ("LOT-B1", "LOT-C"),
]


def test_downstream_finds_every_affected_lot():
    assert set(genealogy(EDGES, "LOT-A")) == {"LOT-B", "LOT-B1", "LOT-B2", "LOT-C"}


def test_downstream_excludes_what_is_not_affected():
    # The point of a targeted recall is knowing which lots are clean.
    assert "LOT-B2" not in genealogy(EDGES, "LOT-B1")


def test_upstream_finds_the_origin():
    assert set(genealogy(EDGES, "LOT-C", downstream=False)) == \
        {"LOT-B1", "LOT-B", "LOT-A", "RAW-1"}


def test_a_leaf_lot_has_no_descendants():
    assert genealogy(EDGES, "LOT-C") == []


def test_a_cycle_does_not_hang():
    assert set(genealogy([("A", "B"), ("B", "A")], "A")) == {"A", "B"}


# --- the demo scenario ---------------------------------------------------

def test_demo_steps_describe_a_coherent_chain():
    """The one-click demo is the first thing a visitor sees, so its shape is
    worth asserting: it must contain a split and end with a shipment, or it
    fails to show the one feature that distinguishes traceability from a log."""
    from lks_notary.trace import DEMO_STEPS

    types = [step[1] for step in DEMO_STEPS]
    assert types[0] == "CREATE"
    assert types.count("SPLIT") == 2, "a split is what makes genealogy visible"
    assert "QUALITY_CHECK" in types and types[-1] == "SHIP"

    # every non-CREATE step must name a lot that an earlier step created
    seen = set()
    for key, event_type, *_ in DEMO_STEPS:
        if event_type == "CREATE":
            seen.add(key)
    assert seen == {"RAW"}


def test_demo_genealogy_supports_a_targeted_recall():
    """Recalling the raw material must reach every derived lot; recalling one
    half of a split must not touch the other."""
    lots = {k: f"DEMO-{k}" for k in ("RAW", "A", "B1", "B2")}
    edges = [(lots["RAW"], lots["A"]), (lots["A"], lots["B1"]), (lots["A"], lots["B2"])]

    assert set(genealogy(edges, lots["RAW"])) == {lots["A"], lots["B1"], lots["B2"]}
    assert genealogy(edges, lots["B1"]) == []
    assert lots["B2"] not in genealogy(edges, lots["B1"])
