"""LKS Log: the seal format, and the agent agreeing with the service byte for byte."""
import hashlib
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from lks_notary import log
from lks_notary.merkle import proof, root

spec = importlib.util.spec_from_file_location(
    "lks_log", pathlib.Path(__file__).resolve().parent.parent / "lks_log.py"
)
lks_log = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lks_log)

T0 = datetime(2026, 11, 2, 9, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(minutes=5)
ROOT = "ab" * 32
PREV = "cd" * 32


def seal(**kw):
    args = dict(stream_id="s-1", sequence=2, interval_seconds=300, entry_count=3,
                window_start=T0, window_end=T1, entries_root=ROOT, previous_seal=PREV)
    args.update(kw)
    return log.canonical_seal(**args)


def agent_seal(**kw):
    fields = dict(stream_id="s-1", sequence=2, interval_seconds=300, entry_count=3,
                  window_start=log.format_time(T0), window_end=log.format_time(T1),
                  entries_root=ROOT, previous_seal=PREV)
    fields.update(kw)
    return lks_log.canonical_seal(fields)


# --- agreement: if these drift, every proof an agent writes stops verifying ---

def test_agent_and_service_build_the_same_record():
    assert agent_seal() == seal()


def test_agent_and_service_agree_on_an_empty_first_seal():
    args = dict(sequence=1, entry_count=0, entries_root=None, previous_seal=None)
    assert agent_seal(**args) == seal(**args)


def test_agent_and_service_build_the_same_leaf():
    secret = b"k" * 32
    for index in (0, 1, 7, 100_000):
        salt = log.entry_salt(secret, index)
        assert lks_log.entry_salt(secret, index) == salt
        assert lks_log.entry_leaf(salt, b"line \xc3\xa8") == log.entry_leaf(salt, b"line \xc3\xa8")


def test_agent_builds_the_same_tree_as_the_notary_for_every_shape():
    for n in range(1, 20):
        leaves = [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]
        assert lks_log.merkle_root(leaves) == root(leaves)
        for i in range(n):
            assert lks_log.merkle_path(leaves, i) == [s.to_json() for s in proof(leaves, i)], \
                f"n={n} i={i}"
            assert lks_log.recompute_root(leaves[i], lks_log.merkle_path(leaves, i)) == root(leaves)


# --- the record -----------------------------------------------------------

def test_record_is_deterministic_and_sorted():
    assert seal(entry_count=0, entries_root=None, sequence=1, previous_seal=None) == (
        b'{"entry_count":0,"interval":300,"sequence":1,"stream":"s-1","v":1,'
        b'"window_end":"2026-11-02T09:05:00Z","window_start":"2026-11-02T09:00:00Z"}'
    )


@pytest.mark.parametrize("bad", [
    {"sequence": 0},
    {"entry_count": -1},
    {"entries_root": None},                       # entries, but no root
    {"entry_count": 0},                           # a root, but no entries
    {"previous_seal": None},                      # not the first, no predecessor
    {"sequence": 1},                              # the first, with a predecessor
    {"window_start": T1, "window_end": T0},
])
def test_inconsistent_seals_are_refused(bad):
    with pytest.raises(log.LogError):
        seal(**bad)


def test_naive_timestamp_is_refused():
    with pytest.raises(log.LogError):
        log.format_time(T0.replace(tzinfo=None))


def test_a_salted_leaf_cannot_be_guessed_from_the_line():
    # The reason the salt exists: siblings travel in a proof, and log lines are guessable.
    line = b"session opened for user root"
    assert log.entry_leaf(log.entry_salt(b"a" * 32, 0), line) != \
        log.entry_leaf(log.entry_salt(b"b" * 32, 0), line)
    assert log.entry_salt(b"a" * 32, 0) != log.entry_salt(b"a" * 32, 1)


# --- chain and gaps -------------------------------------------------------

def chain(n):
    out, previous = [], None
    for i in range(1, n + 1):
        record = seal(sequence=i, previous_seal=previous)
        digest = log.seal_hash(record).hex()
        out.append({"sequence": i, "canonical_record": record.decode(), "seal_hash": digest,
                    "previous_seal": previous})
        previous = digest
    return out


def test_an_intact_chain_has_no_problems():
    assert log.check_chain(chain(5)) == []


def test_a_removed_seal_is_reported():
    seals = chain(5)
    del seals[2]
    assert any("expected seal 3" in p for p in log.check_chain(seals))


def test_an_edited_seal_is_reported():
    seals = chain(3)
    seals[1]["canonical_record"] = seals[1]["canonical_record"].replace('"entry_count":3',
                                                                       '"entry_count":2')
    assert any("does not match" in p for p in log.check_chain(seals))


def test_a_run_from_the_middle_is_checked_against_what_it_continues():
    seals = chain(5)[2:]
    assert log.check_chain(seals, seals[0]["previous_seal"]) == []
    assert log.check_chain(seals, "00" * 32) != []


def test_a_pause_is_a_gap_and_a_slow_cycle_is_not():
    times = [(1, T0), (2, T0 + timedelta(seconds=590)), (3, T0 + timedelta(seconds=5000))]
    gaps = log.find_gaps(times, 300)
    assert [g["after_sequence"] for g in gaps] == [2]
    assert gaps[0]["seconds"] == 4410


def test_a_stream_gone_quiet_is_an_open_gap():
    gaps = log.find_gaps([(1, T0)], 300, now=T0 + timedelta(hours=1))
    assert gaps == [{"after_sequence": 1, "from": "2026-11-02T09:00:00Z", "to": None,
                     "seconds": 3600}]


# --- reading logs ---------------------------------------------------------

def test_a_line_without_its_terminator_waits(tmp_path):
    source = tmp_path / "app.log"
    source.write_bytes(b"one\ntwo\nhalf")
    lines, position = lks_log.read_new_lines(str(source), None, 100)
    assert [raw for _, raw in lines] == [b"one\n", b"two\n"]

    with open(source, "ab") as handle:
        handle.write(b" done\n")
    lines, _ = lks_log.read_new_lines(str(source), position, 100)
    assert lines == [(8, b"half done\n")]


def test_rotation_starts_the_new_file_from_the_beginning(tmp_path):
    source = tmp_path / "app.log"
    source.write_bytes(b"old one\nold two\n")
    _, position = lks_log.read_new_lines(str(source), None, 100)

    source.write_bytes(b"new file, and longer than the old one was\n")
    lines, _ = lks_log.read_new_lines(str(source), position, 100)
    assert lines == [(0, b"new file, and longer than the old one was\n")]


def test_the_budget_leaves_the_rest_for_the_next_seal(tmp_path):
    source = tmp_path / "app.log"
    source.write_bytes(b"1\n2\n3\n")
    lines, position = lks_log.read_new_lines(str(source), None, 2)
    assert len(lines) == 2
    lines, _ = lks_log.read_new_lines(str(source), position, 2)
    assert [raw for _, raw in lines] == [b"3\n"]


def test_a_windows_line_ending_is_not_part_of_the_line():
    assert lks_log.strip_terminator(b"x\r\n") == b"x"
    assert lks_log.strip_terminator(b"x\n") == b"x"
