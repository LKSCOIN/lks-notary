import pytest

from lks_notary.jcs import JcsError, canonicalize


def test_keys_are_sorted_and_whitespace_removed():
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_nested_objects_are_sorted_recursively():
    assert canonicalize({"z": {"y": 1, "x": 2}}) == b'{"z":{"x":2,"y":1}}'


def test_array_order_is_preserved():
    assert canonicalize([3, 1, 2]) == b"[3,1,2]"


def test_rfc8785_appendix_sorting_of_unicode_keys():
    # RFC 8785 sorts by UTF-16 code unit, which is why the emoji key comes last.
    value = {"€": "euro", "a": "letter", "\U0001f600": "emoji"}
    assert canonicalize(value) == '{"a":"letter","€":"euro","\U0001f600":"emoji"}'.encode()


def test_non_ascii_is_not_escaped():
    assert canonicalize({"k": "caffè"}) == '{"k":"caffè"}'.encode("utf-8")


def test_same_record_different_insertion_order_gives_same_bytes():
    a = canonicalize({"hash": "ab", "received_at": "2026-08-25T00:00:00Z", "v": 1})
    b = canonicalize({"v": 1, "received_at": "2026-08-25T00:00:00Z", "hash": "ab"})
    assert a == b


@pytest.mark.parametrize("value", [1.5, float("nan"), float("inf")])
def test_floats_are_refused(value):
    with pytest.raises(JcsError):
        canonicalize({"n": value})


def test_unsafe_integer_is_refused():
    with pytest.raises(JcsError):
        canonicalize({"n": 2**53})


def test_non_string_key_is_refused():
    with pytest.raises(JcsError):
        canonicalize({1: "x"})
