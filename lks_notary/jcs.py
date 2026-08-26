"""JSON Canonicalization Scheme (RFC 8785).

Only the subset a notarization record can legitimately contain is supported.
Anything ambiguous is rejected rather than silently canonicalized in a way a
third-party verifier might not reproduce -- the whole point of the leaf hash is
that anyone can recompute it.

Deliberate restrictions, all raising ``JcsError``:

* floats are refused. A float cannot be re-read from JSON without depending on
  the reader's number parsing, and RFC 8785 number serialisation follows
  ECMAScript rules that are easy to get subtly wrong. Callers that need
  fractional values must send them as strings.
* NaN, Infinity and integers outside the IEEE-754 safe range are refused.
* non-string object keys are refused.
"""
from __future__ import annotations

import json
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


class JcsError(ValueError):
    """The value cannot be canonicalized unambiguously."""


def _check(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise JcsError(f"integer out of the IEEE-754 safe range: {value}")
        return
    if isinstance(value, float):
        raise JcsError("floats are not accepted; send fractional values as strings")
    if isinstance(value, list):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise JcsError(f"object keys must be strings, got {type(key).__name__}")
            _check(item)
        return
    raise JcsError(f"unsupported type: {type(value).__name__}")


def _sort(value: Any) -> Any:
    """Recursively sort object keys by UTF-16 code unit, as RFC 8785 requires."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return {k: _sort(v) for k, v in items}
    if isinstance(value, list):
        return [_sort(v) for v in value]
    return value


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    _check(value)
    return json.dumps(
        _sort(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
