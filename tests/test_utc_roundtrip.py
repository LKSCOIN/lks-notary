"""A datetime read back from MariaDB must rebuild the same leaf.

MariaDB DATETIME has no timezone, so SQLAlchemy hands back naive values. If the
verification endpoint recomputed the canonical record from a naive timestamp,
either it would raise (what happened the first time this ran in production) or
it would silently produce a leaf different from the one published on chain --
which is worse, because every certificate would look forged.
"""
from datetime import datetime, timezone

from lks_notary.leaf import leaf_hash
from lks_notary.leaf import as_utc

DOC = "6258a5e0eb772911d4f92be5b5db0e14511edbe01d1d0ddd1d5a2cb9db9a56ba"


def test_naive_value_from_the_database_rebuilds_the_same_leaf():
    written = datetime(2026, 8, 26, 7, 28, 48, tzinfo=timezone.utc)
    read_back = written.replace(tzinfo=None)          # what MariaDB returns
    assert leaf_hash(DOC, as_utc(read_back), "req") == leaf_hash(DOC, written, "req")


def test_aware_value_is_left_alone():
    written = datetime(2026, 8, 26, 7, 28, 48, tzinfo=timezone.utc)
    assert as_utc(written) is written
