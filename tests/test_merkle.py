import hashlib

import pytest

from lks_notary.merkle import build_levels, proof, root, sha256, verify


def leaves(n: int) -> list[bytes]:
    return [hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n)]


def test_single_leaf_is_its_own_root():
    only = leaves(1)
    assert root(only) == only[0]


def test_two_leaves_are_concatenated_in_order():
    a, b = leaves(2)
    assert root([a, b]) == sha256(a + b)


def test_odd_leaf_is_promoted_not_duplicated():
    a, b, c = leaves(3)
    assert root([a, b, c]) == sha256(sha256(a + b) + c)


def test_promotion_prevents_cve_2012_2459_collision():
    # With Bitcoin's duplication rule, [a, b, c] and [a, b, c, c] share a root.
    a, b, c = leaves(3)
    assert root([a, b, c]) != root([a, b, c, c])


@pytest.mark.parametrize("n", range(1, 34))
def test_every_leaf_proves_its_own_inclusion(n):
    ls = leaves(n)
    r = root(ls)
    for i, leaf in enumerate(ls):
        assert verify(leaf, proof(ls, i), r), f"leaf {i} of {n} failed"


def test_a_foreign_leaf_cannot_be_proven():
    ls = leaves(8)
    outsider = hashlib.sha256(b"never notarized").digest()
    assert not verify(outsider, proof(ls, 3), root(ls))


def test_tampering_with_a_proof_step_breaks_verification():
    ls = leaves(8)
    path = proof(ls, 3)
    path[0] = type(path[0])(hashlib.sha256(b"forged").digest(), path[0].is_left)
    assert not verify(ls[3], path, root(ls))


def test_levels_shrink_to_a_single_root():
    assert [len(level) for level in build_levels(leaves(5))] == [5, 3, 2, 1]


def test_empty_tree_is_refused():
    with pytest.raises(ValueError):
        root([])


def test_wrong_size_leaf_is_refused():
    with pytest.raises(ValueError):
        root([b"too-short"])
