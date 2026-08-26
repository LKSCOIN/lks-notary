"""Merkle tree over SHA-256 leaves.

Two properties matter for the notary and both differ from Bitcoin's tree:

* an odd node is **promoted** to the next level, never duplicated. Duplicating
  it is what makes two distinct trees share a root (CVE-2012-2459) and would let
  someone claim an inclusion proof for a document that was never notarized.
* leaves are ordered by the caller (reception time, then hash), so the tree is
  reproducible by anyone holding the same set of records.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

DIGEST_SIZE = 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the path from a leaf to the root."""

    hash: bytes
    is_left: bool  # True when the sibling sits on the left of the running hash

    def to_json(self) -> dict:
        return {"hash": self.hash.hex(), "position": "left" if self.is_left else "right"}


def _validate(leaves: list[bytes]) -> None:
    if not leaves:
        raise ValueError("cannot build a Merkle tree over an empty leaf set")
    for leaf in leaves:
        if len(leaf) != DIGEST_SIZE:
            raise ValueError(f"leaf must be {DIGEST_SIZE} bytes, got {len(leaf)}")


def build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Return every level of the tree, from the leaves up to the single root."""
    _validate(leaves)
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        nxt: list[bytes] = []
        for i in range(0, len(current) - 1, 2):
            nxt.append(sha256(current[i] + current[i + 1]))
        if len(current) % 2 == 1:
            nxt.append(current[-1])  # promoted, not duplicated
        levels.append(nxt)
    return levels


def root(leaves: list[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]


def proof(leaves: list[bytes], index: int) -> list[ProofStep]:
    """Inclusion proof for the leaf at ``index``."""
    levels = build_levels(leaves)
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range")
    path: list[ProofStep] = []
    for level in levels[:-1]:
        if index == len(level) - 1 and len(level) % 2 == 1:
            index //= 2  # promoted: no sibling at this level, but the index still moves up
            continue
        if index % 2 == 0:
            path.append(ProofStep(level[index + 1], is_left=False))
        else:
            path.append(ProofStep(level[index - 1], is_left=True))
        index //= 2
    return path


def verify(leaf: bytes, path: list[ProofStep], expected_root: bytes) -> bool:
    """Recompute the root from a leaf and its path. Pure function: a third-party
    verifier needs nothing else."""
    running = leaf
    for step in path:
        running = sha256(step.hash + running) if step.is_left else sha256(running + step.hash)
    return running == expected_root
