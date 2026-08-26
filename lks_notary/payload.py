"""The 38-byte OP_RETURN payload written on the LKSCOIN chain.

    offset  len  field
    0       4    magic    b"LKSN"
    4       1    version  0x01
    5       1    type     0x01 batch Merkle root | 0x02 single notarization
    6       32   payload  SHA-256 digest

The magic lets anyone scan the chain and index every notarization without
knowing the service exists. 38 bytes are well inside MAX_OP_RETURN_RELAY (83),
which is the same on LKSCOIN 3.3.0, 4.17.x and 5.18.x -- verified in the
sources and on the live network (plan section 2.1).
"""
from __future__ import annotations

from dataclasses import dataclass

MAGIC = b"LKSN"
VERSION = 1
TYPE_BATCH_ROOT = 1
TYPE_SINGLE = 2
PAYLOAD_LEN = 38


class PayloadError(ValueError):
    pass


@dataclass(frozen=True)
class Payload:
    version: int
    type: int
    digest: bytes

    def encode(self) -> bytes:
        if len(self.digest) != 32:
            raise PayloadError(f"digest must be 32 bytes, got {len(self.digest)}")
        return MAGIC + bytes([self.version, self.type]) + self.digest

    def hex(self) -> str:
        return self.encode().hex()


def batch_root(root: bytes) -> Payload:
    return Payload(VERSION, TYPE_BATCH_ROOT, root)


def single(document_hash: bytes) -> Payload:
    return Payload(VERSION, TYPE_SINGLE, document_hash)


def decode(raw: bytes) -> Payload:
    """Parse a payload read back from the chain. Raises on anything that is not
    ours, so a chain scanner can call it on every nulldata output."""
    if len(raw) != PAYLOAD_LEN:
        raise PayloadError(f"expected {PAYLOAD_LEN} bytes, got {len(raw)}")
    if raw[:4] != MAGIC:
        raise PayloadError("not an LKS Notary payload")
    version, type_ = raw[4], raw[5]
    if version != VERSION:
        raise PayloadError(f"unsupported payload version {version}")
    if type_ not in (TYPE_BATCH_ROOT, TYPE_SINGLE):
        raise PayloadError(f"unknown payload type {type_}")
    return Payload(version, type_, raw[6:])
