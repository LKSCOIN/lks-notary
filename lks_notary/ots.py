"""Bitcoin anchoring through OpenTimestamps.

LKSCOIN's hashrate is small, so a proof that rests only on the LKSCOIN chain is
contestable. Anchoring every batch root to Bitcoin removes that objection: the
attestation is independent of the LKS Foundation, of this service and of the
LKSCOIN network's survival.

We stamp a file whose content is exactly the 32 raw bytes of the Merkle root,
using the official ``ots`` client rather than re-implementing the ``.ots``
serialisation. The Bitcoin attestation therefore covers ``SHA-256(merkle_root)``
-- one extra hash step, documented here and in the verifier, and reproducible by
anyone: write the root to a file, run ``ots verify``.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

log = logging.getLogger(__name__)


def _binary() -> str | None:
    """Locate the ``ots`` client.

    It is normally installed inside the virtualenv, next to the interpreter
    running us -- and systemd gives the service a bare PATH that does not
    include the venv, so looking only at PATH would silently disable Bitcoin
    anchoring. Checked in order: explicit override, next to the interpreter,
    then PATH.
    """
    override = os.getenv("LKS_OTS_BINARY")
    if override:
        return override if os.access(override, os.X_OK) else None
    beside = Path(sys.executable).with_name("ots")
    if beside.is_file() and os.access(beside, os.X_OK):
        return str(beside)
    return shutil.which("ots")


class OtsUnavailable(RuntimeError):
    pass


def available() -> bool:
    return _binary() is not None


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    binary = _binary()
    if binary is None:
        raise OtsUnavailable("the 'ots' client is not installed (pip install opentimestamps-client)")
    return subprocess.run([binary, *args], cwd=cwd, capture_output=True, text=True, timeout=120)


def stamp(merkle_root: bytes) -> bytes:
    """Submit the root to the public calendars and return the .ots proof.

    The proof comes back incomplete: calendars answer immediately with a pending
    attestation and the Bitcoin one only exists after the next block that
    includes their aggregation, typically a few hours. See :func:`upgrade`.
    """
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        target = directory / "root.bin"
        target.write_bytes(merkle_root)
        result = _run(["stamp", target.name], directory)
        proof = directory / "root.bin.ots"
        if result.returncode != 0 or not proof.exists():
            raise RuntimeError(f"ots stamp failed: {result.stderr.strip()}")
        return proof.read_bytes()


def upgrade(merkle_root: bytes, proof: bytes) -> tuple[bytes, bool]:
    """Try to complete a pending proof. Returns (proof, upgraded)."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "root.bin").write_bytes(merkle_root)
        proof_path = directory / "root.bin.ots"
        proof_path.write_bytes(proof)
        result = _run(["upgrade", proof_path.name], directory)
        upgraded = proof_path.read_bytes()
        # The client rewrites the file only when it managed to complete it.
        return upgraded, upgraded != proof and result.returncode == 0


def verify(merkle_root: bytes, proof: bytes) -> str:
    """Run ``ots verify`` and return its human-readable verdict."""
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "root.bin").write_bytes(merkle_root)
        (directory / "root.bin.ots").write_bytes(proof)
        result = _run(["verify", "root.bin.ots"], directory)
        return (result.stderr or result.stdout).strip()
